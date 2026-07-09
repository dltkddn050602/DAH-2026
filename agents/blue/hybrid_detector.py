"""Streaming ML Detector + Drift Monitor — 기술스택 문서 §4.2.

River Half-Space Trees 로 복합·미지 이상 패턴을 보조 점수화하고, River ADWIN 으로
정상 분포 변화(드리프트)를 shadow 로 감시한다.

원칙(문서 §4.2):
  - Half-Space Trees 는 규칙 탐지기를 대체하지 않는다. 알려진 치명 징후는 규칙이
    즉시 잡고, 스트리밍 모델은 복합 이상을 보조 점수로만 제공한다.
  - 모델이 윈도우 단위로 뭉친 이상에 약할 수 있으므로 단독 차단 근거로 쓰지 않는다.
    → ML Finding 은 confidence·risk 를 상한(Medium)으로 제한하고 detector 를 명시한다.
  - river 미설치 시 결정론적으로 비활성화되며 공방·채점은 계속 동작한다.
"""
from __future__ import annotations

from collections import deque

from core.events import AttackFlow, FindingEvent, Risk, TelemetryEvent
from core.geo import haversine_m

try:
    from river import anomaly, drift
    _HAS_RIVER = True
except Exception:  # river 미설치 → 결정론 폴백
    _HAS_RIVER = False


def _feature_vector(f: dict) -> dict[str, float]:
    """텔레메트리 스냅샷 → 수치 특성 벡터(ML 입력)."""
    vec: dict[str, float] = {}
    if (s := f.get("speed")) is not None:
        vec["speed"] = float(s)
    if (b := f.get("battery_pct")) is not None:
        vec["battery"] = float(b)
    if (n := f.get("gps_sats")) is not None:
        vec["sats"] = float(n)
    if (d := f.get("drop_rate_comm")) is not None:
        vec["drop"] = float(d)
    gps, ins = f.get("position_gps"), f.get("position_ins")
    if gps and ins:
        vec["divergence"] = haversine_m(gps[0], gps[1], ins[0], ins[1])
    return vec


class StreamingMLDetector:
    """차량 단위 Half-Space Trees 이상 점수기 + ADWIN 드리프트 감시(shadow)."""
    name = "스트리밍 이상탐지(ML)"

    def __init__(self, cfg) -> None:
        self.enabled = bool(cfg.ml.enabled) and _HAS_RIVER
        self.anomaly_quantile = cfg.ml.anomaly_quantile
        self.warmup = max(30, cfg.ml.window_size // 4)
        self.seen = 0
        self.scores: deque[float] = deque(maxlen=cfg.ml.window_size)
        if self.enabled:
            self.model = anomaly.HalfSpaceTrees(
                n_trees=cfg.ml.n_trees,
                height=cfg.ml.height,
                window_size=cfg.ml.window_size,
                seed=cfg.run.seed,
            )
            # shadow 드리프트: 정상 경로를 오염시키지 않고 분포 변화만 신호
            self.adwin = drift.ADWIN(delta=cfg.ml.drift_delta)
        self._last_drift = 0

    def available(self) -> bool:
        return self.enabled

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        if not self.enabled:
            return []
        vec = _feature_vector(evt.features)
        if len(vec) < 2:
            return []
        score = self.model.score_one(vec)
        self.model.learn_one(vec)
        self.scores.append(score)
        self.seen += 1

        out: list[FindingEvent] = []
        # 드리프트(shadow): 이상 점수 스트림의 분포 변화 감시
        self.adwin.update(score)
        if self.adwin.drift_detected:
            out.append(FindingEvent(
                episode_id=evt.episode_id, vehicle=evt.vehicle,
                detector="분포 변화 감시(ADWIN)",
                signal="정상 분포 드리프트 감지 — shadow 재학습 후보",
                flow=AttackFlow.UNKNOWN, confidence=0.4, risk=Risk.LOW,
                threat_map={"note": "정상 패턴 변화(운영/공격 무관 가능)"},
                evidence={"anomaly_score": round(score, 3)},
                ts=evt.recv_ts,
            ))

        # 이상 점수: 워밍업 이후 경험적 분위수 초과 시 보조 신호
        if self.seen >= self.warmup and len(self.scores) >= self.warmup:
            thresh = self._quantile(self.anomaly_quantile)
            if score >= thresh and score > 0.5:
                out.append(FindingEvent(
                    episode_id=evt.episode_id, vehicle=evt.vehicle,
                    detector=self.name,
                    signal=f"복합 이상 점수 {score:.2f} (임계 {thresh:.2f}) — 미지 패턴 의심",
                    flow=AttackFlow.UNKNOWN,
                    confidence=min(0.6, score),   # 보조 신호 → 상한 제한
                    risk=Risk.MEDIUM,             # 단독 차단 근거로 쓰지 않음
                    threat_map={"ML": "이상탐지(보조)"},
                    evidence={"anomaly_score": round(score, 3),
                              "features": {k: round(v, 2) for k, v in vec.items()}},
                    ts=evt.recv_ts,
                ))
        return out

    def _quantile(self, q: float) -> float:
        s = sorted(self.scores)
        if not s:
            return 1.0
        idx = min(len(s) - 1, int(q * len(s)))
        return s[idx]
