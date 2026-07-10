"""규칙 탐지기 (Rule Detector) — 기술스택 문서 §4.2, 대표공격흐름 A~F.

알려진 고위험 징후를 결정론적·저지연으로 즉시 잡는다. 각 탐지기는
TelemetryEvent 를 소비하고 FindingEvent(위협모델 매핑·위험도·근거) 를 낸다.
안전 경로는 결정론적으로 유지하고, ML/LLM 결과는 별도(hybrid_detector)에서 다룬다.

흐름 커버리지:
  A 경로/상황인식  → RouteConsistencyDetector, GnssInsCrossCheck
  B C2/운용자       → CommandAnomalyDetector
  C 텔레메트리 보정 → StateConsistencyDetector
  D 통신/자율모드   → LinkHealthDetector
  E 센서/AI         → SensorConsensusDetector
  F 군집            → SwarmConsensusDetector (agent 수준, 별 파일 아님)
"""
from __future__ import annotations

import time
from collections import deque
from typing import Any

from core.events import AttackFlow, FindingEvent, Risk, TelemetryEvent
from core.geo import haversine_m


class Detector:
    """탐지기 베이스. update()는 FindingEvent 리스트를 돌려준다."""
    name = "detector"

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        raise NotImplementedError

    def _finding(self, evt: TelemetryEvent, **kw) -> FindingEvent:
        return FindingEvent(
            episode_id=evt.episode_id,
            vehicle=evt.vehicle,
            detector=kw.pop("detector", self.name),
            ts=evt.recv_ts,
            **kw,
        )


class GnssInsCrossCheck(Detector):
    """흐름 A/C — GPS_RAW_INT(원시) vs GLOBAL_POSITION_INT(EKF/INS) 교차검증."""
    name = "GNSS-INS 교차검증"

    def __init__(self, warn_m: float = 30.0, crit_m: float = 100.0) -> None:
        self.warn_m, self.crit_m = warn_m, crit_m

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        gps, ins = f.get("position_gps"), f.get("position_ins")
        if not (gps and ins):
            return []
        if "position_gps" not in f.get("updated", []) and \
           "position_ins" not in f.get("updated", []):
            return []
        d = haversine_m(gps[0], gps[1], ins[0], ins[1])
        if d < self.warn_m:
            return []
        crit = d >= self.crit_m
        return [self._finding(
            evt,
            signal=f"GNSS와 INS 위치가 {d:.0f}m 불일치 (임계 {self.warn_m:.0f}m)",
            flow=AttackFlow.A_ROUTE,
            confidence=min(1.0, d / self.crit_m),
            risk=Risk.CRITICAL if crit else Risk.HIGH,
            threat_map={
                "STRIDE": "Spoofing",
                "TARA": "경로 왜곡 → 임무 실패/충돌 위험",
                "STPA-Sec": "불안전 제어행동(위조 위치 기반 항법)",
            },
            evidence={"gps": gps, "ins": ins, "divergence_m": round(d, 1)},
        )]


class RouteConsistencyDetector(Detector):
    """흐름 A — 위치-속도 정합성. INS 위치 변화율과 보고 속도의 불일치를 본다.

    대표공격흐름 A 탐지단서: "GLOBAL_POSITION_INT 기반 위치 변화율과 보고 속도
    불일치". 미세 경로 편향을 위치 점프가 아니라 정합성 위반으로 포착한다.
    """
    name = "경로 정합성"

    def __init__(self, ratio_warn: float = 2.0, min_speed: float = 1.0) -> None:
        self.ratio_warn = ratio_warn
        self.min_speed = min_speed
        self.last_pos: list[float] | None = None
        self.last_ts: float | None = None

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        pos, rep_speed = f.get("position_ins"), f.get("speed")
        if pos is None or rep_speed is None or "position_ins" not in f.get("updated", []):
            return []
        out: list[FindingEvent] = []
        if self.last_pos is not None and self.last_ts is not None:
            dt = evt.recv_ts - self.last_ts
            if dt > 0.05:
                moved = haversine_m(self.last_pos[0], self.last_pos[1], pos[0], pos[1])
                derived = moved / dt
                # 두 독립 추정(위치미분 vs 보고속도)이 크게 어긋나면 편향 의심
                hi = max(derived, rep_speed)
                lo = max(min(derived, rep_speed), 0.01)
                if hi >= self.min_speed and (hi / lo) >= self.ratio_warn:
                    out.append(self._finding(
                        evt,
                        signal=(f"위치미분 속도 {derived:.1f}m/s vs 보고 속도 "
                                f"{rep_speed:.1f}m/s 불일치"),
                        flow=AttackFlow.A_ROUTE,
                        confidence=min(1.0, (hi / lo) / (self.ratio_warn * 2)),
                        risk=Risk.MEDIUM,
                        threat_map={"STRIDE": "Tampering",
                                    "TARA": "경로/상황인식 미세 편향"},
                        evidence={"derived_mps": round(derived, 2),
                                  "reported_mps": round(rep_speed, 2)},
                    ))
        self.last_pos, self.last_ts = pos, evt.recv_ts
        return out


class LinkHealthDetector(Detector):
    """흐름 D — HEARTBEAT 두절/지연 + 링크 품질(RSSI/손실/오류) → 재밍·DoS."""
    name = "링크 상태 감시"

    def __init__(self, expected_hz: float = 4.0, warn_factor: float = 3.0,
                 crit_gap_s: float = 3.0) -> None:
        self.expected_dt = 1.0 / expected_hz
        self.warn_dt = self.expected_dt * warn_factor
        self.crit_gap = crit_gap_s
        self.last_hb: float | None = None
        self.outage_fired = False

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        out: list[FindingEvent] = []

        # 1) 두절: link_probe 가 since_last_msg_s 를 실어옴
        if f.get("msg_type") == "LINK_PROBE":
            gap = f.get("since_last_msg_s")
            if gap is not None and gap >= self.crit_gap and not self.outage_fired:
                self.outage_fired = True
                out.append(self._finding(
                    evt, detector=self.name,
                    signal=f"텔레메트리 두절 {gap:.1f}s 지속 — 재밍/DoS 의심",
                    flow=AttackFlow.D_LINK, confidence=1.0, risk=Risk.HIGH,
                    threat_map={"STRIDE": "Denial of Service",
                                "TARA": "통신 두절 → 제어 상실"},
                    evidence={"outage_s": round(gap, 2)},
                ))
            return out

        # 2) HEARTBEAT 간격
        if "heartbeat" in f.get("updated", []):
            self.outage_fired = False
            gap = None if self.last_hb is None else evt.recv_ts - self.last_hb
            self.last_hb = evt.recv_ts
            if gap is not None and gap >= self.warn_dt:
                crit = gap >= self.crit_gap
                out.append(self._finding(
                    evt,
                    signal=f"HEARTBEAT 간격 {gap:.1f}s (정상 {self.expected_dt:.2f}s) — 링크 저하",
                    flow=AttackFlow.D_LINK,
                    confidence=min(1.0, gap / self.crit_gap),
                    risk=Risk.HIGH if crit else Risk.MEDIUM,
                    threat_map={"STRIDE": "Denial of Service",
                                "TARA": "통신 두절 → 제어 지연/상실"},
                    evidence={"heartbeat_gap_s": round(gap, 2)},
                ))

        # 3) 링크 품질 직접 지표(SYS_STATUS/RADIO_STATUS)
        drop = f.get("drop_rate_comm", 0.0)
        if "drop_rate_comm" in f.get("updated", []) and drop >= 20.0:
            out.append(self._finding(
                evt, signal=f"통신 손실률 {drop:.0f}% — 링크 품질 급락",
                flow=AttackFlow.D_LINK, confidence=min(1.0, drop / 100),
                risk=Risk.MEDIUM,
                threat_map={"STRIDE": "Denial of Service",
                            "TARA": "링크 가용성 저하"},
                evidence={"drop_rate_comm": drop, "errors_comm": f.get("errors_comm")},
            ))
        return out


class CommandAnomalyDetector(Detector):
    """흐름 B — 명령 빈도 이상 / 예상치 못한 모드 전환 → C2 명령 주입."""
    name = "명령 이상 감시"

    def __init__(self, window_s: float = 3.0, max_cmds: int = 5) -> None:
        self.window_s = window_s
        self.max_cmds = max_cmds
        self.acks: list[float] = []
        self.last_mode: int | None = None

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        out: list[FindingEvent] = []
        upd = f.get("updated", [])

        if "command_ack" in upd:
            now = evt.recv_ts
            self.acks.append(now)
            self.acks = [x for x in self.acks if now - x <= self.window_s]
            if len(self.acks) > self.max_cmds:
                out.append(self._finding(
                    evt,
                    signal=f"{self.window_s:.0f}s 내 명령 {len(self.acks)}건 — 비정상 명령 빈도",
                    flow=AttackFlow.B_C2, confidence=1.0, risk=Risk.HIGH,
                    threat_map={"STRIDE": "Tampering",
                                "TARA": "명령 주입 → 제어권 상실",
                                "STPA-Sec": "불안전 제어행동(권한 없는 명령)"},
                    evidence={"cmds_in_window": len(self.acks),
                              "ack": f.get("command_ack")},
                ))

        if "custom_mode" in upd or "heartbeat" in upd:
            mode = f.get("custom_mode")
            if self.last_mode is not None and mode is not None and mode != self.last_mode:
                out.append(self._finding(
                    evt,
                    signal=f"예상치 못한 모드 전환 {self.last_mode}→{mode}",
                    flow=AttackFlow.B_C2, confidence=0.7, risk=Risk.MEDIUM,
                    threat_map={"STRIDE": "Tampering", "TARA": "임무계획 변조"},
                    evidence={"mode_from": self.last_mode, "mode_to": mode},
                ))
            if mode is not None:
                self.last_mode = mode
        return out


class StateConsistencyDetector(Detector):
    """흐름 C — 텔레메트리 최소 보정. 센서 결과와 Health 상태의 상관 이상.

    대표공격흐름 C: "센서 결과와 Health 상태의 상관관계 이상". 여기서는
    Health(배터리/센서 정상)와 관측 거동(모드/속도)의 정합성을 교차검증한다.
    """
    name = "상태 정합성"

    def __init__(self, batt_jump: int = 25) -> None:
        self.batt_jump = batt_jump
        self.last_batt: int | None = None

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        out: list[FindingEvent] = []
        batt = f.get("battery_pct")
        if batt is not None and "battery_pct" in f.get("updated", []):
            if self.last_batt is not None and abs(batt - self.last_batt) >= self.batt_jump:
                out.append(self._finding(
                    evt,
                    signal=f"배터리 상태 급변 {self.last_batt}%→{batt}% — Health 보고 불일치",
                    flow=AttackFlow.C_TELEMETRY, confidence=0.6, risk=Risk.MEDIUM,
                    threat_map={"STRIDE": "Tampering",
                                "TARA": "상태 보고 위조 → 상황인식 왜곡"},
                    evidence={"batt_from": self.last_batt, "batt_to": batt},
                ))
            self.last_batt = batt
        return out


class SensorConsensusDetector(Detector):
    """흐름 E — 인지모델 회피(적대적 예제) 및 다중 센서 기만 탐지.

    인지 파이프라인(EO/IR 객체탐지 등)이 features["ai"] = {conf, agreement, label}
    로 결과를 주입하면, 카메라를 속이는 공격(attacks/perception/adversarial_patch.py의
    PGD 섭동·adversarial patch)을 **세 가지 상보적 서명**으로 잡는다.

      1) 탐지 신뢰도 붕괴(confidence collapse) — 표적 conf 가 프레임 사이 급락.
      2) 카메라↔LiDAR/타 센서 교차검증 붕괴 — agreement(합의도) 저하.
         (카메라만 속고 LiDAR/레이더는 표적을 계속 보면 합의가 깨진다.)
      3) 프레임 간 라벨 튐(temporal flicker) — 짧은 창에서 표적 클래스 라벨이 반복 반전.
         적대적 섭동은 단일 프레임 신뢰도만이 아니라 시간적으로 불안정한 판단을 유발한다.

    (1)만 보면 정상적인 신뢰도 변동에 오탐할 수 있으므로 (2)(3)을 함께 봐 커버리지를
    넓히고, 상관기(Correlator)의 교차확인으로 최종 오탐을 억제한다.
    이 신호는 텔레메트리만으로는 관측 불가하며 인지 계층에서 주입해야 한다.
    """
    name = "센서/AI 합의 감시"

    def __init__(self, conf_drop: float = 0.4, disagree_thresh: float = 0.5,
                 flicker_window: int = 6, flicker_flips: int = 3) -> None:
        self.conf_drop = conf_drop
        self.disagree = disagree_thresh
        self.flicker_window = flicker_window
        self.flicker_flips = flicker_flips
        self.last_conf: float | None = None
        self.labels: deque[Any] = deque(maxlen=flicker_window)

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        ai = f.get("ai")
        if not ai:
            return []
        out: list[FindingEvent] = []
        conf = ai.get("conf")
        agreement = ai.get("agreement")     # 카메라 vs LiDAR/타 센서 합의도(0~1)
        label = ai.get("label")             # 프레임별 표적 클래스 라벨

        # 1) 탐지 신뢰도 붕괴 (adversarial evasion 의 1차 서명)
        if conf is not None and self.last_conf is not None and \
                (self.last_conf - conf) >= self.conf_drop:
            out.append(self._finding(
                evt,
                signal=f"AI 탐지 신뢰도 급락 {self.last_conf:.2f}→{conf:.2f} (카메라 인지 붕괴)",
                flow=AttackFlow.E_SENSOR, confidence=0.8, risk=Risk.HIGH,
                threat_map={"MITRE ATLAS": "Evasion(적대적 예제/PGD 섭동)",
                            "TARA": "표적 오인식/장애물 회피 실패",
                            "STPA-Sec": "기만된 인지 기반 불안전 판단"},
                evidence={"conf_prev": self.last_conf, "conf_now": conf},
            ))

        # 2) 카메라↔LiDAR/타 센서 교차검증 붕괴
        if agreement is not None and agreement < self.disagree:
            out.append(self._finding(
                evt,
                signal=f"카메라 판단 vs LiDAR/타 센서 교차검증 불일치(합의도 {agreement:.2f})",
                flow=AttackFlow.E_SENSOR, confidence=0.7, risk=Risk.MEDIUM,
                threat_map={"MITRE ATLAS": "Evasion",
                            "STPA-Sec": "센서 기만 기반 불안전 판단"},
                evidence={"sensor_agreement": agreement},
            ))

        # 3) 프레임 간 라벨 튐(temporal flicker)
        if label is not None:
            self.labels.append(label)
            seq = list(self.labels)
            flips = sum(1 for a, b in zip(seq, seq[1:]) if a != b)
            if len(seq) >= self.flicker_window and flips >= self.flicker_flips:
                out.append(self._finding(
                    evt,
                    signal=(f"프레임 간 표적 라벨 반복 반전 {flips}회/{len(seq)}프레임 "
                            f"(temporal flicker — 인지 불안정)"),
                    flow=AttackFlow.E_SENSOR, confidence=0.75, risk=Risk.HIGH,
                    threat_map={"MITRE ATLAS": "Evasion(시간적 불안정 유발)",
                                "TARA": "표적 판단 신뢰 붕괴"},
                    evidence={"label_flips": flips, "window": len(seq),
                              "recent_labels": seq},
                ))

        if conf is not None:
            self.last_conf = conf
        return out


def default_rule_detectors(cfg) -> list[Detector]:
    """설정으로 규칙 탐지기 묶음을 생성(흐름 A~E, 차량 단위)."""
    d = cfg.detect
    return [
        GnssInsCrossCheck(d.gnss.warn_m, d.gnss.crit_m),
        RouteConsistencyDetector(),
        LinkHealthDetector(cfg.run.rate_hz, d.link.warn_factor, d.link.crit_gap_s),
        CommandAnomalyDetector(d.command.window_s, d.command.max_cmds),
        StateConsistencyDetector(),
        SensorConsensusDetector(d.sensor.conf_drop, d.sensor.disagree_thresh,
                                d.sensor.flicker_window, d.sensor.flicker_flips),
    ]
