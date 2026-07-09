"""Swarm Consensus Detector — 흐름 F(군집 신뢰 전파 오염).

여러 UxS 노드의 관측을 교차 비교해 '특정 노드 정보만 반복적으로 어긋나는지'를 본다
(대표공격흐름 문서 흐름 F 탐지단서). 한 노드의 내부 정합성(GPS-INS 편차)이 다른
노드들과 달리 반복적으로 이상하면, 그 노드를 오염 후보로 신뢰도 하향/격리 대상에 올린다.

>=2 노드가 보고할 때만 동작하며, 소수 노드만 반복 이상일 때 발화 → 정상 시 오탐 억제.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from core.events import AttackFlow, FindingEvent, Risk, TelemetryEvent
from core.geo import haversine_m


class SwarmConsensusDetector:
    name = "군집 신뢰 감시"

    def __init__(self, anomaly_m: float = 25.0, window: int = 20,
                 min_ratio: float = 0.6) -> None:
        self.anomaly_m = anomaly_m
        self.window = window
        self.min_ratio = min_ratio      # 창 내 이상 비율 임계
        self.hist: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=window))
        self.nodes: set[str] = set()
        self._fired: dict[str, float] = {}

    def update(self, evt: TelemetryEvent) -> list[FindingEvent]:
        f = evt.features
        gps, ins = f.get("position_gps"), f.get("position_ins")
        if not (gps and ins):
            return []
        self.nodes.add(evt.vehicle)
        if len(self.nodes) < 2:
            return []
        d = haversine_m(gps[0], gps[1], ins[0], ins[1])
        self.hist[evt.vehicle].append(1 if d >= self.anomaly_m else 0)

        h = self.hist[evt.vehicle]
        if len(h) < self.window:
            return []
        ratio = sum(h) / len(h)
        # 이 노드는 반복 이상인데, 다른 노드들은 대체로 정상인가?
        others = [v for v in self.nodes if v != evt.vehicle and len(self.hist[v]) >= 3]
        others_clean = others and all(
            (sum(self.hist[v]) / len(self.hist[v])) < 0.3 for v in others)
        if ratio >= self.min_ratio and others_clean:
            now = time.time()
            if now - self._fired.get(evt.vehicle, 0) < 5.0:
                return []
            self._fired[evt.vehicle] = now
            return [FindingEvent(
                episode_id=evt.episode_id, vehicle=evt.vehicle,
                detector=self.name,
                signal=(f"노드 '{evt.vehicle}'만 반복적 위치 이상(창 내 {ratio:.0%}) — "
                        f"군집 신뢰 전파 오염 의심"),
                flow=AttackFlow.F_SWARM, confidence=min(1.0, ratio), risk=Risk.HIGH,
                threat_map={"STRIDE": "Spoofing",
                            "TARA": "군집 편파 판단 → 협업 임무 실패",
                            "STPA-Sec": "오염 노드 합의 반영"},
                evidence={"anomaly_ratio": round(ratio, 2),
                          "peers": others, "node": evt.vehicle},
                ts=evt.recv_ts,
            )]
        return []
