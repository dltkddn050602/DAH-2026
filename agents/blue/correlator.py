"""Threat Correlator — 기술스택 문서 §4.2.

여러 Finding 을 시간 창 + 공격 그래프로 하나의 공격 캠페인으로 결합한다.
대표공격흐름 문서의 핵심 통찰(단일 큰 변화보다 여러 작은 변화의 누적)을 반영해,
서로 다른 흐름(A~F)의 징후가 짧은 창 안에서 함께 나타나면 신뢰도를 높인다.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from core.events import AttackFlow, FindingEvent, Risk


@dataclass
class Campaign:
    """상관된 공격 캠페인 1건(한 차량, 한 시간 창)."""
    vehicle: str
    correlation_id: str
    started: float
    flows: set[str] = field(default_factory=set)
    detectors: set[str] = field(default_factory=set)
    findings: int = 0
    max_risk: Risk = Risk.LOW
    last_ts: float = 0.0


@dataclass
class CampaignContext:
    """planner 에 전달되는 상관 맥락."""
    correlation_id: str
    flows: list[str]
    findings: int
    escalated_risk: Risk
    multi_flow: bool


class ThreatCorrelator:
    """차량별 슬라이딩 창으로 Finding 을 캠페인에 결합한다."""

    def __init__(self, window_s: float = 15.0) -> None:
        self.window_s = window_s
        self._active: dict[str, Campaign] = {}
        self._recent: deque[FindingEvent] = deque(maxlen=512)

    def add(self, f: FindingEvent) -> CampaignContext:
        now = f.ts or time.time()
        camp = self._active.get(f.vehicle)
        if camp is None or (now - camp.last_ts) > self.window_s:
            camp = Campaign(vehicle=f.vehicle, correlation_id=f.correlation_id,
                            started=now)
            self._active[f.vehicle] = camp
        camp.flows.add(f.flow.value if hasattr(f.flow, "value") else str(f.flow))
        camp.detectors.add(f.detector)
        camp.findings += 1
        if f.risk.rank > camp.max_risk.rank:
            camp.max_risk = f.risk
        camp.last_ts = now
        self._recent.append(f)

        real_flows = camp.flows - {AttackFlow.UNKNOWN.value, "?"}
        multi = len(real_flows) >= 2
        esc = camp.max_risk
        if multi:
            esc = Risk(["Low", "Medium", "High", "Critical"][
                min(3, camp.max_risk.rank + 1)])
        return CampaignContext(
            correlation_id=camp.correlation_id,
            flows=sorted(real_flows),
            findings=camp.findings,
            escalated_risk=esc,
            multi_flow=multi,
        )
