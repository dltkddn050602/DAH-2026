"""Battle Observer — 기술스택 문서 §4.1.

Red 에이전트가 상대(Blue)의 반응을 관측하는 눈. 공통 이벤트 버스에서 Blue 가 내는
finding(탐지) / defense_action(대응) / score(점수) 를 구독해 전투 상태로 집계하고,
  (1) 공격 선택용 문맥 벡터(BattleContext) 와
  (2) 방금 실행한 공격의 결과 창(WindowStats, 보상 계산용)
을 제공한다. 내부 객체를 직접 참조하지 않고 이벤트만 본다(대칭적 관측).

관측 문맥(문서 §4.1): 링크 품질, 최근 탐지기/흐름, Blue 대응(자동/HITL), 임무 상태,
유발한 임팩트(임무 편향). 센서 시간·수신 시간 분리는 이벤트 계약에서 이미 보장된다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from core.event_bus import EventBus, Subscription
from core.events import DefenseAction, FindingEvent, ScoreEvent

# 문맥/보상 정규화 상한(settle 창 ~2s, 4Hz 텔레메트리 기준 대략치)
DET_CAP = 8.0        # 창당 탐지 건수 정규화 상한
ACT_CAP = 8.0        # 창당 대응 건수 정규화 상한
DIV_CAP = 150.0      # 임팩트(divergence/residual) 정규화 상한(m)


@dataclass
class WindowStats:
    """한 공격 실행 창 동안 관측된 Blue 반응 집계(보상·다음 문맥의 근거)."""
    findings: int = 0
    flows: set[str] = field(default_factory=set)
    risk_max_rank: int = -1          # -1=무탐지, 0 Low … 3 Critical
    max_divergence_m: float = 0.0    # 유발한 임무 편향(divergence/residual)
    auto_actions: int = 0            # Blue 자동 조치(저비용 차단)
    hitl_actions: int = 0            # Blue HITL 승인 필요(운용자 개입 유발)

    @property
    def detected(self) -> bool:
        return self.findings > 0


@dataclass
class BattleContext:
    """공격 선택 시점의 관측 문맥. LinUCB 입력 벡터로 변환된다."""
    last_findings: int = 0
    last_hitl: int = 0
    last_auto: int = 0
    availability: float = 100.0
    last_impact_m: float = 0.0

    def to_vector(self) -> np.ndarray:
        def clip01(v: float) -> float:
            return max(0.0, min(1.0, v))
        return np.array([
            1.0,                                    # bias
            clip01(self.last_findings / DET_CAP),   # 탐지 압박
            clip01(self.last_hitl / ACT_CAP),       # 운용자 개입 유발(성과)
            clip01(self.last_auto / ACT_CAP),       # 저비용 자동차단 압박(비용)
            clip01(self.availability / 100.0),      # 링크/임무 건전성
            clip01(self.last_impact_m / DIV_CAP),   # 유발한 임무 편향(임팩트)
        ], dtype=float)


class BattleObserver:
    """Blue 이벤트를 구독해 전투 상태를 집계한다."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._sub_find: Subscription = bus.subscribe("finding")
        self._sub_act: Subscription = bus.subscribe("defense_action")
        self._sub_score: Subscription = bus.subscribe("score")

        self._win = WindowStats()
        self.last_win = WindowStats()        # 직전 창(다음 문맥 구성용)
        self.availability = 100.0
        self.defense_score = 0.0

    # ---------------- 소비 워커(agent 가 Task 로 실행) ----------------
    async def consume_findings(self) -> None:
        async for f in self._sub_find.stream():
            assert isinstance(f, FindingEvent)
            self._win.findings += 1
            flow = f.flow.value if hasattr(f.flow, "value") else str(f.flow)
            self._win.flows.add(flow)
            rank = f.risk.rank if hasattr(f.risk, "rank") else 0
            self._win.risk_max_rank = max(self._win.risk_max_rank, rank)
            div = f.evidence.get("divergence_m") or f.evidence.get("residual_m")
            if div is not None:
                self._win.max_divergence_m = max(
                    self._win.max_divergence_m, float(div))

    async def consume_actions(self) -> None:
        async for a in self._sub_act.stream():
            assert isinstance(a, DefenseAction)
            if a.approval_required:
                self._win.hitl_actions += 1
            else:
                self._win.auto_actions += 1

    async def consume_scores(self) -> None:
        async for s in self._sub_score.stream():
            assert isinstance(s, ScoreEvent)
            self.availability = s.availability
            self.defense_score = s.defense

    # ---------------- 문맥/창 인터페이스 ----------------
    def context(self) -> BattleContext:
        """직전 창 결과 + 현재 가용성으로 공격 선택 문맥을 만든다(폐루프 피드백)."""
        return BattleContext(
            last_findings=self.last_win.findings,
            last_hitl=self.last_win.hitl_actions,
            last_auto=self.last_win.auto_actions,
            availability=self.availability,
            last_impact_m=self.last_win.max_divergence_m,
        )

    def open_window(self) -> None:
        """공격 실행 직전 관측 창을 연다(집계 초기화)."""
        self._win = WindowStats()

    def close_window(self) -> WindowStats:
        """settle 대기 후 창을 닫고 결과를 반환. 다음 문맥용으로 보관."""
        w = self._win
        self.last_win = w
        return w
