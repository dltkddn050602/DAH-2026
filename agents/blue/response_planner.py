"""Response Planner — 기술스택 문서 §4.2.

Finding + 캠페인 맥락 → 대응 플레이북(DefenseAction) 선택. 대응문구를 탐지기에
하드코딩하지 않고 흐름(A~F)·위험도 기반 플레이북 테이블로 분리한다.
선택적 LLM 은 후보/근거 생성에만 쓰고, 미설치·실패 시 결정론 테이블로 폴백한다.

에이전트는 치명 제어를 직접 수행하지 않는다. 저위험은 자동 조치까지,
High↑ 는 approval_required=True 로 HITL 게이트에 넘긴다.
"""
from __future__ import annotations

from core.events import AttackFlow, DefenseAction, FindingEvent, Risk
from agents.blue.correlator import CampaignContext

POLICY_VERSION = "playbook-v2"

# 흐름별 기본 플레이북. 배점 기준(탐지·차단·복구)에 맞춰 대응을 두 단계로 분리한다:
#   block   — 피해 확산 차단(즉시 봉쇄)
#   recover — 정상 상태 회복(축소운용/롤백/safe-hold+handoff). 복구는 방어 배점의 1/3.
PLAYBOOKS: dict[str, dict] = {
    AttackFlow.A_ROUTE.value: {
        "playbook": "downgrade_gnss",
        "block": ["GNSS 신뢰도 하향", "INS/비전 기반 항법 전환",
                  "계획 경로 대비 이탈 감시 강화", "안전속도 제한"],
        "recover": ["INS 기반 축소운용(degraded navigation)으로 임무 지속",
                    "GNSS 신뢰 회복 검증 시 점진적 재신뢰", "임무 경로 재계획"],
    },
    AttackFlow.B_C2.value: {
        "playbook": "require_reauth",
        "block": ["명령 서명검증/운용자 재인증 요구", "명령 정책엔진 상태 기반 허용",
                  "반복 저강도 변경 승인정책 강화", "링크 전환 검토"],
        "recover": ["마지막 신뢰 명령 상태로 롤백", "safe-hold 후 운용자 handoff",
                    "정상 명령권 복구 확인"],
    },
    AttackFlow.C_TELEMETRY.value: {
        "playbook": "cross_verify_state",
        "block": ["하향 명령↔상향 상태 교차검증", "외부 위치 기준 다중 센서 대조",
                  "임무 로그와 텔레메트리 상관 점검"],
        "recover": ["신뢰 가능한 상태 소스로 복구", "상태 재동기화 후 정상화"],
    },
    AttackFlow.D_LINK.value: {
        "playbook": "switch_link",
        "block": ["통신두절 안전정책(사전 정의 경로 복귀)", "대체 링크 전환",
                  "자율/안전 모드 전환 감시"],
        "recover": ["safe-hold 유지 후 링크 안정화 확인", "대체 링크 정상화 검증",
                    "운용자 handoff"],
    },
    AttackFlow.E_SENSOR.value: {
        "playbook": "raise_sensor_check",
        "block": ["카메라 판단 보류", "LiDAR/타 센서 교차검증 우선", "AI 신뢰도 하향",
                  "관측 커버리지 검증", "인간 확인 요청"],
        "recover": ["신뢰 센서(LiDAR 등) 기반 축소운용(degraded perception)",
                    "정상 모델/센서 확인 후 인지 재개", "표적 판단 운용자 handoff"],
    },
    AttackFlow.F_SWARM.value: {
        "playbook": "isolate_node",
        "block": ["오염 의심 노드 신뢰도 하향/격리", "합의 결과 재검증",
                  "개별 센서 관측과 군집 합의 대조"],
        "recover": ["격리 노드 복귀 검증 후 합의 재편입", "군집 상태 재동기화"],
    },
    AttackFlow.UNKNOWN.value: {
        "playbook": "observe",
        "block": ["관측 강화", "상관 분석 대기", "증거 보존"],
        "recover": ["증거 기반 사후 분석", "정상 baseline 확인"],
    },
}


class ResponsePlanner:
    def __init__(self, auto_max_risk: str = "Medium", llm=None) -> None:
        self.auto_max = Risk(auto_max_risk)
        self.llm = llm   # 선택적: rationale/후보 생성 (없으면 결정론)

    def plan(self, f: FindingEvent, ctx: CampaignContext) -> DefenseAction:
        flow = f.flow.value if hasattr(f.flow, "value") else str(f.flow)
        pb = PLAYBOOKS.get(flow, PLAYBOOKS[AttackFlow.UNKNOWN.value])

        # 캠페인 상관으로 위험도 상향(복합 흐름 = 누적 편향 공격 신호)
        risk = ctx.escalated_risk if ctx.escalated_risk.rank > f.risk.rank else f.risk
        approval = risk.rank > self.auto_max.rank

        # 차단(block) + 복구(recover) 를 순서대로 대응 단계로 결합
        steps = [f"[차단] {s}" for s in pb["block"]] + \
                [f"[복구] {s}" for s in pb["recover"]]

        rationale = self._rationale(f, ctx, risk)
        return DefenseAction(
            episode_id=f.episode_id,
            correlation_id=ctx.correlation_id,
            vehicle=f.vehicle,
            playbook=pb["playbook"],
            steps=steps,
            risk=risk,
            approval_required=approval,
            rationale=rationale,
            policy_version=POLICY_VERSION,
            model_version=(getattr(self.llm, "model", "") if self.llm else ""),
            input_refs=[f.correlation_id],
        )

    def _rationale(self, f: FindingEvent, ctx: CampaignContext, risk: Risk) -> str:
        base = f"{f.detector}: {f.signal}"
        if ctx.multi_flow:
            base += f" | 복합 흐름 {'+'.join(ctx.flows)} {ctx.findings}건 상관 → {risk.value} 상향"
        if self.llm is not None:
            try:
                enriched = self.llm.explain(f, ctx)
                if enriched:
                    return enriched
            except Exception:
                pass  # LLM 실패 시 결정론 설명으로 폴백
        return base
