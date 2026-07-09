"""Safety/Approval Gate — 기술스택 문서 §4.2, 자율성 경계.

DefenseAction 의 자동 실행 가능 여부를 결정한다.
  - allowlist: 알려진 안전 플레이북만 자동 실행 대상.
  - HITL: High·Critical(=approval_required) 은 사람 승인 없이 실행하지 않는다.
  - 대상 제한: 실행 계층은 loopback/mock/SITL 로만 제한(자율성 경계).

게이트는 '실행 여부'만 판정하고 실제 제어는 하지 않는다(예선 범위). 판정 결과는
DefenseAction 에 승인 상태로 표기되어 증거·채점에 반영된다.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.events import DefenseAction


@dataclass
class GateDecision:
    action: DefenseAction
    auto_execute: bool          # 자동 실행 허용?
    approval_pending: bool      # HITL 승인 대기?
    reason: str


class SafetyGate:
    def __init__(self, allowed_playbooks: list[str], allowed_targets: list[str]) -> None:
        self.allowed_playbooks = set(allowed_playbooks)
        self.allowed_targets = set(allowed_targets)

    def evaluate(self, action: DefenseAction) -> GateDecision:
        if action.playbook not in self.allowed_playbooks:
            return GateDecision(action, False, False,
                                f"allowlist 미포함 플레이북 '{action.playbook}' → 실행 거부")
        if action.approval_required:
            return GateDecision(action, False, True,
                                f"{action.risk.value} 위험 → HITL 승인 필요(human-in-the-loop)")
        return GateDecision(action, True, False,
                            f"{action.risk.value} 이하 → 자동 조치 승인")

    def target_allowed(self, target: str) -> bool:
        """실행 대상이 loopback/mock/SITL 계열인지(자율성 경계)."""
        t = target.lower()
        return any(a in t for a in self.allowed_targets)
