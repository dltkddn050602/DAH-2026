"""Attack Policy Gate — 기술스택 문서 §4.1, §8(Red 안전 정책).

Blue 의 Safety/Approval Gate 와 대칭. 플래너가 고른 공격 행동(AttackAction)이 실제로
실행 가능한지 판정한다. 자율성 경계를 코드로 강제한다.

  - 도구 allowlist: 허용된 공격 도구만 실행 후보.
  - 대상 제한: loopback/mock/SITL 엔드포인트만 허용(외부 대상 거부).
  - 파라미터 안전 범위: drift/count/duration 을 안전 상한으로 클램프.
  - 예산 상태머신: 공격 예산(횟수)을 초과하면 wait 로 강등.

게이트는 '실행 가능 여부'와 '안전 클램프'만 판정하고 실제 패킷은 보내지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.events import AttackAction


@dataclass
class AttackGateDecision:
    action: AttackAction            # (클램프된) 실행 대상 행동
    allowed: bool
    reason: str
    clamped: dict = field(default_factory=dict)   # 무엇을 클램프했는지


class AttackPolicyGate:
    def __init__(
        self,
        allowed_tools: list[str],
        allowed_targets: list[str],
        max_drift_m: float = 200.0,
        max_c2_count: int = 30,
        max_duration_s: float = 20.0,
        budget: int | None = None,
    ) -> None:
        self.allowed_tools = set(allowed_tools)
        self.allowed_targets = set(t.lower() for t in allowed_targets)
        self.max_drift_m = max_drift_m
        self.max_c2_count = max_c2_count
        self.max_duration_s = max_duration_s
        self.budget = budget            # None=무제한, 아니면 실행 예산(횟수)
        self.spent = 0

    def target_allowed(self, target: str) -> bool:
        """실행 대상이 loopback/mock/SITL 계열인지(자율성 경계) — Blue 와 동일 규칙."""
        t = target.lower()
        return any(a in t for a in self.allowed_targets)

    def evaluate(self, action: AttackAction, target: str) -> AttackGateDecision:
        # 1) 대상 제한(가장 강한 경계) — 외부 대상은 무조건 거부
        if not self.target_allowed(target):
            return AttackGateDecision(
                action, False,
                f"허용되지 않은 대상 '{target}' → 실행 거부(loopback/mock/SITL 만 허용)")

        # 2) 도구 allowlist
        if action.tool not in self.allowed_tools and action.tool != "wait":
            return AttackGateDecision(
                action, False, f"allowlist 미포함 도구 '{action.tool}' → 실행 거부")

        # 3) 예산 상태머신 — 소진 시 wait 로 강등(공격 중단이 아니라 은신)
        if self.budget is not None and self.spent >= self.budget and action.tool != "wait":
            downgraded = AttackAction(
                episode_id=action.episode_id, correlation_id=action.correlation_id,
                tool="wait", parameters={"duration_s": 1.0},
                rationale=f"공격 예산 소진({self.spent}/{self.budget}) → 대기 강등",
                policy_version=action.policy_version)
            return AttackGateDecision(downgraded, True,
                                      "예산 소진 → wait 로 강등", {"budget": "spent"})

        # 4) 파라미터 안전 범위 클램프
        clamped: dict = {}
        params = dict(action.parameters)
        if "drift_m" in params and params["drift_m"] > self.max_drift_m:
            clamped["drift_m"] = (params["drift_m"], self.max_drift_m)
            params["drift_m"] = self.max_drift_m
        if "count" in params and params["count"] > self.max_c2_count:
            clamped["count"] = (params["count"], self.max_c2_count)
            params["count"] = self.max_c2_count
        for k in ("duration_s", "hold_s", "ramp_s"):
            if k in params and params[k] > self.max_duration_s:
                clamped[k] = (params[k], self.max_duration_s)
                params[k] = self.max_duration_s

        safe = AttackAction(
            episode_id=action.episode_id, correlation_id=action.correlation_id,
            tool=action.tool, parameters=params,
            rationale=action.rationale, policy_version=action.policy_version)
        if action.tool != "wait":
            self.spent += 1
        reason = "실행 허용" + (f" (클램프: {list(clamped)})" if clamped else "")
        return AttackGateDecision(safe, True, reason, clamped)
