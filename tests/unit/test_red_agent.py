"""Red(공격) AI 에이전트 검증 (기술스택 문서 §11).

- LinUCB 정책은 시드 고정 시 같은 (문맥,보상) 순서에 같은 행동 순서를 낸다(재현성).
- LinUCB 는 고정 순서가 아니라 관측 문맥·보상에 따라 선택을 바꾼다(적응성).
- 공격 정책 게이트는 외부 대상을 거부하고, 미허용 도구를 거부하며, 파라미터를 클램프한다.
- 보상 설계: 미탐(은밀) > 자동차단, HITL 유발은 가점(비대칭 보상).
- Battle Observer 는 Blue 이벤트를 문맥/창으로 집계한다.
"""
import asyncio

import numpy as np

from core.event_bus import EventBus
from core.events import AttackAction, DefenseAction, FindingEvent, Risk, ScoreEvent
from agents.red.agent import OutcomeEvaluator
from agents.red.observer import BattleContext, BattleObserver
from agents.red.planner import (Arm, BaselinePlanner, LinUCBPlanner, build_arms,
                                make_planner)
from agents.red.policy_gate import AttackPolicyGate

DIM = 6


def _arms():
    return build_arms(["wait", "gnss_spoof", "c2_inject"])


# ---------------- 플래너: 재현성 ----------------
def test_linucb_reproducible_with_seed():
    arms = _arms()
    rng = np.random.default_rng(0)
    contexts = [rng.random(DIM) for _ in range(12)]
    rewards = [float(rng.random()) for _ in range(12)]

    def run():
        p = LinUCBPlanner(arms, dim=DIM, alpha=0.6, seed=20260707)
        picks = []
        for x, r in zip(contexts, rewards):
            sel = p.select(x)
            p.update(sel.arm_index, x, r)
            picks.append(sel.arm_index)
        return picks

    assert run() == run()      # 같은 시드·입력 → 같은 행동 순서


def test_linucb_adapts_to_reward():
    """한 arm 에만 계속 높은 보상을 주면 그 arm 을 선호하게 된다(적응성)."""
    arms = _arms()
    p = LinUCBPlanner(arms, dim=DIM, alpha=0.2, seed=1)
    x = np.array([1.0, 0.5, 0.0, 0.0, 1.0, 0.0])
    target = 2  # gnss_strong 근처
    for _ in range(60):
        sel = p.select(x)
        r = 1.0 if sel.arm_index == target else 0.0
        p.update(sel.arm_index, x, r)
    # 학습 후 같은 문맥에서 target 을 고른다
    assert p.select(x).arm_index == target


def test_baseline_is_fixed_order_and_ignores_reward():
    arms = _arms()
    p = BaselinePlanner(arms, seed=5)
    x = np.zeros(DIM)
    seq = [p.select(x).arm_index for _ in range(len(arms) * 2)]
    # 라운드로빈: 0..n-1, 0..n-1
    assert seq == list(range(len(arms))) * 2
    p.update(0, x, 1.0)        # no-op 이어야 함
    assert p.select(x).arm_index == 0  # 인덱스 진행만, 보상 무시


def test_make_planner_selects_class():
    arms = _arms()
    assert isinstance(make_planner("adaptive", arms, 0.6, 1), LinUCBPlanner)
    assert isinstance(make_planner("baseline", arms, 0.6, 1), BaselinePlanner)


# ---------------- 정책 게이트: 자율성 경계 ----------------
def _gate():
    return AttackPolicyGate(
        allowed_tools=["wait", "gnss_spoof", "c2_inject"],
        allowed_targets=["127.0.0.1", "mock", "sitl"],
        max_drift_m=200.0, max_c2_count=30, max_duration_s=20.0)


def test_gate_rejects_external_target():
    g = _gate()
    a = AttackAction(tool="gnss_spoof", parameters={"drift_m": 100})
    dec = g.evaluate(a, "udpout:8.8.8.8:14555")
    assert dec.allowed is False


def test_gate_allows_loopback_target():
    g = _gate()
    a = AttackAction(tool="gnss_spoof", parameters={"drift_m": 100})
    dec = g.evaluate(a, "udpout:127.0.0.1:14555")
    assert dec.allowed is True


def test_gate_rejects_unlisted_tool():
    g = _gate()
    a = AttackAction(tool="launch_missile", parameters={})
    dec = g.evaluate(a, "udpout:127.0.0.1:14555")
    assert dec.allowed is False


def test_gate_clamps_unsafe_params():
    g = _gate()
    a = AttackAction(tool="gnss_spoof", parameters={"drift_m": 999, "hold_s": 999})
    dec = g.evaluate(a, "udpout:127.0.0.1:14555")
    assert dec.allowed is True
    assert dec.action.parameters["drift_m"] == 200.0
    assert dec.action.parameters["hold_s"] == 20.0
    assert "drift_m" in dec.clamped


def test_gate_budget_downgrades_to_wait():
    g = AttackPolicyGate(["wait", "gnss_spoof"], ["127.0.0.1"], budget=1)
    tgt = "udpout:127.0.0.1:14555"
    assert g.evaluate(AttackAction(tool="gnss_spoof"), tgt).action.tool == "gnss_spoof"
    # 예산 소진 후에는 wait 로 강등
    assert g.evaluate(AttackAction(tool="gnss_spoof"), tgt).action.tool == "wait"


# ---------------- 보상 설계: 비대칭 ----------------
def test_reward_prefers_stealth_over_autoblock():
    from agents.red.observer import WindowStats
    ev = OutcomeEvaluator()
    arm = Arm("gnss_strong", "gnss_spoof", {}, "A")
    stealth = WindowStats(findings=0, max_divergence_m=100.0)   # 미탐
    blocked = WindowStats(findings=4, max_divergence_m=100.0, auto_actions=4)
    assert ev.reward(arm, stealth) > ev.reward(arm, blocked)


def test_reward_hitl_beats_plain_detect():
    from agents.red.observer import WindowStats
    ev = OutcomeEvaluator()
    arm = Arm("gnss_strong", "gnss_spoof", {}, "A")
    hitl = WindowStats(findings=3, max_divergence_m=120.0, hitl_actions=3)
    plain = WindowStats(findings=3, max_divergence_m=120.0, auto_actions=3)
    assert ev.reward(arm, hitl) > ev.reward(arm, plain)


def test_context_vector_shape_and_range():
    ctx = BattleContext(last_findings=4, last_hitl=2, last_auto=1,
                        availability=80.0, last_impact_m=75.0)
    v = ctx.to_vector()
    assert v.shape == (DIM,)
    assert v[0] == 1.0
    assert all(0.0 <= x <= 1.0 for x in v)


# ---------------- Battle Observer: 이벤트 집계 ----------------
def test_observer_aggregates_blue_events():
    async def run():
        bus = EventBus()
        obs = BattleObserver(bus)
        tasks = [asyncio.create_task(obs.consume_findings()),
                 asyncio.create_task(obs.consume_actions()),
                 asyncio.create_task(obs.consume_scores())]
        obs.open_window()
        await bus.publish(FindingEvent(vehicle="uav", detector="d", signal="s",
                                       risk=Risk.HIGH,
                                       evidence={"divergence_m": 120.0}))
        await bus.publish(DefenseAction(vehicle="uav", playbook="downgrade_gnss",
                                        risk=Risk.HIGH, approval_required=True))
        await bus.publish(ScoreEvent(availability=88.0, defense=30.0))
        await asyncio.sleep(0.05)
        w = obs.close_window()
        for t in tasks:
            t.cancel()
        return w, obs.availability

    w, avail = asyncio.run(run())
    assert w.findings == 1 and w.hitl_actions == 1
    assert w.max_divergence_m == 120.0
    assert avail == 88.0
