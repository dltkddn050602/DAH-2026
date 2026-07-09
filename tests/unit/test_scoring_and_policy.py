"""채점 어댑터·플레이북·게이트 검증 (기술스택 문서 §11).

- 세부 배점은 설정(scoring.toml)로만 교체된다.
- High·Critical 방어 행동은 승인 없이 자동 실행되지 않는다(자율성 경계).
- allowlist 미포함 플레이북은 거부된다.
"""
from core.events import AttackFlow, DefenseAction, FindingEvent, Risk
from agents.blue.correlator import CampaignContext, ThreatCorrelator
from agents.blue.response_planner import ResponsePlanner
from agents.blue.safety_gate import SafetyGate
from scoring.adapter import CompetitionScoringAdapter
from scoring.metrics import EpisodeMetrics


def _ctx(risk=Risk.HIGH, flows=("A",), multi=False):
    return CampaignContext(correlation_id="c1", flows=list(flows),
                           findings=1, escalated_risk=risk, multi_flow=multi)


def test_high_risk_requires_hitl():
    planner = ResponsePlanner(auto_max_risk="Medium")
    f = FindingEvent(vehicle="uav", detector="d", signal="s",
                     flow=AttackFlow.A_ROUTE, risk=Risk.HIGH)
    action = planner.plan(f, _ctx(Risk.HIGH))
    assert action.approval_required is True
    assert action.playbook == "downgrade_gnss"


def test_low_risk_auto():
    planner = ResponsePlanner(auto_max_risk="Medium")
    f = FindingEvent(vehicle="uav", detector="d", signal="s",
                     flow=AttackFlow.D_LINK, risk=Risk.LOW)
    action = planner.plan(f, _ctx(Risk.LOW))
    assert action.approval_required is False


def test_gate_rejects_unknown_playbook():
    gate = SafetyGate(allowed_playbooks=["switch_link"], allowed_targets=["127.0.0.1"])
    action = DefenseAction(vehicle="uav", playbook="launch_missile", risk=Risk.LOW)
    dec = gate.evaluate(action)
    assert dec.auto_execute is False and dec.approval_pending is False


def test_gate_target_restricted_to_loopback():
    gate = SafetyGate(allowed_playbooks=[], allowed_targets=["127.0.0.1", "mock", "sitl"])
    assert gate.target_allowed("udpout:127.0.0.1:14555") is True
    assert gate.target_allowed("udpout:8.8.8.8:14555") is False


def test_correlator_escalates_multiflow():
    corr = ThreatCorrelator(window_s=15)
    corr.add(FindingEvent(vehicle="uav", detector="d", signal="s",
                          flow=AttackFlow.A_ROUTE, risk=Risk.HIGH))
    ctx = corr.add(FindingEvent(vehicle="uav", detector="d2", signal="s2",
                                flow=AttackFlow.B_C2, risk=Risk.HIGH))
    assert ctx.multi_flow is True
    assert ctx.escalated_risk == Risk.CRITICAL


def test_scoring_availability_and_config_replaceable():
    adapter = CompetitionScoringAdapter("configs/scoring.toml")
    m = EpisodeMetrics(episode_id="e1", findings=3)
    m.flows_detected = {"A", "B"}
    m.max_link_loss_pct = 10.0
    s = adapter.score(m, attack_points=0.0)
    assert 0.0 <= s.availability <= 100.0
    assert s.defense > 0
    assert s.diagnostics["flows_detected"] == ["A", "B"]
