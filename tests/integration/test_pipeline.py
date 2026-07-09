"""버스 기반 폐루프 통합 검증 (기술스택 문서 §11).

합성 텔레메트리를 버스에 흘려 Detector→finding→(Correlator→Planner→Gate)까지
행동이 생성되고 결정론적으로 재현되는지 확인한다. 네트워크·SITL 불필요.
"""
import asyncio
import time

from core.config import load_config
from core.event_bus import EventBus
from core.events import TelemetryEvent
from agents.blue.rule_detectors import default_rule_detectors
from agents.blue.correlator import ThreatCorrelator
from agents.blue.response_planner import ResponsePlanner
from agents.blue.safety_gate import SafetyGate


def _spoof_stream(n=6):
    """GNSS 스푸핑(원시 GPS만 서쪽으로 편이) 텔레메트리 시퀀스."""
    now = time.time()
    for i in range(n):
        drift = 0.002 * (i + 1)  # 점증 편이 → divergence 증가
        yield TelemetryEvent(
            vehicle="uav", source="test", sensor_ts=now + i, recv_ts=now + i,
            features={
                "position_ins": [37.5000, 127.0000],
                "position_gps": [37.5000, 127.0000 + drift],
                "speed": 12.0,
                "updated": ["position_gps", "position_ins"],
                "msg_type": "GPS_RAW_INT",
            },
        )


def test_bus_closed_loop_generates_hitl_action():
    # pytest-asyncio 없이도 실행되도록 asyncio.run 으로 감싼다.
    asyncio.run(_bus_closed_loop())


async def _bus_closed_loop():
    cfg = load_config()
    bus = EventBus()
    sub = bus.subscribe("finding")
    dets = default_rule_detectors(cfg)
    corr = ThreatCorrelator()
    planner = ResponsePlanner(cfg.response.auto_max_risk)
    gate = SafetyGate(cfg.gate.allowed_playbooks, cfg.gate.allowed_targets)

    # 관측 → 탐지 → finding 발행
    for evt in _spoof_stream():
        for det in dets:
            for f in det.update(evt):
                await bus.publish(f)

    # finding 소비 → 대응 → 게이트
    actions = []
    while not sub.queue.empty():
        f = await sub.get()
        ctx = corr.add(f)
        action = planner.plan(f, ctx)
        decision = gate.evaluate(action)
        actions.append((action.playbook, action.risk.value, decision.approval_pending))

    assert actions, "스푸핑에 대해 대응이 생성되어야 한다"
    playbooks = {a[0] for a in actions}
    assert "downgrade_gnss" in playbooks
    # 큰 편이는 Critical → HITL 승인 대기
    assert any(pending for _, _, pending in actions)


def test_replay_determinism():
    """같은 입력 시퀀스는 같은 finding 순서를 낸다(재현성)."""
    cfg = load_config()

    def run():
        dets = default_rule_detectors(cfg)
        sigs = []
        for evt in _spoof_stream():
            for det in dets:
                for f in det.update(evt):
                    sigs.append((f.detector, f.flow.value, f.risk.value))
        return sigs

    assert run() == run()
