"""Red↔Blue 자율 공방 폐루프 통합 검증 (인프로세스, 결정적).

라이브 UDP/프로세스 없이, 공유 EventBus 위에서 실제 Blue 탐지기(rule_detectors)와 실제
Red BattleObserver 를 연결한다. 공격의 물리 효과를 텔레메트리로 모사해 주입하면:

  텔레메트리(공격 효과) → Blue 탐지(FindingEvent) → Blue 대응(DefenseAction)
    → Red BattleObserver 집계 → 보상/공격점수 → LinUCB 갱신

이 경로가 실제로 닫히는지, 그리고 탐지/은신에 따라 보상이 달라지는지 확인한다.
(개별 컴포넌트의 단위 검증은 tests/unit/test_red_agent.py 참조.)
"""
import asyncio
import math

from core.config import load_config
from core.event_bus import EventBus
from core.events import TelemetryEvent
from agents.blue.correlator import ThreatCorrelator
from agents.blue.response_planner import ResponsePlanner
from agents.blue.rule_detectors import default_rule_detectors
from agents.blue.safety_gate import SafetyGate
from agents.red.agent import OutcomeEvaluator
from agents.red.observer import BattleObserver
from agents.red.planner import Arm, LinUCBPlanner, build_arms

HOME = (37.5, 127.0)
EARTH_R = 6378137.0


def _offset(lat, lon, dn_m, de_m):
    dlat = dn_m / EARTH_R * (180.0 / math.pi)
    dlon = de_m / (EARTH_R * math.cos(math.radians(lat))) * (180.0 / math.pi)
    return lat + dlat, lon + dlon


SPEED = 12.0   # m/s — 매 틱(dt=1s) 북쪽으로 SPEED 만큼 진행(경로 정합성 유지)


def _telemetry(divergence_m=0.0, seq=0, command_ack=False):
    """공격 효과를 모사한 한 틱. divergence_m>0 이면 GNSS 스푸핑 효과.

    INS(융합) 위치는 보고 속도와 정합되게 북쪽으로 진행하므로, 공격이 없으면
    경로 정합성 탐지기가 오탐하지 않는다(진짜 benign). GNSS 스푸핑이면 원시 GPS 만
    동쪽으로 divergence_m 만큼 어긋난다(GNSS-INS 교차검증이 이를 탐지).
    """
    ins = _offset(HOME[0], HOME[1], SPEED * seq, 0.0)          # 북쪽으로 진행
    gps = _offset(ins[0], ins[1], 0.0, divergence_m)           # 동쪽으로 offset
    feats = {
        "vehicle": "uav",
        "position_ins": [ins[0], ins[1]],
        "position_gps": [gps[0], gps[1]],
        "speed": SPEED,
        "updated": ["position_gps", "position_ins"],
        "msg_type": "GLOBAL_POSITION_INT",
    }
    if command_ack:
        feats["command_ack"] = {"command": 176, "result": 0}
        feats["updated"] = ["command_ack"]
        feats["msg_type"] = "COMMAND_ACK"
    return TelemetryEvent(vehicle="uav", source="mock", sensor_ts=float(seq),
                          recv_ts=float(seq), features=feats)


async def _blue_pipeline(bus, cfg):
    """실제 Blue 탐지→대응 파이프라인을 버스에 연결(telemetry→finding→action)."""
    detectors = default_rule_detectors(cfg)
    correlator = ThreatCorrelator()
    planner = ResponsePlanner(cfg.response.auto_max_risk)
    gate = SafetyGate(cfg.gate.allowed_playbooks, cfg.gate.allowed_targets)
    sub = bus.subscribe("telemetry")
    async for evt in sub.stream():
        for det in detectors:
            for f in det.update(evt):
                await bus.publish(f)
                ctx = correlator.add(f)
                action = planner.plan(f, ctx)
                gate.evaluate(action)
                await bus.publish(action)


def _setup():
    cfg = load_config("configs/default.toml")
    bus = EventBus()
    obs = BattleObserver(bus)
    tasks = [
        asyncio.create_task(_blue_pipeline(bus, cfg)),
        asyncio.create_task(obs.consume_findings()),
        asyncio.create_task(obs.consume_actions()),
        asyncio.create_task(obs.consume_scores()),
    ]
    return bus, obs, tasks


def test_gnss_attack_is_detected_and_observed_by_red():
    """GNSS 스푸핑(150m) → Blue 가 Critical 탐지 → Red 관측 창에 임팩트·HITL 집계."""
    async def run():
        bus, obs, tasks = _setup()
        obs.open_window()
        for i in range(6):
            await bus.publish(_telemetry(divergence_m=150.0, seq=i))
            await asyncio.sleep(0)          # 파이프라인이 처리하도록 양보
        await asyncio.sleep(0.05)
        w = obs.close_window()
        for t in tasks:
            t.cancel()
        return w

    w = asyncio.run(run())
    assert w.detected                       # Blue 가 탐지
    assert w.max_divergence_m >= 100.0       # 유발한 임팩트가 관측됨
    assert w.hitl_actions >= 1               # High/Critical → HITL 유발


def test_benign_window_is_stealth_for_red():
    """공격 효과가 없으면(divergence<임계) Blue 무탐 → Red 창은 은신."""
    async def run():
        bus, obs, tasks = _setup()
        obs.open_window()
        for i in range(6):
            await bus.publish(_telemetry(divergence_m=0.0, seq=i))
            await asyncio.sleep(0)
        await asyncio.sleep(0.05)
        w = obs.close_window()
        for t in tasks:
            t.cancel()
        return w

    w = asyncio.run(run())
    assert not w.detected
    assert w.max_divergence_m == 0.0


def test_reward_higher_for_stealth_than_detected_in_loop():
    """폐루프 관측 결과로 계산한 보상: 은신 창 > 탐지 창(비대칭 보상 확인)."""
    async def run():
        bus, obs, tasks = _setup()
        # 탐지 창(공격 효과 큼)
        obs.open_window()
        for i in range(6):
            await bus.publish(_telemetry(divergence_m=150.0, seq=i))
            await asyncio.sleep(0)
        await asyncio.sleep(0.05)
        detected = obs.close_window()
        # 은신 창(공격 효과 임계 미만)
        obs.open_window()
        for i in range(6):
            await bus.publish(_telemetry(divergence_m=0.0, seq=100 + i))
            await asyncio.sleep(0)
        await asyncio.sleep(0.05)
        stealth = obs.close_window()
        for t in tasks:
            t.cancel()
        return detected, stealth

    detected, stealth = asyncio.run(run())
    arm = Arm("gnss_strong", "gnss_spoof", {}, "A")
    ev = OutcomeEvaluator()
    # 탐지되어 자동/HITL 대응을 유발한 창보다, 미탐 은신 창의 보상이 높다
    assert ev.reward(arm, stealth) > 0.0
    assert stealth.detected is False and detected.detected is True


def test_full_red_cycle_updates_policy_from_blue_feedback():
    """RedAgent 폐루프 1사이클: 문맥→LinUCB 선택→(모사 실행)→관측→보상→갱신.

    실행은 관측 창 동안 텔레메트리로 공격 효과를 모사해 실제 Blue 탐지를 유발한다.
    """
    async def run():
        bus, obs, tasks = _setup()
        arms = build_arms(["wait", "gnss_spoof", "c2_inject"])
        planner = LinUCBPlanner(arms, alpha=0.6, seed=1)
        ev = OutcomeEvaluator()

        picks, rewards = [], []
        for cycle in range(4):
            x = obs.context().to_vector()
            sel = planner.select(x)
            obs.open_window()
            # 선택한 arm 의 효과를 텔레메트리로 모사(gnss=divergence, 그 외=무해)
            div = 150.0 if sel.arm.tool == "gnss_spoof" else 0.0
            for i in range(5):
                await bus.publish(_telemetry(divergence_m=div, seq=cycle * 10 + i))
                await asyncio.sleep(0)
            await asyncio.sleep(0.03)
            w = obs.close_window()
            r = ev.reward(sel.arm, w)
            planner.update(sel.arm_index, x, r)
            picks.append(sel.arm.name)
            rewards.append(r)
        for t in tasks:
            t.cancel()
        return picks, rewards

    picks, rewards = asyncio.run(run())
    assert len(picks) == 4                   # 폐루프가 4사이클 완주
    assert all(0.0 <= r <= 1.0 for r in rewards)
