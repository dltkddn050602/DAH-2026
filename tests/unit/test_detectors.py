"""규칙 탐지기 단위 검증 (기술스택 문서 §11).

같은 입력·설정으로 결정론적으로 같은 판단이 나오는지, 흐름 A~F 징후를 잡는지.
"""
import time

from core.events import AttackFlow, Risk, TelemetryEvent
from agents.blue.rule_detectors import (
    GnssInsCrossCheck, LinkHealthDetector, CommandAnomalyDetector,
)


def _tel(vehicle="uav", **features):
    now = time.time()
    features.setdefault("updated", list(features.keys()))
    return TelemetryEvent(vehicle=vehicle, source="test",
                          sensor_ts=now, recv_ts=now, features=features)


def test_gnss_ins_crosscheck_fires_on_divergence():
    det = GnssInsCrossCheck(warn_m=30, crit_m=100)
    # 두 위치가 ~150m 어긋남 → Critical, 흐름 A
    evt = _tel(position_gps=[37.5000, 127.0018], position_ins=[37.5000, 127.0000],
               updated=["position_gps", "position_ins"])
    out = det.update(evt)
    assert len(out) == 1
    assert out[0].flow == AttackFlow.A_ROUTE
    assert out[0].risk == Risk.CRITICAL
    assert out[0].evidence["divergence_m"] > 100


def test_gnss_ins_no_fire_when_consistent():
    det = GnssInsCrossCheck(warn_m=30, crit_m=100)
    evt = _tel(position_gps=[37.5000, 127.0000], position_ins=[37.5000, 127.0000],
               updated=["position_gps", "position_ins"])
    assert det.update(evt) == []


def test_command_flood_detected():
    det = CommandAnomalyDetector(window_s=3.0, max_cmds=5)
    out = []
    for _ in range(8):
        out += det.update(_tel(command_ack={"command": 176, "result": 0},
                               updated=["command_ack"]))
    assert any(f.flow == AttackFlow.B_C2 for f in out)
    assert any("비정상 명령 빈도" in f.signal for f in out)


def test_link_outage_detected_once():
    det = LinkHealthDetector(expected_hz=4, crit_gap_s=3.0)
    probe = _tel(msg_type="LINK_PROBE", since_last_msg_s=5.0, updated=["link_probe"])
    probe.features["msg_type"] = "LINK_PROBE"
    out1 = det.update(probe)
    out2 = det.update(probe)  # 연속 두절은 한 번만 발화
    assert len(out1) == 1 and out1[0].flow == AttackFlow.D_LINK
    assert out2 == []


def test_determinism_same_input_same_output():
    def run():
        det = GnssInsCrossCheck(30, 100)
        e = _tel(position_gps=[37.5, 127.001], position_ins=[37.5, 127.0],
                 updated=["position_gps", "position_ins"])
        f = det.update(e)[0]
        return (f.detector, f.flow, f.risk, round(f.evidence["divergence_m"], 1))
    assert run() == run()
