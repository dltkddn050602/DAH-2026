"""인식(perception) 방어 — SensorConsensusDetector 강화 검증.

카메라를 속이는 공격(attacks/perception/adversarial_patch.py, PGD 섭동)이 인지 출력에
남기는 세 서명을 잡는지 확인한다: (1) 탐지 신뢰도 붕괴 (2) 카메라↔LiDAR 교차검증 붕괴
(3) 프레임 간 라벨 튐(temporal flicker). 정상 구간은 오탐하지 않아야 한다(저오탐).
"""
import time

from core.events import AttackFlow, Risk, TelemetryEvent
from agents.blue.rule_detectors import SensorConsensusDetector


def _ai(conf=None, agreement=None, label=None):
    now = time.time()
    return TelemetryEvent(vehicle="uav", source="test", sensor_ts=now, recv_ts=now,
                          features={"ai": {"conf": conf, "agreement": agreement,
                                           "label": label}, "updated": ["ai"]})


def test_confidence_collapse_detected():
    det = SensorConsensusDetector(conf_drop=0.4)
    det.update(_ai(conf=0.88, agreement=0.95))         # 정상 기준선
    out = det.update(_ai(conf=0.20, agreement=0.95))   # 신뢰도 붕괴
    assert any(f.flow == AttackFlow.E_SENSOR and f.risk == Risk.HIGH for f in out)
    assert any("ATLAS" in "".join(f.threat_map.keys()) for f in out)


def test_camera_lidar_disagreement_detected():
    det = SensorConsensusDetector(disagree_thresh=0.5)
    out = det.update(_ai(conf=0.85, agreement=0.2))    # 카메라 vs LiDAR 불일치
    assert any("교차검증" in f.signal for f in out)


def test_temporal_flicker_detected():
    det = SensorConsensusDetector(flicker_window=6, flicker_flips=3)
    labels = ["person", "car", "person", "car", "person", "car"]  # 5 flips / 6
    out = []
    for lb in labels:
        out = det.update(_ai(conf=0.85, agreement=0.95, label=lb))  # conf/agr 정상
    assert any("flicker" in f.signal for f in out)
    assert any(f.risk == Risk.HIGH for f in out)


def test_benign_stable_no_false_positive():
    det = SensorConsensusDetector()
    findings = []
    for _ in range(8):
        findings += det.update(_ai(conf=0.87, agreement=0.96, label="person"))
    assert findings == []          # 안정 인지 → 오탐 0


def test_no_ai_features_ignored():
    det = SensorConsensusDetector()
    evt = TelemetryEvent(vehicle="uav", source="test", sensor_ts=0.0, recv_ts=0.0,
                         features={"speed": 12.0, "updated": ["speed"]})
    assert det.update(evt) == []   # AI 신호 없으면 무시(텔레메트리만으론 관측 불가)
