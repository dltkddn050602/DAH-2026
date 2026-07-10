"""인지(perception) 회피 → 인식 방어 커플링 실험 (torch 불필요).

attacks/perception/adversarial_patch.py 는 실제 YOLO+PGD 로 카메라를 속이지만
torch/ultralytics(용량 큼)가 필요하다. 본 모듈은 그 공격이 **인지 출력에 남기는
관측 가능한 효과**(탐지 신뢰도 붕괴 · 카메라↔LiDAR 합의 붕괴 · 프레임 간 라벨 튐)를
정직하게 모사해, 강화된 방어 탐지기(SensorConsensusDetector)·대응 플래너·안전 게이트에
통과시킨다. 즉 "카메라를 속이는 공격"과 "속은 카메라를 잡는 방어"의 커플링을 CPU에서
바로 재현·검증한다.

  정상 구간   : conf 안정(≈0.88) · 라벨 고정('person') · 카메라↔LiDAR 합의 높음(≈0.95)
  적대적 구간 : PGD 섭동으로 conf 붕괴(0.88→0.18) · 라벨 flicker · 합의 붕괴(→0.25)

사용:
    python -m attacks.perception.sim_evasion            # 실험 실행 + 증거 저장
"""
from __future__ import annotations

import json
import os
import time

from core.config import load_config
from core.events import TelemetryEvent
from agents.blue.correlator import ThreatCorrelator
from agents.blue.response_planner import ResponsePlanner
from agents.blue.rule_detectors import SensorConsensusDetector
from agents.blue.safety_gate import SafetyGate

# 인지 출력 트레이스(정상 → 적대적 회피). 실제 PGD 데모의 신뢰도 붕괴를 재현.
BENIGN = [  # (conf, camera↔LiDAR 합의도, 표적 라벨)
    (0.88, 0.96, "person"), (0.87, 0.95, "person"), (0.89, 0.97, "person"),
    (0.86, 0.94, "person"), (0.88, 0.96, "person"),
]
ADVERSARIAL = [  # PGD 섭동 개시 — 신뢰도 붕괴 + 라벨 튐 + 카메라/LiDAR 불일치
    (0.30, 0.55, "car"),      # 급격 신뢰도 붕괴(0.88→0.30) → 서명① 발화
    (0.41, 0.30, "person"),   # 카메라↔LiDAR 합의 붕괴 → 서명②
    (0.23, 0.24, "none"),
    (0.35, 0.22, "car"),
    (0.18, 0.20, "none"),
    (0.29, 0.21, "person"),   # 라벨 반복 반전 → 서명③(temporal flicker)
]


def _ai_event(conf, agreement, label, ts):
    return TelemetryEvent(
        vehicle="uav", source="perception", sensor_ts=ts, recv_ts=ts,
        features={"ai": {"conf": conf, "agreement": agreement, "label": label},
                  "updated": ["ai"], "msg_type": "AI_RESULT"})


def run(evidence_dir: str = "logs_perception") -> dict:
    cfg = load_config("configs/default.toml")
    det = SensorConsensusDetector(
        cfg.detect.sensor.conf_drop, cfg.detect.sensor.disagree_thresh,
        cfg.detect.sensor.flicker_window, cfg.detect.sensor.flicker_flips)
    correlator = ThreatCorrelator()
    planner = ResponsePlanner(cfg.response.auto_max_risk)
    gate = SafetyGate(cfg.gate.allowed_playbooks, cfg.gate.allowed_targets)

    findings, actions = [], []
    t0 = time.time()
    trace = [("benign", x) for x in BENIGN] + [("adversarial", x) for x in ADVERSARIAL]
    for i, (phase, (conf, agr, label)) in enumerate(trace):
        evt = _ai_event(conf, agr, label, t0 + i)
        for f in det.update(evt):
            ctx = correlator.add(f)
            action = planner.plan(f, ctx)
            dec = gate.evaluate(action)
            findings.append({"frame": i, "phase": phase, "detector": f.detector,
                             "risk": f.risk.value, "signal": f.signal,
                             "threat_map": f.threat_map, "evidence": f.evidence})
            actions.append({"frame": i, "playbook": action.playbook,
                            "risk": action.risk.value,
                            "approval_required": action.approval_required,
                            "steps": action.steps,
                            "auto_execute": dec.auto_execute,
                            "approval_pending": dec.approval_pending})

    sig_types = {}
    for f in findings:
        key = ("신뢰도붕괴" if "신뢰도 급락" in f["signal"] else
               "라벨flicker" if "flicker" in f["signal"] else
               "센서교차검증" if "교차검증" in f["signal"] else "기타")
        sig_types[key] = sig_types.get(key, 0) + 1

    summary = {
        "experiment": "perception evasion → sensor-consensus defense",
        "frames": len(trace), "benign": len(BENIGN), "adversarial": len(ADVERSARIAL),
        "findings_total": len(findings),
        "findings_by_signal": sig_types,
        "risk_counts": {r: sum(1 for f in findings if f["risk"] == r)
                        for r in ("Medium", "High", "Critical")},
        "hitl_actions": sum(1 for a in actions if a["approval_pending"]),
        "auto_actions": sum(1 for a in actions if a["auto_execute"]),
        "findings": findings, "actions": actions,
    }
    os.makedirs(evidence_dir, exist_ok=True)
    with open(f"{evidence_dir}/evasion_defense.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    return summary


def main() -> None:
    s = run()
    print("=" * 66)
    print("  인지 회피 → 인식 방어(SensorConsensusDetector) 커플링 실험")
    print("=" * 66)
    print(f"  프레임 {s['frames']} (정상 {s['benign']} / 적대적 {s['adversarial']})")
    print(f"  탐지 {s['findings_total']}건 — 서명별 {s['findings_by_signal']}")
    print(f"  위험도 {s['risk_counts']}  ·  HITL {s['hitl_actions']} / 자동 {s['auto_actions']}")
    print(f"  정상 구간 오탐: "
          f"{sum(1 for f in s['findings'] if f['phase'] == 'benign')}건")
    print("\n  [대표 탐지]")
    for f in s["findings"][:5]:
        print(f"   f{f['frame']:02d}({f['phase'][:3]}) {f['risk']:8s} {f['signal']}")
    print(f"\n  → 증거 저장: logs_perception/evasion_defense.json")


if __name__ == "__main__":
    main()
