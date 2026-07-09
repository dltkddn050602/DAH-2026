#!/usr/bin/env python3
"""
MITM 인터셉션 시나리오 — 실행 검증 하니스

토폴로지:
    mock_vehicle(telem→udpout:14550)
        → attacks.mitm_intercept(listen 14550 → forward 14551)   ← 중간자
            → defense.agent(udpin:14551)                          ← 방어

방어를 인터셉터 뒤에 두고, 인터셉터를 수동 도청→능동 변조로 전환시킨 뒤
    · 인터셉터가 도청만으로 재구성한 운용정보(logs_mitm/harvest.json)
    · 방어 에이전트가 능동 변조를 탐지한 인시던트(logs_mitm/incidents.jsonl)
를 수집해 검증 요약(logs_mitm/verify_summary.json)으로 저장한다.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(ROOT, "logs_mitm")
PY = sys.executable

TELEM_PORT = 14550     # 차량 → (원래 GCS가 듣던 포트) 인터셉터
FWD_PORT = 14551       # 인터셉터 → 방어
ACTIVATE_AFTER = 6.0
DURATION = 16.0


def _spawn(args, logname):
    fh = open(os.path.join(EVID, logname), "w")
    p = subprocess.Popen([PY, "-m", *args], cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT)
    return p, fh


def main():
    os.makedirs(EVID, exist_ok=True)
    # 이전 실행 흔적 초기화
    open(os.path.join(EVID, "incidents.jsonl"), "w").close()

    procs = []
    print("[verify] 방어 에이전트 기동 (udpin:%d)" % FWD_PORT)
    d, dfh = _spawn(["defense.agent", "--uav", f"udpin:127.0.0.1:{FWD_PORT}",
                     "--evidence-dir", EVID], "defense.log")
    procs.append((d, dfh))
    time.sleep(1.5)

    print("[verify] MITM 인터셉터 삽입 (listen %d → forward %d)" % (TELEM_PORT, FWD_PORT))
    itc, ifh = _spawn(["attacks.mitm_intercept",
                       "--listen", f"udpin:127.0.0.1:{TELEM_PORT}",
                       "--forward", f"udpout:127.0.0.1:{FWD_PORT}",
                       "--activate-after", str(ACTIVATE_AFTER),
                       "--duration", str(DURATION),
                       "--drift-m", "120"], "interceptor.log")
    procs.append((itc, ifh))
    time.sleep(0.8)

    print("[verify] mock 차량(UAV/copter) 기동 (telem→%d)" % TELEM_PORT)
    v, vfh = _spawn(["sim.mock_vehicle", "--vehicle", "copter",
                     "--port", str(TELEM_PORT)], "vehicle.log")
    procs.append((v, vfh))

    print(f"[verify] 진행 중… 수동 도청 {ACTIVATE_AFTER:.0f}s → 능동 변조 "
          f"(총 {DURATION:.0f}s)")
    itc.wait(timeout=DURATION + 15)
    time.sleep(2.0)   # 방어가 잔여 프레임 처리

    # 정리
    for p, fh in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
    time.sleep(0.5)
    for p, fh in procs:
        if p.poll() is None:
            p.kill()
        fh.close()

    # 결과 수집
    harvest = _load_json(os.path.join(EVID, "harvest.json"))
    incidents = _load_jsonl(os.path.join(EVID, "incidents.jsonl"))
    by_det = {}
    for r in incidents:
        by_det.setdefault(r["detector"], []).append(r)

    summary = {
        "topology": f"vehicle→[MITM {TELEM_PORT}→{FWD_PORT}]→defense",
        "activate_after_s": ACTIVATE_AFTER, "duration_s": DURATION,
        "harvest": {
            "sysid": harvest.get("sysid"), "mode": harvest.get("mode"),
            "armed": harvest.get("armed"), "battery_pct": harvest.get("battery_pct"),
            "home": harvest.get("home"), "last_pos": harvest.get("last_pos"),
            "track_points": len(harvest.get("track", [])),
            "frames_relayed": harvest.get("frames_relayed"),
            "frames_tampered": harvest.get("frames_tampered"),
            "msg_counts": harvest.get("msg_counts"),
        },
        "incident_total": len(incidents),
        "incident_by_detector": {k: len(v) for k, v in by_det.items()},
        "incident_by_risk": _count(incidents, "risk"),
        "samples": incidents[:6],
    }
    with open(os.path.join(EVID, "verify_summary.json"), "w") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    _print_report(summary)


def _load_json(p):
    try:
        with open(p) as fh:
            return json.load(fh)
    except Exception:
        return {}


def _load_jsonl(p):
    out = []
    try:
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except Exception:
        pass
    return out


def _count(rows, key):
    c = {}
    for r in rows:
        c[r.get(key)] = c.get(r.get(key), 0) + 1
    return c


def _print_report(s):
    h = s["harvest"]
    print("\n" + "=" * 64)
    print("  MITM 인터셉션 검증 요약")
    print("=" * 64)
    print("  [1단계 도청] 링크 암호화 없이 탈취한 운용정보:")
    print(f"     sysid={h['sysid']} mode={h['mode']} armed={h['armed']} "
          f"batt={h['battery_pct']}%")
    print(f"     home={h['home']} last={h['last_pos']} track={h['track_points']}점")
    print(f"     중계 프레임={h['frames_relayed']} (변조 {h['frames_tampered']})")
    print("  [2단계 변조] 방어 에이전트 탐지 결과:")
    print(f"     총 인시던트 {s['incident_total']}건  위험도={s['incident_by_risk']}")
    for det, n in s["incident_by_detector"].items():
        print(f"     · {det}: {n}건")
    print("=" * 64)
    print(f"  증거: {EVID}/harvest.json, incidents.jsonl, verify_summary.json")


if __name__ == "__main__":
    main()
