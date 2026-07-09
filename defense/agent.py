"""
방어 AI 에이전트 (Defense AI Agent) — 프로토타입

방어 전략 문서의 '방어 AI 에이전트가 해야 할 10가지'를 실행 가능한 형태로 구현한다.
    1) 텔레메트리/로그 실시간 수집
    2~5) 통신·항법·센서·AI 이상징후 탐지
    6) 이상징후 → TARA/STRIDE/STPA-Sec/MITRE ATLAS 위협모델 매핑
    7) 피해영향·공격가능성·임무중요도 기반 위험도 재평가
    8) 위험도별 대응 플레이북 추천 (저위험 자동 / 고위험 인간 승인)
    9) 고위험 조치는 운용자 승인 표시
    10) 사고 증거 보존 + (후처리) 위협모델 KB 갱신

에이전트는 치명적 제어를 직접 수행하지 않는다. 탐지·분석·권고·저위험 조치까지만
담당하고, 고위험 조치는 human-in-the-loop 로 표시한다.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime

from pymavlink import mavutil

from defense.detectors import (
    GnssInsCrossCheck, LinkHealthMonitor,
    CommandAnomalyMonitor, SensorConsensusMonitor,
    InterceptionMonitor,
)

try:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()
except Exception:  # rich 미설치 시 폴백
    _console = None

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
RISK_COLOR = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "bold red"}
AUTO_MAX = "Medium"   # 이 이하 위험도는 자동 조치, 초과는 인간 승인


class VehicleMonitor:
    def __init__(self, name, conn_str, expected_hz=4.0):
        self.name = name
        self.conn = mavutil.mavlink_connection(conn_str)
        self.gnss = GnssInsCrossCheck()
        self.link = LinkHealthMonitor(expected_hz=expected_hz)
        self.cmd = CommandAnomalyMonitor()
        self.sensor = SensorConsensusMonitor()
        self.mitm = InterceptionMonitor()
        self._dedup = {}   # detector.signal -> last_fire_ts (알림 폭주 억제)

    def detectors(self):
        return [self.gnss, self.link, self.cmd, self.mitm]

    def pump(self):
        findings = []
        while True:
            msg = self.conn.recv_match(blocking=False)
            if msg is None:
                break
            for det in self.detectors():
                r = det.update(msg)
                if r is None:
                    continue
                findings.extend(r if isinstance(r, list) else [r])
        # 두절 검사(메시지 없을 때)
        r = self.link.tick()
        if r:
            findings.append(r)
        return findings


class DefenseAgent:
    def __init__(self, vehicles, evidence_dir="logs"):
        self.vehicles = vehicles
        self.evidence_dir = evidence_dir
        os.makedirs(evidence_dir, exist_ok=True)
        self.incident_count = 0

    def run(self):
        self._banner()
        while True:
            for vm in self.vehicles:
                for f in vm.pump():
                    if self._should_emit(vm, f):
                        self.handle(vm.name, f)
            time.sleep(0.05)

    def _should_emit(self, vm, f, cooldown=2.0):
        key = f"{f.detector}|{f.signal[:20]}"
        now = time.time()
        if now - vm._dedup.get(key, 0) < cooldown:
            return False
        vm._dedup[key] = now
        return True

    def handle(self, vehicle, f):
        self.incident_count += 1
        auto = RISK_ORDER[f.risk] <= RISK_ORDER[AUTO_MAX]
        gate = "🟢 자동 조치" if auto else "🔴 인간 승인 필요(human-in-the-loop)"
        self._alert(vehicle, f, gate)
        self._preserve(vehicle, f, auto)

    # ---------- 출력 ----------
    def _alert(self, vehicle, f, gate):
        mapping = "  ".join(f"{k}:{v}" for k, v in f.threat_map.items())
        if _console:
            color = RISK_COLOR[f.risk]
            body = (f"[bold]{f.detector}[/]  ([{color}]{f.risk}[/])\n"
                    f"징후 : {f.signal}\n"
                    f"매핑 : {mapping}\n"
                    f"대응 : {f.response}\n"
                    f"게이트: {gate}\n"
                    f"증거 : {json.dumps(f.evidence, ensure_ascii=False)}")
            _console.print(Panel(body, title=f"[{color}]⚠ {vehicle.upper()} 위협 탐지[/]",
                                 border_style=color))
        else:
            print(f"\n⚠ [{vehicle}] {f.detector} ({f.risk})")
            print(f"  징후: {f.signal}\n  매핑: {mapping}\n  대응: {f.response}\n  게이트: {gate}")

    # ---------- 증거 보존 ----------
    def _preserve(self, vehicle, f, auto):
        rec = {
            "incident": self.incident_count,
            "time": datetime.now().isoformat(timespec="seconds"),
            "vehicle": vehicle,
            "detector": f.detector,
            "signal": f.signal,
            "threat_map": f.threat_map,
            "risk": f.risk,
            "response": f.response,
            "auto_action": auto,
            "evidence": f.evidence,
        }
        path = os.path.join(self.evidence_dir, "incidents.jsonl")
        with open(path, "a") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _banner(self):
        msg = ("Defense AI Agent 가동 — 감시 대상: "
               + ", ".join(v.name.upper() for v in self.vehicles)
               + f"\n증거 로그: {self.evidence_dir}/incidents.jsonl")
        if _console:
            _console.print(Panel(msg, title="🛡  DAH 방어 에이전트", border_style="cyan"))
        else:
            print("=" * 60 + f"\n{msg}\n" + "=" * 60)


def main():
    ap = argparse.ArgumentParser(description="방어 AI 에이전트")
    ap.add_argument("--uav", default="udpin:127.0.0.1:14550",
                    help="UAV 텔레메트리 수신 (mock/SITL)")
    ap.add_argument("--ugv", default=None,
                    help="UGV 텔레메트리 수신 (예: udpin:127.0.0.1:14560)")
    ap.add_argument("--rate", type=float, default=4.0)
    ap.add_argument("--evidence-dir", default="logs")
    args = ap.parse_args()

    vehicles = [VehicleMonitor("uav", args.uav, args.rate)]
    if args.ugv:
        vehicles.append(VehicleMonitor("ugv", args.ugv, args.rate))

    DefenseAgent(vehicles, args.evidence_dir).run()


if __name__ == "__main__":
    main()
