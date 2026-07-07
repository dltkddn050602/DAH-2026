"""
경량 MAVLink 목(mock) 차량 — UAV(Copter) / UGV(Rover)

목적
----
ArduPilot SITL 풀스택(Docker 빌드 ~20분)을 기다리지 않고도, 공격/방어 코드를
end-to-end로 개발·시연하기 위한 경량 대체 차량이다. 실제 SITL과 동일한 MAVLink
메시지(HEARTBEAT / GLOBAL_POSITION_INT / GPS_RAW_INT / SYS_STATUS / COMMAND_ACK)를
방출하므로, 여기서 검증한 공수/방어 스크립트는 SITL에 그대로 붙는다.

토폴로지
--------
    mock_vehicle --(telemetry)--> udpout  ─▶  defense.agent (udpin)
    attacker/GCS --(command)-----> udpin   (cmd-in 포트)

모델링한 공격 표면
------------------
1) C2 명령 주입: cmd-in 포트로 SET_MODE / COMMAND_LONG(RTL 등)이 들어오면 상태 변경.
   → HEARTBEAT.custom_mode 변화 + COMMAND_ACK 로 텔레메트리에 반영(방어가 관측).
2) GNSS 스푸핑: 공격자가 GPS_INPUT 메시지를 주입하면, 그 좌표로 GPS_RAW_INT 를
   덮어쓴다. 반면 GLOBAL_POSITION_INT(EKF/INS 융합)는 잠시 참(True) 경로를 유지 →
   GPS_RAW vs GLOBAL_POSITION 간 divergence 발생(방어의 GNSS-INS 교차검증이 탐지).
   * 실제 RF 스푸핑을 프로토콜 수준(GPS_INPUT 외부 GPS 주입)으로 정직하게 모델링한 것.
     SITL에서는 SIM_GPS* 파라미터로 대체 가능.

주의: 격리된 로컬 시뮬레이션 전용. 실제 기체/무선에 사용 금지.
"""
from __future__ import annotations

import argparse
import math
import time

from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mav

# --- 참(true) 시작 좌표 (임의의 훈련장) ---
HOME_LAT = 37.5000  # deg
HOME_LON = 127.0000
HOME_ALT = 100.0    # m MSL

EARTH_R = 6378137.0  # m


def meters_to_latlon(dlat_m: float, dlon_m: float, lat0: float):
    dlat = dlat_m / EARTH_R * (180.0 / math.pi)
    dlon = dlon_m / (EARTH_R * math.cos(math.radians(lat0))) * (180.0 / math.pi)
    return dlat, dlon


class MockVehicle:
    def __init__(self, vehicle: str, out: str, cmd_in: str, rate_hz: float = 4.0):
        self.vehicle = vehicle
        self.is_air = vehicle == "copter"
        self.rate = rate_hz
        self.dt = 1.0 / rate_hz

        # 텔레메트리 송신(우리가 push) + 명령 수신(대기)
        self.tx = mavutil.mavlink_connection(out, source_system=1)
        self.cmd = mavutil.mavlink_connection(cmd_in, source_system=1)

        self.mav_type = (mav.MAV_TYPE_QUADROTOR if self.is_air
                         else mav.MAV_TYPE_GROUND_ROVER)

        # 상태
        self.t0 = time.time()
        self.boot0 = self.t0
        self.mode = "AUTO"           # 커스텀 모드 이름
        self.custom_mode = 3         # AUTO
        self.armed = True
        self.batt_pct = 92

        # 참 위치(참 경로) — 원형/직선 순찰
        self.true_x = 0.0  # m East
        self.true_y = 0.0  # m North
        self.speed = 12.0 if self.is_air else 4.0  # m/s
        self.heading = 0.0

        # GPS 스푸핑 상태 (GPS_INPUT 주입 시 설정)
        self.gps_spoof_offset = None  # (dx_m, dy_m) or None
        self.spoof_hits = 0

    # ---------- 물리(아주 단순한 순찰 경로) ----------
    def step_physics(self):
        t = time.time() - self.t0
        if self.mode == "RTL":
            # 홈으로 수렴
            self.true_x *= 0.96
            self.true_y *= 0.96
        else:
            # 반경 200m 원형 순찰
            R = 200.0
            w = self.speed / R
            self.true_x = R * math.sin(w * t)
            self.true_y = R * (1 - math.cos(w * t))
            self.heading = (math.degrees(w * t)) % 360

    # ---------- 텔레메트리 방출 ----------
    def send_telemetry(self):
        now_ms = int((time.time() - self.boot0) * 1000)

        # HEARTBEAT
        base_mode = (mav.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED |
                     (mav.MAV_MODE_FLAG_SAFETY_ARMED if self.armed else 0))
        self.tx.mav.heartbeat_send(
            self.mav_type, mav.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode, self.custom_mode, mav.MAV_STATE_ACTIVE)

        # 참 위치 → 위경도
        tlat_d, tlon_d = meters_to_latlon(self.true_y, self.true_x, HOME_LAT)
        true_lat = HOME_LAT + tlat_d
        true_lon = HOME_LON + tlon_d
        alt_mm = int((HOME_ALT if self.is_air else 0.0) * 1000)

        # GLOBAL_POSITION_INT = EKF/INS 융합 (참 경로 유지, 소량 드리프트)
        self.tx.mav.global_position_int_send(
            now_ms,
            int(true_lat * 1e7), int(true_lon * 1e7),
            alt_mm, alt_mm,
            int(self.speed * 100 * math.cos(math.radians(self.heading))),
            int(self.speed * 100 * math.sin(math.radians(self.heading))),
            0, int(self.heading * 100))

        # GPS_RAW_INT = 원시 GPS (스푸핑 주입 시 이쪽만 변조됨)
        gps_lat, gps_lon = true_lat, true_lon
        if self.gps_spoof_offset is not None:
            dx, dy = self.gps_spoof_offset
            slat, slon = meters_to_latlon(dy, dx, HOME_LAT)
            gps_lat += slat
            gps_lon += slon
        self.tx.mav.gps_raw_int_send(
            now_ms * 1000, mav.GPS_FIX_TYPE_3D_FIX,
            int(gps_lat * 1e7), int(gps_lon * 1e7), alt_mm,
            121, 121, int(self.speed * 100), 0, 12)  # 12 sats

        # SYS_STATUS (배터리)
        self.tx.mav.sys_status_send(
            0, 0, 0, 500, 12000, int(self.batt_pct * 100 / 100 * 100) // 100 * 100,
            self.batt_pct, 0, 0, 0, 0, 0, 0)

    # ---------- 명령 처리 ----------
    def poll_commands(self):
        while True:
            msg = self.cmd.recv_match(blocking=False)
            if msg is None:
                return
            mtype = msg.get_type()

            if mtype == "COMMAND_LONG":
                self._handle_command_long(msg)
            elif mtype == "SET_MODE":
                self.custom_mode = msg.custom_mode
                self._log(f"[CMD] SET_MODE custom_mode={msg.custom_mode}")
                self._ack(mav.MAV_CMD_DO_SET_MODE)
            elif mtype == "GPS_INPUT":
                self._handle_gps_input(msg)

    def _handle_command_long(self, msg):
        cid = msg.command
        if cid == mav.MAV_CMD_NAV_RETURN_TO_LAUNCH:
            self.mode = "RTL"
            self.custom_mode = 6
            self._log("[CMD] RETURN_TO_LAUNCH 수신 → RTL 전환")
        elif cid == mav.MAV_CMD_COMPONENT_ARM_DISARM:
            self.armed = bool(msg.param1)
            self._log(f"[CMD] ARM/DISARM param1={msg.param1}")
        elif cid == mav.MAV_CMD_DO_SET_MODE:
            self.custom_mode = int(msg.param2)
            self._log(f"[CMD] DO_SET_MODE → {self.custom_mode}")
        else:
            self._log(f"[CMD] COMMAND_LONG id={cid} 수신")
        # COMMAND_ACK 를 텔레메트리 채널로도 내보내 방어가 관측하게 함
        self._ack(cid)

    def _handle_gps_input(self, msg):
        # 주입 좌표를 HOME 기준 변위 벡터로 환산해 GPS_RAW에 additive 적용.
        # → GPS_RAW = 참위치 + 오프셋 이므로 GNSS-INS divergence ≈ 주입 오차(정직한 모델).
        inj_lat = msg.lat / 1e7
        inj_lon = msg.lon / 1e7
        dy = (inj_lat - HOME_LAT) * EARTH_R * math.pi / 180.0
        dx = (inj_lon - HOME_LON) * EARTH_R * math.cos(math.radians(HOME_LAT)) * math.pi / 180.0
        self.gps_spoof_offset = (dx, dy)
        self.spoof_hits += 1
        if self.spoof_hits % 10 == 1:
            self._log(f"[!] GPS_INPUT 주입 감지: 오프셋≈({dx:.0f},{dy:.0f})m")

    def _ack(self, cid):
        self.tx.mav.command_ack_send(cid, mav.MAV_RESULT_ACCEPTED)

    def _log(self, s):
        print(f"  {self.vehicle:6s} {s}", flush=True)

    # ---------- 메인 루프 ----------
    def run(self):
        print(f"[mock_vehicle] {self.vehicle} 구동")
        print(f"  telemetry out : {self.tx.address if hasattr(self.tx,'address') else self.tx}")
        print(f"  command  in   : listening")
        next_t = time.time()
        while True:
            self.poll_commands()
            self.step_physics()
            self.send_telemetry()
            next_t += self.dt
            sleep = next_t - time.time()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_t = time.time()


def main():
    ap = argparse.ArgumentParser(description="경량 MAVLink 목 차량 (UAV/UGV)")
    ap.add_argument("--vehicle", choices=["copter", "rover"], default="copter")
    ap.add_argument("--port", type=int, default=14550,
                    help="텔레메트리 송신 포트 (defense가 udpin으로 수신)")
    ap.add_argument("--cmd-port", type=int, default=None,
                    help="명령 수신 포트 (기본: port+5)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--rate", type=float, default=4.0)
    args = ap.parse_args()

    cmd_port = args.cmd_port or (args.port + 5)
    out = f"udpout:{args.host}:{args.port}"
    cmd_in = f"udpin:{args.host}:{cmd_port}"
    print(f"[mock_vehicle] telemetry→{out}  commands←{cmd_in}")

    MockVehicle(args.vehicle, out, cmd_in, args.rate).run()


if __name__ == "__main__":
    main()
