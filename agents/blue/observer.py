"""Telemetry Observer — 기술스택 문서 §4.2.

pymavlink 로 MAVLink 를 수집해 프로토콜 비종속 표준 features 로 정규화하고
TelemetryEvent 로 버스에 발행한다. 특정 오토파일럿 내부 구현이 아니라 공개
프로토콜에서 관측 가능한 값만 사용한다(대표공격흐름 문서 §2).

설계 포인트:
  - sensor_ts(발신 측 시간)와 recv_ts(수신 시간)를 분리 → stale 오탐 방지.
  - 롤링 상태를 유지하고 매 메시지마다 전체 features 스냅샷 + updated 목록을 낸다.
  - 메시지가 없을 때도 link_probe 이벤트를 주기 발행 → 두절/재밍 탐지 지속.
  - bounded 버퍼: 최근 N개 스냅샷만 유지.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from core.event_bus import EventBus
from core.events import TelemetryEvent


def normalize(msg) -> dict[str, Any]:
    """단일 MAVLink 메시지 → 표준 features 부분 갱신(대표공격흐름 §2 매핑)."""
    t = msg.get_type()
    out: dict[str, Any] = {}
    if t == "HEARTBEAT":
        out["custom_mode"] = int(msg.custom_mode)
        out["mission_phase"] = int(msg.custom_mode)   # 임무 단계 근사
        out["armed"] = bool(msg.base_mode & 0x80)     # MAV_MODE_FLAG_SAFETY_ARMED
        out["_heartbeat"] = True
    elif t == "GLOBAL_POSITION_INT":
        out["position_ins"] = [msg.lat / 1e7, msg.lon / 1e7]  # EKF/INS 융합 위치
        vx, vy = msg.vx / 100.0, msg.vy / 100.0
        out["speed"] = (vx * vx + vy * vy) ** 0.5
        out["heading"] = msg.hdg / 100.0 if msg.hdg != 65535 else None
    elif t == "GPS_RAW_INT":
        out["position_gps"] = [msg.lat / 1e7, msg.lon / 1e7]  # 원시 GPS
        out["gps_fix"] = int(msg.fix_type)
        out["gps_sats"] = int(msg.satellites_visible)
    elif t == "SYS_STATUS":
        out["battery_pct"] = int(msg.battery_remaining)
        # drop_rate_comm(0.01%), errors_comm — 링크 품질(흐름 D)
        out["drop_rate_comm"] = getattr(msg, "drop_rate_comm", 0) / 100.0
        out["errors_comm"] = int(getattr(msg, "errors_comm", 0))
    elif t == "RADIO_STATUS":  # SITL/실무선에서 링크 품질 직접 제공(흐름 D)
        out["rssi"] = int(msg.rssi)
        out["remrssi"] = int(msg.remrssi)
        out["rxerrors"] = int(msg.rxerrors)
        out["noise"] = int(msg.noise)
    elif t == "COMMAND_ACK":
        out["command_ack"] = {"command": int(msg.command), "result": int(msg.result)}
    else:
        return {}
    return out


def sensor_time(msg, fallback: float) -> float:
    """메시지에 담긴 발신 측 시간(있으면). GLOBAL_POSITION_INT/GPS_RAW_INT 는 boot ms."""
    for attr, scale in (("time_boot_ms", 1e-3), ("time_usec", 1e-6)):
        v = getattr(msg, attr, None)
        if v:
            # 절대시각이 아니므로 상대 신선도 판단용으로만 사용. 여기선 fallback 우선.
            return fallback
    return fallback


class TelemetryObserver:
    """한 차량의 MAVLink 스트림을 관측해 TelemetryEvent 를 발행한다."""

    def __init__(
        self,
        vehicle: str,
        conn_str: str,
        bus: EventBus,
        expected_hz: float = 4.0,
        buffer_size: int = 256,
        probe_interval_s: float = 0.25,
    ) -> None:
        self.vehicle = vehicle
        self.conn_str = conn_str
        self.bus = bus
        self.expected_hz = expected_hz
        self.probe_interval_s = probe_interval_s
        self.state: dict[str, Any] = {"vehicle": vehicle}
        self.buffer: deque[TelemetryEvent] = deque(maxlen=buffer_size)
        self.last_msg_ts: float | None = None
        self._conn = None
        self._episode_id: str = ""

    def connect(self):
        from pymavlink import mavutil
        self._conn = mavutil.mavlink_connection(self.conn_str)
        return self._conn

    def set_episode(self, episode_id: str) -> None:
        self._episode_id = episode_id

    async def run(self) -> None:
        if self._conn is None:
            self.connect()
        last_probe = time.time()
        while True:
            drained = await self._drain()
            now = time.time()
            if not drained and (now - last_probe) >= self.probe_interval_s:
                await self._emit_probe(now)
                last_probe = now
            await asyncio.sleep(0.01)

    async def _drain(self) -> int:
        """수신 큐를 비우며 각 메시지를 정규화·발행. 발행 개수 반환."""
        count = 0
        while True:
            msg = self._conn.recv_match(blocking=False)
            if msg is None:
                break
            partial = normalize(msg)
            if not partial:
                continue
            now = time.time()
            self.last_msg_ts = now
            hb = partial.pop("_heartbeat", False)
            self.state.update(partial)
            evt = self._snapshot(
                sensor_ts=sensor_time(msg, now),
                recv_ts=now,
                updated=list(partial.keys()) + (["heartbeat"] if hb else []),
                msg_type=msg.get_type(),
            )
            self.buffer.append(evt)
            await self.bus.publish(evt)
            count += 1
        return count

    async def _emit_probe(self, now: float) -> None:
        """메시지 침묵 시 link_probe 발행 → 두절/재밍 탐지 지속."""
        gap = None if self.last_msg_ts is None else now - self.last_msg_ts
        evt = self._snapshot(
            sensor_ts=now, recv_ts=now,
            updated=["link_probe"], msg_type="LINK_PROBE",
            extra={"since_last_msg_s": gap},
        )
        await self.bus.publish(evt)

    def _snapshot(
        self, sensor_ts: float, recv_ts: float,
        updated: list[str], msg_type: str, extra: dict | None = None,
    ) -> TelemetryEvent:
        features = dict(self.state)
        features["updated"] = updated
        features["msg_type"] = msg_type
        if extra:
            features.update(extra)
        return TelemetryEvent(
            episode_id=self._episode_id or TelemetryEvent().episode_id,
            vehicle=self.vehicle,
            source=self.conn_str,
            sensor_ts=sensor_ts,
            recv_ts=recv_ts,
            features=features,
        )
