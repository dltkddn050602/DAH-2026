"""
방어 이상탐지기 — 공통 관측데이터(텔레메트리) 기반

방어 전략 문서의 원칙을 그대로 구현한다: 특정 오토파일럿 내부 구현에 의존하지 않고,
어떤 무인체계에서도 공통으로 얻을 수 있는 텔레메트리/네트워크/센서 신호만으로 이상을
탐지한다. 각 탐지기는 이상징후를 TARA/STRIDE/STPA-Sec/MITRE ATLAS 위협모델에
매핑하고 위험도와 대응 플레이북을 함께 산출한다.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


@dataclass
class Finding:
    detector: str
    signal: str                 # 관측된 이상징후
    threat_map: dict            # {STRIDE, TARA, STPA-Sec, ATLAS ...}
    risk: str                   # Low / Medium / High / Critical
    response: str               # 추천 대응
    evidence: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


EARTH_R = 6378137.0


def haversine_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_R * math.asin(math.sqrt(a))


class GnssInsCrossCheck:
    """GNSS 원시위치(GPS_RAW_INT) vs 관성/EKF 위치(GLOBAL_POSITION_INT) 교차검증."""
    def __init__(self, warn_m=30.0, crit_m=100.0):
        self.warn_m, self.crit_m = warn_m, crit_m
        self.last_gps = None    # (lat, lon)
        self.last_glob = None

    def update(self, msg):
        t = msg.get_type()
        if t == "GPS_RAW_INT":
            self.last_gps = (msg.lat / 1e7, msg.lon / 1e7)
        elif t == "GLOBAL_POSITION_INT":
            self.last_glob = (msg.lat / 1e7, msg.lon / 1e7)
        else:
            return None
        if not (self.last_gps and self.last_glob):
            return None
        d = haversine_m(*self.last_gps, *self.last_glob)
        if d < self.warn_m:
            return None
        risk = "Critical" if d >= self.crit_m else "High"
        return Finding(
            detector="GNSS-INS 교차검증",
            signal=f"GNSS와 INS 위치가 {d:.0f}m 불일치 (임계 {self.warn_m:.0f}m)",
            threat_map={
                "STRIDE": "Spoofing",
                "TARA": "경로 왜곡 → 임무 실패/충돌 위험",
                "STPA-Sec": "불안전 제어행동(위조 위치 기반 항법)",
            },
            risk=risk,
            response=("GNSS 신뢰도 하향, INS/비전 기반 항법 전환, 안전속도 제한"
                      + (", 즉시 귀환/정지 권고(운용자 승인)" if risk == "Critical" else "")),
            evidence={"gps": self.last_gps, "ins": self.last_glob, "divergence_m": round(d, 1)},
        )


class LinkHealthMonitor:
    """HEARTBEAT 간격 급증 / 텔레메트리 두절 → 재밍·DoS 탐지."""
    def __init__(self, expected_hz=4.0, warn_factor=3.0, crit_gap_s=3.0):
        self.expected_dt = 1.0 / expected_hz
        self.warn_dt = self.expected_dt * warn_factor
        self.crit_gap = crit_gap_s
        self.last_hb = None
        self.fired = False

    def update(self, msg):
        now = time.time()
        if msg.get_type() != "HEARTBEAT":
            # 두절 중에도 호출되도록 tick()에서 별도 검사
            return None
        gap = None if self.last_hb is None else now - self.last_hb
        self.last_hb = now
        self.fired = False
        if gap is None or gap < self.warn_dt:
            return None
        risk = "High" if gap >= self.crit_gap else "Medium"
        return Finding(
            detector="링크 상태 감시",
            signal=f"HEARTBEAT 간격 {gap:.1f}s (정상 {self.expected_dt:.2f}s) — 링크 저하",
            threat_map={"STRIDE": "Denial of Service",
                        "TARA": "통신 두절 → 제어 지연/상실"},
            risk=risk,
            response=("자율 안전모드 유지, 통신두절 안전정책(사전 정의 경로 복귀), "
                      "링크 전환(다중 링크)"),
            evidence={"heartbeat_gap_s": round(gap, 2)},
        )

    def tick(self):
        """메시지가 없을 때도 두절을 감지하기 위한 주기 점검."""
        if self.last_hb is None:
            return None
        gap = time.time() - self.last_hb
        if gap >= self.crit_gap and not self.fired:
            self.fired = True
            return Finding(
                detector="링크 상태 감시",
                signal=f"텔레메트리 두절 {gap:.1f}s 지속 — 재밍/DoS 의심",
                threat_map={"STRIDE": "Denial of Service",
                            "TARA": "통신 두절 → 제어 상실"},
                risk="High",
                response="통신두절 안전정책 발동: 사전 정의 경로 복귀 / 정지, 링크 전환",
                evidence={"outage_s": round(gap, 2)},
            )
        return None


class CommandAnomalyMonitor:
    """명령 빈도 이상 / 예상치 못한 모드 전환 → C2 명령 주입 탐지."""
    def __init__(self, window_s=3.0, max_cmds=5):
        self.window_s = window_s
        self.max_cmds = max_cmds
        self.acks = []          # COMMAND_ACK 타임스탬프
        self.last_mode = None

    def update(self, msg):
        t = msg.get_type()
        now = time.time()
        findings = []

        if t == "COMMAND_ACK":
            self.acks.append(now)
            self.acks = [x for x in self.acks if now - x <= self.window_s]
            if len(self.acks) > self.max_cmds:
                findings.append(Finding(
                    detector="명령 이상 감시",
                    signal=f"{self.window_s:.0f}s 내 명령 {len(self.acks)}건 — 비정상 명령 빈도",
                    threat_map={"STRIDE": "Tampering",
                                "TARA": "명령 주입 → 제어권 상실",
                                "STPA-Sec": "불안전 제어행동(권한 없는 명령)"},
                    risk="High",
                    response="명령 서명검증/재인증 요구, 명령 차단, 링크 전환",
                    evidence={"cmds_in_window": len(self.acks)},
                ))

        if t == "HEARTBEAT":
            mode = msg.custom_mode
            if self.last_mode is not None and mode != self.last_mode:
                findings.append(Finding(
                    detector="명령 이상 감시",
                    signal=f"예상치 못한 모드 전환 {self.last_mode}→{mode}",
                    threat_map={"STRIDE": "Tampering",
                                "TARA": "임무계획 변조"},
                    risk="Medium",
                    response="운용자 재인증, 명령 정책엔진 검증, 상태 기반 명령 허용",
                    evidence={"mode_from": self.last_mode, "mode_to": mode},
                ))
            self.last_mode = mode

        return findings or None


class InterceptionMonitor:
    """데이터링크 MITM/도청 → 능동 변조 탐지.

    도청(수동 릴레이)은 프레임을 바이트 그대로 중계하므로 텔레메트리 '내용'상 서명이
    없다 — 순수 기밀성 상실은 텔레메트리만으로는 관측 불가하다(정직한 한계, 링크 인증/
    암호화·네트워크 계층 대책의 영역). 그러나 공격자가 상황인식을 오염시키려 능동
    변조/주입하는 순간, 특정 오토파일럿에 무관한 두 공통 서명이 나타난다.

      (1) 운동학 정합성 위반: 보고된 위치의 프레임 간 변화량이 같은 프레임의 속도
          필드(vx,vy)와 어긋난다. 공격자는 좌표만 밀어내고 속도는 그대로 두기 때문.
      (2) 발신원 시퀀스 불연속: 재기록/주입된 프레임이 원 발신원과 다른 MAVLink
          시퀀스로 방출되어, 동일 sysid의 seq가 역행·급점프한다.
    """

    def __init__(self, kin_warn_m=6.0, kin_crit_m=25.0, seq_jump=8, seq_window=12):
        self.kin_warn_m = kin_warn_m
        self.kin_crit_m = kin_crit_m
        self.seq_jump = seq_jump
        self.seq_window = seq_window
        self.last_pos = None        # (lat, lon)
        self.last_t = None          # time_boot_ms (s)
        self.last_seq = {}          # sysid -> seq
        self.seq_anoms = []         # 최근 시퀀스 이상 타임스탬프

    def update(self, msg):
        t = msg.get_type()
        findings = []

        # (2) 발신원 시퀀스 정합성 — 모든 프레임에 적용
        sysid = msg.get_srcSystem()
        seq = msg.get_seq()
        prev = self.last_seq.get(sysid)
        self.last_seq[sysid] = seq
        if prev is not None:
            delta = (seq - prev) % 256          # 정상 링크는 1 (유실 시 소폭 증가)
            backward = delta > 128              # 롤오버 제외한 역행
            big_jump = self.seq_jump < delta <= 128
            if backward or big_jump:
                now = time.time()
                self.seq_anoms = [x for x in self.seq_anoms if now - x <= 3.0]
                self.seq_anoms.append(now)
                if len(self.seq_anoms) >= 3:
                    self.seq_anoms.clear()
                    findings.append(Finding(
                        detector="MITM 인터셉션 감시",
                        signal=(f"동일 sysid({sysid}) MAVLink 시퀀스 불연속 다발 "
                                f"(Δseq={delta}) — 프레임 주입/재기록 의심"),
                        threat_map={"STRIDE": "Tampering/Spoofing",
                                    "TARA": "중간자 변조 → 상황인식 오염",
                                    "ATT&CK-ICS": "Adversary-in-the-Middle(T0830)"},
                        risk="High",
                        response=("링크 무결성(서명/시퀀스) 검증, 텔레메트리 발신원 재인증, "
                                  "링크 암호화·경로 무결성 점검, 링크 전환"),
                        evidence={"sysid": sysid, "delta_seq": delta},
                    ))

        # (1) 운동학 정합성 — 융합 위치 프레임에 적용
        if t == "GLOBAL_POSITION_INT":
            lat, lon = msg.lat / 1e7, msg.lon / 1e7
            tb = msg.time_boot_ms / 1000.0
            v = math.hypot(msg.vx, msg.vy) / 100.0     # cm/s → m/s (보고 속도)
            if self.last_pos is not None and self.last_t is not None:
                dt = tb - self.last_t
                if 0.02 < dt < 5.0:
                    actual = haversine_m(*self.last_pos, lat, lon)
                    expected = v * dt
                    residual = abs(actual - expected)
                    if residual >= self.kin_warn_m:
                        risk = "Critical" if residual >= self.kin_crit_m else "High"
                        findings.append(Finding(
                            detector="MITM 인터셉션 감시",
                            signal=(f"위치 변화 {actual:.0f}m 가 보고 속도 기대치 "
                                    f"{expected:.0f}m 와 {residual:.0f}m 불일치 — 위치 위조 주입"),
                            threat_map={"STRIDE": "Tampering",
                                        "TARA": "위조 피드백 → 상황인식 오염/오항법",
                                        "STPA-Sec": "위조 피드백 기반 불안전 제어행동"},
                            risk=risk,
                            response=("융합위치 신뢰도 하향, 원시 GPS·INS 교차검증, "
                                      "링크 무결성 검증"
                                      + (", 즉시 안전모드/정지 권고(운용자 승인)"
                                         if risk == "Critical" else "")),
                            evidence={"actual_move_m": round(actual, 1),
                                      "expected_move_m": round(expected, 1),
                                      "residual_m": round(residual, 1)},
                        ))
            self.last_pos = (lat, lon)
            self.last_t = tb

        return findings or None


class SensorConsensusMonitor:
    """다중 센서/AI 판단 불일치 → 적대적 예제·센서 기만 탐지.

    perception 모듈(또는 SITL 카메라 파이프라인)이 산출한 탐지 신뢰도/합의 결과를
    inject_ai_result()로 주입하면 평가한다. (텔레메트리만으로는 관측 불가한 AI 신호)
    """
    def __init__(self, conf_drop=0.4, disagree_thresh=0.5,
                 flicker_window=6, flicker_flips=3):
        self.conf_drop = conf_drop
        self.disagree = disagree_thresh
        self.flicker_window = flicker_window
        self.flicker_flips = flicker_flips
        self.last_conf = None
        self._labels = []

    def inject_ai_result(self, model_conf: float, sensor_agreement: float,
                         label=None):
        """인지 파이프라인의 프레임 결과(신뢰도·카메라↔LiDAR 합의도·표적 라벨)를 평가.

        세 상보 서명: (1) 신뢰도 붕괴 (2) 카메라↔LiDAR 교차검증 붕괴
        (3) 프레임 간 라벨 튐(temporal flicker).
        """
        findings = []
        if self.last_conf is not None and (self.last_conf - model_conf) >= self.conf_drop:
            findings.append(Finding(
                detector="센서/AI 합의 감시",
                signal=f"AI 탐지 신뢰도 급락 {self.last_conf:.2f}→{model_conf:.2f} (카메라 인지 붕괴)",
                threat_map={"MITRE ATLAS": "Evasion(적대적 예제/PGD 섭동)",
                            "TARA": "표적 오인식/장애물 회피 실패"},
                risk="High",
                response="센서 재검증, 다중 센서 합의 요구, AI 신뢰도 하향, 인간 확인 요청",
                evidence={"conf_prev": self.last_conf, "conf_now": model_conf},
            ))
        if sensor_agreement < self.disagree:
            findings.append(Finding(
                detector="센서/AI 합의 감시",
                signal=f"카메라 판단 vs LiDAR/타 센서 교차검증 불일치(합의도 {sensor_agreement:.2f})",
                threat_map={"MITRE ATLAS": "Evasion",
                            "STPA-Sec": "센서 기만 기반 불안전 판단"},
                risk="Medium",
                response="표적판단 보류, 다중 센서 교차검증, 인간 확인 요청",
                evidence={"sensor_agreement": sensor_agreement},
            ))
        if label is not None:
            self._labels.append(label)
            self._labels = self._labels[-self.flicker_window:]
            flips = sum(1 for a, b in zip(self._labels, self._labels[1:]) if a != b)
            if len(self._labels) >= self.flicker_window and flips >= self.flicker_flips:
                findings.append(Finding(
                    detector="센서/AI 합의 감시",
                    signal=f"프레임 간 표적 라벨 반복 반전 {flips}회/{len(self._labels)}프레임 (temporal flicker)",
                    threat_map={"MITRE ATLAS": "Evasion(시간적 불안정 유발)",
                                "TARA": "표적 판단 신뢰 붕괴"},
                    risk="High",
                    response="표적판단 보류, 다중 센서 교차검증, 인간 확인 요청",
                    evidence={"label_flips": flips, "window": len(self._labels)},
                ))
        self.last_conf = model_conf
        return findings or None
