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


class SensorConsensusMonitor:
    """다중 센서/AI 판단 불일치 → 적대적 예제·센서 기만 탐지.

    perception 모듈(또는 SITL 카메라 파이프라인)이 산출한 탐지 신뢰도/합의 결과를
    inject_ai_result()로 주입하면 평가한다. (텔레메트리만으로는 관측 불가한 AI 신호)
    """
    def __init__(self, conf_drop=0.4, disagree_thresh=0.5):
        self.conf_drop = conf_drop
        self.disagree = disagree_thresh
        self.last_conf = None

    def inject_ai_result(self, model_conf: float, sensor_agreement: float):
        findings = []
        if self.last_conf is not None and (self.last_conf - model_conf) >= self.conf_drop:
            findings.append(Finding(
                detector="센서/AI 합의 감시",
                signal=f"AI 탐지 신뢰도 급락 {self.last_conf:.2f}→{model_conf:.2f}",
                threat_map={"MITRE ATLAS": "Evasion(적대적 예제)",
                            "TARA": "표적 오인식/장애물 회피 실패"},
                risk="High",
                response="센서 재검증, 다중 센서 합의 요구, AI 신뢰도 하향, 인간 확인 요청",
                evidence={"conf_prev": self.last_conf, "conf_now": model_conf},
            ))
        if sensor_agreement < self.disagree:
            findings.append(Finding(
                detector="센서/AI 합의 감시",
                signal=f"센서 간 표적 판단 불일치(합의도 {sensor_agreement:.2f})",
                threat_map={"MITRE ATLAS": "Evasion",
                            "STPA-Sec": "센서 기만 기반 불안전 판단"},
                risk="Medium",
                response="표적판단 보류, 다중 센서 교차검증, 인간 확인 요청",
                evidence={"sensor_agreement": sensor_agreement},
            ))
        self.last_conf = model_conf
        return findings or None
