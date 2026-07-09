"""공통 이벤트 계약 (Common Event Contract) — 기술스택 문서 §6.

모든 에이전트/모듈은 내부 객체를 직접 참조하지 않고 아래 이벤트만 교환한다.
Pydantic 2 로 경계 입력을 검증하며, 로그/LLM 출력이 동일한 스키마를 재사용한다.

필수 규칙(문서 §6):
  - 센서 시간(sensor_ts)과 수신 시간(recv_ts)을 분리해 stale sample 오탐을 막는다.
  - 각 이벤트는 episode_id, correlation_id, schema_version 을 가진다.
  - 행동 이벤트(AttackAction/DefenseAction)는 선택 당시 정책/모델 버전과
    입력 증거 참조(input_refs)를 남긴다.
"""
from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class Risk(str, Enum):
    """위험도 4단계. 순서 비교를 위해 rank 제공."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}[self.value]


class AttackFlow(str, Enum):
    """대표공격흐름 문서 A~F 축. 상관/보고용 태그."""
    A_ROUTE = "A"          # 경로/상황인식 미세 편향
    B_C2 = "B"             # C2 명령 신뢰 훼손 및 운용자 개입 회피
    C_TELEMETRY = "C"      # 텔레메트리 최소 보정
    D_LINK = "D"           # 통신 품질 저하와 자율 모드 전환
    E_SENSOR = "E"         # 센서/AI 인식 신뢰 저하
    F_SWARM = "F"          # 군집 신뢰 전파 오염
    UNKNOWN = "?"


class _Envelope(BaseModel):
    """모든 이벤트의 공통 봉투(envelope)."""
    schema_version: str = SCHEMA_VERSION
    episode_id: str = Field(default_factory=_new_id)
    correlation_id: str = Field(default_factory=_new_id)

    # model_version 필드가 pydantic 보호 네임스페이스(model_)와 충돌하지 않도록 해제
    model_config = {"extra": "forbid", "use_enum_values": False,
                    "protected_namespaces": ()}


class TelemetryEvent(_Envelope):
    """Observer → Detector. 공통 관측 상태를 표준화한 한 틱."""
    kind: Literal["telemetry"] = "telemetry"
    vehicle: str                      # "uav" | "ugv" | swarm node id
    source: str                       # "mock" | "sitl" | "mavlink:14550"
    sensor_ts: float                  # 센서/발신 측 시간(초)
    recv_ts: float                    # 방어 측 수신 시간(초)
    features: dict[str, Any]          # 표준화된 상태 필드(position, speed, ...)

    @property
    def freshness(self) -> float:
        """수신-센서 시간차(초). 클수록 stale — 오탐 억제에 사용."""
        return max(0.0, self.recv_ts - self.sensor_ts)


class FindingEvent(_Envelope):
    """Detector → Correlator. 단일 이상징후 1건."""
    kind: Literal["finding"] = "finding"
    vehicle: str
    detector: str
    signal: str                       # 사람이 읽는 이상징후 설명
    flow: AttackFlow = AttackFlow.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    risk: Risk = Risk.MEDIUM
    threat_map: dict[str, str] = Field(default_factory=dict)  # STRIDE/TARA/STPA/ATLAS
    evidence: dict[str, Any] = Field(default_factory=dict)
    ts: float = 0.0                   # 탐지 시각(수신 시간 기준)


class AttackAction(_Envelope):
    """Red Planner → Gate/Executor. (Blue 전용 빌드에서도 계약 완결성 위해 정의)"""
    kind: Literal["attack_action"] = "attack_action"
    tool: str                         # jam | mitm | gnss_spoof | c2_inject | wait
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    policy_version: str = ""


class DefenseAction(_Envelope):
    """Blue Planner → Gate/Executor. 대응 플레이북 1건."""
    kind: Literal["defense_action"] = "defense_action"
    vehicle: str
    playbook: str                     # 대응 플레이북 식별자
    steps: list[str] = Field(default_factory=list)
    risk: Risk = Risk.LOW
    approval_required: bool = False    # True면 HITL 승인 전까지 실행 보류
    rationale: str = ""
    policy_version: str = ""
    model_version: str = ""
    input_refs: list[str] = Field(default_factory=list)  # 근거 Finding correlation_id


class OutcomeEvent(_Envelope):
    """Simulator → Evaluator. 행동의 결과."""
    kind: Literal["outcome"] = "outcome"
    objective: str
    success: bool
    latency_s: float = 0.0
    side_effects: dict[str, Any] = Field(default_factory=dict)


class ScoreEvent(_Envelope):
    """Scoring Adapter → 양측 Planner. 공식 점수 축(공격/방어/가용성)."""
    kind: Literal["score"] = "score"
    attack: float = 0.0
    defense: float = 0.0
    availability: float = Field(ge=0.0, le=100.0, default=100.0)  # SLA 0..100
    diagnostics: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(_Envelope):
    """모든 모듈 → Evidence Store. 재현·설명 가능성을 위한 감사 로그."""
    kind: Literal["audit"] = "audit"
    actor: str                        # 모듈/에이전트 이름
    decision: str                     # 무엇을 판단/선택했는가
    input_refs: list[str] = Field(default_factory=list)
    model_version: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    ts: float = 0.0


AnyEvent = (
    TelemetryEvent | FindingEvent | AttackAction
    | DefenseAction | OutcomeEvent | ScoreEvent | AuditEvent
)
