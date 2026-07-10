"""설정 로더 — TOML + Pydantic (기술스택 문서 §5).

tomllib(3.11+) 로 TOML 을 읽어 Pydantic 모델로 검증한다. 임계값·포트·배점을
코드에 박지 않고 설정만 교체할 수 있게 한다.
"""
from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class GnssCfg(BaseModel):
    warn_m: float = 30.0
    crit_m: float = 100.0


class LinkCfg(BaseModel):
    warn_factor: float = 3.0
    crit_gap_s: float = 3.0


class CommandCfg(BaseModel):
    window_s: float = 3.0
    max_cmds: int = 5


class RouteCfg(BaseModel):
    xtrack_warn_m: float = 40.0
    route_change_window_s: float = 10.0
    route_change_max: int = 3


class SensorCfg(BaseModel):
    conf_drop: float = 0.4
    disagree_thresh: float = 0.5
    flicker_window: int = 6       # 프레임 간 라벨 튐 관측 창(프레임 수)
    flicker_flips: int = 3        # 창 내 라벨 반전 임계


class SwarmCfg(BaseModel):
    consensus_m: float = 25.0
    node_trust_drop: float = 0.3


class DetectCfg(BaseModel):
    gnss: GnssCfg = GnssCfg()
    link: LinkCfg = LinkCfg()
    command: CommandCfg = CommandCfg()
    route: RouteCfg = RouteCfg()
    sensor: SensorCfg = SensorCfg()
    swarm: SwarmCfg = SwarmCfg()


class MlCfg(BaseModel):
    enabled: bool = True
    n_trees: int = 25
    height: int = 8
    window_size: int = 250
    anomaly_quantile: float = 0.995
    drift_delta: float = 0.002


class ResponseCfg(BaseModel):
    auto_max_risk: str = "Medium"


class GateCfg(BaseModel):
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_playbooks: list[str] = Field(default_factory=list)


class RunCfg(BaseModel):
    seed: int = 20260707
    rate_hz: float = 4.0
    tick_s: float = 0.05


class BusCfg(BaseModel):
    maxsize: int = 1024
    policy: str = "block"


class VehicleCfg(BaseModel):
    source: str
    expected_hz: float = 4.0


class EvidenceCfg(BaseModel):
    dir: str = "logs"
    jsonl: str = "logs/events.jsonl"
    sqlite: str = "logs/episodes.db"


class LlmCfg(BaseModel):
    enabled: bool = False
    endpoint: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    timeout_s: float = 8.0


class ScoringRefCfg(BaseModel):
    config: str = "configs/scoring.toml"


class RedCfg(BaseModel):
    """Red(공격) AI 에이전트 설정 — 기술스택 문서 §4.1, §8.

    적응형 공격 정책(LinUCB)의 하이퍼파라미터, 공격 예산·안전 범위, 실행 대상,
    증거 경로를 코드에 박지 않고 설정으로 교체한다.
    """
    enabled: bool = True
    policy: str = "adaptive"          # adaptive(LinUCB) | baseline(고정순서)
    seed: int = 20260707             # 정책 재현용 시드
    alpha: float = 0.6               # LinUCB 탐험 계수
    inject_target: str = "udpout:127.0.0.1:14555"  # UAV cmd-in(=telem port+5)
    settle_s: float = 2.0            # 공격 후 Blue 반응 관측 창(초)
    decisions: int = 24              # 캠페인 1회 의사결정 횟수
    # 실행 허용 도구(자율성 경계). 기본 라이브 루프는 주입 포트로 동작하는 도구만.
    allowed_tools: list[str] = Field(
        default_factory=lambda: ["wait", "gnss_spoof", "c2_inject"])
    # 파라미터 안전 상한(격리 시뮬레이션 보호)
    max_drift_m: float = 200.0
    max_c2_count: int = 30
    max_duration_s: float = 20.0
    evidence_dir: str = "logs_red"


class Config(BaseModel):
    schema_version: str = "1.0"
    run: RunCfg = RunCfg()
    bus: BusCfg = BusCfg()
    vehicles: dict[str, VehicleCfg] = Field(default_factory=dict)
    detect: DetectCfg = DetectCfg()
    ml: MlCfg = MlCfg()
    response: ResponseCfg = ResponseCfg()
    gate: GateCfg = GateCfg()
    red: RedCfg = RedCfg()
    scoring: ScoringRefCfg = ScoringRefCfg()
    evidence: EvidenceCfg = EvidenceCfg()
    llm: LlmCfg = LlmCfg()

    model_config = {"extra": "ignore"}


def load_config(path: str | Path = "configs/default.toml") -> Config:
    data: dict[str, Any] = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return Config.model_validate(data)


def load_toml(path: str | Path) -> dict[str, Any]:
    return tomllib.loads(Path(path).read_text(encoding="utf-8"))
