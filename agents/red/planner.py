"""Adaptive Attack Planner — 기술스택 문서 §4.1.

관측 문맥(BattleContext)에 따라 다음 공격 행동을 스스로 고르는 공격 정책. 자유 텍스트가
아니라 유한 도구 집합(Arm)에서 선택하며, seeded LinUCB(문맥적 밴딧)로 온라인 학습한다.

  - 왜 LinUCB인가: 소량의 경기 데이터에서도 문맥별 행동을 실시간으로 고를 수 있고,
    선택 근거(신뢰상한)와 보상을 기록하기 쉬우며, 대규모 강화학습 환경이 필요 없다.
  - NumPy만 사용하고 난수 시드를 고정 → 같은 (문맥, 보상) 순서면 같은 행동 순서(재현성).
  - BaselinePlanner(고정 순서)는 동일 공격 예산 하 비교군으로 함께 제공한다.

행동 공간(문서 §4.1):
    jam(drop_rate, latency_ms, duration_s)
    mitm(mode, mutation_strength, duration_s)
    gnss_spoof(drift_m, ramp_s, hold_s)
    c2_inject(command, rate, count)
    wait(duration_s)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

POLICY_VERSION = "red-linucb-v1"

# 문맥 벡터 차원(observer.BattleContext.to_vector 와 일치해야 함)
CONTEXT_DIM = 6


@dataclass(frozen=True)
class Arm:
    """유한 행동 하나. 도구 + 파라미터 프리셋 + 대응 Blue 흐름(보고용)."""
    name: str
    tool: str                       # wait | gnss_spoof | c2_inject | jam | mitm
    params: dict = field(default_factory=dict)
    flow: str = "?"                 # 이 공격이 겨냥하는 대표 흐름(A~F)
    intent: str = ""                # 사람이 읽는 공격 의도


# 라이브 루프(주입 포트)에서 실제로 동작하는 기본 행동 집합.
# jam/mitm 은 링크 경로 토폴로지가 필요하므로 정책 게이트로 기본 비활성(설계 완결용 정의).
DEFAULT_ARMS: list[Arm] = [
    Arm("wait", "wait", {"duration_s": 1.0}, "?",
        "전략적 대기 — 탐지 압박이 높을 때 은신"),
    Arm("gnss_weak", "gnss_spoof",
        {"drift_m": 45.0, "ramp_s": 3.0, "hold_s": 2.0, "rate": 5.0}, "A",
        "저강도 GNSS 스푸핑 — 임계 근처로 서서히 램프업"),
    Arm("gnss_strong", "gnss_spoof",
        {"drift_m": 150.0, "ramp_s": 4.0, "hold_s": 3.0, "rate": 5.0}, "A",
        "고강도 GNSS 스푸핑 — 항법 교란 극대화"),
    Arm("c2_weak", "c2_inject",
        {"command": "flood", "count": 6}, "B",
        "저빈도 명령 폭주 — 빈도 임계 아래로 회피 시도"),
    Arm("c2_strong", "c2_inject",
        {"command": "flood", "count": 18}, "B",
        "고빈도 명령 폭주 — 임무 탈취 압박"),
]

# 설계 완결용 확장 행동(정책 게이트 allowed_tools 로 활성화). 링크 경로 삽입 필요.
EXTENDED_ARMS: list[Arm] = [
    Arm("jam_mid", "jam",
        {"loss": 0.7, "delay_ms": 400.0, "duration_s": 6.0}, "D",
        "재밍 — 관측 품질 저하 + 무결성 탐지기 오탐 유발"),
    Arm("mitm_mid", "mitm",
        {"drift_m": 120.0, "duration_s": 10.0, "activate_after": 2.0}, "?",
        "MITM 능동 변조 — 융합위치 위조(속도 유지)"),
]


def build_arms(allowed_tools: Sequence[str]) -> list[Arm]:
    """allowed_tools 에 포함된 도구의 Arm 만 추린다(정책 게이트와 정합)."""
    allow = set(allowed_tools)
    arms = [a for a in (DEFAULT_ARMS + EXTENDED_ARMS) if a.tool in allow]
    return arms or [DEFAULT_ARMS[0]]  # 최소 wait 는 보장


@dataclass
class Selection:
    """플래너 선택 결과 — 근거(신뢰상한) 포함해 감사 로그에 남긴다."""
    arm_index: int
    arm: Arm
    ucb: float
    exploit: float          # θᵀx (활용 성분)
    explore: float          # α·√(xᵀA⁻¹x) (탐험 성분)
    scores: list[float]     # 전 arm UCB(디버그/설명용)


class LinUCBPlanner:
    """Disjoint LinUCB (Li et al., 2010) — NumPy·시드 고정.

    각 arm a 마다 A_a(d×d), b_a(d) 를 유지한다.
      p_a = θ_aᵀx + α·√(xᵀ A_a⁻¹ x),  θ_a = A_a⁻¹ b_a
    관측 후: A_a += x xᵀ,  b_a += r·x
    """

    def __init__(self, arms: list[Arm], dim: int = CONTEXT_DIM,
                 alpha: float = 0.6, seed: int = 20260707) -> None:
        self.arms = arms
        self.n = len(arms)
        self.d = dim
        self.alpha = alpha
        self.rng = np.random.default_rng(seed)
        self.A = [np.identity(dim) for _ in range(self.n)]
        self.b = [np.zeros(dim) for _ in range(self.n)]
        self._A_inv = [np.identity(dim) for _ in range(self.n)]  # 캐시

    def select(self, x: np.ndarray) -> Selection:
        x = np.asarray(x, dtype=float).reshape(self.d)
        exploit = np.empty(self.n)
        explore = np.empty(self.n)
        for a in range(self.n):
            A_inv = self._A_inv[a]
            theta = A_inv @ self.b[a]
            exploit[a] = float(theta @ x)
            explore[a] = float(self.alpha * np.sqrt(max(0.0, x @ A_inv @ x)))
        ucb = exploit + explore
        best = float(ucb.max())
        # 동점은 시드 고정 RNG 로 결정적 선택(재현성)
        cands = np.flatnonzero(ucb >= best - 1e-9)
        a = int(cands[0]) if cands.size == 1 else int(self.rng.choice(cands))
        return Selection(a, self.arms[a], float(ucb[a]),
                         exploit[a], explore[a], ucb.tolist())

    def update(self, arm_index: int, x: np.ndarray, reward: float) -> None:
        x = np.asarray(x, dtype=float).reshape(self.d)
        self.A[arm_index] += np.outer(x, x)
        self.b[arm_index] += reward * x
        self._A_inv[arm_index] = np.linalg.inv(self.A[arm_index])


class BaselinePlanner:
    """비교군 — 문맥을 무시하고 고정 순서(라운드로빈)로 선택.

    동일 공격 예산 하에서 adaptive(LinUCB) 대비 효과를 비교하기 위한 대조군.
    update 는 no-op 이므로 관측 문맥에 반응하지 않는다(기술스택 §11 비교표 근거).
    """

    def __init__(self, arms: list[Arm], seed: int = 20260707, **_: object) -> None:
        self.arms = arms
        self.n = len(arms)
        self._i = 0
        self.rng = np.random.default_rng(seed)

    def select(self, x: np.ndarray) -> Selection:
        a = self._i % self.n
        self._i += 1
        return Selection(a, self.arms[a], 0.0, 0.0, 0.0, [0.0] * self.n)

    def update(self, arm_index: int, x: np.ndarray, reward: float) -> None:
        return None


def make_planner(policy: str, arms: list[Arm], alpha: float, seed: int):
    """policy 문자열로 플래너 생성."""
    if policy == "baseline":
        return BaselinePlanner(arms, seed=seed)
    return LinUCBPlanner(arms, alpha=alpha, seed=seed)
