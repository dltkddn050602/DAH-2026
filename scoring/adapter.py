"""CompetitionScoringAdapter — 기술스택 문서 §7.

공식 평가 축(공격 점수, 방어 점수, 가용성 SLA 0~100)을 계산한다. 세부 배점을 코드에
박지 않고 scoring.toml 설정만 교체하면 공식 규칙에 맞출 수 있게 캡슐화한다.

Blue 전용 빌드에서 attack_points 는 외부(Red/심판)에서 주입되며, 없으면 0.
방어 점수·가용성은 내부 지표(EpisodeMetrics)로 계산한다. 가용성은 공격/방어와
독립된 공통 제약으로 관리한다(문서 §7).
"""
from __future__ import annotations

from core.config import load_toml
from core.events import ScoreEvent
from scoring.metrics import EpisodeMetrics


class CompetitionScoringAdapter:
    def __init__(self, scoring_toml: str = "configs/scoring.toml") -> None:
        cfg = load_toml(scoring_toml)
        self.w = cfg.get("weights", {})
        self.targets = cfg.get("targets", {})
        self.av = cfg.get("availability", {})

    def defense_points(self, m: EpisodeMetrics) -> float:
        """지상검증이 있으면 TP/FP/미탐 기반, 없으면 탐지 활동 기반 근사."""
        w = self.w
        if m.true_positives or m.false_positives or m.missed:
            pts = (m.true_positives * w.get("true_positive", 10.0)
                   + m.false_positives * w.get("false_positive", -4.0)
                   + m.missed * w.get("missed", -8.0))
        else:
            # 라벨 없는 데모: 탐지 건수 기반 근사(정탐 가정)
            pts = m.findings * w.get("true_positive", 10.0)
        if m.mean_detect_latency() and \
                m.mean_detect_latency() <= self.targets.get("detect_latency_s", 2.0):
            pts += w.get("fast_detect_bonus", 3.0) * max(1, len(m.flows_detected))
        return round(pts, 2)

    def availability(self, m: EpisodeMetrics) -> float:
        av = self.av
        score = av.get("base", 100.0)
        score -= m.max_link_loss_pct * av.get("link_loss_penalty", 0.5)
        score -= (m.max_mission_deviation_m / 100.0) * \
            av.get("mission_deviation_penalty", 2.0)
        score -= m.rejected_actions * av.get("overreaction_penalty", 1.5)
        return round(max(0.0, min(100.0, score)), 1)

    def score(self, m: EpisodeMetrics, attack_points: float = 0.0) -> ScoreEvent:
        return ScoreEvent(
            episode_id=m.episode_id,
            attack=round(attack_points, 2),
            defense=self.defense_points(m),
            availability=self.availability(m),
            diagnostics=m.summary(),
        )
