"""내부 평가 지표 — 기술스택 문서 §7.

공식 점수(공격/방어/가용성)를 대체하지 않고 원인분석·정책학습에 쓰는 내부 지표를
집계한다. Blue 이벤트 스트림을 받아 누적한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EpisodeMetrics:
    episode_id: str = ""
    findings: int = 0
    flows_detected: set[str] = field(default_factory=set)
    auto_actions: int = 0
    hitl_actions: int = 0
    rejected_actions: int = 0
    detect_latencies_s: list[float] = field(default_factory=list)
    max_link_loss_pct: float = 0.0
    max_mission_deviation_m: float = 0.0
    # 지상검증(있으면): 실제 공격 라벨과 대조해 TP/FP/미탐 계산
    true_positives: int = 0
    false_positives: int = 0
    missed: int = 0

    def on_finding(self, flow: str, latency_s: float | None = None) -> None:
        self.findings += 1
        self.flows_detected.add(flow)
        if latency_s is not None:
            self.detect_latencies_s.append(latency_s)

    def on_action(self, auto_execute: bool, approval_pending: bool,
                  rejected: bool) -> None:
        if rejected:
            self.rejected_actions += 1
        elif approval_pending:
            self.hitl_actions += 1
        elif auto_execute:
            self.auto_actions += 1

    def mean_detect_latency(self) -> float:
        return (sum(self.detect_latencies_s) / len(self.detect_latencies_s)
                if self.detect_latencies_s else 0.0)

    def summary(self) -> dict:
        return {
            "findings": self.findings,
            "flows_detected": sorted(self.flows_detected),
            "auto_actions": self.auto_actions,
            "hitl_actions": self.hitl_actions,
            "rejected_actions": self.rejected_actions,
            "mean_detect_latency_s": round(self.mean_detect_latency(), 3),
            "max_link_loss_pct": self.max_link_loss_pct,
            "max_mission_deviation_m": round(self.max_mission_deviation_m, 1),
            "tp": self.true_positives,
            "fp": self.false_positives,
            "missed": self.missed,
        }
