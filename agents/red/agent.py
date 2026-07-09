"""Red AI Agent 오케스트레이터 — 기술스택 문서 §3, §4.1.

관측→판단→행동→평가의 폐루프를 Blue 와 대칭으로 구현한다.

  BattleObserver ──context──▶ AdaptiveAttackPlanner(LinUCB) ──action──▶ PolicyGate
        ▲                                                                   │
        │                                            (loopback/mock/SITL 만) │
        └──────── Blue finding/action/score ◀── SIM ◀── ToolExecutor ◀──────┘
                         (reward)                       jam·mitm·gnss·c2·wait

공격 스크립트를 순서대로 실행하는 데모가 아니라, Blue 의 탐지·차단·점수를 관측해 다음
공격 종류·강도·대기를 스스로 바꾸는 적응형 공방 에이전트다. LLM 은 쓰지 않으며, 정책은
seeded LinUCB 로 온라인 학습한다(설명 가능·재현 가능).
"""
from __future__ import annotations

import argparse
import asyncio
import time
import uuid

from core.audit import EvidenceRecorder
from core.config import Config, load_config
from core.event_bus import EventBus
from core.events import AttackAction, AuditEvent
from agents.red.executor import ToolExecutor
from agents.red.observer import ACT_CAP, DIV_CAP, BattleObserver, WindowStats
from agents.red.planner import POLICY_VERSION, Arm, build_arms, make_planner

try:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()
except Exception:
    _console = None


def _clip01(v: float) -> float:
    return max(0.0, min(1.0, v))


class OutcomeEvaluator:
    """Outcome Evaluator — 공격 성공/보상을 계산한다(문서 §4.1).

    보상 설계(비대칭): 은밀하게 임무를 편향시키는 공격을 학습하도록 유도한다.
      + 임팩트(유발한 임무 편향/divergence)
      + 운용자 개입 유발(HITL) — 방어 부담 가중
      + 은신 보너스(공격했으나 미탐)
      − 저비용 자동차단(즉시 auto 조치는 공격 비용)
    wait 는 소액 기본가치(모두 차단당할 때의 전략적 후퇴 옵션).
    """

    @staticmethod
    def reward(arm: Arm, w: WindowStats) -> float:
        impact = _clip01(w.max_divergence_m / DIV_CAP)
        hitl = _clip01(w.hitl_actions / ACT_CAP)
        auto = _clip01(w.auto_actions / ACT_CAP)
        if arm.tool == "wait":
            return 0.15
        stealth = 0.5 if not w.detected else 0.0
        return _clip01(0.30 * impact + 0.30 * hitl + stealth - 0.40 * auto)

    @staticmethod
    def attack_points(arm: Arm, w: WindowStats) -> float:
        impact = _clip01(w.max_divergence_m / DIV_CAP)
        pts = 6.0 * impact + 3.0 * w.hitl_actions
        if arm.tool != "wait" and not w.detected:
            pts += 5.0    # 은밀 성공(미탐 지속)
        return round(pts, 2)


class RedAgent:
    def __init__(self, cfg: Config, bus: EventBus,
                 episode_id: str | None = None, dry_run: bool = False) -> None:
        self.cfg = cfg
        self.r = cfg.red
        self.episode_id = episode_id or uuid.uuid4().hex[:12]
        self.bus = bus

        self.arms: list[Arm] = build_arms(self.r.allowed_tools)
        self.planner = make_planner(self.r.policy, self.arms, self.r.alpha, self.r.seed)
        self.observer = BattleObserver(bus)
        from agents.red.policy_gate import AttackPolicyGate
        self.gate = AttackPolicyGate(
            self.r.allowed_tools, cfg.gate.allowed_targets,
            self.r.max_drift_m, self.r.max_c2_count, self.r.max_duration_s)
        self.executor = ToolExecutor(self.r.inject_target, dry_run=dry_run)
        self.evaluator = OutcomeEvaluator()

        self.recorder = EvidenceRecorder(
            f"{self.r.evidence_dir}/events.jsonl", f"{self.r.evidence_dir}/episodes.db")
        self.attack_points = 0.0
        self.decisions = self.r.decisions
        self._log: list[dict] = []      # 의사결정 로그(요약·비교표용)

    # ---------------- 실행 ----------------
    async def run(self) -> None:
        self._banner()
        tasks = [
            asyncio.create_task(self.observer.consume_findings()),
            asyncio.create_task(self.observer.consume_actions()),
            asyncio.create_task(self.observer.consume_scores()),
        ]
        try:
            for i in range(self.decisions):
                await self._one_decision(i)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._final_summary()
            self.recorder.close()

    async def _one_decision(self, i: int) -> None:
        ctx = self.observer.context()
        x = ctx.to_vector()
        sel = self.planner.select(x)

        action = AttackAction(
            episode_id=self.episode_id, tool=sel.arm.tool,
            parameters=dict(sel.arm.params),
            rationale=(f"{sel.arm.intent} | UCB={sel.ucb:.3f} "
                       f"(활용 {sel.exploit:.3f}+탐험 {sel.explore:.3f})"),
            policy_version=POLICY_VERSION)
        decision = self.gate.evaluate(action, self.r.inject_target)
        self.recorder.record_event(decision.action)

        # 관측 창을 열고 실행 → Blue 반응 관측 → settle 후 창 닫기
        self.observer.open_window()
        if decision.allowed:
            result = await self.executor.execute(decision.action)
        else:
            result = None
        await asyncio.sleep(self.r.settle_s)
        w = self.observer.close_window()

        reward = self.evaluator.reward(sel.arm, w)
        self.planner.update(sel.arm_index, x, reward)
        pts = self.evaluator.attack_points(sel.arm, w)
        self.attack_points += pts

        rec = {
            "i": i, "arm": sel.arm.name, "tool": sel.arm.tool, "flow": sel.arm.flow,
            "ctx_avail": round(ctx.availability, 1),
            "ctx_last_findings": ctx.last_findings,
            "ucb": round(sel.ucb, 3),
            "detected": w.detected, "findings": w.findings,
            "auto": w.auto_actions, "hitl": w.hitl_actions,
            "impact_m": round(w.max_divergence_m, 1),
            "reward": round(reward, 3), "attack_pts_delta": pts,
        }
        self._log.append(rec)
        self._record_audit(sel, action, w, reward)
        self._alert(i, sel, decision, w, reward)

    # ---------------- 증거/감사 ----------------
    def _record_audit(self, sel, action, w: WindowStats, reward: float) -> None:
        self.recorder.record_event(AuditEvent(
            episode_id=self.episode_id, actor="red.planner",
            decision=f"select {sel.arm.name} (tool={sel.arm.tool})",
            model_version=POLICY_VERSION,
            input_refs=[action.correlation_id],
            payload={"ucb": sel.ucb, "exploit": sel.exploit, "explore": sel.explore,
                     "scores": [round(s, 3) for s in sel.scores],
                     "detected": w.detected, "reward": reward},
            ts=time.time()))

    # ---------------- 출력 ----------------
    def _banner(self) -> None:
        arms = ", ".join(a.name for a in self.arms)
        msg = (f"Red AI Agent 가동 — 에피소드 {self.episode_id}\n"
               f"정책: {self.r.policy}  (seed={self.r.seed}, α={self.r.alpha})\n"
               f"행동 집합: {arms}\n"
               f"주입 대상: {self.r.inject_target}  ·  의사결정 {self.decisions}회\n"
               f"증거: {self.r.evidence_dir}/events.jsonl")
        if _console:
            _console.print(Panel(msg, title="🗡  DAH 2026 Red Agent", border_style="red"))
        else:
            print("=" * 64 + f"\n{msg}\n" + "=" * 64)

    def _alert(self, i, sel, decision, w: WindowStats, reward: float) -> None:
        tag = ("🩶 미탐(은밀)" if not w.detected else
               ("🔴 HITL 유발" if w.hitl_actions else "🟢 자동차단"))
        line = (f"[{i+1:02d}/{self.decisions}] {sel.arm.name:11s} "
                f"→ {tag}  탐지 {w.findings} · auto {w.auto_actions} · "
                f"hitl {w.hitl_actions} · 임팩트 {w.max_divergence_m:.0f}m · "
                f"보상 {reward:.2f} · 누적공격점수 {self.attack_points:.1f}")
        if _console:
            color = "grey62" if not w.detected else ("red" if w.hitl_actions else "green")
            _console.print(f"[{color}]{line}[/]")
        else:
            print(line)

    def _final_summary(self) -> None:
        n = max(1, len(self._log))
        detected = sum(1 for r in self._log if r["detected"])
        stealth = n - detected
        hitl = sum(r["hitl"] for r in self._log)
        auto = sum(r["auto"] for r in self._log)
        used = {}
        for r in self._log:
            used[r["arm"]] = used.get(r["arm"], 0) + 1
        mix = ", ".join(f"{k}×{v}" for k, v in sorted(used.items()))
        summary = (f"에피소드 {self.episode_id} 종료 — 정책 {self.r.policy}\n"
                   f"누적 공격 점수: {self.attack_points:.1f}\n"
                   f"의사결정 {n}회 · 미탐(은밀) {stealth} / 탐지 {detected}\n"
                   f"유발한 Blue 대응: 자동 {auto} · HITL {hitl}\n"
                   f"행동 분포: {mix}")
        if _console:
            _console.print(Panel(summary, title="🏁 Red 캠페인 요약", border_style="magenta"))
        else:
            print("\n" + summary)


def main() -> None:
    ap = argparse.ArgumentParser(description="DAH 2026 Red AI Agent (standalone)")
    ap.add_argument("--config", default="configs/default.toml")
    ap.add_argument("--policy", default=None, help="adaptive | baseline (기본: config)")
    ap.add_argument("--target", default=None, help="주입 대상(기본: config)")
    ap.add_argument("--decisions", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true", help="실제 패킷 전송 없이 정책만 구동")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.policy:
        cfg.red.policy = args.policy
    if args.target:
        cfg.red.inject_target = args.target
    if args.decisions:
        cfg.red.decisions = args.decisions

    bus = EventBus(maxsize=cfg.bus.maxsize, policy=cfg.bus.policy)
    agent = RedAgent(cfg, bus, dry_run=args.dry_run)
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
