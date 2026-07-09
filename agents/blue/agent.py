"""Blue AI Agent 오케스트레이터 — 기술스택 문서 §3, §4.2.

논리 에이전트(Observer/Detector/Correlator/Planner/Gate/Evidence)를 asyncio.Task 로
같은 프로세스에서 실행하고 EventBus 로 연결한다. 관측→판단→행동→평가의 폐루프.

  Observer ──telemetry──▶ Detector(규칙+ML) ──finding──▶ Analysis
                          Swarm    ──finding──▶  (Correlator→Planner→Gate→Evidence)
                                                        └▶ Metrics ─▶ Scoring
"""
from __future__ import annotations

import argparse
import asyncio
import time
import uuid

from core.audit import EvidenceRecorder
from core.config import Config, load_config
from core.event_bus import EventBus
from core.events import FindingEvent, Risk, TelemetryEvent
from agents.blue.observer import TelemetryObserver
from agents.blue.rule_detectors import default_rule_detectors
from agents.blue.hybrid_detector import StreamingMLDetector
from agents.blue.swarm import SwarmConsensusDetector
from agents.blue.correlator import ThreatCorrelator
from agents.blue.response_planner import ResponsePlanner
from agents.blue.safety_gate import SafetyGate
from scoring.adapter import CompetitionScoringAdapter
from scoring.metrics import EpisodeMetrics

try:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()
except Exception:
    _console = None

RISK_COLOR = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "bold red"}


class BlueAgent:
    def __init__(self, cfg: Config, vehicles: dict[str, str],
                 bus: EventBus | None = None) -> None:
        self.cfg = cfg
        self.episode_id = uuid.uuid4().hex[:12]
        # bus 를 외부에서 주입하면(캠페인) Red 등 다른 에이전트와 이벤트를 공유한다.
        self.bus = bus if bus is not None else EventBus(
            maxsize=cfg.bus.maxsize, policy=cfg.bus.policy)

        # Observers
        self.observers = [
            TelemetryObserver(name, src, self.bus, cfg.run.rate_hz)
            for name, src in vehicles.items()
        ]
        for o in self.observers:
            o.set_episode(self.episode_id)

        # 차량별 탐지기(규칙+ML)
        self.rule_sets = {v: default_rule_detectors(cfg) for v in vehicles}
        self.ml_sets = {v: StreamingMLDetector(cfg) for v in vehicles}
        self.swarm = SwarmConsensusDetector(cfg.detect.swarm.consensus_m)

        # 분석 파이프라인
        self.correlator = ThreatCorrelator()
        self.planner = ResponsePlanner(cfg.response.auto_max_risk, llm=None)
        self.gate = SafetyGate(cfg.gate.allowed_playbooks, cfg.gate.allowed_targets)

        # 증거·지표·채점
        self.recorder = EvidenceRecorder(cfg.evidence.jsonl, cfg.evidence.sqlite)
        self.metrics = EpisodeMetrics(episode_id=self.episode_id)
        self.scorer = CompetitionScoringAdapter(cfg.scoring.config)

        self._cooldown: dict[str, float] = {}
        self._stop = asyncio.Event()

    # ---------------- 실행 ----------------
    async def run(self) -> None:
        self._banner()
        tasks = [asyncio.create_task(o.run()) for o in self.observers]
        tasks += [
            asyncio.create_task(self._detector_worker()),
            asyncio.create_task(self._swarm_worker()),
            asyncio.create_task(self._analysis_worker()),
            asyncio.create_task(self._scoring_timer()),
        ]
        try:
            await self._stop.wait()
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._final_score()
            self.recorder.close()

    def stop(self) -> None:
        self._stop.set()

    # ---------------- 워커 ----------------
    async def _detector_worker(self) -> None:
        sub = self.bus.subscribe("telemetry")
        async for evt in sub.stream():
            assert isinstance(evt, TelemetryEvent)
            self._track_availability(evt)
            dets = self.rule_sets.get(evt.vehicle, [])
            findings: list[FindingEvent] = []
            for det in dets:
                findings.extend(det.update(evt))
            ml = self.ml_sets.get(evt.vehicle)
            if ml is not None:
                findings.extend(ml.update(evt))
            for f in findings:
                await self.bus.publish(f)

    async def _swarm_worker(self) -> None:
        sub = self.bus.subscribe("telemetry")
        async for evt in sub.stream():
            for f in self.swarm.update(evt):
                await self.bus.publish(f)

    async def _analysis_worker(self) -> None:
        sub = self.bus.subscribe("finding")
        async for f in sub.stream():
            assert isinstance(f, FindingEvent)
            self.recorder.record_finding(f)
            latency = max(0.0, time.time() - f.ts)
            self.metrics.on_finding(
                f.flow.value if hasattr(f.flow, "value") else str(f.flow), latency)
            self._track_mission_dev(f)

            ctx = self.correlator.add(f)
            action = self.planner.plan(f, ctx)
            decision = self.gate.evaluate(action)
            self.recorder.record_action(action, decision.auto_execute)
            # 대응 행동을 버스에도 발행 → Red BattleObserver 등 구독자가 관측(대칭 관측)
            await self.bus.publish(action)
            self.metrics.on_action(decision.auto_execute, decision.approval_pending,
                                   rejected=not (decision.auto_execute or
                                                 decision.approval_pending))
            if self._should_alert(f):
                self._alert(f, action, decision)

    async def _scoring_timer(self) -> None:
        while True:
            await asyncio.sleep(10.0)
            s = self.scorer.score(self.metrics)
            self.recorder.record_score(s)
            await self.bus.publish(s)   # Red 가 가용성/방어점수를 관측(폐루프)

    # ---------------- 가용성/임무 지표 ----------------
    def _track_availability(self, evt: TelemetryEvent) -> None:
        drop = evt.features.get("drop_rate_comm")
        if drop is not None:
            self.metrics.max_link_loss_pct = max(self.metrics.max_link_loss_pct, drop)

    def _track_mission_dev(self, f: FindingEvent) -> None:
        d = f.evidence.get("divergence_m")
        if d is not None:
            self.metrics.max_mission_deviation_m = max(
                self.metrics.max_mission_deviation_m, float(d))

    # ---------------- 출력 ----------------
    def _should_alert(self, f: FindingEvent, cooldown: float = 2.0) -> bool:
        key = f"{f.vehicle}|{f.detector}|{f.signal[:24]}"
        now = time.time()
        if now - self._cooldown.get(key, 0) < cooldown:
            return False
        self._cooldown[key] = now
        return True

    def _alert(self, f: FindingEvent, action, decision) -> None:
        risk = action.risk.value if hasattr(action.risk, "value") else str(action.risk)
        gate = ("🟢 자동 조치" if decision.auto_execute else
                ("🔴 HITL 승인 필요" if decision.approval_pending else "⛔ 실행 거부"))
        mapping = "  ".join(f"{k}:{v}" for k, v in f.threat_map.items())
        flow = f.flow.value if hasattr(f.flow, "value") else str(f.flow)
        if _console:
            color = RISK_COLOR.get(risk, "white")
            body = (f"[bold]{f.detector}[/]  (흐름 {flow} · [{color}]{risk}[/] · "
                    f"conf {f.confidence:.2f})\n"
                    f"징후 : {f.signal}\n"
                    f"매핑 : {mapping}\n"
                    f"대응 : {action.playbook} — {', '.join(action.steps[:3])}\n"
                    f"게이트: {gate}  ({decision.reason})\n"
                    f"근거 : {action.rationale}")
            _console.print(Panel(body, title=f"[{color}]⚠ {f.vehicle.upper()} 위협 탐지[/]",
                                 border_style=color))
        else:
            print(f"\n⚠ [{f.vehicle}] {f.detector} (흐름 {flow}/{risk}) {gate}")
            print(f"  징후: {f.signal}\n  대응: {action.playbook}\n  {decision.reason}")

    def _final_score(self) -> None:
        s = self.scorer.score(self.metrics)
        self.recorder.record_score(s)
        summary = (f"에피소드 {self.episode_id} 종료\n"
                   f"방어 점수: {s.defense}   가용성(SLA): {s.availability}\n"
                   f"탐지 {self.metrics.findings}건 · 흐름 {sorted(self.metrics.flows_detected)}\n"
                   f"자동 {self.metrics.auto_actions} · HITL {self.metrics.hitl_actions} · "
                   f"거부 {self.metrics.rejected_actions}")
        if _console:
            _console.print(Panel(summary, title="🏁 채점 요약", border_style="cyan"))
        else:
            print("\n" + summary)

    def _banner(self) -> None:
        ml = "on" if any(m.available() for m in self.ml_sets.values()) else "off(river 미설치)"
        msg = (f"Blue AI Agent 가동 — 에피소드 {self.episode_id}\n"
               f"감시 대상: {', '.join(v.upper() for v in self.rule_sets)}\n"
               f"규칙 탐지기: 흐름 A~F  ·  스트리밍 ML: {ml}\n"
               f"증거: {self.cfg.evidence.jsonl}  ·  집계: {self.cfg.evidence.sqlite}")
        if _console:
            _console.print(Panel(msg, title="🛡  DAH 2026 Blue Agent", border_style="cyan"))
        else:
            print("=" * 64 + f"\n{msg}\n" + "=" * 64)


def main() -> None:
    ap = argparse.ArgumentParser(description="DAH 2026 Blue AI Agent")
    ap.add_argument("--config", default="configs/default.toml")
    ap.add_argument("--uav", default=None, help="UAV 텔레메트리 (기본: config)")
    ap.add_argument("--ugv", default=None, help="UGV 텔레메트리 (기본: config)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    vehicles: dict[str, str] = {}
    if "uav" in cfg.vehicles:
        vehicles["uav"] = args.uav or cfg.vehicles["uav"].source
    if "ugv" in cfg.vehicles:
        vehicles["ugv"] = args.ugv or cfg.vehicles["ugv"].source
    if args.uav and "uav" not in vehicles:
        vehicles["uav"] = args.uav
    if args.ugv and "ugv" not in vehicles:
        vehicles["ugv"] = args.ugv

    agent = BlueAgent(cfg, vehicles)

    async def _run():
        loop = asyncio.get_running_loop()
        import signal
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, agent.stop)
            except NotImplementedError:
                pass
        await agent.run()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
