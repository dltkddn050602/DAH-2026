"""Campaign Runner — Blue+Red 자율 공방 폐루프 (기술스택 문서 §3, §9).

하나의 공유 EventBus 위에서 Blue AI Agent 와 Red AI Agent 를 같은 프로세스의
asyncio.Task 로 실행한다(문서 §3: 예선은 같은 프로세스, 본선은 컨테이너 분리).
Blue 는 mock 차량 텔레메트리를 관측(udpin:14550)하고, Red 는 명령/스푸핑을 주입
(udpout:14555)하며, 둘은 시뮬레이션 차량과 공통 이벤트를 통해 상호작용한다.

종료 시 공식 축(공격/방어/가용성)을 한 번에 출력한다 — 공격 점수는 Red 가 산출한
attack_points 를 CompetitionScoringAdapter 에 주입한다(문서 §7).

사용:
    # 터미널 1: mock UAV
    python -m sim.mock_vehicle --vehicle copter --port 14550
    # 터미널 2: 공방 캠페인(adaptive 또는 baseline)
    python -m agents.red.campaign --policy adaptive --decisions 16
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os

from core.config import load_config
from core.event_bus import EventBus
from agents.blue.agent import BlueAgent
from agents.red.agent import RedAgent

try:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()
except Exception:
    _console = None


async def run_campaign(config: str, policy: str | None, decisions: int | None,
                       uav: str, target: str | None, dry_run: bool = False) -> dict:
    cfg = load_config(config)
    if policy:
        cfg.red.policy = policy
    if decisions:
        cfg.red.decisions = decisions
    if target:
        cfg.red.inject_target = target

    bus = EventBus(maxsize=cfg.bus.maxsize, policy=cfg.bus.policy)

    blue = BlueAgent(cfg, {"uav": uav}, bus=bus)
    red = RedAgent(cfg, bus, episode_id=blue.episode_id, dry_run=dry_run)

    blue_task = asyncio.create_task(blue.run())
    await asyncio.sleep(1.5)          # Blue observer 가 mock 에 붙을 시간
    try:
        await red.run()               # 유한 의사결정 루프 — 끝나면 반환
    finally:
        blue.stop()
        await blue_task

    # 통합 채점: 공격 점수(Red) 주입 → 공식 축 한 번에
    s = blue.scorer.score(blue.metrics, attack_points=red.attack_points)
    result = {
        "episode_id": blue.episode_id,
        "policy": cfg.red.policy,
        "attack": s.attack,
        "defense": s.defense,
        "availability": s.availability,
        "red_decisions": len(red._log),
        "red_stealth": sum(1 for r in red._log if not r["detected"]),
        "red_detected": sum(1 for r in red._log if r["detected"]),
        "blue_findings": blue.metrics.findings,
        "blue_flows": sorted(blue.metrics.flows_detected),
        "blue_auto": blue.metrics.auto_actions,
        "blue_hitl": blue.metrics.hitl_actions,
        "red_log": red._log,
    }
    os.makedirs(cfg.red.evidence_dir, exist_ok=True)
    with open(f"{cfg.red.evidence_dir}/campaign_summary.json", "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)

    _print_score(result)
    return result


def _print_score(r: dict) -> None:
    msg = (f"에피소드 {r['episode_id']} · 정책 {r['policy']}\n"
           f"공식 축 →  공격 {r['attack']}   방어 {r['defense']}   "
           f"가용성(SLA) {r['availability']}\n"
           f"Red: 의사결정 {r['red_decisions']} · 은밀 {r['red_stealth']} / "
           f"탐지 {r['red_detected']}\n"
           f"Blue: 탐지 {r['blue_findings']} · 흐름 {r['blue_flows']} · "
           f"자동 {r['blue_auto']} · HITL {r['blue_hitl']}")
    if _console:
        _console.print(Panel(msg, title="🎯 공방 캠페인 통합 채점", border_style="cyan"))
    else:
        print("\n" + msg)


def main() -> None:
    ap = argparse.ArgumentParser(description="DAH 2026 Blue+Red 자율 공방 캠페인")
    ap.add_argument("--config", default="configs/default.toml")
    ap.add_argument("--policy", default=None, help="adaptive | baseline")
    ap.add_argument("--decisions", type=int, default=None)
    ap.add_argument("--uav", default="udpin:127.0.0.1:14550",
                    help="Blue 가 관측할 UAV 텔레메트리")
    ap.add_argument("--target", default=None, help="Red 주입 대상(기본: config)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    asyncio.run(run_campaign(args.config, args.policy, args.decisions,
                             args.uav, args.target, args.dry_run))


if __name__ == "__main__":
    main()
