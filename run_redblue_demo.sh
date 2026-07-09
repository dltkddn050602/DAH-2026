#!/usr/bin/env bash
# DAH 2026 자율 공방 데모 — mock UAV + Blue AI Agent + Red AI Agent(적응형 LinUCB).
# 인터넷·외부 API·GPU 없이 한 명령으로 Red↔Blue 폐루프가 완주된다(기술스택 §11).
# 종료 시 공식 축(공격/방어/가용성)이 통합 출력되고, baseline↔adaptive 비교가 남는다.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PY:-python3}
CONFIG=${CONFIG:-configs/default.toml}
DECISIONS=${DECISIONS:-16}
pids=()
cleanup() { echo; echo "[demo] 정리 중..."; for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "[demo] mock UAV(14550, cmd-in 14555) 구동"
$PY -m sim.mock_vehicle --vehicle copter --port 14550 >/tmp/dah_uav.log 2>&1 & pids+=($!)
sleep 1

echo; echo "════════ ① Adaptive(LinUCB) 정책 공방 ════════"
$PY -m agents.red.campaign --config "$CONFIG" --policy adaptive --decisions "$DECISIONS"

echo; echo "════════ ② Baseline(고정순서) 정책 공방 — 동일 예산 비교군 ════════"
$PY -m agents.red.campaign --config "$CONFIG" --policy baseline --decisions "$DECISIONS"

echo; echo "[demo] 완료."
echo "  Red 증거(JSONL): logs_red/events.jsonl"
echo "  캠페인 요약(JSON): logs_red/campaign_summary.json"
echo "  Blue 증거(JSONL): logs/events.jsonl"
