#!/usr/bin/env bash
# DAH 2026 Blue Agent 데모 — mock 차량(UAV+UGV) + Blue AI Agent + 순차 공격.
# 인터넷·외부 API·GPU 없이 한 명령으로 mock 공방이 완주된다(기술스택 §11).
# 종료 시 방어 점수·가용성(SLA)·흐름별 탐지 요약이 출력된다.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PY:-python3}
CONFIG=${CONFIG:-configs/default.toml}
pids=()
cleanup() { echo; echo "[demo] 정리 중..."; for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "[demo] mock 차량 구동: UAV(14550) + UGV(14560)"
$PY -m sim.mock_vehicle --vehicle copter --port 14550 >/tmp/dah_uav.log 2>&1 & pids+=($!)
$PY -m sim.mock_vehicle --vehicle rover  --port 14560 >/tmp/dah_ugv.log 2>&1 & pids+=($!)
sleep 1

echo "[demo] Blue AI Agent 구동 (관측→탐지→상관→대응→게이트→채점)"
$PY -m agents.blue.agent --config "$CONFIG" \
    --uav udpin:127.0.0.1:14550 --ugv udpin:127.0.0.1:14560 & AGENT=$!; pids+=($AGENT)
sleep 2

echo; echo "════════ 공격 A/D · GNSS 스푸핑 (UAV, 흐름 A) ════════"
$PY -m attacks.gnss_spoof --target udpout:127.0.0.1:14555 --drift-m 150 --ramp-s 4 --hold-s 3

echo; echo "════════ 공격 B · C2 명령 주입 (UGV, 흐름 B) ════════"
$PY -m attacks.c2_injection --target udpout:127.0.0.1:14565 --command flood --count 15
sleep 2

echo; echo "[demo] 에이전트 종료 → 채점 요약 출력"
kill -INT "$AGENT" 2>/dev/null || true
wait "$AGENT" 2>/dev/null || true

echo; echo "[demo] 완료."
echo "  증거(JSONL): logs/events.jsonl"
echo "  집계(SQLite): logs/episodes.db  —  sqlite3 logs/episodes.db 'select * from scores'"
