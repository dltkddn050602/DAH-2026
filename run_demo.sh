#!/usr/bin/env bash
# DAH 2026 공방 데모 — mock 차량(UAV+UGV) + 방어 에이전트 + 순차 공격 시연
# 데모 영상 녹화용. 각 공격 사이에 방어 에이전트의 탐지 패널이 뜬다.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PY:-python3}
pids=()
cleanup() { echo; echo "[demo] 정리 중..."; for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "[demo] mock 차량 구동: UAV(14550) + UGV(14560)"
$PY -m sim.mock_vehicle --vehicle copter --port 14550 >/tmp/dah_uav.log 2>&1 & pids+=($!)
$PY -m sim.mock_vehicle --vehicle rover  --port 14560 >/tmp/dah_ugv.log 2>&1 & pids+=($!)
sleep 1

echo "[demo] 방어 AI 에이전트 구동 (UAV+UGV 동시 감시)"
$PY -m defense.agent --uav udpin:127.0.0.1:14550 --ugv udpin:127.0.0.1:14560 & pids+=($!)
sleep 2

echo; echo "════════ 공격 1/3 · GNSS 스푸핑 (UAV) ════════"
$PY -m attacks.gnss_spoof --target udpout:127.0.0.1:14555 --drift-m 150 --ramp-s 4 --hold-s 3
sleep 2

echo; echo "════════ 공격 2/3 · C2 명령 주입 (UGV 강제정지+폭주) ════════"
$PY -m attacks.c2_injection --target udpout:127.0.0.1:14565 --command rtl
$PY -m attacks.c2_injection --target udpout:127.0.0.1:14565 --command flood --count 15
sleep 2

echo; echo "════════ 공격 3/3 · AI 적대적 예제 (인지모델 회피) ════════"
echo "  (torch/ultralytics 설치 시) python -m attacks.perception.adversarial_patch"
$PY -m attacks.perception.adversarial_patch 2>/dev/null || \
    echo "  [skip] torch/ultralytics 미설치 — pip install torch torchvision ultralytics 후 실행"

echo; echo "[demo] 완료. 증거 로그: logs/incidents.jsonl"
sleep 1
