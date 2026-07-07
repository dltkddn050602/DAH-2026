"""
공격 #3 — 통신 재밍 / DoS (링크 저하)

위협모델: STRIDE-DoS, TARA(통신 두절→제어 지연/상실)

원리
----
RF 재밍은 데이터링크의 패킷 손실·지연·대역폭 저하를 유발한다. netem(tc)은 macOS
루프백에서 제약이 있으므로, 본 도구는 텔레메트리 경로 중간에 삽입되는 UDP 릴레이로
동일한 효과(패킷 드롭 + 지연 + 지터)를 재현한다. 방어는 heartbeat 간격 급증 /
패킷 손실률 상승으로 재밍/DoS를 탐지하고 '통신두절 안전정책(사전 정의 경로 복귀)'을
발동한다.

토폴로지 (재밍 데모 시):
    mock_vehicle --out--> :14550  ─▶  [jamming_dos 릴레이]  ─▶ :14551 --> defense
    python -m sim.mock_vehicle --vehicle copter --port 14550
    python -m attacks.jamming_dos --listen 14550 --forward 14551 --loss 0.7 --delay-ms 400
    python -m defense.agent --uav udpin:127.0.0.1:14551

사용:
    python -m attacks.jamming_dos --listen 14550 --forward 14551 --loss 0.6
"""
from __future__ import annotations

import argparse
import random
import socket
import threading
import time


def main():
    ap = argparse.ArgumentParser(description="재밍/DoS 링크 저하 릴레이")
    ap.add_argument("--listen", type=int, default=14550,
                    help="차량 텔레메트리가 도착하는 포트")
    ap.add_argument("--forward", type=int, default=14551,
                    help="방어 에이전트가 수신할 포트")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--loss", type=float, default=0.6, help="패킷 드롭 확률 0~1")
    ap.add_argument("--delay-ms", type=float, default=300.0, help="평균 지연(ms)")
    ap.add_argument("--jitter-ms", type=float, default=150.0, help="지연 지터(ms)")
    ap.add_argument("--duration", type=float, default=20.0, help="재밍 지속(s)")
    args = ap.parse_args()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind((args.host, args.listen))
    rx.settimeout(0.5)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd = (args.host, args.forward)

    print(f"[jamming_dos] :{args.listen} → :{args.forward}  "
          f"loss={args.loss:.0%} delay={args.delay_ms}±{args.jitter_ms}ms "
          f"({args.duration}s)")

    stats = {"in": 0, "drop": 0, "fwd": 0}

    def deliver(data):
        d = max(0.0, (args.delay_ms + random.uniform(-args.jitter_ms, args.jitter_ms)) / 1000)
        time.sleep(d)
        tx.sendto(data, fwd)
        stats["fwd"] += 1

    t0 = time.time()
    while time.time() - t0 < args.duration:
        try:
            data, _ = rx.recvfrom(65535)
        except socket.timeout:
            continue
        stats["in"] += 1
        if random.random() < args.loss:
            stats["drop"] += 1
            continue
        threading.Thread(target=deliver, args=(data,), daemon=True).start()

    time.sleep(0.5)
    print(f"[jamming_dos] 종료 — 수신 {stats['in']} / 드롭 {stats['drop']} "
          f"/ 전달 {stats['fwd']}  (실측 손실률 "
          f"{stats['drop']/max(1,stats['in']):.0%})")


if __name__ == "__main__":
    main()
