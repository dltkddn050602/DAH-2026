# 공방 시뮬레이션 아키텍처 (보고서 ③ AI 에이전트 · ① 공격 근거)

## 계층 구조

| 계층 | 구성요소 | 대응 방어 문서 영역 |
|------|----------|----------------------|
| 제어(A) | ArduPilot SITL / mock 차량 (UAV Copter, UGV Rover) | UAV/UGV 탑재·전술통신 영역 |
| 통신 | MAVLink (텔레메트리 push / 명령 in) | C2/Telemetry Link |
| Red team | `attacks/` C2주입·GNSS스푸핑·재밍·적대적예제 | 공격 시나리오 표 6종 |
| Blue team | `defense/` Defense AI Agent + detectors | 방어 AI 에이전트 10대 임무 |
| 인지(B) | YOLO + PGD 적대적 예제 | MITRE ATLAS Evasion |

## 공격 → 관측 서명 → 방어 매핑 (검증됨)

| 공격 | 관측 서명(공통 텔레메트리) | 탐지기 | 위협모델 | 대응 |
|------|---------------------------|--------|----------|------|
| GNSS 스푸핑 | GPS_RAW vs GLOBAL_POSITION divergence ↑ | `GnssInsCrossCheck` | STRIDE-Spoofing / STPA-Sec | 신뢰도 하향→INS 항법 전환→(Critical)귀환 |
| C2 명령 주입 | COMMAND_ACK 빈도 ↑, 모드 급변 | `CommandAnomalyMonitor` | STRIDE-Tampering | 재인증·명령 차단·링크 전환 |
| 재밍/DoS | HEARTBEAT 간격 ↑, 두절 | `LinkHealthMonitor` | STRIDE-DoS | 통신두절 안전정책·경로 복귀 |
| 적대적 예제(인지) | ①AI 신뢰도 붕괴 ②카메라↔LiDAR 불일치 ③프레임 라벨 flicker | `SensorConsensusDetector` | ATLAS-Evasion | 카메라 판단 보류·LiDAR 교차검증·(복구)LiDAR 축소운용·handoff |

## 방어 에이전트 설계 원칙 (문서와 일치)
- **특정 오토파일럿 비종속**: 공통 관측 데이터(텔레메트리/네트워크/센서/AI출력)만 사용
- **탐지→위협모델 매핑→위험 재평가→플레이북**의 폐루프
- **Human-in-the-loop 게이트**: Medium 이하 자동 조치, High↑는 운용자 승인
- **증거 보존**: 모든 인시던트를 `logs/incidents.jsonl`에 구조화 저장 → 사후 분석·위협모델 KB 갱신

## 실측 데모 결과 (mock 차량 기준)
- GNSS 스푸핑: divergence 35→150m, 위험도 High→**Critical** 자동 에스컬레이션
- C2 폭주 15건: 3초 창 내 명령 빈도 초과 → **High** '비정상 명령 빈도' 탐지
- 모든 인시던트 위협모델 매핑 + 대응 플레이북 + 증거 JSON 자동 기록
