# DAH 2026 Blue AI Agent — 설계·구현 설명서

> UAV/UGV 사이버 공방 시뮬레이션의 **방어(Blue) AI 에이전트**.
> 두 스펙 문서 — `agent_technology_stack.pdf`(기술 스택), `DAH2026_UxS_대표공격흐름.pdf`(공격 흐름) — 를
> 근거로, 관측→판단→행동→평가가 닫힌 루프를 이루는 방어 에이전트를 실행 가능한 코드로 구현한 것.

---

## 1. 한 줄 요약

MAVLink 텔레메트리를 관측해 **대표 공격 흐름 A~F**를 탐지하고, 위협모델에 매핑하고,
여러 징후를 하나의 공격 캠페인으로 상관하고, 위험도별 대응 플레이북을 선택해
**안전 게이트(자동 조치 / 사람 승인)** 를 통과시킨 뒤, 모든 판단을 증거로 남기고
**공식 축(공격/방어/가용성)** 으로 채점하는 — 인터넷·GPU 없이 한 명령으로 완주되는 방어 에이전트.

---

## 2. 왜 이렇게 만들었나 (설계 원칙)

기술 스택 문서 §2의 원칙을 그대로 코드 구조에 반영했다.

| 원칙 | 구현에서의 의미 |
|------|-----------------|
| **오프라인 우선** | 외부 API·인터넷 없이 CPU에서 동작. `river`(ML) 미설치 시 규칙만으로 자동 폴백. |
| **안전 경로 / 지능 경로 분리** | 규칙 탐지기는 결정론적(즉시 차단 근거). ML/LLM 결과는 보조 점수로만, 위험도 상한을 둔다. |
| **설명 가능성** | 모든 판단이 입력 증거·정책 버전·모델 버전·선택 근거를 남긴다(JSONL+SQLite). |
| **재현성** | 난수 시드 고정, 같은 입력 → 같은 판단 순서(테스트로 검증). |
| **단일 프로세스에서 시작** | 논리 에이전트를 `asyncio.Task`로 실행하되, 이벤트 계약으로 통신 → 본선에서 컨테이너 분리 가능. |
| **점수 규칙 격리** | 배점을 코드에 박지 않고 `configs/scoring.toml`로 분리(공식 규칙 공개 시 설정만 교체). |

**자율성 경계** (기술 스택 문서 §1): 에이전트는 치명적 제어를 직접 수행하지 않는다.
Low·Medium 대응만 자동 실행하고, High·Critical은 `approval_required=True`로 표시해
사람 승인(HITL) 없이는 실행하지 않는다. 실행 대상은 loopback/mock/SITL로만 제한한다.

---

## 3. 아키텍처 한눈에

```
 ┌──────────┐  telemetry   ┌───────────────────────────┐  finding   ┌──────────────────────────┐
 │ Observer │ ───────────▶ │ Detector                  │ ─────────▶ │ Analysis                 │
 │ (MAVLink)│              │  · 규칙 탐지 (흐름 A~E)    │            │  Correlator (시간창+그래프)│
 │          │              │  · 스트리밍 ML (보조)      │            │      ↓                   │
 │ Swarm(F) │ ───────────▶ │  · 군집 신뢰 (흐름 F)      │            │  Response Planner         │
 └──────────┘              └───────────────────────────┘            │      ↓                   │
       ▲                                                            │  Safety Gate (allowlist·HITL)│
       │ MAVLink UDP                                                │      ↓                   │
 ┌─────┴───────────────┐                                           │  Evidence (JSONL+SQLite) │
 │ mock_vehicle / SITL │◀── attacks/ (Red: GNSS·C2·재밍·적대예제)   │      ↓                   │
 └─────────────────────┘                                           │  Scoring (공격/방어/SLA) │
                                                                    └──────────────────────────┘
```

모든 상자는 논리 에이전트/모듈이며, 내부 객체를 직접 참조하지 않고 **공통 이벤트**만 교환한다.
예선 단계에서는 같은 프로세스의 `asyncio.Task`로 실행된다(네트워크 마이크로서비스 아님).

---

## 4. 공통 이벤트 계약 (`core/events.py`)

기술 스택 문서 §6의 이벤트 계약을 Pydantic 2 스키마로 구현. 경계 입력을 검증하고,
로그·(선택적)LLM 출력이 같은 스키마를 재사용한다.

| 이벤트 | 핵심 필드 | 생산자 → 소비자 |
|--------|-----------|-----------------|
| `TelemetryEvent` | vehicle, source, **sensor_ts / recv_ts**, features | Observer → Detector |
| `FindingEvent` | detector, signal, **flow(A~F)**, confidence, risk, threat_map, evidence | Detector → Correlator |
| `DefenseAction` | playbook, steps, risk, **approval_required**, rationale, input_refs | Planner → Gate |
| `OutcomeEvent` | objective, success, latency, side_effects | Simulator → Evaluator |
| `ScoreEvent` | attack, defense, **availability(SLA 0~100)**, diagnostics | Scoring → Planner |
| `AuditEvent` | actor, decision, input_refs, model_version | 모든 모듈 → Evidence |

**필수 규칙(문서 §6) 준수:**
- 센서 시간(`sensor_ts`)과 수신 시간(`recv_ts`)을 분리해 stale sample 오탐을 막는다.
- 모든 이벤트가 `episode_id`, `correlation_id`, `schema_version`을 가진다.
- 행동 이벤트는 선택 당시 정책/모델 버전과 입력 증거 참조(`input_refs`)를 남긴다.

---

## 5. 공격 흐름 A~F 커버리지

대표공격흐름 문서의 여섯 축을 탐지기로 하나씩 대응시켰다. 핵심 통찰 —
*"단일 큰 변화보다 여러 작은 변화의 누적으로 임무 결과를 편향시킨다"* — 은
상관기(Correlator)가 여러 흐름을 캠페인으로 묶어 위험도를 상향하는 방식으로 반영했다.

| 흐름 | 흔드는 신뢰 | 탐지기(모듈) | 주요 관측 서명 |
|------|-------------|--------------|----------------|
| **A** 경로/상황인식 | 항법·경로·COP | `GnssInsCrossCheck`, `RouteConsistencyDetector` | GPS_RAW ↔ GLOBAL_POSITION 편차, 위치미분↔보고속도 불일치 |
| **B** C2/운용자 | 명령 정통성·승인 정책 | `CommandAnomalyDetector` | COMMAND_ACK 빈도 급증, 예상 밖 모드 전환 |
| **C** 텔레메트리 보정 | 상향 상태·상황인식 | `StateConsistencyDetector` | Health(배터리) 급변 등 상태 보고 불일치 |
| **D** 통신/자율모드 | 링크 가용성·원격 개입 | `LinkHealthDetector` | HEARTBEAT 두절/지연, drop_rate_comm·RSSI 저하 |
| **E** 센서/AI | 센서 신뢰·AI 판단 | `SensorConsensusDetector` | AI 신뢰도 급락, 센서 간 합의도 저하 |
| **F** 군집 | 노드 간 공유정보·합의 | `SwarmConsensusDetector` | 특정 노드만 반복적 위치 이상, 합의 결과 불일치 |

각 탐지기는 이상징후를 **STRIDE / TARA / STPA-Sec / MITRE ATLAS** 위협모델에 매핑하고
위험도와 대응 플레이북 근거를 함께 낸다.

---

## 6. 핵심 모듈 상세

### 6.1 Telemetry Observer (`agents/blue/observer.py`)
- pymavlink로 MAVLink를 수집해 **프로토콜 비종속 표준 features**로 정규화(특정 오토파일럿에 종속 안 함).
- `sensor_ts`(발신)와 `recv_ts`(수신)를 분리 → 신선도(freshness) 기반 stale 오탐 억제.
- 메시지가 없을 때도 `LINK_PROBE`를 주기 발행 → 두절/재밍 탐지 지속.
- bounded 버퍼로 최근 N개 스냅샷만 유지.

### 6.2 규칙 탐지기 (`agents/blue/rule_detectors.py`, `swarm.py`)
- 알려진 고위험 징후를 **결정론적·저지연**으로 즉시 포착(안전 경로).
- `TelemetryEvent`를 소비하고 `FindingEvent`(위협모델 매핑·위험도·근거)를 발행.

### 6.3 스트리밍 ML + 드리프트 (`agents/blue/hybrid_detector.py`)
- **River Half-Space Trees**로 복합·미지 이상 패턴을 보조 점수화.
- **River ADWIN**으로 정상 분포 변화를 shadow로 감시(경기 중 오염 방지).
- 규칙 탐지기를 **대체하지 않는다** — confidence·risk를 상한(Medium)으로 제한하고 단독 차단 근거로 쓰지 않는다.
- `river` 미설치 시 결정론적으로 비활성화되며 공방·채점은 계속 동작.

### 6.4 Threat Correlator (`agents/blue/correlator.py`)
- 차량별 슬라이딩 시간 창으로 여러 `FindingEvent`를 **하나의 공격 캠페인**으로 결합.
- 서로 다른 흐름(A~F)이 짧은 창에서 함께 나타나면 → **위험도 한 단계 상향**(누적 편향 대응).

### 6.5 Response Planner (`agents/blue/response_planner.py`)
- 대응문구를 탐지기에 하드코딩하지 않고 **흐름별 플레이북 테이블**로 분리.
- 위험도 + 상태(캠페인 맥락) 기반 선택. 선택적 LLM은 근거 생성에만, 실패 시 결정론 폴백.
- High↑는 `approval_required=True`로 게이트에 넘긴다.

### 6.6 Safety/Approval Gate (`agents/blue/safety_gate.py`)
- **allowlist**: 알려진 안전 플레이북만 자동 실행 후보.
- **HITL**: High·Critical은 사람 승인 없이 실행하지 않음.
- **대상 제한**: 실행 계층은 loopback/mock/SITL로만.

### 6.7 Evidence Recorder (`core/audit.py`)
- 모든 이벤트를 **append-only JSONL**로(사람이 읽고 보고서에 인용).
- episode 단위 집계는 **SQLite**로 질의(findings/actions/scores 테이블).

### 6.8 채점 (`scoring/adapter.py`, `metrics.py`)
- **CompetitionScoringAdapter**: 공식 축(공격/방어/가용성 SLA)을 계산, 세부 배점은 `scoring.toml`로 교체.
- 가용성(SLA)은 공격/방어와 독립된 공통 제약으로 관리(문서 §7).
- 내부 지표(탐지 지연, 오탐/미탐, 자동/HITL 수 등)는 공식 점수를 대체하지 않고 원인분석용.

---

## 7. 디렉토리 구조

```
core/
  events.py         # Pydantic 이벤트 계약 (§6)
  event_bus.py      # asyncio bounded 큐 + backpressure
  config.py         # TOML + Pydantic 설정 로더
  audit.py          # Evidence Recorder (JSONL + SQLite)
  geo.py            # 위경도 거리 유틸
agents/blue/
  observer.py       # MAVLink → 표준 TelemetryEvent
  rule_detectors.py # 흐름 A~E 결정론 탐지기
  swarm.py          # 흐름 F 군집 신뢰
  hybrid_detector.py# River Half-Space Trees + ADWIN
  correlator.py     # 캠페인 상관·위험도 상향
  response_planner.py
  safety_gate.py
  agent.py          # 오케스트레이터 (asyncio.Task + EventBus)
scoring/
  adapter.py        # CompetitionScoringAdapter
  metrics.py        # 내부 평가 지표
configs/
  default.toml      # 임계값·포트
  scoring.toml      # 배점(교체 가능)
tests/
  unit/  integration/
defense/            # (구버전) 단일 규칙 루프 — 호환 유지
sim/ attacks/       # mock/SITL 차량, Red 공격 툴킷
```

---

## 8. 실행 방법

```bash
# 의존성 (단일 파일; 코어·ML·개발 포함, torch류만 선택 주석)
pip install -r requirements.txt

# 원커맨드 데모: mock UAV+UGV + Blue Agent + 순차 공격 + 채점 요약
./run_blue_demo.sh

# 수동 실행
python -m sim.mock_vehicle --vehicle copter --port 14550    # 터미널 1
python -m sim.mock_vehicle --vehicle rover  --port 14560    # 터미널 2
python -m agents.blue.agent --uav udpin:127.0.0.1:14550 --ugv udpin:127.0.0.1:14560  # 터미널 3
python -m attacks.gnss_spoof   --target udpout:127.0.0.1:14555 --drift-m 150         # 터미널 4
python -m attacks.c2_injection --target udpout:127.0.0.1:14555 --command flood --count 20

# 테스트
python -m pytest -q
```

> **포트 주의:** 텔레메트리 수신은 `port`(14550), 명령/스푸핑 주입은 cmd-in 포트 `port+5`(14555).

---

## 9. 검증 결과 (실측)

mock UAV+UGV에 GNSS 스푸핑 + C2 폭주를 주입한 실행:

- 흐름 **A(경로) · B(C2) · F(군집)** 탐지, 복합 흐름 상관 시 위험도 **Critical 자동 상향**
- High·Critical 대응은 **HITL 승인 대기**로 보류(자동 실행 0건) — 자율성 경계 준수
- 모든 이벤트가 `logs/events.jsonl` + `logs/episodes.db`에 구조화 저장
- 종료 시 **방어 점수 · 가용성(SLA) · 흐름별 탐지 요약** 출력
- 에러/트레이스백 없음, 단위·통합 테스트 **13/13 통과**

**기술 스택 문서 §11 검증 기준 충족:**
인터넷·외부 API·GPU 없이 한 명령 완주 / 같은 시드·설정으로 재현 / 규칙 탐지와 ML 이상점수 병행 기록 /
High·Critical 무승인 실행 차단 / 공격 도구는 loopback·mock·SITL 외 대상 거부 /
공격·방어·가용성 점수를 episode 단위 출력 / LLM 없이도 공방·채점·로그 동작.

---

## 10. 남은 작업 (Phase 6+)

기술 스택 문서의 "본선 진출 후 확장"에 해당하는 미착수 항목:

- **선택적 Local LLM** (Ollama): 여러 Finding을 위협 가설·공격 단계로 요약, 한국어 상황 설명 생성
  (Pydantic JSON Schema 검증 + 타임아웃·실패 시 결정론 폴백).
- **Red 적응형 공격기** (seeded LinUCB): 관측 문맥에 따라 공격 종류·강도를 바꾸는 상대 →
  Blue+Red 완전 폐루프, 공격 점수 실측.
- **shadow 모델 승격 정책**: 새 데이터 학습은 shadow에서, replay·SLA 회귀 검사 통과 시만 승격.
- **흐름 C/E 탐지 정교화**: 현재 근사 → 명령↔상태 교차검증, 관측 커버리지 검증 강화.
- **재생 대시보드**: 모델 레지스트리, 서명된 정책 번들, baseline↔adaptive 비교.

---

## 11. 참고

- 상위 개요·아키텍처 표: [README.md](../README.md)
- 계층/공격 매핑: [docs/architecture.md](architecture.md)
- 스펙 문서: `agent_technology_stack.pdf`(기술 스택), `DAH2026_UxS_대표공격흐름.pdf`(공격 흐름)
