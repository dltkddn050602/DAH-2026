# DAH 2026 — UAV/UGV 자율 사이버 공방 시뮬레이션

> **Defense AI Cyber Security Hackathon 2026** · 팀 **Cau멜레온**
>
> UAV(무인항공기)·UGV(무인지상차량)를 대상으로, **AI 공격(Red) 에이전트와 AI 방어(Blue)
> 에이전트가 상대의 행동·결과를 관찰하며 다음 행동을 스스로 선택**하는 자율 사이버 공방 환경.
> 공격 스크립트를 순서대로 돌리는 데모가 아니라, 관측→판단→행동→평가가 닫힌 **폐루프**다.
> 인터넷·GPU 없이 CPU 단일 환경에서 한 명령으로 완주한다.

---

## 핵심 특징

- **대칭 구조의 두 에이전트** — 공통 이벤트 계약(Pydantic) 위에서 Blue/Red가 같은 버스로 통신
- **적응형 공격(Red)** — seeded **LinUCB** 문맥적 밴딧으로 Blue의 탐지·차단·점수를 보고 다음
  공격을 스스로 선택 (고정 순서 baseline 대비 동일 예산에서 공격 점수 **+19%** 실측)
- **하이브리드 탐지(Blue)** — 결정론 규칙(안전 경로) + River 스트리밍 ML(지능 경로, 보조 점수)
- **위협모델 매핑** — 모든 탐지를 STRIDE·TARA·STPA-Sec·MITRE ATLAS로 매핑하고 위험도·플레이북 산출
- **자율성 경계(HITL)** — Low·Medium만 자동 조치, High·Critical은 사람 승인 없이는 미실행.
  공격 도구·방어 실행은 loopback/mock/SITL 대상으로만 제한
- **재현성·설명 가능성** — 시드 고정, 모든 판단을 append-only JSONL + SQLite 증거로 보존
- **오프라인 우선** — river/torch 미설치 시 자동 폴백, LLM 없이도 공방·채점·로그 동작

---

## 아키텍처

```
        ┌──────────────────────────────────────────────┐
        │  시뮬레이션 (제어 계층)                        │
        │  sim.mock_vehicle (Copter/Rover) 또는 SITL    │
        └───────────────┬──────────────────────────────┘
              MAVLink UDP │ telem 14550 / cmd-in 14555
   ┌────────────────────┼────────────────────┐
   │      공통 EventBus (Pydantic Event Schema)      │
   ├────────────────────┼────────────────────┤
   │  Red AI Agent      │      Blue AI Agent          │
   │  Observer          │      Observer               │
   │  → LinUCB Planner  │      → Rule + ML Detector    │
   │  → Policy Gate     │      → Correlator            │
   │  → Tool Executor   │      → Response Planner       │
   │  → Outcome Eval    │      → Safety/HITL Gate       │
   └────────────────────┴──────────┬─────────────────┘
                    Evidence (JSONL+SQLite) · Scoring(공격/방어/SLA)
```

공격 흐름 A~F와 각 공격의 **공통 텔레메트리 관측 서명**으로 탐지하므로, 특정 오토파일럿
(PX4·ArduPilot) 내부 구현에 종속되지 않는다. 상세 설계는 [docs/](docs/) 참조.

---

## 빠른 시작

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # 코어·ML·개발 (torch류만 선택 주석)
```

### 데모 ① — Blue 단독 (mock UAV+UGV + 순차 공격 + 채점)
```bash
./run_blue_demo.sh
```

### 데모 ② — Red↔Blue 자율 공방 (적응형 LinUCB + baseline 비교)
```bash
./run_redblue_demo.sh
```

### 수동 실행 — 자율 공방 캠페인
```bash
python -m sim.mock_vehicle --vehicle copter --port 14550        # 터미널 1
python -m agents.red.campaign --policy adaptive --decisions 16  # 터미널 2 (공방)
python -m agents.red.campaign --policy baseline --decisions 16  # 비교군
```

> **포트 규칙:** 텔레메트리 수신 `port`(14550), 명령/스푸핑 주입 `port+5`(14555).
> 모든 공격 대상은 loopback/mock/SITL 엔드포인트로만 제한된다(안전 경계).

### 테스트
```bash
python -m pytest -q        # 30 passed (단위 26 + 통합 4)
```

---

## 공격 시나리오 (Red)

| 흐름 | 공격 | 모듈 | 관측 서명 | 대응 탐지기 |
|---|---|---|---|---|
| A | GNSS 스푸핑 | `attacks/gnss_spoof.py` | GPS_RAW↔GLOBAL_POSITION divergence | GNSS-INS 교차검증 |
| B | C2 명령 주입 | `attacks/c2_injection.py` | COMMAND_ACK 빈도↑·모드 급변 | 명령 이상 감시 |
| D | 재밍/DoS | `attacks/jamming_dos.py` | HEARTBEAT 간격↑·두절 | 링크 상태 감시 |
| E | AI 적대적 예제 | `attacks/perception/` | AI 신뢰도 급락·센서 불일치 | 센서/AI 합의 감시 |
| G | MITM 인터셉션 | `attacks/mitm_intercept.py` | 운동학 잔차·seq 불연속 | MITM 인터셉션 감시 |

Red AI 에이전트(`agents/red/`)는 위 도구를 allowlist 어댑터로 감싸, 관측 문맥에 따라 종류·강도를
LinUCB로 선택한다.

## 방어 (Blue)

관측→탐지(규칙+스트리밍 ML)→상관→대응→안전 게이트→증거→채점 폐루프(`agents/blue/`).
탐지기: GNSS-INS 교차검증 · 경로 정합성 · 링크 상태 · 명령 이상 · 상태 정합성 · 센서/AI 합의 ·
군집 신뢰. 복합 흐름을 하나의 캠페인으로 상관해 위험도를 자동 상향한다.

---

## 디렉터리 구조

```
core/          공통 이벤트 계약(Pydantic)·이벤트 버스·설정·증거(JSONL+SQLite)·지오
agents/
  blue/        방어 에이전트 (observer·rule/ML detector·correlator·planner·safety_gate)
  red/         공격 에이전트 (observer·LinUCB planner·policy_gate·executor·campaign)
attacks/       Red 공격 툴킷 (C2·GNSS·재밍·MITM + perception/ 적대적 예제)
defense/       (구버전) 단일 규칙 방어 루프 — 호환 유지
scoring/       CompetitionScoringAdapter (공격/방어/가용성 SLA) + 내부 지표
sim/           경량 mock 차량 + ArduPilot SITL Dockerfile
configs/       default.toml(임계값·포트·Red) · scoring.toml(배점)
tests/         unit/ + integration/ (30 passed)
docs/          아키텍처·공격 시나리오·Blue/Red 설계·예선 보고서(.md)
```

---

## 문서

- [docs/DAH2026_예선보고서.md](docs/DAH2026_예선보고서.md) — 예선 보고서(공격 시나리오·방어 아키텍처·AI 에이전트)
- [docs/architecture.md](docs/architecture.md) — 계층·공격→방어 매핑
- [docs/attack_scenarios.md](docs/attack_scenarios.md) — 공격 시나리오 A~G 상세·라이브 테스트
- [docs/blue_agent.md](docs/blue_agent.md) — 방어(Blue) 에이전트 설계·구현
- [docs/agent_technology_stack.md](docs/agent_technology_stack.md) — 기술 스택·이벤트 계약·로드맵

---

## 안전·윤리 고지

본 코드는 **격리된 로컬 시뮬레이션 환경**에서 DAH 2026 방어 전략 검증 목적으로만 사용된다.
실제 항공기·차량·무선 스펙트럼·네트워크를 대상으로 한 사용을 금지한다. 모든 공격은 로컬
mock/SITL의 MAVLink 엔드포인트(loopback)에만 적용되며, 치명적 제어는 사람 승인 절차 뒤에 둔다.

## 라이선스

[MIT](LICENSE)
