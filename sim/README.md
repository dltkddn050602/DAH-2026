# 시뮬레이션 (제어 계층 A)

두 가지 충실도(fidelity)의 차량을 제공한다. **공수/방어 스크립트는 둘 다 동일한
MAVLink 인터페이스를 쓰므로 코드 수정 없이 교체 가능**하다.

## 1) 경량 mock 차량 — 즉시 실행 (권장 개발/시연)

Docker·빌드 불필요. 실제 SITL과 동일한 MAVLink 메시지를 방출한다.

```bash
# UAV
python -m sim.mock_vehicle --vehicle copter --port 14550   # telem 14550, cmd 14555
# UGV (다른 터미널)
python -m sim.mock_vehicle --vehicle rover  --port 14560   # telem 14560, cmd 14565
```

- 텔레메트리: `HEARTBEAT / GLOBAL_POSITION_INT / GPS_RAW_INT / SYS_STATUS / COMMAND_ACK`
- 명령 수신 포트 = 텔레메트리 포트 + 5
- 모델링한 공격 표면: C2 명령 주입(cmd 포트), GNSS 스푸핑(GPS_INPUT 주입)

## 2) ArduPilot SITL — 풀피델리티 (본선/최종 검증용)

실제 오토파일럿(ArduCopter/Rover)을 컨테이너로 구동한다.

```bash
docker compose up --build          # 최초 빌드 15-25분
# 텔레메트리: UAV udp 14550, UGV udp 14560 → 호스트로 push
```

호스트에서 방어/공격은 동일하게:

```bash
python -m defense.agent --uav udpin:127.0.0.1:14550 --ugv udpin:127.0.0.1:14560
python -m attacks.c2_injection --target udpout:127.0.0.1:14550   # SITL은 telem=cmd 동일 포트
```

### SITL에서의 GNSS 스푸핑
mock은 `GPS_INPUT` 주입으로 모델링하지만, SITL에서는 시뮬레이터 파라미터로 더
사실적으로 재현한다 (MAVProxy 콘솔에서):

```
param set SIM_GPS_GLITCH_X 0.0015   # 위도 방향 글리치(도)
param set SIM_GPS_GLITCH_Y 0.0015   # 경도 방향 글리치(도)
# 또는 GPS 완전 차단:  param set SIM_GPS_DISABLE 1
```

이때도 방어의 GNSS-INS 교차검증 탐지 로직은 동일하게 동작한다.

## 왜 ArduPilot SITL인가
- **하나의 코드베이스로 Copter(UAV)+Rover(UGV)** → "UAV/UGV 균형" 요건 충족
- 둘 다 MAVLink → 공격 스크립트 재사용
- PX4+Gazebo 대비 경량, 헤드리스로 CI/데모에 적합
