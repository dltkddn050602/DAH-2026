# ArduPilot SITL (Copter=UAV, Rover=UGV) — 풀피델리티 제어 계층
# 경량 mock_vehicle 로 검증한 공수/방어 스크립트를 실제 오토파일럿 SITL에 붙이기 위한 이미지.
# 주의: 소스 빌드는 최초 1회 ~15-25분 소요된다.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV USER=root

RUN apt-get update && apt-get install -y --no-install-recommends \
        git python3 python3-pip python3-dev python3-setuptools \
        sudo lsb-release tzdata rsync build-essential ccache \
        gawk g++ libtool && \
    rm -rf /var/lib/apt/lists/*

# ArduPilot 클론 (필요 시 특정 태그 고정 권장: --branch Copter-4.5)
RUN git clone --recurse-submodules --depth 1 https://github.com/ArduPilot/ardupilot.git /ardupilot
WORKDIR /ardupilot

# 빌드 의존성 설치 (대화형 프롬프트 비활성화)
RUN USER=root Tools/environment_install/install-prereqs-ubuntu.sh -y || true
ENV PATH="/root/.local/bin:/ardupilot/Tools/autotest:${PATH}"

# SITL 빌드 (Copter + Rover)
RUN . ~/.profile 2>/dev/null; ./waf configure --board sitl && \
    ./waf copter rover

# 텔레메트리 아웃 포트: Copter 14550, Rover 14560 (docker-compose에서 매핑)
EXPOSE 14550/udp 14560/udp

# 기본은 Copter. compose에서 command 로 오버라이드.
CMD ["python3", "Tools/autotest/sim_vehicle.py", "-v", "ArduCopter", \
     "-l", "37.5000,127.0000,100,0", "--no-rebuild", \
     "--out", "udpout:host.docker.internal:14550", "-w"]
