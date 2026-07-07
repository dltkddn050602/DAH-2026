"""
공격 #4 — AI 적대적 예제 (인지모델 회피 / Evasion)

위협모델: MITRE ATLAS — Evasion(적대적 예제), TARA — 표적 오인식/장애물 회피 실패

원리
----
UAV/UGV의 표적탐지·객체식별은 딥러닝 인지모델에 의존한다. 공격자가 EO/IR 프레임에
사람 눈에는 거의 티 안 나는 미세 섭동(adversarial perturbation) 또는 물리적
adversarial patch를 주입하면, 모델이 표적을 놓치거나(miss) 오분류하게 만들 수 있다.
이는 통신/항법 보안만으로는 막을 수 없는 'AI 고유 위협'으로, 방어 문서의
MITRE ATLAS 축과 직결된다.

본 데모는 YOLO 탐지기에 PGD(Projected Gradient Descent) 기반 L∞ 섭동을 걸어
표적 탐지 신뢰도를 붕괴시키고, 그 전/후 신뢰도를 방어 에이전트의
SensorConsensusMonitor 에 주입해 '탐지→매핑→대응'이 작동함을 보인다.

의존성 (용량이 커 기본 requirements에서 분리):
    pip install torch torchvision ultralytics

사용:
    python -m attacks.perception.adversarial_patch                 # 샘플 이미지 자동 사용
    python -m attacks.perception.adversarial_patch --image path.jpg --eps 0.03 --steps 40
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np


def _need(pkg):
    print(f"[!] '{pkg}' 미설치. 인지 계층 데모 실행:")
    print("    pip install torch torchvision ultralytics")
    sys.exit(1)


def load_sample_image(path):
    """이미지 경로가 없으면 ultralytics 샘플(bus.jpg)을 EO/IR 프레임 대용으로 내려받음."""
    from PIL import Image
    if path and os.path.exists(path):
        return Image.open(path).convert("RGB")
    import urllib.request
    url = "https://ultralytics.com/images/bus.jpg"
    dst = "docs/sample_target.jpg"
    os.makedirs("docs", exist_ok=True)
    if not os.path.exists(dst):
        print(f"[i] 샘플 표적 프레임 다운로드: {url}")
        urllib.request.urlretrieve(url, dst)
    from PIL import Image as I
    return I.open(dst).convert("RGB")


def max_conf(results):
    """YOLO 결과에서 최고 탐지 신뢰도."""
    confs = []
    for r in results:
        if r.boxes is not None and len(r.boxes) > 0:
            confs.extend(r.boxes.conf.detach().cpu().numpy().tolist())
    return float(max(confs)) if confs else 0.0


def pgd_evasion(model, img_t, eps, alpha, steps, device):
    """탐지 objectness/confidence를 낮추는 방향으로 L∞ PGD 섭동 생성."""
    import torch
    orig = img_t.clone().detach()
    adv = img_t.clone().detach()
    adv = adv + torch.empty_like(adv).uniform_(-eps, eps)
    adv = adv.clamp(0, 1)

    for i in range(steps):
        adv.requires_grad_(True)
        # ultralytics 내부 모델의 raw 출력에서 objectness/conf 합을 손실로 사용
        preds = model.model(adv)
        raw = preds[0] if isinstance(preds, (list, tuple)) else preds
        # raw: [B, no, N] — 마지막 채널들에 클래스 점수. 최대 점수 합을 최소화.
        obj = raw[:, 4:, :].sigmoid().amax(dim=1).sum()
        grad = torch.autograd.grad(obj, adv, retain_graph=False)[0]
        with torch.no_grad():
            adv = adv - alpha * grad.sign()          # 신뢰도 낮추는 방향
            adv = torch.min(torch.max(adv, orig - eps), orig + eps).clamp(0, 1)
        adv = adv.detach()
        if (i + 1) % max(1, steps // 5) == 0:
            print(f"  PGD step {i+1}/{steps}  objective={float(obj):.3f}")
    return adv.detach()


def main():
    ap = argparse.ArgumentParser(description="AI 적대적 예제(인지모델 회피) 데모")
    ap.add_argument("--image", default=None, help="EO/IR 프레임 이미지(없으면 샘플)")
    ap.add_argument("--model", default="yolov8n.pt")
    ap.add_argument("--eps", type=float, default=0.03, help="L∞ 섭동 예산(0~1)")
    ap.add_argument("--alpha", type=float, default=0.006)
    ap.add_argument("--steps", type=int, default=40)
    ap.add_argument("--feed-defense", action="store_true",
                    help="결과를 방어 SensorConsensusMonitor에 주입해 탐지 확인")
    args = ap.parse_args()

    try:
        import torch
        from ultralytics import YOLO
    except Exception:
        _need("torch/ultralytics")

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"[adversarial_patch] device={device} eps={args.eps} steps={args.steps}")

    img = load_sample_image(args.image)
    model = YOLO(args.model)
    model.model.to(device).eval()

    import torchvision.transforms as T
    to_t = T.Compose([T.Resize((640, 640)), T.ToTensor()])
    img_t = to_t(img).unsqueeze(0).to(device)

    # --- 공격 전 ---
    base = model.predict(img, verbose=False)
    base_conf = max_conf(base)
    base_n = sum(len(r.boxes) for r in base if r.boxes is not None)
    print(f"\n[공격 전] 탐지 객체 {base_n}개, 최고 신뢰도 {base_conf:.3f}")

    # --- PGD 적대적 섭동 ---
    adv_t = pgd_evasion(model, img_t, args.eps, args.alpha, args.steps, device)

    # 텐서→이미지로 되돌려 재탐지
    from PIL import Image
    adv_np = (adv_t.squeeze(0).permute(1, 2, 0).cpu().numpy() * 255).astype("uint8")
    adv_img = Image.fromarray(adv_np)
    os.makedirs("docs", exist_ok=True)
    adv_img.save("docs/adversarial_frame.jpg")
    adv = model.predict(adv_img, verbose=False)
    adv_conf = max_conf(adv)
    adv_n = sum(len(r.boxes) for r in adv if r.boxes is not None)

    print(f"[공격 후] 탐지 객체 {adv_n}개, 최고 신뢰도 {adv_conf:.3f}")
    print(f"[결과] 신뢰도 {base_conf:.3f} → {adv_conf:.3f}  "
          f"(Δ{base_conf-adv_conf:+.3f}), 탐지 {base_n}→{adv_n}개")
    print("       adversarial 프레임 저장: docs/adversarial_frame.jpg")

    # --- 방어 에이전트 탐지 연동 ---
    if args.feed_defense or True:
        from defense.detectors import SensorConsensusMonitor
        mon = SensorConsensusMonitor(conf_drop=0.3)
        mon.inject_ai_result(base_conf, sensor_agreement=1.0)      # 정상 기준선
        findings = mon.inject_ai_result(adv_conf,
                                        sensor_agreement=0.2 if adv_n < base_n else 0.8)
        print("\n[방어 에이전트 판단]")
        for f in (findings or []):
            print(f"  ⚠ ({f.risk}) {f.signal}")
            print(f"     매핑: {f.threat_map}")
            print(f"     대응: {f.response}")
        if not findings:
            print("  (신뢰도 변화가 임계 미만 — eps/steps를 키워 재시도)")


if __name__ == "__main__":
    main()
