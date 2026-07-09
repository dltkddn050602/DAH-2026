#!/usr/bin/env python3
"""
MITM 인터셉션 시나리오 — 검증 리포트 PDF 생성기

logs_mitm/verify_summary.json, harvest.json, incidents.jsonl 의 라이브 검증 결과를
읽어 공격 서사 + 구현 코드 + 실행 검증 결과 + 위협모델 매핑을 하나의 한글 PDF로 만든다.
저장소의 기존 문서(docs/attack_scenarios.md) 스타일을 따른다.

    python make_report_mitm.py            # → DAH2026_MITM_인터셉션_검증리포트.pdf
"""
from __future__ import annotations

import json
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, Preformatted, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

ROOT = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(ROOT, "logs_mitm")
OUT = os.path.join(ROOT, "DAH2026_MITM_인터셉션_검증리포트.pdf")

# ---------- 한글 폰트 등록 ----------
NANUM = "/usr/share/fonts/truetype/nanum"
pdfmetrics.registerFont(TTFont("KR", f"{NANUM}/NanumGothic.ttf"))
pdfmetrics.registerFont(TTFont("KR-B", f"{NANUM}/NanumGothicBold.ttf"))
pdfmetrics.registerFont(TTFont("KRmono", f"{NANUM}/NanumGothicCoding.ttf"))

INK = colors.HexColor("#1f2933")
ACCENT = colors.HexColor("#7b1e1e")     # 진한 적색(공격)
BLUE = colors.HexColor("#1e3a5f")       # 진한 청색(방어)
LIGHT = colors.HexColor("#f2ede6")
CODEBG = colors.HexColor("#f5f3ef")
GRID = colors.HexColor("#c9c1b6")

styles = getSampleStyleSheet()


def S(name, **kw):
    base = dict(fontName="KR", textColor=INK, leading=15, fontSize=9.5)
    base.update(kw)
    return ParagraphStyle(name, **base)


BODY = S("body")
H1 = S("h1", fontName="KR-B", fontSize=17, textColor=ACCENT, leading=21, spaceBefore=6, spaceAfter=6)
H2 = S("h2", fontName="KR-B", fontSize=12.5, textColor=BLUE, leading=17, spaceBefore=12, spaceAfter=4)
SMALL = S("small", fontSize=8, textColor=colors.HexColor("#6b6459"), leading=11)
CODE = S("code", fontName="KRmono", fontSize=6.9, leading=8.6, textColor=colors.HexColor("#20303a"))
CELL = S("cell", fontSize=8.3, leading=11)
CELLB = S("cellb", fontName="KR-B", fontSize=8.3, leading=11, textColor=colors.white)
TAG = S("tag", fontName="KR-B", fontSize=8.3, leading=11, textColor=INK)


def load():
    def j(p, d):
        try:
            return json.load(open(os.path.join(EVID, p)))
        except Exception:
            return d
    summary = j("verify_summary.json", {})
    harvest = j("harvest.json", {})
    incidents = []
    try:
        for line in open(os.path.join(EVID, "incidents.jsonl")):
            line = line.strip()
            if line:
                incidents.append(json.loads(line))
    except Exception:
        pass
    return summary, harvest, incidents


def para(t, s=BODY):
    return Paragraph(t, s)


def code_block(text):
    return Table(
        [[Preformatted(text.strip("\n"), CODE)]],
        colWidths=[17.0 * cm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CODEBG),
            ("BOX", (0, 0), (-1, -1), 0.5, GRID),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]),
    )


def kv_table(rows, w1=4.7, w2=12.3):
    data = [[para(k, TAG), para(v, CELL)] for k, v in rows]
    t = Table(data, colWidths=[w1 * cm, w2 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def header_table(headers, rows, widths, head_bg=BLUE, zebra=True):
    data = [[para(h, CELLB) for h in headers]]
    data += [[para(c, CELL) for c in r] for r in rows]
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), head_bg),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if zebra:
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#faf8f5")))
    t.setStyle(TableStyle(style))
    return t


# ===================== 콘텐츠 =====================

def build():
    summary, harvest, incidents = load()
    h = summary.get("harvest", harvest)
    by_det = summary.get("incident_by_detector", {})
    by_risk = summary.get("incident_by_risk", {})
    total = summary.get("incident_total", len(incidents))

    def g(k, d="—"):
        v = h.get(k, d)
        return d if v is None else v

    flow = []

    # ---- 표지 헤더 ----
    flow.append(para("DAH 2026 · UAV/UGV 사이버 공방 시뮬레이션", SMALL))
    flow.append(para("데이터링크 MITM 인터셉션 공격 시나리오 및 코드 검증", H1))
    flow.append(para(
        "대상: 시퀀스 다이어그램의 <b>UxS(UAV/UGV) ↔ GCS/UCS</b> 데이터 통신(데이터링크/전술망). "
        "다운링크 텔레메트리·센서·Health 및 업링크 명령 경로를 하나의 공격 표면으로 보고, "
        "저장소의 red/blue 코드로 재현·검증한 결과를 정리한다.", BODY))
    flow.append(Spacer(1, 3))
    flow.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    flow.append(Spacer(1, 6))

    # ---- 1. 개요 ----
    flow.append(para("1. 개요 — 다이어그램의 어떤 흐름을 공격하는가", H2))
    flow.append(para(
        "다이어그램에서 UxS는 GCS로 <b>텔레메트리(위치·속도·배터리·상태)·센서·Health</b> 데이터를 올리고, "
        "GCS는 UxS로 <b>임무명령·경로·제어 요청</b>을 내린다. 이 양방향 통신은 데이터링크/전술망이라는 "
        "전송 계층을 지난다. 공격자가 이 전송 계층에 <b>중간자(MITM)</b>로 삽입되면 데이터를 "
        "가로채고(도청) 나아가 변조할 수 있다. 본 리포트는 이 MITM 인터셉션을 프로토콜 수준에서 "
        "정직하게 모델링해 재현하고, 방어 에이전트가 이를 탐지하는지 실제 코드로 검증한다.", BODY))
    flow.append(Spacer(1, 4))
    flow.append(kv_table([
        ("공격 표면", "데이터링크/전술망(전송 계층) — UxS↔GCS 양방향"),
        ("공격 유형", "Adversary-in-the-Middle: 수동 도청(기밀성) → 능동 변조(무결성)"),
        ("구현 모듈", "attacks/mitm_intercept.py (red) · defense/detectors.py:InterceptionMonitor (blue)"),
        ("검증 방식", "mock 차량 → MITM 릴레이 → 방어 에이전트 폐루프, MAVLink 실트래픽"),
    ]))

    # ---- 2. 위협모델 매핑 ----
    flow.append(para("2. 위협모델 매핑", H2))
    flow.append(header_table(
        ["프레임워크", "매핑"],
        [["STRIDE", "Information Disclosure(도청) + Tampering(텔레메트리 변조)"],
         ["TARA", "기밀성 상실(임무·위치·상태 노출) + 상황인식 오염(위조 피드백)"],
         ["STPA-Sec", "위조된 피드백에 기반한 불안전 제어행동(오항법·오판단)"],
         ["MITRE ATT&CK ICS", "Adversary-in-the-Middle(T0830), Spoof Reporting Message(T0856)"]],
        widths=[4.2, 12.8]))

    # ---- 3. 공격 시나리오 서사 ----
    flow.append(para("3. 공격 시나리오 (서사)", H2))
    flow.append(para(
        "공격자가 UxS↔GCS 경로에 MITM으로 삽입된다(무선 릴레이 하이재킹, 악성 게이트웨이, "
        "경로/ARP 오염 등). 본 환경은 이를 차량 텔레메트리 포트와 GCS 사이에 삽입되는 UDP 릴레이로 "
        "모델링한다. 공격은 두 단계로 진행된다.", BODY))
    flow.append(Spacer(1, 3))
    flow.append(para("① 수동 도청 (Passive Eavesdropping) — 기밀성 침해", S("s3a", fontName="KR-B", fontSize=10, textColor=ACCENT, leading=14)))
    flow.append(para(
        "인터셉터는 모든 MAVLink 프레임을 <b>바이트 단위로 그대로 중계</b>하면서 복호·파싱해 "
        "위치·비행모드·배터리·무장상태·명령이력을 탈취한다. 프레임을 변경하지 않으므로 "
        "텔레메트리 '내용'상 서명이 없다 — <b>도청은 본질적으로 은밀</b>하며, 이 단계의 피해는 "
        "순수 기밀성 상실이다. 이 은밀성이야말로 방어가 링크 인증·암호화·네트워크 계층 대책을 "
        "함께 갖춰야 하는 이유다(텔레메트리 이상탐지만으로는 관측 불가한 정직한 한계).", BODY))
    flow.append(Spacer(1, 3))
    flow.append(para("② 능동 변조 (Active Tampering) — 무결성·상황인식 침해", S("s3b", fontName="KR-B", fontSize=10, textColor=ACCENT, leading=14)))
    flow.append(para(
        "공격자가 상황인식을 오염시키려는 순간 은밀성은 깨진다. 인터셉터가 "
        "GLOBAL_POSITION_INT(운용자가 신뢰하는 융합 위치)의 좌표에 점증 오프셋을 주입하되 "
        "<b>속도 필드(vx,vy)는 그대로 둔다.</b> 그 결과 세 가지 공통 서명이 GCS 관측 텔레메트리에 "
        "나타난다: (1) 위치 변화량이 보고된 속도와 불일치(운동학 정합성 위반), (2) 재기록된 프레임이 "
        "새 MAVLink 시퀀스로 방출되어 동일 sysid의 seq 역행·급점프(발신원 정합성 위반), "
        "(3) 위조된 융합위치 vs 참(true) 원시 GPS 간 divergence.", BODY))

    flow.append(PageBreak())

    # ---- 4. 구현 코드 ----
    flow.append(para("4. 핵심 구현 코드", H2))
    flow.append(para("4.1 공격 — 능동 변조 (attacks/mitm_intercept.py · Interceptor.tamper)", S("c1", fontName="KR-B", fontSize=9.5, textColor=ACCENT, leading=13)))
    flow.append(para("융합 위치에만 오프셋을 더하고 속도·헤딩은 유지해 운동학 불일치를 유발한다. "
                     "재기록 프레임은 인터셉터의 새 시퀀스로 나가므로 발신원 seq도 불연속이 된다.", SMALL))
    flow.append(code_block(CODE_TAMPER))
    flow.append(Spacer(1, 4))
    flow.append(para("4.2 방어 — MITM 탐지 (defense/detectors.py · InterceptionMonitor)", S("c2", fontName="KR-B", fontSize=9.5, textColor=BLUE, leading=13)))
    flow.append(para("특정 오토파일럿·암호화에 무관한 공통 서명 두 가지로 능동 변조를 탐지한다.", SMALL))
    flow.append(code_block(CODE_DETECT))

    flow.append(PageBreak())

    # ---- 5. 검증 방법 ----
    flow.append(para("5. 검증 방법 (실행 하니스)", H2))
    flow.append(para(
        "방어 에이전트를 인터셉터 뒤에 두고, 인터셉터를 수동 도청→능동 변조로 자동 전환시킨 뒤 "
        "① 도청만으로 재구성한 운용정보와 ② 방어가 탐지한 인시던트를 수집한다. 모든 트래픽은 "
        "실제 MAVLink UDP다(verify_mitm.py).", BODY))
    flow.append(Spacer(1, 3))
    flow.append(code_block(TOPOLOGY))
    flow.append(Spacer(1, 3))
    flow.append(kv_table([
        ("토폴로지", summary.get("topology", "vehicle→[MITM 14550→14551]→defense")),
        ("도청 유지", f"{summary.get('activate_after_s','—')}s (이후 능동 변조 전환)"),
        ("총 동작", f"{summary.get('duration_s','—')}s"),
        ("재현 명령", "python verify_mitm.py"),
    ]))

    # ---- 6. 검증 결과 ----
    flow.append(para("6. 검증 결과 (라이브 실행)", H2))
    flow.append(para("6.1 1단계 도청 — 링크 암호화 없이 재구성한 운용 상황도", S("r1", fontName="KR-B", fontSize=9.5, textColor=ACCENT, leading=13)))
    flow.append(para("인터셉터가 프레임을 변조하지 않고 <b>가로채기만</b> 해서 아래 정보를 복원했다. "
                     "링크에 기밀성 보호가 없으면 적이 임무 전체를 실시간 관측할 수 있음을 보인다.", SMALL))
    mc = g("msg_counts", {})
    mc_str = ", ".join(f"{k}:{v}" for k, v in mc.items()) if isinstance(mc, dict) else str(mc)
    flow.append(kv_table([
        ("대상 시스템", f"sysid={g('sysid')} · 무장={'ARMED' if g('armed') else 'DISARMED'} · 모드={g('mode')}"),
        ("배터리", f"{g('battery_pct')}%"),
        ("추정 홈 좌표", str(g("home"))),
        ("최종 관측 위치", str(g("last_pos"))),
        ("탈취 궤적 샘플", f"{g('track_points', len(harvest.get('track', [])))}개 지점"),
        ("중계/변조 프레임", f"{g('frames_relayed')} 프레임 (변조 {g('frames_tampered')})"),
        ("관측 메시지 유형", mc_str),
    ]))
    flow.append(Spacer(1, 5))

    flow.append(para("6.2 2단계 변조 — 방어 에이전트 탐지 결과", S("r2", fontName="KR-B", fontSize=9.5, textColor=BLUE, leading=13)))
    flow.append(para(
        f"수동 도청 구간에서는 프레임이 참값 그대로여서 내용 기반 탐지가 0건(은밀). "
        f"능동 변조 전환 직후 총 <b>{total}건</b>의 인시던트가 탐지되었다.", BODY))
    flow.append(Spacer(1, 3))

    det_rows = []
    det_label = {
        "MITM 인터셉션 감시": ("운동학 정합성 + 발신원 시퀀스", "STRIDE-Tampering / ATT&CK T0830"),
        "GNSS-INS 교차검증": ("위조 융합위치 vs 참 GPS divergence", "STRIDE-Spoofing"),
        "링크 상태 감시": ("HEARTBEAT 간격", "STRIDE-DoS"),
        "명령 이상 감시": ("명령 빈도/모드", "STRIDE-Tampering"),
    }
    for det, n in by_det.items():
        sig, mp = det_label.get(det, ("—", "—"))
        det_rows.append([det, str(n), sig, mp])
    if det_rows:
        flow.append(header_table(
            ["탐지기", "건수", "관측 서명", "위협 매핑"],
            det_rows, widths=[3.6, 1.2, 6.6, 5.6]))
    flow.append(Spacer(1, 4))

    risk_rows = [[k, str(v)] for k, v in sorted(
        by_risk.items(), key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x[0], 9))]
    flow.append(para("위험도 분포 (High↑는 human-in-the-loop 승인 게이트)", SMALL))
    flow.append(header_table(["위험도", "건수"], risk_rows, widths=[3.0, 2.0],
                             head_bg=ACCENT, zebra=False))
    flow.append(Spacer(1, 4))

    # 대표 인시던트 샘플
    samples = summary.get("samples", incidents[:5])
    ev_rows = []
    for r in samples[:5]:
        ev = r.get("evidence", {})
        ev_str = ", ".join(f"{k}={v}" for k, v in ev.items())
        ev_rows.append([r.get("detector", "—"), r.get("risk", "—"),
                        (r.get("signal", "")[:52] + ("…" if len(r.get("signal", "")) > 52 else "")),
                        ev_str[:40]])
    if ev_rows:
        flow.append(para("대표 인시던트(증거 JSON 자동 보존, logs_mitm/incidents.jsonl)", SMALL))
        flow.append(header_table(["탐지기", "위험", "징후", "증거"], ev_rows,
                                 widths=[3.2, 1.3, 6.7, 5.8]))

    # ---- 7. 시사점 & 대응 ----
    flow.append(para("7. 시사점과 대응 플레이북", H2))
    flow.append(para(
        "• <b>도청은 은밀하다.</b> 수동 MITM은 텔레메트리 이상탐지로 잡히지 않는다 — 링크 인증·"
        "암호화·발신원 서명이 1차 방어선이며, 이상탐지는 그 우회·변조 시점을 잡는 2차 방어선이다.", BODY))
    flow.append(para(
        "• <b>변조는 교차검증으로 드러난다.</b> 공격자가 위치만 밀고 속도를 그대로 두는 순간, "
        "운동학 정합성·발신원 시퀀스·GNSS-INS 세 독립 서명이 동시에 어긋난다. 단일 신호가 아닌 "
        "다중 신호 합의가 오탐을 억제하고 확신을 높인다.", BODY))
    flow.append(para(
        "• <b>대응 플레이북.</b> 링크 무결성(서명/시퀀스) 검증 → 텔레메트리 발신원 재인증 → "
        "융합위치 신뢰도 하향·원시GPS/INS 교차검증 → 링크 암호화·경로 무결성 점검 → 링크 전환. "
        "운동학 잔차 6~25m·시퀀스 불연속은 High, 잔차 25m↑는 Critical로 운용자 승인을 요구한다.", BODY))

    flow.append(Spacer(1, 6))
    flow.append(HRFlowable(width="100%", thickness=0.6, color=GRID))
    flow.append(para(
        "재현: <font face='KRmono'>python verify_mitm.py</font> → "
        "<font face='KRmono'>python make_report_mitm.py</font>. "
        "본 코드·결과는 격리된 로컬 시뮬레이션(mock/SITL의 MAVLink 엔드포인트) 전용이며, "
        "실제 항공기·차량·무선 스펙트럼·네트워크 대상 사용을 금지한다. DAH 2026 방어 전략 검증 목적.",
        SMALL))

    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        title="DAH2026 MITM 인터셉션 검증 리포트", author="DAH 2026")
    doc.build(flow, onLaterPages=_footer, onFirstPage=_footer)
    print(f"[report] 생성 완료 → {OUT}")


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("KR", 7.5)
    canvas.setFillColor(colors.HexColor("#9a9284"))
    canvas.drawString(2 * cm, 1.0 * cm, "DAH 2026 · UAV/UGV 공방 시뮬레이션 · MITM 인터셉션 검증")
    canvas.drawRightString(19 * cm, 1.0 * cm, f"{doc.page}")
    canvas.restoreState()


# ===================== 코드 스니펫(실제 구현 발췌) =====================

CODE_TAMPER = """\
def tamper(self, msg, active_frac):
    # 융합 위치에 오프셋 주입 — 속도(vx,vy)·헤딩은 그대로 → 운동학 불일치
    off = self.drift_m * active_frac
    dn = off * math.cos(math.radians(self.bearing))
    de = off * math.sin(math.radians(self.bearing))
    dlat, dlon = meters_to_latlon(dn, de, msg.lat / 1e7)
    self.tx.mav.global_position_int_send(          # ← 인터셉터의 새 seq로 재방출
        msg.time_boot_ms,
        msg.lat + int(dlat * 1e7), msg.lon + int(dlon * 1e7),
        msg.alt, msg.relative_alt,
        msg.vx, msg.vy, msg.vz, msg.hdg)           # 속도·헤딩 = 원본 유지
    self.tampered += 1

# 릴레이 루프: 수동 도청 구간은 msg.get_msgbuf()를 바이트 그대로 중계(seq 보존).
# 능동 구간의 GLOBAL_POSITION_INT만 tamper()로 재기록한다.
"""

CODE_DETECT = """\
# (1) 운동학 정합성 — 위치 변화량 vs 보고된 속도
if t == "GLOBAL_POSITION_INT":
    lat, lon = msg.lat / 1e7, msg.lon / 1e7
    tb = msg.time_boot_ms / 1000.0
    v = math.hypot(msg.vx, msg.vy) / 100.0            # 보고 속도(m/s)
    if self.last_pos and self.last_t and 0.02 < (tb - self.last_t) < 5.0:
        actual   = haversine_m(*self.last_pos, lat, lon)   # 실제 이동량
        expected = v * (tb - self.last_t)                  # 속도 기대 이동량
        residual = abs(actual - expected)
        if residual >= self.kin_warn_m:                    # 6m↑ High, 25m↑ Critical
            risk = "Critical" if residual >= self.kin_crit_m else "High"
            # → Finding(운동학 정합성 위반, STRIDE-Tampering, 대응 플레이북, 증거)
    self.last_pos, self.last_t = (lat, lon), tb

# (2) 발신원 시퀀스 정합성 — 동일 sysid seq 역행/급점프 = 프레임 주입/재기록
sysid, seq = msg.get_srcSystem(), msg.get_seq()
prev = self.last_seq.get(sysid); self.last_seq[sysid] = seq
if prev is not None:
    delta = (seq - prev) % 256                # 정상 링크 = 1 (유실 시 소폭↑)
    if delta > 128 or self.seq_jump < delta <= 128:   # 역행 또는 급점프
        # 3s 창 내 3회 이상 누적 시 → Finding(발신원 정합성 위반, T0830)
        ...
"""

TOPOLOGY = """\
   mock_vehicle              attacks.mitm_intercept            defense.agent
   (UAV/copter)                 (중간자 MITM)                   (방어 AI)
  telem →udpout:14550  ─▶  udpin:14550  ──(중계/변조)──▶  udpout:14551  ─▶  udpin:14551
                            │ 1단계: 바이트 그대로 중계 + 도청(harvest.json)
                            │ 2단계: GLOBAL_POSITION_INT 좌표 변조(속도 유지)
                            ▼
                       logs_mitm/{capture.jsonl, harvest.json, incidents.jsonl}
"""


if __name__ == "__main__":
    build()
