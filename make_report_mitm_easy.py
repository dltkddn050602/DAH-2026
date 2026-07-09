#!/usr/bin/env python3
"""
MITM 인터셉션 시나리오 — '쉬운 상세 해설본' PDF 생성기

기존 검증 리포트(make_report_mitm.py)와 동일한 라이브 데이터를 쓰되, 배경지식이 없는
독자도 읽을 수 있도록 (1) 30초 요약, (2) 시스템 구조 그림, (3) 비유 기반 설명,
(4) 용어사전을 추가한 확장판이다.

    python make_report_mitm_easy.py   # → DAH2026_MITM_인터셉션_쉬운상세해설.pdf
"""
from __future__ import annotations

import json
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable, HRFlowable, PageBreak, Paragraph, Preformatted,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)

ROOT = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(ROOT, "logs_mitm")
OUT = os.path.join(ROOT, "DAH2026_MITM_인터셉션_쉬운상세해설.pdf")

NANUM = "/usr/share/fonts/truetype/nanum"
pdfmetrics.registerFont(TTFont("KR", f"{NANUM}/NanumGothic.ttf"))
pdfmetrics.registerFont(TTFont("KR-B", f"{NANUM}/NanumGothicBold.ttf"))
pdfmetrics.registerFont(TTFont("KRmono", f"{NANUM}/NanumGothicCoding.ttf"))

INK = colors.HexColor("#1f2933")
ACCENT = colors.HexColor("#7b1e1e")
BLUE = colors.HexColor("#1e3a5f")
GREEN = colors.HexColor("#1f5136")
LIGHT = colors.HexColor("#f2ede6")
CODEBG = colors.HexColor("#f5f3ef")
CALLBG = colors.HexColor("#fbf3f0")
TIPBG = colors.HexColor("#eef3f0")
GRID = colors.HexColor("#c9c1b6")

styles = getSampleStyleSheet()


def S(name, **kw):
    base = dict(fontName="KR", textColor=INK, leading=15.5, fontSize=9.6)
    base.update(kw)
    return ParagraphStyle(name, **base)


BODY = S("body")
H1 = S("h1", fontName="KR-B", fontSize=18, textColor=ACCENT, leading=22, spaceAfter=4)
H2 = S("h2", fontName="KR-B", fontSize=13, textColor=BLUE, leading=18, spaceBefore=12, spaceAfter=4)
H3 = S("h3", fontName="KR-B", fontSize=10.5, textColor=ACCENT, leading=15, spaceBefore=7, spaceAfter=2)
SMALL = S("small", fontSize=8, textColor=colors.HexColor("#6b6459"), leading=11)
CODE = S("code", fontName="KRmono", fontSize=6.9, leading=8.6, textColor=colors.HexColor("#20303a"))
CELL = S("cell", fontSize=8.6, leading=11.5)
CELLB = S("cellb", fontName="KR-B", fontSize=8.6, leading=11.5, textColor=colors.white)
TAG = S("tag", fontName="KR-B", fontSize=8.6, leading=11.5, textColor=INK)
LEAD = S("lead", fontSize=10.5, leading=17, textColor=INK)


def para(t, s=BODY):
    return Paragraph(t, s)


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


def callout(title, body, bg=CALLBG, edge=ACCENT, tstyle=None):
    inner = [para(title, tstyle or S("cot", fontName="KR-B", fontSize=9.6, textColor=edge, leading=14))]
    if isinstance(body, str):
        inner.append(para(body, BODY))
    else:
        inner.extend(body)
    t = Table([[inner]], colWidths=[17.0 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEABOVE", (0, 0), (-1, 0), 0, bg),
        ("BOX", (0, 0), (-1, -1), 0.6, edge),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


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
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
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
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    if zebra:
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#faf8f5")))
    t.setStyle(TableStyle(style))
    return t


class Pipeline(Flowable):
    """시스템 데이터 경로를 세로 파이프라인으로 그리고, MITM 삽입 지점을 강조한다."""

    def __init__(self, stages, width=17.0 * cm):
        super().__init__()
        self.stages = stages
        self.width = width
        self.box_h = 1.02 * cm
        self.gap = 0.5 * cm
        self.bw = 8.2 * cm

    def wrap(self, aw, ah):
        n = len(self.stages)
        self.height = n * self.box_h + (n - 1) * self.gap
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        x = (self.width - self.bw) / 2.0
        y = self.height - self.box_h
        for i, s in enumerate(self.stages):
            hl = s.get("hl", False)
            bg = colors.HexColor("#f6e4e0") if hl else s.get("bg", LIGHT)
            edge = ACCENT if hl else colors.HexColor("#8b8375")
            c.setFillColor(bg)
            c.setStrokeColor(edge)
            c.setLineWidth(1.4 if hl else 0.7)
            c.roundRect(x, y, self.bw, self.box_h, 5, fill=1, stroke=1)

            label = s["label"]
            sub = s.get("sub")
            c.setFillColor(ACCENT if hl else INK)
            if sub:
                c.setFont("KR-B", 9)
                c.drawCentredString(x + self.bw / 2, y + self.box_h / 2 + 1.5, label)
                c.setFont("KR", 7.2)
                c.setFillColor(colors.HexColor("#6b6459"))
                c.drawCentredString(x + self.bw / 2, y + self.box_h / 2 - 8, sub)
            else:
                c.setFont("KR-B", 9.4)
                c.drawCentredString(x + self.bw / 2, y + self.box_h / 2 - 3, label)

            # 강조 박스 우측 콜아웃
            note = s.get("note")
            if note:
                c.setFillColor(ACCENT)
                c.setFont("KR-B", 8.4)
                c.drawString(x + self.bw + 10, y + self.box_h / 2 - 3, note)

            # 아래로 향하는 화살표
            if i < len(self.stages) - 1:
                cx = x + self.bw / 2
                y_top = y
                y_bot = y - self.gap
                c.setStrokeColor(colors.HexColor("#8b8375"))
                c.setLineWidth(0.9)
                c.line(cx, y_top, cx, y_bot + 3)
                c.setFillColor(colors.HexColor("#8b8375"))
                p = c.beginPath()
                p.moveTo(cx - 3, y_bot + 4)
                p.lineTo(cx + 3, y_bot + 4)
                p.lineTo(cx, y_bot)
                p.close()
                c.drawPath(p, fill=1, stroke=0)
            y -= (self.box_h + self.gap)


# ===================== 본문 =====================

def build():
    summary, harvest, incidents = load()
    h = summary.get("harvest", harvest)
    by_det = summary.get("incident_by_detector", {})
    by_risk = summary.get("incident_by_risk", {})
    total = summary.get("incident_total", len(incidents))

    def g(k, d="—"):
        v = h.get(k, d)
        return d if v is None else v

    F = []

    # ---------- 표지 ----------
    F.append(para("DAH 2026 · UAV/UGV 사이버 공방 시뮬레이션 — 쉬운 상세 해설본", SMALL))
    F.append(para("데이터링크 MITM 인터셉션", H1))
    F.append(para("무인기와 지상통제소 사이의 통신을 '가로채는' 공격 — 쉽게 풀어 쓴 공격 시나리오와 코드 검증", S("subt", fontSize=10.5, textColor=BLUE, leading=15)))
    F.append(Spacer(1, 4))
    F.append(callout("이 문서를 읽는 법", [
        para("사이버보안·드론을 처음 접하는 독자도 읽을 수 있도록 <b>비유와 그림</b>으로 설명하고, "
             "전문 용어는 맨 뒤 <b>용어사전(9장)</b>에 모았습니다. 굵게 표시된 낯선 단어는 용어사전에서 "
             "찾아보세요. 숫자와 코드는 모두 <b>실제로 프로그램을 돌려 나온 결과</b>이며, "
             "명령 한 줄로 재현할 수 있습니다(8장).", BODY),
    ], bg=TIPBG, edge=BLUE))
    F.append(Spacer(1, 6))

    # ---------- 0. 30초 요약 ----------
    F.append(para("0. 30초 요약", H2))
    F.append(callout("한 문단으로", [
        para(f"공격자가 무인기(<b>UAV/UGV</b>)와 지상통제소(<b>GCS</b>) 사이의 통신선"
             f"(<b>전술통신망/데이터링크</b>)에 몰래 끼어들었습니다. 그리고 ① 오가는 데이터를 전부 "
             f"엿보고(<b>도청</b>), ② 무인기의 위치를 가짜로 바꿔 지휘소 화면을 속였습니다(<b>변조</b>). "
             f"이 공격을 실제 코드로 재현했고, 방어 AI가 변조가 시작된 순간 <b>{total}건</b>의 이상을 "
             f"잡아냈습니다(위험도 High {by_risk.get('High','?')} · Critical {by_risk.get('Critical','?')}). "
             f"다만 '엿보기만' 하는 동안은 통신 내용에 아무 흔적이 남지 않아 탐지되지 않습니다 — "
             f"그래서 <b>통신 암호화·발신자 인증</b>이 1차 방어선으로 반드시 필요합니다.", LEAD),
    ]))

    # ---------- 1. 이 시스템은 어떻게 생겼나 ----------
    F.append(para("1. 먼저, 이 시스템은 어떻게 생겼나", H2))
    F.append(para("무인체계는 여러 계층이 사슬처럼 연결됩니다. 위에서 내린 명령이 아래 무인기까지 내려가고, "
                  "무인기가 수집한 정보가 다시 위로 올라와 지휘관의 화면(<b>공통작전상황도, COP</b>)에 그려집니다. "
                  "그 사슬의 한가운데, 통제소와 무인기를 잇는 <b>전술통신망/데이터링크</b> 구간이 이번 공격의 무대입니다.", BODY))
    F.append(Spacer(1, 6))
    F.append(Pipeline([
        {"label": "지휘통제소 / 운용자", "sub": "운용 관점 (OV)"},
        {"label": "C5I 임무통제체계 → UxS 임무관리 서버", "sub": "시스템 관점 (SV)"},
        {"label": "UCS/GCS 무인체계 통제장비", "sub": "지상통제소 — 사람이 무인기를 조종·감시"},
        {"label": "전술통신망 / 데이터링크", "sub": "무선 통신 구간",
         "hl": True, "note": "◀ ★ 여기에 MITM 삽입"},
        {"label": "UAV / UGV 플랫폼", "sub": "실제 무인기(공중/지상)"},
        {"label": "센서·위치 데이터 → 공통작전상황도 (COP)", "sub": "무인기가 올린 정보가 지휘관 화면에 표시"},
    ]))
    F.append(Spacer(1, 4))
    F.append(para("• <b>아래로(명령):</b> 지휘통제소 → C5I → GCS → 데이터링크 → 무인기. \"어디로 가라\" 같은 임무명령·경로.<br/>"
                  "• <b>위로(보고, 텔레메트리):</b> 무인기 → 데이터링크 → GCS → COP. 위치·속도·배터리·영상·센서 정보.<br/>"
                  "이번 공격은 주로 <b>위로 올라오는 보고(텔레메트리)</b>를 노립니다. 지휘관이 보는 무인기 위치를 "
                  "가짜로 만들면 상황 판단 전체가 오염되기 때문입니다.", BODY))

    F.append(PageBreak())

    # ---------- 2. MITM이란 ----------
    F.append(para("2. MITM(중간자) 공격이란 — 우체부 비유", H2))
    F.append(callout("쉬운 비유", [
        para("편지를 배달하는 우체부가 사실은 스파이라고 상상해 보세요.", BODY),
        para("<b>1단계(도청):</b> 우체부가 편지를 몰래 뜯어 읽고, 내용을 수첩에 베낀 뒤, 감쪽같이 다시 봉해 배달합니다. "
             "받는 사람은 누가 읽었는지 <b>전혀 눈치채지 못합니다</b>. 편지 자체는 바뀐 게 없으니까요.", BODY),
        para("<b>2단계(변조):</b> 어느 날 우체부가 편지 내용을 <b>살짝 바꿔치기</b>합니다. \"3시에 만나자\"를 "
             "\"5시에 만나자\"로 고쳐 다시 봉합니다. 이제부터는 이야기가 어긋나기 시작하고, 주의 깊은 사람은 "
             "\"뭔가 이상하다\"고 느낍니다.", BODY),
        para("네트워크에서 이 스파이 우체부가 바로 <b>MITM(Man/Adversary-in-the-Middle, 중간자)</b>입니다. "
             "무인기와 통제소 사이 통신선에 끼어들어 데이터를 엿보고(도청) 바꿔치기(변조)합니다.", BODY),
    ], bg=TIPBG, edge=BLUE))
    F.append(Spacer(1, 5))
    F.append(para("왜 위험한가? 무인기 통신에 쓰이는 <b>MAVLink</b> 같은 프로토콜은 원래 무결성·발신자 인증이 약합니다. "
                  "즉 \"이 메시지를 정말 무인기가 보냈는지\"를 검증하는 장치가 기본적으로 없어서, 중간에 낀 공격자가 "
                  "메시지를 읽고 위조하기 쉽습니다. 이번 시뮬레이션은 이 현실을 프로토콜 수준에서 정직하게 재현합니다.", BODY))

    # ---------- 3. 공격 시나리오 ----------
    F.append(para("3. 공격은 이렇게 진행된다 (단계별)", H2))
    F.append(para("3.1 ① 수동 도청 — 아무 흔적 없이 임무 전체를 엿본다", H3))
    F.append(para("공격자는 처음엔 아무것도 바꾸지 않습니다. 지나가는 모든 메시지를 <b>그대로 전달</b>하면서 몰래 "
                  "복사만 합니다. 이것만으로도 무인기의 운용 상황을 통째로 재구성할 수 있습니다. 실제로 인터셉터가 "
                  "링크 암호화 없이 아래 정보를 복원했습니다:", BODY))
    F.append(Spacer(1, 3))
    mc = g("msg_counts", {})
    mc_str = ", ".join(f"{k}:{v}" for k, v in mc.items()) if isinstance(mc, dict) else str(mc)
    F.append(kv_table([
        ("무인기 정체", f"시스템ID={g('sysid')} · 종류=멀티로터(UAV) · 무장상태={'무장(ARMED)' if g('armed') else '해제'}"),
        ("비행 모드", f"{g('mode')} (자동 임무비행 중)"),
        ("배터리 잔량", f"{g('battery_pct')}%"),
        ("이륙 지점(홈)", f"{g('home')}  ← 부대/발진 위치가 노출됨"),
        ("현재 위치", f"{g('last_pos')}"),
        ("비행 궤적", f"{g('track_points', len(harvest.get('track', [])))}개 지점 — 어디를 어떻게 도는지 전부 파악"),
        ("엿본 메시지", f"{g('frames_relayed')}개 프레임 ({mc_str})"),
    ]))
    F.append(Spacer(1, 4))
    F.append(callout("여기서 핵심", [
        para("이 단계에서 방어 시스템은 <b>아무것도 탐지하지 못합니다</b>. 데이터를 바꾸지 않았으니 통신 내용상 "
             "이상 징후가 전혀 없기 때문입니다. 도청은 본질적으로 <b>은밀</b>합니다. 그래서 '내용을 감시'하는 "
             "이상탐지가 아니라, 애초에 '엿볼 수 없게' 하는 <b>암호화</b>와 '가짜를 못 만들게' 하는 "
             "<b>발신자 인증</b>이 먼저 있어야 합니다.", BODY),
    ]))
    F.append(Spacer(1, 5))
    F.append(para("3.2 ② 능동 변조 — 지휘소 화면을 속이는 순간, 꼬리가 잡힌다", H3))
    F.append(para("공격자가 상황을 유리하게 틀려고 무인기의 <b>위치 보고를 가짜로 바꾸기</b> 시작합니다. 구체적으로 "
                  "무인기가 \"내 융합 위치는 여기\"라고 보고하는 메시지(<b>GLOBAL_POSITION_INT</b>)의 좌표에만 "
                  "점점 커지는 오차(최대 120m)를 더합니다. 그런데 공격자는 편의상 <b>속도 값은 건드리지 않습니다</b>. "
                  "바로 이 부주의가 세 가지 모순을 만들어 냅니다.", BODY))

    F.append(PageBreak())

    # ---------- 4. 왜 들켰나 ----------
    F.append(para("4. 방어 AI는 어떻게 알아챘나 — 3가지 단서", H2))
    F.append(para("변조가 시작되자 방어 에이전트는 서로 <b>독립된 3가지 이상 신호</b>를 동시에 포착했습니다. "
                  "하나만으로도 의심스럽지만, 셋이 함께 어긋나면 거의 확실합니다. 각 단서를 비유로 설명합니다.", BODY))
    F.append(Spacer(1, 4))

    F.append(callout("단서 1 · 속도와 위치가 모순된다 (운동학 정합성)", [
        para("무인기가 \"나는 초속 12m(시속 약 43km)로 간다\"고 스스로 보고합니다. 그렇다면 0.25초 동안 갈 수 있는 "
             "거리는 3m 정도입니다. 그런데 지도상 위치는 한 프레임 만에 <b>15m</b>나 움직였습니다. "
             "속도계는 천천히 간다는데 지도 위 점은 순간이동한 셈이죠 — 물리적으로 불가능합니다.", BODY),
        para("방어는 '실제로 움직인 거리'와 '보고한 속도로 갈 수 있는 거리'의 차이(<b>잔차</b>)를 계산합니다. "
             "정상 통신에서는 이 값이 0에 가깝지만(약 0.1m), 변조 순간 <b>11.9m</b>까지 벌어져 탐지됐습니다. "
             "공격자가 위치만 밀고 속도를 그대로 둔 대가입니다.", BODY),
    ]))
    F.append(Spacer(1, 4))
    F.append(callout("단서 2 · 송장번호가 뒤죽박죽 (발신원 시퀀스)", [
        para("모든 MAVLink 메시지에는 택배 송장번호 같은 <b>시퀀스 번호(seq)</b>가 붙어, 보낼 때마다 1씩 늘어납니다. "
             "진짜 무인기가 보낸 번호는 …, 100, 101, 102… 처럼 이어집니다. 그런데 공격자가 위조 메시지를 "
             "<b>자기 번호</b>로 새로 포장해 끼워넣자, 방어가 받는 번호가 갑자기 <b>169만큼 건너뛰거나 거꾸로</b> "
             "가기 시작했습니다.", BODY),
        para("한 명(같은 시스템ID)이 보낸다는데 번호 흐름이 두 갈래로 튄다 — 이는 \"원래 보낸 사람이 아닌 다른 손이 "
             "소포를 새로 포장해 끼워넣었다\"는 강한 증거입니다. 방어는 이 불연속을 <b>프레임 주입/재기록</b>으로 "
             "판정했습니다.", BODY),
    ]))
    F.append(Spacer(1, 4))
    F.append(callout("단서 3 · 두 개의 위치가 서로 다른 말을 한다 (GNSS-INS 교차검증)", [
        para("무인기는 자기 위치를 두 가지로 압니다: 위성 신호로 아는 <b>원시 GPS</b>와, 자기 움직임을 계산해 아는 "
             "<b>관성항법(INS)</b>을 합친 융합 위치. 평소엔 둘이 같은 곳을 가리킵니다. 공격자가 융합 위치만 위조하니 "
             "둘이 어긋나기 시작했고, 그 차이가 <b>41m·53m</b>까지 벌어졌습니다. 둘이 이렇게 다르면 하나는 거짓말입니다.", BODY),
        para("이 검증기(GnssInsCrossCheck)는 원래 GPS 스푸핑을 잡으려고 만든 것인데, MITM 위치 변조도 똑같이 잡아냈습니다. "
             "서로 다른 목적의 검증기들이 <b>같은 사건을 교차 확인</b>해 준 셈이라 신뢰도가 높습니다.", BODY),
    ]))

    F.append(PageBreak())

    # ---------- 5. 코드로 검증 ----------
    F.append(para("5. 말이 아니라 코드로 — 어떻게 검증했나", H2))
    F.append(para("실제 <b>MAVLink UDP 트래픽</b>을 흘려보내는 폐루프를 구성했습니다. 가짜 무인기(mock)가 텔레메트리를 "
                  "쏘면, 그 사이에 낀 MITM 인터셉터가 도청/변조한 뒤 방어 에이전트로 넘깁니다. 방어는 탐지 결과를 "
                  "증거 파일로 남깁니다.", BODY))
    F.append(Spacer(1, 3))
    F.append(code_block(TOPOLOGY))
    F.append(Spacer(1, 4))
    F.append(para("5.1 공격 코드의 핵심 — 위치만 바꾸고 속도는 남겨둔다", H3))
    F.append(para("아래가 '단서 1'을 만든 바로 그 대목입니다. 좌표(lat, lon)에는 오프셋을 더하지만 속도(vx, vy)와 "
                  "헤딩은 원본 그대로 내보냅니다.", SMALL))
    F.append(code_block(CODE_TAMPER))
    F.append(Spacer(1, 4))
    F.append(para("5.2 방어 코드의 핵심 — 두 가지 모순을 계산한다", H3))
    F.append(para("'실제 이동거리 vs 속도 기대거리'(운동학)와 '시퀀스 번호 연속성'(발신원)을 검사합니다.", SMALL))
    F.append(code_block(CODE_DETECT))

    F.append(PageBreak())

    # ---------- 6. 결과 ----------
    F.append(para("6. 실행 결과 한눈에", H2))
    F.append(para(f"수동 도청 구간(처음 6초)에는 프레임이 참값 그대로여서 <b>탐지 0건(은밀)</b>. 능동 변조로 전환된 "
                  f"직후 총 <b>{total}건</b>의 인시던트가 탐지됐습니다. 각 인시던트에는 위협모델 매핑·대응 방안·증거가 "
                  f"자동으로 붙어 <b>logs_mitm/incidents.jsonl</b>에 저장됩니다.", BODY))
    F.append(Spacer(1, 4))
    det_label = {
        "MITM 인터셉션 감시": ("운동학 모순 + 시퀀스 불연속", "단서 1·2"),
        "GNSS-INS 교차검증": ("두 위치원이 어긋남", "단서 3"),
        "링크 상태 감시": ("통신 끊김/지연", "—"),
        "명령 이상 감시": ("명령 빈도/모드 급변", "—"),
    }
    det_rows = []
    for det, n in by_det.items():
        sig, clue = det_label.get(det, ("—", "—"))
        det_rows.append([det, str(n), sig, clue])
    F.append(header_table(["탐지기", "건수", "무엇을 보고 잡았나", "본문 단서"],
                          det_rows, widths=[4.0, 1.3, 6.6, 5.1]))
    F.append(Spacer(1, 4))
    risk_rows = [[("🔴 Critical(즉시 승인 대응)" if k == "Critical"
                   else "🟠 High(운용자 승인)" if k == "High"
                   else k), str(v)]
                 for k, v in sorted(by_risk.items(),
                                    key=lambda x: {"Critical": 0, "High": 1, "Medium": 2}.get(x[0], 9))]
    F.append(para("위험도 분포 — High 이상은 사람이 최종 승인하는 <b>human-in-the-loop</b> 게이트로 넘어갑니다.", SMALL))
    F.append(header_table(["위험도", "건수"], risk_rows, widths=[6.0, 2.0], head_bg=ACCENT, zebra=False))
    F.append(Spacer(1, 5))
    samples = summary.get("samples", incidents[:5])
    ev_rows = []
    for r in samples[:5]:
        ev = r.get("evidence", {})
        ev_str = ", ".join(f"{k}={v}" for k, v in ev.items())
        sig = r.get("signal", "")
        ev_rows.append([r.get("detector", "—"), r.get("risk", "—"),
                        sig[:50] + ("…" if len(sig) > 50 else ""), ev_str[:38]])
    if ev_rows:
        F.append(para("실제로 저장된 대표 인시던트(증거 JSON)", SMALL))
        F.append(header_table(["탐지기", "위험", "탐지 징후", "증거"], ev_rows,
                              widths=[3.2, 1.3, 6.6, 5.9]))

    # ---------- 7. 대응 ----------
    F.append(para("7. 그래서 어떻게 막나 — 대응 플레이북", H2))
    F.append(callout("교훈 세 가지", [
        para("① <b>도청은 은밀하다.</b> 내용을 감시하는 이상탐지만으로는 못 잡습니다. "
             "<b>통신 암호화 + 발신자 인증(서명)</b>이 1차 방어선, 이상탐지는 공격자가 변조하는 순간을 잡는 2차 방어선입니다.", BODY),
        para("② <b>변조는 교차검증으로 드러난다.</b> 공격자가 위치만 밀고 속도를 그대로 두는 순간 "
             "세 신호(운동학·시퀀스·GNSS-INS)가 동시에 어긋납니다. 여러 신호의 합의가 오탐을 줄이고 확신을 높입니다.", BODY),
        para("③ <b>사람이 최종 확인한다.</b> High 이상 위협은 자동으로 조치하지 않고 운용자 승인을 요구합니다. "
             "AI는 탐지·분석·권고까지, 치명적 결정은 사람이.", BODY),
    ], bg=TIPBG, edge=GREEN, tstyle=S("cog", fontName="KR-B", fontSize=9.6, textColor=GREEN, leading=14)))
    F.append(Spacer(1, 5))
    F.append(para("실제 대응 순서(권고): 링크 무결성(서명/시퀀스) 검증 → 텔레메트리 발신원 재인증 → 융합위치 신뢰도 하향·"
                  "원시GPS/INS 교차검증 → 링크 암호화·경로 무결성 점검 → 필요 시 링크 전환. "
                  "운동학 잔차 6~25m·시퀀스 불연속은 High, 잔차 25m 이상은 Critical로 분류됩니다.", BODY))

    # ---------- 8. 재현 ----------
    F.append(para("8. 직접 재현하는 법", H2))
    F.append(code_block(REPRO))
    F.append(para("첫 명령이 공격·방어를 폐루프로 실행해 증거(logs_mitm/)를 남기고, 둘째 명령이 이 PDF를 다시 만듭니다.", SMALL))

    F.append(PageBreak())

    # ---------- 9. 용어사전 ----------
    F.append(para("9. 용어사전", H2))
    F.append(para("본문에 굵게 표시된 용어를 쉬운 말로 풀었습니다.", SMALL))
    F.append(Spacer(1, 3))
    F.append(header_table(["용어", "쉬운 설명"], GLOSSARY, widths=[4.3, 12.7]))

    F.append(Spacer(1, 8))
    F.append(HRFlowable(width="100%", thickness=0.6, color=GRID))
    F.append(para("본 코드·결과는 격리된 로컬 시뮬레이션(mock/SITL의 MAVLink 엔드포인트) 전용이며, 실제 항공기·차량·"
                  "무선 스펙트럼·네트워크 대상 사용을 금지합니다. DAH 2026 방어 전략 검증 목적으로 작성되었습니다.", SMALL))

    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        title="DAH2026 MITM 인터셉션 쉬운 상세 해설", author="DAH 2026")
    doc.build(F, onFirstPage=_footer, onLaterPages=_footer)
    print(f"[report] 생성 완료 → {OUT}")


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("KR", 7.5)
    canvas.setFillColor(colors.HexColor("#9a9284"))
    canvas.drawString(2 * cm, 1.0 * cm, "DAH 2026 · MITM 인터셉션 · 쉬운 상세 해설본")
    canvas.drawRightString(19 * cm, 1.0 * cm, f"{doc.page}")
    canvas.restoreState()


# ===================== 코드/텍스트 스니펫 =====================

CODE_TAMPER = """\
def tamper(self, msg, active_frac):
    # 융합 위치(lat,lon)에만 오프셋을 더하고 속도(vx,vy)·헤딩은 원본 유지
    off = self.drift_m * active_frac                  # 시간에 따라 0→120m 로 증가
    dn = off * math.cos(math.radians(self.bearing))
    de = off * math.sin(math.radians(self.bearing))
    dlat, dlon = meters_to_latlon(dn, de, msg.lat / 1e7)
    self.tx.mav.global_position_int_send(             # ← 인터셉터의 새 seq로 재방출
        msg.time_boot_ms,
        msg.lat + int(dlat * 1e7), msg.lon + int(dlon * 1e7),   # 위치 = 위조
        msg.alt, msg.relative_alt,
        msg.vx, msg.vy, msg.vz, msg.hdg)              # 속도·헤딩 = 그대로 → 모순 발생
    self.tampered += 1
"""

CODE_DETECT = """\
# 단서 1) 운동학: 실제 이동거리 vs 보고한 속도로 갈 수 있는 거리
if t == "GLOBAL_POSITION_INT":
    v = math.hypot(msg.vx, msg.vy) / 100.0            # 보고 속도(m/s)
    actual   = haversine_m(*self.last_pos, lat, lon)  # 실제로 움직인 거리
    expected = v * (tb - self.last_t)                 # 속도로 갈 수 있는 거리
    residual = abs(actual - expected)                 # 둘의 차이(잔차)
    if residual >= self.kin_warn_m:                   # 6m↑ High, 25m↑ Critical
        # → "위치 위조 주입" 경보 발생 (증거: 실제/기대/잔차 기록)

# 단서 2) 발신원 시퀀스: 같은 시스템ID의 seq가 1씩 늘어야 정상
delta = (seq - prev) % 256                            # 정상=1, 유실 시 소폭↑
if delta > 128 or self.seq_jump < delta <= 128:       # 역행 또는 급점프
    # → 3초 내 3회 이상 누적되면 "프레임 주입/재기록" 경보 발생
"""

TOPOLOGY = """\
   가짜 무인기(mock)          MITM 인터셉터              방어 AI 에이전트
   telem →udpout:14550  ─▶  udpin:14550 ─(중계/변조)─▶ udpout:14551 ─▶ udpin:14551
                            │ 1단계: 그대로 중계 + 몰래 복사(도청)  → harvest.json
                            │ 2단계: 위치 보고만 위조(속도는 유지)
                            ▼
                       logs_mitm/{capture.jsonl, harvest.json, incidents.jsonl}
"""

REPRO = """\
# 1) 공격+방어 폐루프 실행 (16초, 실제 MAVLink UDP 트래픽)
python verify_mitm.py

# 2) 위 결과로 이 해설 PDF 다시 만들기
python make_report_mitm_easy.py
"""

GLOSSARY = [
    ["UxS / UAV / UGV", "무인체계(Unmanned System)의 통칭. UAV=무인항공기(드론), UGV=무인지상차량."],
    ["GCS / UCS", "지상통제소. 사람이 무인기를 조종·감시하는 컴퓨터·장비."],
    ["C5I / COP", "C5I=지휘통제 상위 체계. COP=공통작전상황도, 모두가 보는 통합 상황 지도."],
    ["전술통신망/데이터링크", "무인기와 통제소를 잇는 무선 통신 구간. 이번 공격의 무대."],
    ["MAVLink", "드론·무인기가 널리 쓰는 통신 규약(메시지 형식). 기본적으로 암호화·인증이 약함."],
    ["텔레메트리", "무인기가 실시간으로 올려보내는 상태 보고(위치·속도·배터리 등)."],
    ["MITM (중간자)", "통신 경로 중간에 몰래 끼어들어 데이터를 엿보거나 바꾸는 공격자."],
    ["도청 / 변조", "도청=내용을 몰래 훔쳐봄(기밀성 침해). 변조=내용을 바꿔치기함(무결성 침해)."],
    ["GNSS / GPS", "위성 항법 시스템. 위성 신호로 현재 위치를 알아냄."],
    ["INS / EKF", "관성항법. 센서로 자기 움직임을 계산해 위치를 추정. EKF는 GPS+INS를 합치는 필터."],
    ["시퀀스 번호(seq)", "메시지마다 붙는 일련번호. 보낼 때마다 1씩 증가 — 택배 송장번호 같은 것."],
    ["시스템ID(sysid)", "각 무인기의 고유 번호. 누가 보낸 메시지인지 식별."],
    ["잔차(residual)", "여기서는 '실제 이동거리 − 속도 기대거리'의 차이. 크면 위치가 조작됐다는 신호."],
    ["STRIDE / TARA", "위협을 분류하는 보안 분석 틀. STRIDE=위협 유형, TARA=위험 평가."],
    ["MITRE ATT&CK ICS", "산업제어시스템 공격 기법 지식베이스. T0830=중간자 공격."],
    ["human-in-the-loop", "AI가 자동으로 끝내지 않고, 위험한 조치는 사람이 최종 승인하게 하는 방식."],
]


if __name__ == "__main__":
    build()
