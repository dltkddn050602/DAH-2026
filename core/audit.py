"""Evidence Recorder — 기술스택 문서 §4.2, §5.

모든 이벤트를 append-only JSONL 로 남기고(사람이 읽고 보고서에 인용), episode 단위
집계는 SQLite 로 질의한다. 입력·판단·행동·점수·모델버전을 보존해 재현·설명을 돕는다.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from core.events import (
    AuditEvent, DefenseAction, FindingEvent, ScoreEvent, TelemetryEvent,
)


class EvidenceRecorder:
    def __init__(self, jsonl_path: str, sqlite_path: str) -> None:
        self.jsonl_path = jsonl_path
        Path(jsonl_path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(jsonl_path, "a", encoding="utf-8")
        self.db = sqlite3.connect(sqlite_path)
        self._init_db()

    def _init_db(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                episode_id TEXT, correlation_id TEXT, vehicle TEXT,
                detector TEXT, flow TEXT, risk TEXT, confidence REAL,
                signal TEXT, ts REAL
            );
            CREATE TABLE IF NOT EXISTS actions (
                episode_id TEXT, correlation_id TEXT, vehicle TEXT,
                playbook TEXT, risk TEXT, approval_required INTEGER,
                auto_execute INTEGER, policy_version TEXT, ts REAL
            );
            CREATE TABLE IF NOT EXISTS scores (
                episode_id TEXT, attack REAL, defense REAL,
                availability REAL, ts REAL
            );
            """
        )
        self.db.commit()

    def _write_jsonl(self, obj: dict) -> None:
        self._fh.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        self._fh.flush()

    def record_event(self, event) -> None:
        """모든 이벤트를 JSONL 로. Pydantic 모델은 model_dump 사용."""
        obj = event.model_dump(mode="json") if hasattr(event, "model_dump") else dict(event)
        obj.setdefault("_logged_at", time.time())
        self._write_jsonl(obj)

    def record_finding(self, f: FindingEvent) -> None:
        self.record_event(f)
        flow = f.flow.value if hasattr(f.flow, "value") else str(f.flow)
        risk = f.risk.value if hasattr(f.risk, "value") else str(f.risk)
        self.db.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
            (f.episode_id, f.correlation_id, f.vehicle, f.detector, flow,
             risk, f.confidence, f.signal, f.ts),
        )
        self.db.commit()

    def record_action(self, action: DefenseAction, auto_execute: bool) -> None:
        self.record_event(action)
        risk = action.risk.value if hasattr(action.risk, "value") else str(action.risk)
        self.db.execute(
            "INSERT INTO actions VALUES (?,?,?,?,?,?,?,?,?)",
            (action.episode_id, action.correlation_id, action.vehicle,
             action.playbook, risk, int(action.approval_required),
             int(auto_execute), action.policy_version, time.time()),
        )
        self.db.commit()

    def record_score(self, s: ScoreEvent) -> None:
        self.record_event(s)
        self.db.execute(
            "INSERT INTO scores VALUES (?,?,?,?,?)",
            (s.episode_id, s.attack, s.defense, s.availability, time.time()),
        )
        self.db.commit()

    def close(self) -> None:
        try:
            self._fh.close()
        finally:
            self.db.close()
