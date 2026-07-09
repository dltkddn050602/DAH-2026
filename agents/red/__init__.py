"""Red(공격) AI 에이전트 — 관측→판단(LinUCB)→행동→평가 폐루프.

기술스택 문서 §4.1 의 Red Agent 설계를 실행 가능한 코드로 구현한 것.
Blue 에이전트와 대칭 구조(Observer/Planner/Gate/Executor/Evaluator)이며, 공통 이벤트
버스를 통해 상대의 탐지·대응·점수를 관측한다.
"""
from agents.red.agent import OutcomeEvaluator, RedAgent
from agents.red.executor import ExecResult, ToolExecutor
from agents.red.observer import BattleContext, BattleObserver, WindowStats
from agents.red.planner import (Arm, BaselinePlanner, LinUCBPlanner, Selection,
                                build_arms, make_planner)
from agents.red.policy_gate import AttackGateDecision, AttackPolicyGate

__all__ = [
    "RedAgent", "OutcomeEvaluator",
    "BattleObserver", "BattleContext", "WindowStats",
    "LinUCBPlanner", "BaselinePlanner", "Selection", "Arm",
    "build_arms", "make_planner",
    "AttackPolicyGate", "AttackGateDecision",
    "ToolExecutor", "ExecResult",
]
