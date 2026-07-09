"""asyncio Event Bus — 기술스택 문서 §3, §7.

토픽별 bounded 큐 + backpressure 로 논리 에이전트(asyncio.Task)를 느슨하게 연결한다.
예선 제출 전에는 같은 프로세스의 Task 로 실행하며, 본선에서 broker 전송 계층만
교체할 수 있도록 publish/subscribe 인터페이스만 노출한다.

backpressure 정책:
  - block  : 큐가 가득 차면 생산자가 대기(기본, 손실 없음).
  - drop_new : 가득 차면 새 이벤트를 버린다(실시간 우선, 오래된 것 유지).
  - drop_old : 가득 차면 가장 오래된 것을 버리고 새 것을 넣는다(최신 우선).
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import AsyncIterator

from core.events import AnyEvent


class Subscription:
    """단일 소비자용 bounded 큐 래퍼."""

    def __init__(self, topic: str, maxsize: int, policy: str) -> None:
        self.topic = topic
        self.policy = policy
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    async def put(self, event: AnyEvent) -> None:
        if self.policy == "block":
            await self.queue.put(event)
            return
        if self.queue.full():
            if self.policy == "drop_new":
                self.dropped += 1
                return
            if self.policy == "drop_old":
                try:
                    self.queue.get_nowait()
                    self.dropped += 1
                except asyncio.QueueEmpty:
                    pass
        self.queue.put_nowait(event)

    async def get(self) -> AnyEvent:
        return await self.queue.get()

    async def stream(self) -> AsyncIterator[AnyEvent]:
        while True:
            yield await self.queue.get()


class EventBus:
    """토픽 문자열 기반 pub/sub. 토픽은 이벤트 kind 를 그대로 쓴다.

    예: "telemetry", "finding", "defense_action", "score", "audit".
    """

    def __init__(self, maxsize: int = 1024, policy: str = "block") -> None:
        self._default_maxsize = maxsize
        self._default_policy = policy
        self._subs: dict[str, list[Subscription]] = defaultdict(list)

    def subscribe(
        self, topic: str, maxsize: int | None = None, policy: str | None = None
    ) -> Subscription:
        sub = Subscription(
            topic,
            maxsize or self._default_maxsize,
            policy or self._default_policy,
        )
        self._subs[topic].append(sub)
        return sub

    async def publish(self, event: AnyEvent) -> None:
        """이벤트의 kind 를 토픽으로 사용해 모든 구독자에게 fan-out."""
        topic = getattr(event, "kind", None) or event.__class__.__name__.lower()
        for sub in self._subs.get(topic, ()):
            await sub.put(event)

    def stats(self) -> dict[str, dict[str, int]]:
        return {
            topic: {
                "subscribers": len(subs),
                "dropped": sum(s.dropped for s in subs),
                "pending": sum(s.queue.qsize() for s in subs),
            }
            for topic, subs in self._subs.items()
        }
