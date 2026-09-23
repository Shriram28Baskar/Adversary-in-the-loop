"""Ingest quotas so a flood cannot exhaust the shared database (ARCHITECTURE.md §9).

- ``SessionByteQuota``: bytes staged per Cowrie session. Beyond the limit, a
  session's further events are dropped and counted (reported in heartbeats),
  and one quarantine record marks the session the first time. Content-based,
  so a replay makes the same decisions within one shipper run.
- ``RateLimiter``: records per minute across all sessions. It throttles (waits)
  rather than drops: the source file is the buffer, so nothing is lost.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Literal

__all__ = ["RateLimiter", "SessionByteQuota"]

Admission = Literal["ok", "first_exceeded", "exceeded"]


class SessionByteQuota:
    def __init__(self, limit_bytes: int, max_sessions: int) -> None:
        if limit_bytes <= 0 or max_sessions <= 0:
            raise ValueError("quota limits must be positive")
        self.limit_bytes = limit_bytes
        self.max_sessions = max_sessions
        # session -> (bytes admitted, exceeded); least recently seen evicted first.
        self._sessions: OrderedDict[str, tuple[int, bool]] = OrderedDict()

    def admit(self, session: str, size: int) -> Admission:
        used, exceeded = self._sessions.pop(session, (0, False))
        if len(self._sessions) >= self.max_sessions:
            self._sessions.popitem(last=False)
        if exceeded:
            self._sessions[session] = (used, True)
            return "exceeded"
        if used + size > self.limit_bytes:
            self._sessions[session] = (used, True)
            return "first_exceeded"
        self._sessions[session] = (used + size, False)
        return "ok"


class RateLimiter:
    """Token bucket over records; ``acquire`` blocks until ``count`` tokens exist."""

    def __init__(
        self,
        records_per_minute: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if records_per_minute <= 0:
            raise ValueError("rate must be positive")
        self.capacity = float(records_per_minute)
        self.rate = records_per_minute / 60.0
        self.tokens = self.capacity
        self.clock = clock
        self.sleep = sleep
        self.updated = clock()

    def _refill(self) -> None:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now

    def acquire(self, count: int) -> float:
        """Wait until ``count`` records may be written; return seconds waited."""
        waited = 0.0
        remaining = float(count)
        while remaining > 0:
            self._refill()
            take = min(remaining, self.tokens)
            self.tokens -= take
            remaining -= take
            if remaining > 0:
                delay = min(remaining, self.capacity) / self.rate
                self.sleep(delay)
                waited += delay
        return waited
