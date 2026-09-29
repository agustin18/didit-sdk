"""Webhook idempotency and deduplication storage protocols and engines."""

from __future__ import annotations

import hashlib
import threading
import time
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from didit.errors import DiditDedupError, DiditDedupSaturationError
from didit.models.webhook import WebhookPayload


class DedupFailureMode(str, Enum):
    """Behavior when a backing deduplication store (e.g. Redis) is unavailable."""

    RAISE = "raise"
    FAIL_OPEN = "fail_open"


@runtime_checkable
class WebhookDedupStore(Protocol):
    """Synchronous interface for webhook deduplication stores."""

    def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Attempt to atomically record and claim key.

        Returns:
            True if the key was claimed for the first time (not a duplicate).
            False if the key was already present and not expired (duplicate).
        """
        ...


@runtime_checkable
class AsyncWebhookDedupStore(Protocol):
    """Asynchronous interface for webhook deduplication stores."""

    async def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Attempt to atomically record and claim key asynchronously.

        Returns:
            True if the key was claimed for the first time (not a duplicate).
            False if the key was already present and not expired (duplicate).
        """
        ...


class InMemoryWebhookDedupStore:
    """Thread-safe in-memory deduplication store with TTL eviction and saturation protection.

    Rejects silent LRU eviction of valid unexpired claims when capacity is exceeded to ensure
    cryptographic and operational replay defense guarantees are never silently compromised.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be greater than or equal to 1")
        self.max_entries = max_entries
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge_expired_locked(self, now: float) -> None:
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Atomically claim key if not already present or if expired."""
        with self._lock:
            now = time.time()
            if key in self._entries and self._entries[key] > now:
                return False

            if len(self._entries) >= self.max_entries:
                self._purge_expired_locked(now)
                if len(self._entries) >= self.max_entries:
                    raise DiditDedupSaturationError(
                        f"InMemoryWebhookDedupStore reached saturation ({self.max_entries}) "
                        f"with valid unexpired claims; refuses silent eviction"
                    )

            self._entries[key] = now + ttl_seconds
            return True

    async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Asynchronous claim helper for event-loop compatibility."""
        return self.claim(key, ttl_seconds=ttl_seconds)


class RedisWebhookDedupStore:
    """Production Redis deduplication store leveraging atomic single-command SET NX EX."""

    def __init__(
        self,
        client: Any,
        prefix: str = "didit:dedup:",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
    ) -> None:
        self._client = client
        self.prefix = prefix
        self.failure_mode = failure_mode

    def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Atomically claim key in Redis with TTL expiration."""
        full_key = f"{self.prefix}{key}"
        try:
            result = self._client.set(full_key, "1", nx=True, ex=ttl_seconds)
            return bool(result)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return True
            raise DiditDedupError(f"Redis dedup store failed: {exc}") from exc


class AsyncRedisWebhookDedupStore:
    """Production async Redis deduplication store leveraging atomic SET NX EX."""

    def __init__(
        self,
        client: Any,
        prefix: str = "didit:dedup:",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
    ) -> None:
        self._client = client
        self.prefix = prefix
        self.failure_mode = failure_mode

    async def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Atomically claim key in Redis asynchronously with TTL expiration."""
        full_key = f"{self.prefix}{key}"
        try:
            result = await self._client.set(full_key, "1", nx=True, ex=ttl_seconds)
            return bool(result)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return True
            raise DiditDedupError(f"Async Redis dedup store failed: {exc}") from exc


def compute_dedup_key(payload: WebhookPayload, signature: str | None = None) -> str:
    """Build canonical deduplication key from webhook payload and headers."""
    if payload.event_id:
        return payload.event_id

    status_val = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
    parts = [payload.session_id, status_val]
    if payload.timestamp is not None:
        parts.append(str(payload.timestamp))
    elif signature:
        parts.append(hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16])
    return ":".join(parts)
