"""Webhook idempotency and deduplication storage protocols and engines."""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from didit.errors import DiditConfigurationError, DiditDedupError, DiditDedupSaturationError
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

    def release(self, key: str) -> None:
        """Release/delete a claimed key if downstream processing failed."""
        ...


@runtime_checkable
class AsyncWebhookDedupStore(Protocol):
    """Asynchronous interface for webhook deduplication stores."""

    async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Attempt to atomically record and claim key asynchronously.

        Returns:
            True if the key was claimed for the first time (not a duplicate).
            False if the key was already present and not expired (duplicate).
        """
        ...

    async def arelease(self, key: str) -> None:
        """Release/delete a claimed key asynchronously if downstream processing failed."""
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
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        with self._lock:
            now = time.monotonic()
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

    def release(self, key: str) -> None:
        """Release/delete a claimed key (e.g. on downstream processing failure)."""
        with self._lock:
            self._entries.pop(key, None)

    async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Asynchronous claim helper for event-loop compatibility."""
        return self.claim(key, ttl_seconds=ttl_seconds)

    async def arelease(self, key: str) -> None:
        """Asynchronous release helper for event-loop compatibility."""
        self.release(key)


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

    def release(self, key: str) -> None:
        """Release/delete a claimed key in Redis."""
        full_key = f"{self.prefix}{key}"
        try:
            self._client.delete(full_key)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return
            raise DiditDedupError(f"Redis dedup store release failed: {exc}") from exc


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

    async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Atomically claim key in Redis asynchronously with TTL expiration."""
        full_key = f"{self.prefix}{key}"
        try:
            result = await self._client.set(full_key, "1", nx=True, ex=ttl_seconds)
            return bool(result)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return True
            raise DiditDedupError(f"Async Redis dedup store failed: {exc}") from exc

    async def arelease(self, key: str) -> None:
        """Release/delete a claimed key in Redis asynchronously."""
        full_key = f"{self.prefix}{key}"
        try:
            await self._client.delete(full_key)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return
            raise DiditDedupError(f"Async Redis dedup store release failed: {exc}") from exc

    async def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Backward-compatible alias for aclaim."""
        return await self.aclaim(key, ttl_seconds=ttl_seconds)

    async def release(self, key: str) -> None:
        """Backward-compatible alias for arelease."""
        await self.arelease(key)


def compute_dedup_key(payload: WebhookPayload, signature: str | None = None) -> str:
    """Build canonical deduplication key from webhook payload and headers."""
    if payload.event_id:
        return payload.event_id

    status_val = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
    webhook_type = payload.webhook_type or "unknown"
    return f"didit:event:{payload.session_id}:{webhook_type}:{status_val}"


async def aclaim_webhook_event(
    store: WebhookDedupStore | AsyncWebhookDedupStore,
    key: str,
    ttl_seconds: int = 86400,
) -> bool:
    """Safely claim a webhook event across sync and async dedup stores."""
    if hasattr(store, "aclaim") and callable(store.aclaim):
        return bool(await store.aclaim(key, ttl_seconds=ttl_seconds))
    claim_fn = getattr(store, "claim", None)
    if claim_fn is None or not callable(claim_fn):
        raise DiditConfigurationError("Dedup store does not implement claim() or aclaim().")
    if inspect.iscoroutinefunction(claim_fn):
        return bool(await claim_fn(key, ttl_seconds=ttl_seconds))
    return bool(await asyncio.to_thread(claim_fn, key, ttl_seconds))


def release_webhook_event(
    store: WebhookDedupStore | AsyncWebhookDedupStore,
    key: str,
) -> None:
    """Safely release a webhook event reservation synchronously."""
    release_fn = getattr(store, "release", None)
    if (
        release_fn is not None
        and callable(release_fn)
        and not inspect.iscoroutinefunction(release_fn)
    ):
        release_fn(key)


async def arelease_webhook_event(
    store: WebhookDedupStore | AsyncWebhookDedupStore,
    key: str,
) -> None:
    """Safely release a webhook event reservation across sync and async dedup stores."""
    if hasattr(store, "arelease") and callable(store.arelease):
        await store.arelease(key)
        return
    release_fn = getattr(store, "release", None)
    if release_fn is None or not callable(release_fn):
        return
    if inspect.iscoroutinefunction(release_fn):
        await release_fn(key)
    else:
        await asyncio.to_thread(release_fn, key)
