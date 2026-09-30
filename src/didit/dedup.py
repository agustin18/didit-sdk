"""Webhook idempotency and deduplication storage protocols and engines."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast, runtime_checkable

from didit.errors import DiditConfigurationError, DiditDedupError, DiditDedupSaturationError
from didit.models.webhook import WebhookPayload


class DedupFailureMode(str, Enum):
    """Behavior when a backing deduplication store (e.g. Redis) is unavailable."""

    RAISE = "raise"
    FAIL_OPEN = "fail_open"


class ReservationState(str, Enum):
    """Lifecycle state of a webhook event reservation."""

    ACQUIRED = "acquired"
    PROCESSING = "processing"
    COMPLETED = "completed"


@dataclass(frozen=True)
class WebhookReservation:
    """Active lease token proving ownership of an in-flight webhook execution."""

    event_id: str
    token: str
    expires_at: float  # monotonic timestamp in seconds


@dataclass(frozen=True)
class ReservationAttempt:
    """Outcome of attempting to reserve a webhook event."""

    state: ReservationState
    reservation: WebhookReservation | None = None
    degraded: bool = False


@runtime_checkable
class WebhookDedupStore(Protocol):
    """Synchronous interface for legacy webhook deduplication stores."""

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
    """Asynchronous interface for legacy webhook deduplication stores."""

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


@runtime_checkable
class WebhookReservationStore(Protocol):
    """Synchronous interface for crash-recoverable tokenized webhook reservations."""

    def reserve(
        self, event_id: str, token: str | None = None, ttl_seconds: int = 30
    ) -> ReservationAttempt:
        """Attempt to acquire an in-flight processing lease for an event."""
        ...

    def complete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
        """Transition an in-flight reservation to COMPLETED state idempotently."""
        ...

    def release(self, event_id: str, token: str) -> bool:
        """Release an in-flight reservation if processing failed and token matches."""
        ...

    def renew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
        """Extend lease TTL if token matches in-flight reservation."""
        ...


@runtime_checkable
class AsyncWebhookReservationStore(Protocol):
    """Asynchronous interface for crash-recoverable tokenized webhook reservations."""

    async def areserve(
        self, event_id: str, token: str | None = None, ttl_seconds: int = 30
    ) -> ReservationAttempt:
        """Attempt to acquire an in-flight processing lease asynchronously."""
        ...

    async def acomplete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
        """Transition an in-flight reservation to COMPLETED state asynchronously."""
        ...

    async def arelease(self, event_id: str, token: str) -> bool:
        """Release an in-flight reservation asynchronously if processing failed."""
        ...

    async def arenew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
        """Extend lease TTL asynchronously if token matches in-flight reservation."""
        ...


def build_reservation_key(event_id: str, namespace: str = "default") -> str:
    """Build standard distributed Redis key with sha256 digest and no fixed cluster hashtag."""
    if "{" in namespace or "}" in namespace:
        raise ValueError(
            "namespace cannot contain '{' or '}' as they alter Redis Cluster slot hashing"
        )
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    return f"didit:webhook:{namespace}:{digest}"


# Atomic Lua CAS scripts for RedisWebhookReservationStore
LUA_RESERVE = """
local current = redis.call('GET', KEYS[1])
if not current then
    redis.call('SET', KEYS[1], 'PROCESSING:' .. ARGV[1], 'EX', ARGV[2])
    return 'ACQUIRED'
elseif current == ('PROCESSING:' .. ARGV[1]) then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
    return 'ACQUIRED'
elseif current == 'COMPLETED' then
    return 'COMPLETED'
else
    return 'PROCESSING'
end
"""

LUA_COMPLETE = """
local current = redis.call('GET', KEYS[1])
if current == ('PROCESSING:' .. ARGV[1]) then
    redis.call('SET', KEYS[1], 'COMPLETED', 'EX', ARGV[2])
    return 1
elseif current == 'COMPLETED' then
    return 1
else
    return 0
end
"""

LUA_RELEASE = """
local current = redis.call('GET', KEYS[1])
if current == ('PROCESSING:' .. ARGV[1]) then
    return redis.call('DEL', KEYS[1])
else
    return 0
end
"""

LUA_RENEW = """
local current = redis.call('GET', KEYS[1])
if current == ('PROCESSING:' .. ARGV[1]) then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
else
    return 0
end
"""


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


class InMemoryWebhookReservationStore:
    """Thread-safe in-memory reservation store with crash-recoverable lease lifecycle.

    Maintains identical state machine to RedisWebhookReservationStore:
    ABSENT -> reserve() -> PROCESSING:<token> -> complete() -> COMPLETED.
    Rejects silent eviction upon saturation and uses monotonic clock for lease expiration.
    """

    def __init__(self, max_entries: int = 10_000, namespace: str = "default") -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be greater than or equal to 1")
        self.max_entries = max_entries
        self.namespace = namespace
        # key -> (state, token, expires_at)
        self._entries: dict[str, tuple[ReservationState, str, float]] = {}
        self._lock = threading.Lock()

    def _purge_expired_locked(self, now: float) -> None:
        expired = [key for key, (_, _, expiry) in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def reserve(
        self, event_id: str, token: str | None = None, ttl_seconds: int = 30
    ) -> ReservationAttempt:
        """Attempt to acquire a processing lease for an event."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        tok = token or secrets.token_urlsafe(16)
        key = build_reservation_key(event_id, namespace=self.namespace)
        with self._lock:
            now = time.monotonic()
            entry = self._entries.get(key)
            if entry is not None and entry[2] <= now:
                del self._entries[key]
                entry = None

            if entry is None:
                if len(self._entries) >= self.max_entries:
                    self._purge_expired_locked(now)
                    if len(self._entries) >= self.max_entries:
                        raise DiditDedupSaturationError(
                            f"InMemoryWebhookReservationStore reached saturation "
                            f"({self.max_entries}) with valid unexpired leases; "
                            "refuses silent eviction"
                        )
                expires_at = now + ttl_seconds
                self._entries[key] = (ReservationState.PROCESSING, tok, expires_at)
                return ReservationAttempt(
                    state=ReservationState.ACQUIRED,
                    reservation=WebhookReservation(
                        event_id=event_id, token=tok, expires_at=expires_at
                    ),
                )

            curr_state, curr_tok, curr_expiry = entry
            if curr_state == ReservationState.PROCESSING:
                if curr_tok == tok:
                    new_expiry = now + ttl_seconds
                    self._entries[key] = (ReservationState.PROCESSING, tok, new_expiry)
                    return ReservationAttempt(
                        state=ReservationState.ACQUIRED,
                        reservation=WebhookReservation(
                            event_id=event_id, token=tok, expires_at=new_expiry
                        ),
                    )
                return ReservationAttempt(state=ReservationState.PROCESSING)

            return ReservationAttempt(state=ReservationState.COMPLETED)

    def complete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
        """Transition an in-flight reservation to COMPLETED state idempotently."""
        if completed_ttl <= 0:
            raise ValueError("completed_ttl must be greater than zero")
        key = build_reservation_key(event_id, namespace=self.namespace)
        with self._lock:
            now = time.monotonic()
            entry = self._entries.get(key)
            if entry is not None and entry[2] <= now:
                del self._entries[key]
                entry = None

            if entry is None:
                return False

            curr_state, curr_tok, _ = entry
            if curr_state == ReservationState.PROCESSING and curr_tok == token:
                self._entries[key] = (ReservationState.COMPLETED, "", now + completed_ttl)
                return True
            return curr_state == ReservationState.COMPLETED

    def release(self, event_id: str, token: str) -> bool:
        """Release an in-flight reservation if processing failed and token matches."""
        key = build_reservation_key(event_id, namespace=self.namespace)
        with self._lock:
            now = time.monotonic()
            entry = self._entries.get(key)
            if entry is None:
                return False

            if entry[2] <= now:
                del self._entries[key]
                return False

            curr_state, curr_tok, _ = entry
            if curr_state == ReservationState.PROCESSING and curr_tok == token:
                del self._entries[key]
                return True
            return False

    def renew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
        """Extend lease TTL if token matches in-flight reservation."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        key = build_reservation_key(event_id, namespace=self.namespace)
        with self._lock:
            now = time.monotonic()
            entry = self._entries.get(key)
            if entry is None:
                return False

            if entry[2] <= now:
                del self._entries[key]
                return False

            curr_state, curr_tok, _ = entry
            if curr_state == ReservationState.PROCESSING and curr_tok == token:
                self._entries[key] = (ReservationState.PROCESSING, token, now + ttl_seconds)
                return True
            return False

    # Backward compatibility with WebhookDedupStore
    def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Backward-compatible claim using default lease acquisition."""
        attempt = self.reserve(key, ttl_seconds=ttl_seconds)
        return attempt.state == ReservationState.ACQUIRED

    def release_claim(self, key: str) -> None:
        """Backward-compatible best-effort release."""
        full_key = build_reservation_key(key, namespace=self.namespace)
        with self._lock:
            self._entries.pop(full_key, None)

    async def arelease_claim(self, key: str) -> None:
        """Backward-compatible best-effort release asynchronously."""
        self.release_claim(key)

    # Async helpers for event-loop compatibility
    async def areserve(
        self, event_id: str, token: str | None = None, ttl_seconds: int = 30
    ) -> ReservationAttempt:
        """Asynchronously attempt to acquire a processing lease."""
        return self.reserve(event_id, token=token, ttl_seconds=ttl_seconds)

    async def acomplete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
        """Asynchronously transition an in-flight reservation to COMPLETED state."""
        return self.complete(event_id, token, completed_ttl=completed_ttl)

    async def arelease(self, event_id: str, token: str) -> bool:
        """Asynchronously release an in-flight reservation."""
        return self.release(event_id, token)

    async def arenew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
        """Asynchronously extend lease TTL."""
        return self.renew(event_id, token, ttl_seconds=ttl_seconds)

    async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Asynchronously claim key."""
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

    @classmethod
    def from_url(
        cls,
        url: str,
        prefix: str = "didit:dedup:",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
        **kwargs: Any,
    ) -> RedisWebhookDedupStore:
        """Create a RedisWebhookDedupStore from a Redis connection URL."""
        import redis

        client = redis.Redis.from_url(url, **kwargs)
        return cls(client=client, prefix=prefix, failure_mode=failure_mode)

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

    @classmethod
    def from_url(
        cls,
        url: str,
        prefix: str = "didit:dedup:",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
        **kwargs: Any,
    ) -> AsyncRedisWebhookDedupStore:
        """Create an AsyncRedisWebhookDedupStore from a Redis connection URL."""
        import redis.asyncio as aioredis

        client = aioredis.Redis.from_url(url, **kwargs)
        return cls(client=client, prefix=prefix, failure_mode=failure_mode)

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


class RedisWebhookReservationStore:
    """Production Redis reservation store leveraging atomic Lua CAS scripts.

    Distributes leases across Redis Cluster shards via standard non-hashtag keys:
    `didit:webhook:<namespace>:<sha256(event_id)>`.
    """

    def __init__(
        self,
        client: Any,
        namespace: str = "default",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
    ) -> None:
        self._client = client
        self.namespace = namespace
        self.failure_mode = failure_mode

    @classmethod
    def from_url(
        cls,
        url: str,
        namespace: str = "default",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
        **kwargs: Any,
    ) -> RedisWebhookReservationStore:
        """Create a RedisWebhookReservationStore from a Redis connection URL."""
        try:
            import redis
        except (ImportError, ModuleNotFoundError) as err:
            raise DiditConfigurationError(
                "redis-py is required to use RedisWebhookReservationStore.from_url(). "
                "Install it via: pip install didit-sdk[redis]"
            ) from err

        client = redis.Redis.from_url(url, **kwargs)
        return cls(client=client, namespace=namespace, failure_mode=failure_mode)

    def reserve(
        self, event_id: str, token: str | None = None, ttl_seconds: int = 30
    ) -> ReservationAttempt:
        """Atomically acquire an in-flight processing lease for an event."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        tok = token or secrets.token_urlsafe(16)
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            started_at = time.monotonic()
            raw_res = self._client.eval(LUA_RESERVE, 1, key, tok, str(ttl_seconds))
            res = (
                raw_res.decode("utf-8") if isinstance(raw_res, (bytes, bytearray)) else str(raw_res)
            )
            if res == "ACQUIRED":
                return ReservationAttempt(
                    state=ReservationState.ACQUIRED,
                    reservation=WebhookReservation(
                        event_id=event_id, token=tok, expires_at=started_at + ttl_seconds
                    ),
                )
            if res == "COMPLETED":
                return ReservationAttempt(state=ReservationState.COMPLETED)
            return ReservationAttempt(state=ReservationState.PROCESSING)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return ReservationAttempt(
                    state=ReservationState.ACQUIRED,
                    reservation=WebhookReservation(
                        event_id=event_id, token=tok, expires_at=time.monotonic() + ttl_seconds
                    ),
                    degraded=True,
                )
            raise DiditDedupError(f"Redis reservation store reserve failed: {exc}") from exc

    def complete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
        """Idempotently transition an in-flight reservation to COMPLETED state."""
        if completed_ttl <= 0:
            raise ValueError("completed_ttl must be greater than zero")
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            res = self._client.eval(LUA_COMPLETE, 1, key, token, str(completed_ttl))
            return bool(int(res) == 1)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return False
            raise DiditDedupError(f"Redis reservation store complete failed: {exc}") from exc

    def release(self, event_id: str, token: str) -> bool:
        """Release an in-flight reservation if token matches."""
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            res = self._client.eval(LUA_RELEASE, 1, key, token)
            return bool(int(res) == 1)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return False
            raise DiditDedupError(f"Redis reservation store release failed: {exc}") from exc

    def renew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
        """Extend lease TTL if token matches in-flight reservation."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            res = self._client.eval(LUA_RENEW, 1, key, token, str(ttl_seconds))
            return bool(int(res) == 1)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return False
            raise DiditDedupError(f"Redis reservation store renew failed: {exc}") from exc

    # Backward compatibility with WebhookDedupStore
    def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Backward-compatible claim."""
        attempt = self.reserve(key, ttl_seconds=ttl_seconds)
        return attempt.state == ReservationState.ACQUIRED

    def release_claim(self, key: str) -> None:
        """Deprecated: Blind key deletion for legacy compatibility.

        Does not verify token ownership.
        """
        full_key = build_reservation_key(key, namespace=self.namespace)
        try:
            self._client.delete(full_key)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return
            raise DiditDedupError(f"Redis reservation store release_claim failed: {exc}") from exc


class AsyncRedisWebhookReservationStore:
    """Production asynchronous Redis reservation store leveraging atomic Lua CAS scripts.

    Distributes leases across Redis Cluster shards via standard non-hashtag keys:
    `didit:webhook:<namespace>:<sha256(event_id)>`.
    """

    def __init__(
        self,
        client: Any,
        namespace: str = "default",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
    ) -> None:
        self._client = client
        self.namespace = namespace
        self.failure_mode = failure_mode

    @classmethod
    def from_url(
        cls,
        url: str,
        namespace: str = "default",
        failure_mode: DedupFailureMode = DedupFailureMode.RAISE,
        **kwargs: Any,
    ) -> AsyncRedisWebhookReservationStore:
        """Create an AsyncRedisWebhookReservationStore from a Redis connection URL."""
        try:
            import redis.asyncio as aioredis
        except (ImportError, ModuleNotFoundError) as err:
            raise DiditConfigurationError(
                "redis-py is required to use AsyncRedisWebhookReservationStore.from_url(). "
                "Install it via: pip install didit-sdk[redis]"
            ) from err

        client = aioredis.Redis.from_url(url, **kwargs)
        return cls(client=client, namespace=namespace, failure_mode=failure_mode)

    async def areserve(
        self, event_id: str, token: str | None = None, ttl_seconds: int = 30
    ) -> ReservationAttempt:
        """Atomically acquire an in-flight processing lease asynchronously."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        tok = token or secrets.token_urlsafe(16)
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            started_at = time.monotonic()
            raw_res = await self._client.eval(LUA_RESERVE, 1, key, tok, str(ttl_seconds))
            res = (
                raw_res.decode("utf-8") if isinstance(raw_res, (bytes, bytearray)) else str(raw_res)
            )
            if res == "ACQUIRED":
                return ReservationAttempt(
                    state=ReservationState.ACQUIRED,
                    reservation=WebhookReservation(
                        event_id=event_id, token=tok, expires_at=started_at + ttl_seconds
                    ),
                )
            if res == "COMPLETED":
                return ReservationAttempt(state=ReservationState.COMPLETED)
            return ReservationAttempt(state=ReservationState.PROCESSING)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return ReservationAttempt(
                    state=ReservationState.ACQUIRED,
                    reservation=WebhookReservation(
                        event_id=event_id, token=tok, expires_at=time.monotonic() + ttl_seconds
                    ),
                    degraded=True,
                )
            raise DiditDedupError(f"Async Redis reservation store reserve failed: {exc}") from exc

    async def acomplete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
        """Idempotently transition an in-flight reservation to COMPLETED state asynchronously."""
        if completed_ttl <= 0:
            raise ValueError("completed_ttl must be greater than zero")
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            res = await self._client.eval(LUA_COMPLETE, 1, key, token, str(completed_ttl))
            return bool(int(res) == 1)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return False
            raise DiditDedupError(f"Async Redis reservation store complete failed: {exc}") from exc

    async def arelease(self, event_id: str, token: str) -> bool:
        """Release an in-flight reservation asynchronously if token matches."""
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            res = await self._client.eval(LUA_RELEASE, 1, key, token)
            return bool(int(res) == 1)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return False
            raise DiditDedupError(f"Async Redis reservation store release failed: {exc}") from exc

    async def arenew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
        """Extend lease TTL asynchronously if token matches in-flight reservation."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        key = build_reservation_key(event_id, namespace=self.namespace)
        try:
            res = await self._client.eval(LUA_RENEW, 1, key, token, str(ttl_seconds))
            return bool(int(res) == 1)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return False
            raise DiditDedupError(f"Async Redis reservation store renew failed: {exc}") from exc

    # Backward compatibility with WebhookDedupStore
    async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
        """Backward-compatible async claim."""
        attempt = await self.areserve(key, ttl_seconds=ttl_seconds)
        return attempt.state == ReservationState.ACQUIRED

    async def arelease_claim(self, key: str) -> None:
        """Deprecated: Blind key deletion for legacy compatibility.

        Does not verify token ownership.
        """
        full_key = build_reservation_key(key, namespace=self.namespace)
        try:
            await self._client.delete(full_key)
        except Exception as exc:
            if self.failure_mode == DedupFailureMode.FAIL_OPEN:
                return
            raise DiditDedupError(
                f"Async Redis reservation store arelease_claim failed: {exc}"
            ) from exc


def compute_dedup_key(payload: WebhookPayload, signature: str | None = None) -> str:
    """Build canonical deduplication key from webhook payload and headers."""
    if payload.event_id:
        return payload.event_id

    status_val = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
    webhook_type = payload.webhook_type or "unknown"
    return f"didit:event:{payload.session_id}:{webhook_type}:{status_val}"


# Dispatch helpers supporting both tokenized reservation stores and legacy dedup stores


def reserve_webhook_event(
    store: Any,
    event_id: str,
    token: str | None = None,
    ttl_seconds: int = 30,
    legacy_ttl_seconds: int = 86400,
) -> ReservationAttempt:
    """Synchronously reserve a webhook event across reservation stores or legacy stores."""
    reserve_fn = getattr(store, "reserve", None)
    if (
        reserve_fn is not None
        and callable(reserve_fn)
        and not inspect.iscoroutinefunction(reserve_fn)
    ):
        return cast(ReservationAttempt, reserve_fn(event_id, token=token, ttl_seconds=ttl_seconds))

    claim_fn = getattr(store, "claim", None)
    if claim_fn is not None and callable(claim_fn) and not inspect.iscoroutinefunction(claim_fn):
        claimed = bool(claim_fn(event_id, ttl_seconds=legacy_ttl_seconds))
        if claimed:
            tok = token or secrets.token_urlsafe(16)
            return ReservationAttempt(
                state=ReservationState.ACQUIRED,
                reservation=WebhookReservation(
                    event_id=event_id, token=tok, expires_at=time.monotonic() + legacy_ttl_seconds
                ),
            )
        return ReservationAttempt(state=ReservationState.COMPLETED)

    raise DiditConfigurationError("Store does not implement synchronous reserve() or claim().")


async def areserve_webhook_event(
    store: Any,
    event_id: str,
    token: str | None = None,
    ttl_seconds: int = 30,
    legacy_ttl_seconds: int = 86400,
) -> ReservationAttempt:
    """Asynchronously reserve a webhook event across stores or legacy stores."""
    if hasattr(store, "areserve") and callable(store.areserve):
        return cast(
            ReservationAttempt,
            await store.areserve(event_id, token=token, ttl_seconds=ttl_seconds),
        )

    reserve_fn = getattr(store, "reserve", None)
    if reserve_fn is not None and callable(reserve_fn):
        if inspect.iscoroutinefunction(reserve_fn):
            return cast(
                ReservationAttempt,
                await reserve_fn(event_id, token=token, ttl_seconds=ttl_seconds),
            )
        return cast(
            ReservationAttempt,
            await asyncio.to_thread(reserve_fn, event_id, token, ttl_seconds),
        )

    # Fallback to claim / aclaim using legacy_ttl_seconds (default 86400)
    if hasattr(store, "aclaim") and callable(store.aclaim):
        claimed = bool(await store.aclaim(event_id, ttl_seconds=legacy_ttl_seconds))
    else:
        claim_fn = getattr(store, "claim", None)
        if claim_fn is None or not callable(claim_fn):
            raise DiditConfigurationError(
                "Store does not implement reserve(), areserve(), claim(), or aclaim()."
            )
        if inspect.iscoroutinefunction(claim_fn):
            claimed = bool(await claim_fn(event_id, ttl_seconds=legacy_ttl_seconds))
        else:
            claimed = bool(await asyncio.to_thread(claim_fn, event_id, legacy_ttl_seconds))

    if claimed:
        tok = token or secrets.token_urlsafe(16)
        return ReservationAttempt(
            state=ReservationState.ACQUIRED,
            reservation=WebhookReservation(
                event_id=event_id, token=tok, expires_at=time.monotonic() + legacy_ttl_seconds
            ),
        )
    return ReservationAttempt(state=ReservationState.COMPLETED)


def complete_webhook_event(
    store: Any,
    event_id: str,
    token: str,
    completed_ttl: int = 86400,
) -> bool:
    """Synchronously complete a webhook event reservation."""
    complete_fn = getattr(store, "complete", None)
    if (
        complete_fn is not None
        and callable(complete_fn)
        and not inspect.iscoroutinefunction(complete_fn)
    ):
        return bool(complete_fn(event_id, token, completed_ttl=completed_ttl))
    # Legacy stores do not implement complete; acknowledge success
    return True


async def acomplete_webhook_event(
    store: Any,
    event_id: str,
    token: str,
    completed_ttl: int = 86400,
) -> bool:
    """Asynchronously complete a webhook event reservation."""
    if hasattr(store, "acomplete") and callable(store.acomplete):
        return bool(await store.acomplete(event_id, token, completed_ttl=completed_ttl))
    complete_fn = getattr(store, "complete", None)
    if complete_fn is not None and callable(complete_fn):
        if inspect.iscoroutinefunction(complete_fn):
            return bool(await complete_fn(event_id, token, completed_ttl=completed_ttl))
        return bool(await asyncio.to_thread(complete_fn, event_id, token, completed_ttl))
    return True


def release_webhook_event(
    store: Any,
    event_id: str,
    token: str | None = None,
) -> None:
    """Safely release a webhook event reservation synchronously."""
    release_fn = getattr(store, "release", None)
    if (
        release_fn is not None
        and callable(release_fn)
        and not inspect.iscoroutinefunction(release_fn)
    ):
        sig = inspect.signature(release_fn)
        if len(sig.parameters) >= 2 and token is not None:
            release_fn(event_id, token)
        else:
            release_fn(event_id)


async def arelease_webhook_event(
    store: Any,
    event_id: str,
    token: str | None = None,
) -> None:
    """Safely release a webhook event reservation across sync and async stores."""
    if hasattr(store, "arelease") and callable(store.arelease):
        sig = inspect.signature(store.arelease)
        if len(sig.parameters) >= 2 and token is not None:
            await store.arelease(event_id, token)
        else:
            await store.arelease(event_id)
        return

    release_fn = getattr(store, "release", None)
    if release_fn is None or not callable(release_fn):
        return

    sig = inspect.signature(release_fn)
    takes_token = len(sig.parameters) >= 2 and token is not None

    if inspect.iscoroutinefunction(release_fn):
        if takes_token:
            await release_fn(event_id, token)
        else:
            await release_fn(event_id)
    else:
        if takes_token:
            await asyncio.to_thread(release_fn, event_id, token)
        else:
            await asyncio.to_thread(release_fn, event_id)


def renew_webhook_event(
    store: Any,
    event_id: str,
    token: str,
    ttl_seconds: int = 30,
) -> bool:
    """Synchronously extend lease TTL if token matches in-flight reservation."""
    renew_fn = getattr(store, "renew", None)
    if renew_fn is not None and callable(renew_fn) and not inspect.iscoroutinefunction(renew_fn):
        return bool(renew_fn(event_id, token, ttl_seconds=ttl_seconds))
    return False


async def arenew_webhook_event(
    store: Any,
    event_id: str,
    token: str,
    ttl_seconds: int = 30,
) -> bool:
    """Asynchronously extend lease TTL if token matches in-flight reservation."""
    if hasattr(store, "arenew") and callable(store.arenew):
        return bool(await store.arenew(event_id, token, ttl_seconds=ttl_seconds))
    renew_fn = getattr(store, "renew", None)
    if renew_fn is not None and callable(renew_fn):
        if inspect.iscoroutinefunction(renew_fn):
            return bool(await renew_fn(event_id, token, ttl_seconds=ttl_seconds))
        return bool(await asyncio.to_thread(renew_fn, event_id, token, ttl_seconds))
    return False


async def aclaim_webhook_event(
    store: WebhookDedupStore | AsyncWebhookDedupStore | Any,
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
