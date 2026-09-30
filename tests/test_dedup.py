"""Targeted tests for webhook deduplication protocols and storage engines."""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from didit.dedup import (
    AsyncRedisWebhookDedupStore,
    AsyncWebhookDedupStore,
    DedupFailureMode,
    InMemoryWebhookDedupStore,
    RedisWebhookDedupStore,
    WebhookDedupStore,
    compute_dedup_key,
)
from didit.errors import DiditDedupError, DiditDedupSaturationError
from didit.models.enums import SessionStatus
from didit.models.webhook import WebhookPayload


class TestDedupProtocols:
    def test_protocol_conformance(self) -> None:
        sync_store = InMemoryWebhookDedupStore()
        assert isinstance(sync_store, WebhookDedupStore)

        mock_sync_redis = RedisWebhookDedupStore(client=MagicMock())
        assert isinstance(mock_sync_redis, WebhookDedupStore)

        mock_async_redis = AsyncRedisWebhookDedupStore(client=MagicMock())
        assert isinstance(mock_async_redis, AsyncWebhookDedupStore)


class TestInMemoryDedupStore:
    def test_invalid_max_entries(self) -> None:
        with pytest.raises(ValueError, match="max_entries must be greater than or equal to 1"):
            InMemoryWebhookDedupStore(max_entries=0)

    def test_invalid_ttl(self) -> None:
        store = InMemoryWebhookDedupStore()
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            store.claim("evt", ttl_seconds=0)
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            store.claim("evt", ttl_seconds=-1)

    def test_claim_and_duplicate(self) -> None:
        store = InMemoryWebhookDedupStore(max_entries=100)
        assert store.claim("evt_1", ttl_seconds=60) is True
        assert store.claim("evt_1", ttl_seconds=60) is False
        assert store.claim("evt_2", ttl_seconds=60) is True

    def test_expiration_allows_reclaim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryWebhookDedupStore(max_entries=100)
        current_time = 1_000_000.0
        monkeypatch.setattr(time, "monotonic", lambda: current_time)

        assert store.claim("evt_exp", ttl_seconds=10) is True
        assert store.claim("evt_exp", ttl_seconds=10) is False

        # Advance time beyond TTL
        current_time += 11.0
        assert store.claim("evt_exp", ttl_seconds=10) is True

    def test_saturation_purges_expired_then_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryWebhookDedupStore(max_entries=2)
        current_time = 1_000_000.0
        monkeypatch.setattr(time, "monotonic", lambda: current_time)

        # Fill with 2 items: evt_1 expires in 5s, evt_2 in 20s
        assert store.claim("evt_1", ttl_seconds=5) is True
        assert store.claim("evt_2", ttl_seconds=20) is True

        # Advance time by 6s (evt_1 expired, evt_2 still active)
        current_time += 6.0

        # Adding evt_3 should purge evt_1 and succeed
        assert store.claim("evt_3", ttl_seconds=20) is True

        # Now store has evt_2 and evt_3, both unexpired
        with pytest.raises(DiditDedupSaturationError, match="reached saturation"):
            store.claim("evt_4", ttl_seconds=20)

    def test_thread_safety_concurrent_claims(self) -> None:
        store = InMemoryWebhookDedupStore(max_entries=500)
        key = "evt_concurrent"
        results: list[bool] = []

        def attempt_claim() -> bool:
            return store.claim(key, ttl_seconds=60)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(attempt_claim) for _ in range(50)]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        # Exactly one worker thread must have claimed successfully
        assert results.count(True) == 1
        assert results.count(False) == 49

    @pytest.mark.asyncio
    async def test_async_aclaim(self) -> None:
        store = InMemoryWebhookDedupStore()
        assert await store.aclaim("evt_async", ttl_seconds=60) is True
        assert await store.aclaim("evt_async", ttl_seconds=60) is False


class TestRedisDedupStore:
    def test_claim_and_duplicate(self) -> None:
        mock_client = MagicMock()
        mock_client.set.side_effect = [True, None]

        store = RedisWebhookDedupStore(client=mock_client, prefix="custom:dedup:")
        assert store.claim("evt_redis_1", ttl_seconds=120) is True
        mock_client.set.assert_called_once_with("custom:dedup:evt_redis_1", "1", nx=True, ex=120)

        assert store.claim("evt_redis_1", ttl_seconds=120) is False

    @pytest.mark.parametrize(
        ("failure_mode", "expect_error"),
        [
            (DedupFailureMode.RAISE, True),
            (DedupFailureMode.FAIL_OPEN, False),
        ],
    )
    def test_failure_modes(self, failure_mode: DedupFailureMode, expect_error: bool) -> None:
        mock_client = MagicMock()
        mock_client.set.side_effect = ConnectionError("Redis cluster unreachable")

        store = RedisWebhookDedupStore(client=mock_client, failure_mode=failure_mode)
        if expect_error:
            with pytest.raises(DiditDedupError, match="Redis cluster unreachable"):
                store.claim("evt_down", ttl_seconds=60)
        else:
            # FAIL_OPEN allows processing to continue
            assert store.claim("evt_down", ttl_seconds=60) is True


class TestAsyncRedisDedupStore:
    @pytest.mark.asyncio
    async def test_async_claim_and_duplicate(self) -> None:
        mock_client = MagicMock()
        mock_client.set = AsyncMock(side_effect=[True, False])

        store = AsyncRedisWebhookDedupStore(client=mock_client, prefix="async:didit:")
        assert await store.claim("evt_async_1", ttl_seconds=300) is True
        mock_client.set.assert_called_once_with("async:didit:evt_async_1", "1", nx=True, ex=300)
        assert await store.claim("evt_async_1", ttl_seconds=300) is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("failure_mode", "expect_error"),
        [
            (DedupFailureMode.RAISE, True),
            (DedupFailureMode.FAIL_OPEN, False),
        ],
    )
    async def test_async_failure_modes(
        self, failure_mode: DedupFailureMode, expect_error: bool
    ) -> None:
        mock_client = MagicMock()
        mock_client.set = AsyncMock(side_effect=TimeoutError("Async Redis timeout"))

        store = AsyncRedisWebhookDedupStore(client=mock_client, failure_mode=failure_mode)
        if expect_error:
            with pytest.raises(DiditDedupError, match="Async Redis timeout"):
                await store.claim("evt_async_down", ttl_seconds=60)
        else:
            assert await store.claim("evt_async_down", ttl_seconds=60) is True


class TestComputeDedupKey:
    @pytest.mark.parametrize(
        ("kwargs", "signature", "expected"),
        [
            (
                {
                    "event_id": "evt_custom_123",
                    "session_id": "sess_1",
                    "status": SessionStatus.APPROVED,
                },
                None,
                "evt_custom_123",
            ),
            (
                {
                    "event_id": None,
                    "session_id": "sess_2",
                    "status": SessionStatus.DECLINED,
                    "timestamp": 1727640000,
                },
                None,
                "didit:event:sess_2:unknown:Declined",
            ),
            (
                {
                    "event_id": None,
                    "session_id": "sess_3",
                    "status": SessionStatus.IN_REVIEW,
                    "webhook_type": "custom.status",
                    "timestamp": None,
                },
                "sig_hex_abc",
                "didit:event:sess_3:custom.status:In Review",
            ),
            (
                {
                    "event_id": None,
                    "session_id": "sess_4",
                    "status": SessionStatus.EXPIRED,
                    "timestamp": None,
                },
                None,
                "didit:event:sess_4:unknown:Expired",
            ),
        ],
    )
    def test_compute_dedup_key_variants(
        self, kwargs: dict[str, Any], signature: str | None, expected: str
    ) -> None:
        payload = WebhookPayload(**kwargs)
        assert compute_dedup_key(payload, signature=signature) == expected


class TestReleaseWebhookEvent:
    def test_in_memory_release(self) -> None:
        store = InMemoryWebhookDedupStore()
        assert store.claim("k1", ttl_seconds=60) is True
        assert store.claim("k1", ttl_seconds=60) is False
        store.release("k1")
        assert store.claim("k1", ttl_seconds=60) is True

    @pytest.mark.asyncio
    async def test_in_memory_arelease(self) -> None:
        store = InMemoryWebhookDedupStore()
        assert await store.aclaim("k2", ttl_seconds=60) is True
        assert await store.aclaim("k2", ttl_seconds=60) is False
        await store.arelease("k2")
        assert await store.aclaim("k2", ttl_seconds=60) is True

    def test_redis_release(self) -> None:
        mock_client = MagicMock()
        store = RedisWebhookDedupStore(client=mock_client, prefix="didit:test:")
        store.release("key_1")
        mock_client.delete.assert_called_once_with("didit:test:key_1")

    @pytest.mark.parametrize(
        ("failure_mode", "expect_error"),
        [
            (DedupFailureMode.RAISE, True),
            (DedupFailureMode.FAIL_OPEN, False),
        ],
    )
    def test_redis_release_error_handling(
        self, failure_mode: DedupFailureMode, expect_error: bool
    ) -> None:
        mock_client = MagicMock()
        mock_client.delete.side_effect = ConnectionError("Redis failure")
        store = RedisWebhookDedupStore(client=mock_client, failure_mode=failure_mode)
        if expect_error:
            with pytest.raises(DiditDedupError, match="Redis dedup store release failed"):
                store.release("key_err")
        else:
            store.release("key_err")

    @pytest.mark.asyncio
    async def test_async_redis_release(self) -> None:
        mock_client = MagicMock()
        mock_client.delete = AsyncMock()
        store = AsyncRedisWebhookDedupStore(client=mock_client, prefix="async:test:")
        await store.arelease("async_k1")
        mock_client.delete.assert_called_once_with("async:test:async_k1")
        await store.release("async_k2")
        mock_client.delete.assert_called_with("async:test:async_k2")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("failure_mode", "expect_error"),
        [
            (DedupFailureMode.RAISE, True),
            (DedupFailureMode.FAIL_OPEN, False),
        ],
    )
    async def test_async_redis_release_error_handling(
        self, failure_mode: DedupFailureMode, expect_error: bool
    ) -> None:
        mock_client = MagicMock()
        mock_client.delete = AsyncMock(side_effect=TimeoutError("Async timeout"))
        store = AsyncRedisWebhookDedupStore(client=mock_client, failure_mode=failure_mode)
        if expect_error:
            with pytest.raises(DiditDedupError, match="Async Redis dedup store release failed"):
                await store.arelease("err_k")
        else:
            await store.arelease("err_k")

    @pytest.mark.asyncio
    async def test_helpers_release_and_arelease(self) -> None:
        from didit.dedup import arelease_webhook_event, release_webhook_event

        # No release method: graceful no-op
        release_webhook_event(object(), "noop")  # type: ignore[arg-type]
        await arelease_webhook_event(object(), "noop")  # type: ignore[arg-type]

        # Sync store
        sync_store = InMemoryWebhookDedupStore()
        assert sync_store.claim("test_h", ttl_seconds=60) is True
        release_webhook_event(sync_store, "test_h")
        assert sync_store.claim("test_h", ttl_seconds=60) is True

        # Async store via arelease_webhook_event
        assert sync_store.claim("test_h2", ttl_seconds=60) is True
        await arelease_webhook_event(sync_store, "test_h2")
        assert sync_store.claim("test_h2", ttl_seconds=60) is True

        # Store with coroutine release
        class CoroReleaseStore:
            def __init__(self) -> None:
                self.released = False

            async def release(self, key: str) -> None:
                self.released = True

        coro_store = CoroReleaseStore()
        await arelease_webhook_event(coro_store, "k")  # type: ignore[arg-type]
        assert coro_store.released is True

        # Store with only synchronous release (no arelease)
        class PureSyncReleaseStore:
            def __init__(self) -> None:
                self.released = False

            def release(self, key: str) -> None:
                self.released = True

        sync_only_store = PureSyncReleaseStore()
        await arelease_webhook_event(sync_only_store, "k_sync")  # type: ignore[arg-type]
        assert sync_only_store.released is True


class TestAclaimWebhookEvent:
    @pytest.mark.asyncio
    async def test_invalid_store_raises_configuration_error(self) -> None:
        from didit.dedup import aclaim_webhook_event
        from didit.errors import DiditConfigurationError

        with pytest.raises(DiditConfigurationError, match="does not implement"):
            await aclaim_webhook_event(object(), "key")  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_async_claim_coroutine(self) -> None:
        from didit.dedup import aclaim_webhook_event

        class CoroutineClaimStore:
            async def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
                return True

        assert await aclaim_webhook_event(CoroutineClaimStore(), "key") is True  # type: ignore[arg-type]
