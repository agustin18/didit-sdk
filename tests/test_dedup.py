"""Targeted tests for webhook deduplication protocols and storage engines."""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from didit.dedup import (
    AsyncRedisWebhookDedupStore,
    AsyncRedisWebhookReservationStore,
    AsyncWebhookDedupStore,
    AsyncWebhookReservationStore,
    DedupFailureMode,
    InMemoryWebhookDedupStore,
    InMemoryWebhookReservationStore,
    RedisWebhookDedupStore,
    RedisWebhookReservationStore,
    ReservationAttempt,
    ReservationState,
    WebhookDedupStore,
    WebhookReservation,
    WebhookReservationStore,
    acomplete_webhook_event,
    arelease_webhook_event,
    arenew_webhook_event,
    areserve_webhook_event,
    build_reservation_key,
    complete_webhook_event,
    compute_dedup_key,
    release_webhook_event,
    renew_webhook_event,
    reserve_webhook_event,
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

    def test_redis_dedup_store_from_url(self) -> None:
        with patch("redis.Redis.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client
            store = RedisWebhookDedupStore.from_url(
                "redis://localhost:6379/0", prefix="pfx:", failure_mode=DedupFailureMode.FAIL_OPEN
            )
            mock_from_url.assert_called_once_with("redis://localhost:6379/0")
            assert store.prefix == "pfx:"
            assert store.failure_mode == DedupFailureMode.FAIL_OPEN
            assert store._client is mock_client


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

    def test_async_redis_dedup_store_from_url(self) -> None:
        with patch("redis.asyncio.Redis.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client
            store = AsyncRedisWebhookDedupStore.from_url(
                "redis://localhost:6379/0", prefix="async_pfx:"
            )
            mock_from_url.assert_called_once_with("redis://localhost:6379/0")
            assert store.prefix == "async_pfx:"
            assert store._client is mock_client


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


class TestKeyBuilder:
    def test_build_reservation_key_format(self) -> None:
        key = build_reservation_key("session_123", namespace="prod")
        assert key.startswith("didit:webhook:prod:")
        # Crucial: NO curly braces to prevent Redis Cluster hot shards
        assert "{" not in key
        assert "}" not in key
        # Digest is SHA-256 (64 hex characters)
        digest = key.split(":")[-1]
        assert len(digest) == 64

    def test_build_reservation_key_default_namespace(self) -> None:
        key = build_reservation_key("session_456")
        assert key.startswith("didit:webhook:default:")

    def test_build_reservation_key_rejects_braces(self) -> None:
        with pytest.raises(ValueError, match="namespace cannot contain '{' or '}'"):
            build_reservation_key("session_123", namespace="{prod}")
        with pytest.raises(ValueError, match="namespace cannot contain '{' or '}'"):
            build_reservation_key("session_123", namespace="prod}")
        with pytest.raises(ValueError, match="namespace cannot contain '{' or '}'"):
            build_reservation_key("session_123", namespace="{all")


class TestReservationProtocols:
    def test_reservation_protocol_conformance(self) -> None:
        in_memory = InMemoryWebhookReservationStore()
        assert isinstance(in_memory, WebhookReservationStore)
        assert isinstance(in_memory, AsyncWebhookReservationStore)

        sync_redis = RedisWebhookReservationStore(client=MagicMock())
        assert isinstance(sync_redis, WebhookReservationStore)

        async_redis = AsyncRedisWebhookReservationStore(client=MagicMock())
        assert isinstance(async_redis, AsyncWebhookReservationStore)


class TestInMemoryReservationStore:
    def test_invalid_constructor_args(self) -> None:
        with pytest.raises(ValueError, match="max_entries must be greater than or equal to 1"):
            InMemoryWebhookReservationStore(max_entries=0)

    def test_invalid_reserve_args(self) -> None:
        store = InMemoryWebhookReservationStore()
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            store.reserve("evt", ttl_seconds=0)

    def test_invalid_complete_args(self) -> None:
        store = InMemoryWebhookReservationStore()
        with pytest.raises(ValueError, match="completed_ttl must be greater than zero"):
            store.complete("evt", "tok", completed_ttl=0)

    def test_invalid_renew_args(self) -> None:
        store = InMemoryWebhookReservationStore()
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            store.renew("evt", "tok", ttl_seconds=0)

    def test_reservation_lifecycle(self) -> None:
        store = InMemoryWebhookReservationStore()
        # Initial reservation
        attempt = store.reserve("evt_1", ttl_seconds=30)
        assert attempt.state == ReservationState.ACQUIRED
        assert attempt.reservation is not None
        assert attempt.reservation.event_id == "evt_1"
        tok = attempt.reservation.token

        # Competing attempt with different token -> PROCESSING
        competing = store.reserve("evt_1", token="other_token", ttl_seconds=30)
        assert competing.state == ReservationState.PROCESSING
        assert competing.reservation is None

        # Re-entrant retry with same token -> ACQUIRED (same token recovery)
        retry = store.reserve("evt_1", token=tok, ttl_seconds=30)
        assert retry.state == ReservationState.ACQUIRED
        assert retry.reservation is not None
        assert retry.reservation.token == tok

        # Renew lease
        assert store.renew("evt_1", tok, ttl_seconds=60) is True
        # Renew with wrong token
        assert store.renew("evt_1", "bad_token", ttl_seconds=60) is False

        # Complete lease
        assert store.complete("evt_1", tok, completed_ttl=100) is True
        # Complete is idempotent
        assert store.complete("evt_1", tok, completed_ttl=100) is True

        # Subsequent reserve after completion -> COMPLETED
        post_complete = store.reserve("evt_1", ttl_seconds=30)
        assert post_complete.state == ReservationState.COMPLETED

        # Cannot release or renew completed lease
        assert store.release("evt_1", tok) is False
        assert store.renew("evt_1", tok, ttl_seconds=30) is False

    def test_release_and_renew_nonexistent_key(self) -> None:
        store = InMemoryWebhookReservationStore()
        assert store.release("nonexistent", "tok") is False
        assert store.renew("nonexistent", "tok", ttl_seconds=30) is False

    def test_release_processing_lease(self) -> None:
        store = InMemoryWebhookReservationStore()
        attempt = store.reserve("evt_rel", ttl_seconds=30)
        assert attempt.state == ReservationState.ACQUIRED
        assert attempt.reservation is not None
        tok = attempt.reservation.token

        # Release with wrong token fails
        assert store.release("evt_rel", "wrong") is False
        # Release with correct token succeeds
        assert store.release("evt_rel", tok) is True

        # Can now be reserved again
        new_attempt = store.reserve("evt_rel", ttl_seconds=30)
        assert new_attempt.state == ReservationState.ACQUIRED

    def test_same_token_ttl_refresh(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryWebhookReservationStore()
        current_time = 1_000.0
        monkeypatch.setattr(time, "monotonic", lambda: current_time)

        attempt1 = store.reserve("evt_refresh", token="tok_a", ttl_seconds=30)
        assert attempt1.state == ReservationState.ACQUIRED
        assert attempt1.reservation is not None
        assert attempt1.reservation.expires_at == 1030.0

        current_time = 1020.0
        attempt2 = store.reserve("evt_refresh", token="tok_a", ttl_seconds=30)
        assert attempt2.state == ReservationState.ACQUIRED
        assert attempt2.reservation is not None
        # Must be refreshed to current_time + 30 = 1050.0, NOT original 1030.0!
        assert attempt2.reservation.expires_at == 1050.0

    def test_lease_expiry_during_old_worker_execution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = InMemoryWebhookReservationStore()
        current_time = 1_000.0
        monkeypatch.setattr(time, "monotonic", lambda: current_time)

        # Worker A acquires lease for 30s
        attempt_a = store.reserve("evt_steal", token="worker_a", ttl_seconds=30)
        assert attempt_a.state == ReservationState.ACQUIRED

        # Worker A stalls; clock advances past lease
        current_time = 1035.0

        # Worker B acquires the expired lease
        attempt_b = store.reserve("evt_steal", token="worker_b", ttl_seconds=30)
        assert attempt_b.state == ReservationState.ACQUIRED

        # Stale Worker A wakes up and attempts to release its lease with worker_a token
        assert store.release("evt_steal", "worker_a") is False

        # Verify Worker B's lease was NOT altered or deleted by Worker A
        competing = store.reserve("evt_steal", token="worker_c", ttl_seconds=30)
        assert competing.state == ReservationState.PROCESSING

        # Worker B successfully completes
        assert store.complete("evt_steal", "worker_b") is True

    def test_expiration_re_reservation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryWebhookReservationStore()
        current_time = 1_000_000.0
        monkeypatch.setattr(time, "monotonic", lambda: current_time)

        # 1. reserve on expired entry
        attempt = store.reserve("evt_exp", ttl_seconds=10)
        assert attempt.state == ReservationState.ACQUIRED
        assert store.reserve("evt_exp", ttl_seconds=10).state == ReservationState.PROCESSING
        current_time += 11.0
        re_attempt = store.reserve("evt_exp", ttl_seconds=10)
        assert re_attempt.state == ReservationState.ACQUIRED

        # 2. complete on expired entry
        store.reserve("evt_comp_exp", ttl_seconds=10)
        current_time += 11.0
        assert store.complete("evt_comp_exp", "tok") is False

        # 3. renew on expired entry
        store.reserve("evt_renew_exp", ttl_seconds=10)
        current_time += 11.0
        assert store.renew("evt_renew_exp", "tok", 10) is False

        # 4. release on expired entry
        store.reserve("evt_rel_exp", ttl_seconds=10)
        current_time += 11.0
        assert store.release("evt_rel_exp", "tok") is False

    def test_saturation_and_purging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryWebhookReservationStore(max_entries=2)
        current_time = 1_000_000.0
        monkeypatch.setattr(time, "monotonic", lambda: current_time)

        store.reserve("evt_1", ttl_seconds=5)
        store.reserve("evt_2", ttl_seconds=20)

        # Advance time so evt_1 expires
        current_time += 6.0

        # evt_3 succeeds by purging evt_1
        assert store.reserve("evt_3", ttl_seconds=20).state == ReservationState.ACQUIRED

        # Now evt_2 and evt_3 are unexpired; evt_4 triggers saturation
        with pytest.raises(DiditDedupSaturationError, match="reached saturation"):
            store.reserve("evt_4", ttl_seconds=20)

    def test_concurrent_reservations(self) -> None:
        store = InMemoryWebhookReservationStore(max_entries=100)
        event_id = "evt_conc"
        results: list[ReservationState] = []

        def worker() -> ReservationState:
            return store.reserve(event_id, ttl_seconds=60).state

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(30)]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        # Exactly 1 ACQUIRED, 29 PROCESSING
        assert results.count(ReservationState.ACQUIRED) == 1
        assert results.count(ReservationState.PROCESSING) == 29

    @pytest.mark.asyncio
    async def test_async_methods_and_backward_compatibility(self) -> None:
        store = InMemoryWebhookReservationStore()
        # Async reserve
        att = await store.areserve("evt_async", ttl_seconds=30)
        assert att.state == ReservationState.ACQUIRED
        assert att.reservation is not None
        tok = att.reservation.token

        # Async renew
        assert await store.arenew("evt_async", tok, ttl_seconds=30) is True

        # Async complete
        assert await store.acomplete("evt_async", tok) is True

        # Async release on completed returns False
        assert await store.arelease("evt_async", tok) is False

        # Backward compatibility methods
        store2 = InMemoryWebhookReservationStore()
        assert store2.claim("legacy_1", ttl_seconds=30) is True
        assert store2.claim("legacy_1", ttl_seconds=30) is False
        store2.release_claim("legacy_1")
        assert store2.claim("legacy_1", ttl_seconds=30) is True

        assert await store2.aclaim("legacy_async", ttl_seconds=30) is True
        assert await store2.aclaim("legacy_async", ttl_seconds=30) is False
        await store2.arelease_claim("legacy_async")
        assert await store2.aclaim("legacy_async", ttl_seconds=30) is True


class TestRedisReservationStore:
    def test_from_url_success(self) -> None:
        with patch("redis.Redis.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client
            store = RedisWebhookReservationStore.from_url(
                "redis://localhost:6379/0", namespace="ns1"
            )
            assert store.namespace == "ns1"
            assert store._client is mock_client

    def test_from_url_import_error(self) -> None:
        from didit.errors import DiditConfigurationError

        with (
            patch.dict("sys.modules", {"redis": None}),
            pytest.raises(DiditConfigurationError, match="redis-py is required"),
        ):
            RedisWebhookReservationStore.from_url("redis://localhost:6379/0")

    def test_invalid_arguments(self) -> None:
        store = RedisWebhookReservationStore(client=MagicMock())
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            store.reserve("evt", ttl_seconds=0)
        with pytest.raises(ValueError, match="completed_ttl must be greater than zero"):
            store.complete("evt", "tok", completed_ttl=0)
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            store.renew("evt", "tok", ttl_seconds=0)

    @pytest.mark.parametrize(
        ("lua_output", "expected_state"),
        [
            ("ACQUIRED", ReservationState.ACQUIRED),
            (b"ACQUIRED", ReservationState.ACQUIRED),
            ("PROCESSING", ReservationState.PROCESSING),
            (b"PROCESSING", ReservationState.PROCESSING),
            ("COMPLETED", ReservationState.COMPLETED),
            (b"COMPLETED", ReservationState.COMPLETED),
            ("UNKNOWN", ReservationState.PROCESSING),
        ],
    )
    def test_reserve_outcomes(self, lua_output: Any, expected_state: ReservationState) -> None:
        client = MagicMock()
        client.eval.return_value = lua_output
        store = RedisWebhookReservationStore(client=client)
        attempt = store.reserve("evt_1", token="tok_123", ttl_seconds=45)
        assert attempt.state == expected_state
        if expected_state == ReservationState.ACQUIRED:
            assert attempt.reservation is not None
            assert attempt.reservation.token == "tok_123"
        else:
            assert attempt.reservation is None

    @pytest.mark.parametrize(
        ("failure_mode", "expected_state", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, ReservationState.ACQUIRED, False),
        ],
    )
    def test_reserve_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected_state: ReservationState | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval.side_effect = ConnectionError("Redis connection lost")
        store = RedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(DiditDedupError, match="Redis reservation store reserve failed"):
                store.reserve("evt_err", token="tok")
        else:
            attempt = store.reserve("evt_err", token="tok")
            assert attempt.state == expected_state

    def test_redis_lua_reserve_script_contract(self) -> None:
        from didit.dedup import LUA_COMPLETE, LUA_RELEASE, LUA_RESERVE

        # Lua reserve MUST call EXPIRE on same-token reentrancy to refresh TTL
        assert "redis.call('EXPIRE', KEYS[1], ARGV[2])" in LUA_RESERVE
        assert "PROCESSING:' .. ARGV[1]" in LUA_RESERVE
        assert "COMPLETED" in LUA_COMPLETE
        assert "redis.call('DEL', KEYS[1])" in LUA_RELEASE

    def test_redis_ambiguous_reserve_recovery(self) -> None:
        client = MagicMock()
        # Attempt 1: command executed in Redis, but network response timed out
        # Attempt 2: retry with the exact same token succeeds via Lua same-token CAS branch
        client.eval.side_effect = [TimeoutError("ambiguous network disconnect"), "ACQUIRED"]
        store = RedisWebhookReservationStore(client=client, failure_mode=DedupFailureMode.RAISE)

        with pytest.raises(DiditDedupError):
            store.reserve("evt_ambig", token="worker_token_1", ttl_seconds=30)

        # Retry with the same token recovers the lease and refreshes TTL
        retry_attempt = store.reserve("evt_ambig", token="worker_token_1", ttl_seconds=30)
        assert retry_attempt.state == ReservationState.ACQUIRED
        assert retry_attempt.reservation is not None
        assert retry_attempt.reservation.token == "worker_token_1"

    @pytest.mark.parametrize(
        ("lua_output", "expected"),
        [(1, True), (0, False)],
    )
    def test_complete_outcomes(self, lua_output: int, expected: bool) -> None:
        client = MagicMock()
        client.eval.return_value = lua_output
        store = RedisWebhookReservationStore(client=client)
        assert store.complete("evt_1", "tok_1", completed_ttl=3600) is expected

    @pytest.mark.parametrize(
        ("failure_mode", "expected", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, False, False),
        ],
    )
    def test_complete_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected: bool | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval.side_effect = TimeoutError("Redis timeout")
        store = RedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(DiditDedupError, match="Redis reservation store complete failed"):
                store.complete("evt_err", "tok")
        else:
            assert store.complete("evt_err", "tok") is expected

    @pytest.mark.parametrize(
        ("lua_output", "expected"),
        [(1, True), (0, False)],
    )
    def test_release_outcomes(self, lua_output: int, expected: bool) -> None:
        client = MagicMock()
        client.eval.return_value = lua_output
        store = RedisWebhookReservationStore(client=client)
        assert store.release("evt_1", "tok_1") is expected

    @pytest.mark.parametrize(
        ("failure_mode", "expected", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, False, False),
        ],
    )
    def test_release_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected: bool | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval.side_effect = TimeoutError("Redis timeout")
        store = RedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(DiditDedupError, match="Redis reservation store release failed"):
                store.release("evt_err", "tok")
        else:
            assert store.release("evt_err", "tok") is expected

    @pytest.mark.parametrize(
        ("lua_output", "expected"),
        [(1, True), (0, False)],
    )
    def test_renew_outcomes(self, lua_output: int, expected: bool) -> None:
        client = MagicMock()
        client.eval.return_value = lua_output
        store = RedisWebhookReservationStore(client=client)
        assert store.renew("evt_1", "tok_1", ttl_seconds=30) is expected

    @pytest.mark.parametrize(
        ("failure_mode", "expected", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, False, False),
        ],
    )
    def test_renew_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected: bool | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval.side_effect = TimeoutError("Redis timeout")
        store = RedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(DiditDedupError, match="Redis reservation store renew failed"):
                store.renew("evt_err", "tok", ttl_seconds=30)
        else:
            assert store.renew("evt_err", "tok", ttl_seconds=30) is expected

    def test_backward_compatibility_claim_and_release(self) -> None:
        client = MagicMock()
        client.eval.side_effect = ["ACQUIRED", "PROCESSING"]
        client.delete.return_value = 1
        store = RedisWebhookReservationStore(client=client)

        assert store.claim("legacy_k") is True
        assert store.claim("legacy_k") is False
        store.release_claim("legacy_k")
        client.delete.assert_called_once()

    def test_backward_compatibility_release_error_handling(self) -> None:
        client = MagicMock()
        client.delete.side_effect = TimeoutError("Redis down")
        store = RedisWebhookReservationStore(client=client, failure_mode=DedupFailureMode.FAIL_OPEN)
        store.release_claim("legacy_k")

        store_raise = RedisWebhookReservationStore(
            client=client, failure_mode=DedupFailureMode.RAISE
        )
        with pytest.raises(DiditDedupError, match="Redis reservation store release_claim failed"):
            store_raise.release_claim("legacy_k")


class TestAsyncRedisReservationStore:
    def test_from_url_success(self) -> None:
        with patch("redis.asyncio.Redis.from_url") as mock_from_url:
            mock_client = MagicMock()
            mock_from_url.return_value = mock_client
            store = AsyncRedisWebhookReservationStore.from_url(
                "redis://localhost:6379/0", namespace="async_ns"
            )
            assert store.namespace == "async_ns"
            assert store._client is mock_client

    def test_from_url_import_error(self) -> None:
        from didit.errors import DiditConfigurationError

        with (
            patch.dict("sys.modules", {"redis.asyncio": None}),
            pytest.raises(DiditConfigurationError, match="redis-py is required"),
        ):
            AsyncRedisWebhookReservationStore.from_url("redis://localhost:6379/0")

    @pytest.mark.asyncio
    async def test_invalid_arguments(self) -> None:
        store = AsyncRedisWebhookReservationStore(client=MagicMock())
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            await store.areserve("evt", ttl_seconds=0)
        with pytest.raises(ValueError, match="completed_ttl must be greater than zero"):
            await store.acomplete("evt", "tok", completed_ttl=0)
        with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
            await store.arenew("evt", "tok", ttl_seconds=0)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("lua_output", "expected_state"),
        [
            ("ACQUIRED", ReservationState.ACQUIRED),
            (b"ACQUIRED", ReservationState.ACQUIRED),
            ("PROCESSING", ReservationState.PROCESSING),
            ("COMPLETED", ReservationState.COMPLETED),
        ],
    )
    async def test_areserve_outcomes(
        self, lua_output: Any, expected_state: ReservationState
    ) -> None:
        client = MagicMock()
        client.eval = AsyncMock(return_value=lua_output)
        store = AsyncRedisWebhookReservationStore(client=client)
        attempt = await store.areserve("evt_1", token="tok_1", ttl_seconds=30)
        assert attempt.state == expected_state

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("lua_output", "expected"),
        [(1, True), (0, False)],
    )
    async def test_acomplete_outcomes(self, lua_output: int, expected: bool) -> None:
        client = MagicMock()
        client.eval = AsyncMock(return_value=lua_output)
        store = AsyncRedisWebhookReservationStore(client=client)
        assert await store.acomplete("evt_1", "tok_1", completed_ttl=3600) is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("lua_output", "expected"),
        [(1, True), (0, False)],
    )
    async def test_arelease_outcomes(self, lua_output: int, expected: bool) -> None:
        client = MagicMock()
        client.eval = AsyncMock(return_value=lua_output)
        store = AsyncRedisWebhookReservationStore(client=client)
        assert await store.arelease("evt_1", "tok_1") is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("lua_output", "expected"),
        [(1, True), (0, False)],
    )
    async def test_arenew_outcomes(self, lua_output: int, expected: bool) -> None:
        client = MagicMock()
        client.eval = AsyncMock(return_value=lua_output)
        store = AsyncRedisWebhookReservationStore(client=client)
        assert await store.arenew("evt_1", "tok_1", ttl_seconds=30) is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("failure_mode", "expected_state", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, ReservationState.ACQUIRED, False),
        ],
    )
    async def test_areserve_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected_state: ReservationState | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval = AsyncMock(side_effect=ConnectionError("Async Redis error"))
        store = AsyncRedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(
                DiditDedupError, match="Async Redis reservation store reserve failed"
            ):
                await store.areserve("evt_err", token="tok")
        else:
            attempt = await store.areserve("evt_err", token="tok")
            assert attempt.state == expected_state

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("failure_mode", "expected", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, False, False),
        ],
    )
    async def test_acomplete_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected: bool | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval = AsyncMock(side_effect=TimeoutError("Timeout"))
        store = AsyncRedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(
                DiditDedupError, match="Async Redis reservation store complete failed"
            ):
                await store.acomplete("evt_err", "tok")
        else:
            assert await store.acomplete("evt_err", "tok") is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("failure_mode", "expected", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, False, False),
        ],
    )
    async def test_arelease_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected: bool | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval = AsyncMock(side_effect=TimeoutError("Timeout"))
        store = AsyncRedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(
                DiditDedupError, match="Async Redis reservation store release failed"
            ):
                await store.arelease("evt_err", "tok")
        else:
            assert await store.arelease("evt_err", "tok") is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("failure_mode", "expected", "should_raise"),
        [
            (DedupFailureMode.RAISE, None, True),
            (DedupFailureMode.FAIL_OPEN, False, False),
        ],
    )
    async def test_arenew_failure_modes(
        self,
        failure_mode: DedupFailureMode,
        expected: bool | None,
        should_raise: bool,
    ) -> None:
        client = MagicMock()
        client.eval = AsyncMock(side_effect=TimeoutError("Timeout"))
        store = AsyncRedisWebhookReservationStore(client=client, failure_mode=failure_mode)

        if should_raise:
            with pytest.raises(DiditDedupError, match="Async Redis reservation store renew failed"):
                await store.arenew("evt_err", "tok", ttl_seconds=30)
        else:
            assert await store.arenew("evt_err", "tok", ttl_seconds=30) is expected

    @pytest.mark.asyncio
    async def test_async_backward_compatibility(self) -> None:
        client = MagicMock()
        client.eval = AsyncMock(side_effect=["ACQUIRED", "PROCESSING"])
        client.delete = AsyncMock(return_value=1)
        store = AsyncRedisWebhookReservationStore(client=client)

        assert await store.aclaim("k_legacy") is True
        assert await store.aclaim("k_legacy") is False
        await store.arelease_claim("k_legacy")
        client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_backward_compatibility_release_error_handling(self) -> None:
        client = MagicMock()
        client.delete = AsyncMock(side_effect=TimeoutError("Redis down"))
        store = AsyncRedisWebhookReservationStore(
            client=client, failure_mode=DedupFailureMode.FAIL_OPEN
        )
        await store.arelease_claim("k_legacy")

        store_raise = AsyncRedisWebhookReservationStore(
            client=client, failure_mode=DedupFailureMode.RAISE
        )
        with pytest.raises(
            DiditDedupError, match="Async Redis reservation store arelease_claim failed"
        ):
            await store_raise.arelease_claim("k_legacy")

    def test_sync_methods_do_not_exist(self) -> None:
        store = AsyncRedisWebhookReservationStore(client=MagicMock())
        assert not hasattr(store, "reserve")
        assert not hasattr(store, "complete")
        assert not hasattr(store, "release")
        assert not hasattr(store, "renew")
        assert not hasattr(store, "claim")


class TestReservationDispatchHelpers:
    def test_sync_reserve_and_complete(self) -> None:
        store = InMemoryWebhookReservationStore()
        attempt = reserve_webhook_event(store, "evt_disp", ttl_seconds=30)
        assert attempt.state == ReservationState.ACQUIRED
        assert attempt.reservation is not None
        tok = attempt.reservation.token

        assert renew_webhook_event(store, "evt_disp", tok, ttl_seconds=30) is True
        assert complete_webhook_event(store, "evt_disp", tok) is True

    def test_sync_reserve_with_legacy_claim_store(self) -> None:
        class LegacySyncStore:
            def __init__(self) -> None:
                self.claimed = False

            def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
                if not self.claimed:
                    self.claimed = True
                    return True
                return False

        legacy = LegacySyncStore()
        att1 = reserve_webhook_event(legacy, "k_leg", ttl_seconds=30)
        assert att1.state == ReservationState.ACQUIRED
        att2 = reserve_webhook_event(legacy, "k_leg", ttl_seconds=30)
        assert att2.state == ReservationState.COMPLETED
        # Legacy store has no complete or renew; helper returns defaults
        assert complete_webhook_event(legacy, "k_leg", "tok") is True
        assert renew_webhook_event(legacy, "k_leg", "tok", ttl_seconds=30) is False

    def test_sync_reserve_invalid_store_raises(self) -> None:
        from didit.errors import DiditConfigurationError

        with pytest.raises(DiditConfigurationError, match="does not implement"):
            reserve_webhook_event(object(), "bad")

    @pytest.mark.asyncio
    async def test_areserve_and_acomplete_with_various_stores(self) -> None:
        # Async store with areserve
        async_store = InMemoryWebhookReservationStore()
        att = await areserve_webhook_event(async_store, "evt_a")
        assert att.state == ReservationState.ACQUIRED
        assert att.reservation is not None
        tok = att.reservation.token
        assert await arenew_webhook_event(async_store, "evt_a", tok) is True
        assert await acomplete_webhook_event(async_store, "evt_a", tok) is True

        # Store with coroutine reserve
        class CoroReserveStore:
            async def reserve(
                self, event_id: str, token: str | None = None, ttl_seconds: int = 30
            ) -> ReservationAttempt:
                return ReservationAttempt(
                    state=ReservationState.ACQUIRED,
                    reservation=WebhookReservation(
                        event_id=event_id, token=token or "t", expires_at=100.0
                    ),
                )

            async def renew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
                return True

            async def complete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
                return True

        coro_store = CoroReserveStore()
        att_c = await areserve_webhook_event(coro_store, "evt_coro")
        assert att_c.state == ReservationState.ACQUIRED
        assert await arenew_webhook_event(coro_store, "evt_coro", "t") is True
        assert await acomplete_webhook_event(coro_store, "evt_coro", "t") is True

        # Store with synchronous reserve
        class SyncOnlyReserveStore:
            def reserve(
                self, event_id: str, token: str | None = None, ttl_seconds: int = 30
            ) -> ReservationAttempt:
                return ReservationAttempt(state=ReservationState.ACQUIRED)

            def complete(self, event_id: str, token: str, completed_ttl: int = 86400) -> bool:
                return True

        sync_only = SyncOnlyReserveStore()
        att_s = await areserve_webhook_event(sync_only, "evt_s")
        assert att_s.state == ReservationState.ACQUIRED
        assert await acomplete_webhook_event(sync_only, "evt_s", "t") is True

        # Store with aclaim
        class AclaimOnlyStore:
            async def aclaim(self, event_id: str, ttl_seconds: int = 30) -> bool:
                return True

        aclaim_store = AclaimOnlyStore()
        att_ac = await areserve_webhook_event(aclaim_store, "evt_ac")
        assert att_ac.state == ReservationState.ACQUIRED

        # Store with sync claim
        class SyncClaimOnlyStore:
            def claim(self, event_id: str, ttl_seconds: int = 30) -> bool:
                return False

        sync_claim_store = SyncClaimOnlyStore()
        att_sc = await areserve_webhook_event(sync_claim_store, "evt_sc")
        assert att_sc.state == ReservationState.COMPLETED

        # Store without reserve or claim
        from didit.errors import DiditConfigurationError

        with pytest.raises(DiditConfigurationError, match="does not implement"):
            await areserve_webhook_event(object(), "bad")

        # Store with coroutine claim (not aclaim)
        class CoroClaimStore:
            async def claim(self, event_id: str, ttl_seconds: int = 30) -> bool:
                return True

        coro_claim = CoroClaimStore()
        att_cc = await areserve_webhook_event(coro_claim, "evt_cc")
        assert att_cc.state == ReservationState.ACQUIRED

        # acomplete_webhook_event with store having no complete method
        assert await acomplete_webhook_event(object(), "evt_nocomplete", "tok") is True

        # arenew_webhook_event with sync renew and store without renew
        class SyncRenewStore:
            def renew(self, event_id: str, token: str, ttl_seconds: int = 30) -> bool:
                return True

        assert await arenew_webhook_event(SyncRenewStore(), "k", "t") is True
        assert await arenew_webhook_event(object(), "k", "t") is False

    @pytest.mark.asyncio
    async def test_release_helpers(self) -> None:
        # Store with release(event_id, token)
        store = InMemoryWebhookReservationStore()
        att = store.reserve("rel_1", ttl_seconds=30)
        assert att.reservation is not None
        tok = att.reservation.token
        release_webhook_event(store, "rel_1", token=tok)
        assert store.reserve("rel_1", ttl_seconds=30).state == ReservationState.ACQUIRED

        # Store with legacy release(event_id)
        class LegacyReleaseStore:
            def __init__(self) -> None:
                self.released_key: str | None = None

            def release(self, event_id: str) -> None:
                self.released_key = event_id

        legacy_rel = LegacyReleaseStore()
        release_webhook_event(legacy_rel, "leg_k", token="ignored_tok")
        assert legacy_rel.released_key == "leg_k"

        # Async arelease_webhook_event with token
        att2 = await store.areserve("rel_2", ttl_seconds=30)
        assert att2.reservation is not None
        tok2 = att2.reservation.token
        await arelease_webhook_event(store, "rel_2", token=tok2)
        assert (await store.areserve("rel_2", ttl_seconds=30)).state == ReservationState.ACQUIRED

        # Async store with arelease(event_id, token)
        class AsyncReleaseStore:
            def __init__(self) -> None:
                self.released = False

            async def arelease(self, event_id: str, token: str) -> None:
                self.released = True

        async_rel = AsyncReleaseStore()
        await arelease_webhook_event(async_rel, "k", token="tok")
        assert async_rel.released is True

        # Coroutine release with token
        class CoroReleaseWithTokenStore:
            def __init__(self) -> None:
                self.released = False

            async def release(self, event_id: str, token: str) -> None:
                self.released = True

        coro_tok = CoroReleaseWithTokenStore()
        await arelease_webhook_event(coro_tok, "k", token="tok")
        assert coro_tok.released is True

        # Sync release with token via arelease_webhook_event
        class SyncReleaseWithTokenStore:
            def __init__(self) -> None:
                self.released = False

            def release(self, event_id: str, token: str) -> None:
                self.released = True

        sync_tok = SyncReleaseWithTokenStore()
        await arelease_webhook_event(sync_tok, "k", token="tok")
        assert sync_tok.released is True

    @pytest.mark.asyncio
    async def test_aclaim_webhook_event_branches(self) -> None:
        from didit.dedup import aclaim_webhook_event

        class AclaimBranchStore:
            async def aclaim(self, key: str, ttl_seconds: int = 86400) -> bool:
                return True

        assert await aclaim_webhook_event(AclaimBranchStore(), "k") is True

        class SyncClaimBranchStore:
            def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
                return True

        assert await aclaim_webhook_event(SyncClaimBranchStore(), "k") is True
