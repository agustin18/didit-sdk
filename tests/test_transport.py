"""Unit tests for the transport engine, safe retries, and requestors."""

from __future__ import annotations

import asyncio
import datetime
import os
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from didit.errors import (
    DiditAPIError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditNotFoundError,
    DiditPoolTimeoutError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
from didit.events import DiditEventSink, DiditSDKEvent, RequestRetryScheduled
from didit.transport import (
    RequestOptions,
    RetryPolicy,
    _AsyncRequestor,
    _SyncRequestor,
    should_retry,
)


class TestRequestOptions:
    def test_request_options_defaults(self) -> None:
        opts = RequestOptions()
        assert opts.idempotency_key is None
        assert opts.timeout is None
        assert opts.max_retries is None
        assert opts.headers is None

    def test_request_options_custom(self) -> None:
        opts = RequestOptions(
            idempotency_key="idem_123",
            timeout=5.0,
            max_retries=1,
            headers={"X-Custom-Header": "custom-val"},
        )
        assert opts.idempotency_key == "idem_123"
        assert opts.timeout == 5.0
        assert opts.max_retries == 1
        assert opts.headers == {"X-Custom-Header": "custom-val"}

    def test_request_options_frozen(self) -> None:
        import dataclasses

        opts = RequestOptions()
        with pytest.raises(dataclasses.FrozenInstanceError):
            opts.idempotency_key = "mutated"  # type: ignore[misc]


class TestRetryPolicy:
    def test_calculate_delay_jitter_false(self) -> None:
        policy = RetryPolicy(base_delay=1.0, backoff_factor=2.0, max_delay=10.0, jitter=False)
        assert policy.calculate_delay(0) == 1.0
        assert policy.calculate_delay(1) == 2.0
        assert policy.calculate_delay(2) == 4.0
        assert policy.calculate_delay(3) == 8.0
        assert policy.calculate_delay(4) == 10.0  # capped at max_delay

    def test_calculate_delay_jitter_true(self) -> None:
        policy = RetryPolicy(base_delay=1.0, backoff_factor=2.0, max_delay=10.0, jitter=True)
        for attempt in range(5):
            delay = policy.calculate_delay(attempt)
            cap = min(10.0, 1.0 * (2.0**attempt))
            assert 0.0 <= delay <= cap

    @pytest.mark.parametrize(
        ("header_val", "expected"),
        [
            ("10", 10.0),
            ("0.5", 0.5),
            ("0", 0.0),
            ("-5", 0.0),
            ("120", 120.0),
            ("not-a-number", None),
            ("", None),
            (None, None),
        ],
    )
    def test_parse_retry_after_seconds(
        self, header_val: str | None, expected: float | None
    ) -> None:
        policy = RetryPolicy(max_retry_after=60.0)
        parsed = policy.parse_retry_after(header_val)
        assert parsed == expected

    def test_parse_retry_after_http_date(self) -> None:
        policy = RetryPolicy(max_retry_after=60.0)
        # 10 seconds in the future
        future_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=10)
        # Format as RFC 7231 / RFC 2822: "Wed, 21 Oct 2026 07:28:00 GMT"
        date_str = future_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
        parsed = policy.parse_retry_after(date_str)
        assert parsed is not None
        assert 8.0 <= parsed <= 12.0

        # Past date returns 0.0
        past_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)
        past_date_str = past_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert policy.parse_retry_after(past_date_str) == 0.0


class TestShouldRetry:
    @pytest.mark.parametrize(
        ("method", "status", "exc", "attempt", "max_retries", "idempotency_key", "expected"),
        [
            # Safe GET methods on server/rate errors
            ("GET", 408, None, 0, 3, None, True),
            ("GET", 429, None, 0, 3, None, True),
            ("GET", 500, None, 0, 3, None, True),
            ("GET", 502, None, 0, 3, None, True),
            ("GET", 503, None, 0, 3, None, True),
            ("GET", 504, None, 0, 3, None, True),
            # Non-retryable client errors
            ("GET", 400, None, 0, 3, None, False),
            ("GET", 401, None, 0, 3, None, False),
            ("GET", 403, None, 0, 3, None, False),
            ("GET", 404, None, 0, 3, None, False),
            ("GET", 422, None, 0, 3, None, False),
            # POST safety: 5xx and 429 without idempotency key are NOT retried
            ("POST", 500, None, 0, 3, None, False),
            ("POST", 503, None, 0, 3, None, False),
            ("POST", 429, None, 0, 3, None, False),
            # POST with idempotency key IS retried
            ("POST", 500, None, 0, 3, "idem_abc", True),
            ("POST", 503, None, 0, 3, "idem_abc", True),
            ("POST", 429, None, 0, 3, "idem_abc", True),
            # Attempt exhaustion
            ("GET", 503, None, 3, 3, None, False),
            ("GET", 503, None, 4, 3, None, False),
            # PoolTimeout is NEVER retried (prevents pool starvation)
            ("GET", None, httpx.PoolTimeout("exhausted"), 0, 3, None, False),
            ("POST", None, httpx.PoolTimeout("exhausted"), 0, 3, "idem_abc", False),
            # ConnectError can be safely retried even on POST
            ("POST", None, httpx.ConnectError("refused"), 0, 3, None, True),
            ("GET", None, httpx.ConnectTimeout("conn timeout"), 0, 3, None, True),
            # ReadTimeout is retried only if safe or idempotent
            ("GET", None, httpx.ReadTimeout("read timeout"), 0, 3, None, True),
            ("POST", None, httpx.ReadTimeout("read timeout"), 0, 3, None, False),
            ("POST", None, httpx.ReadTimeout("read timeout"), 0, 3, "idem_abc", True),
            # Other errors and null cases
            ("GET", None, None, 0, 3, None, False),
            ("GET", None, httpx.DecodingError("decoding"), 0, 3, None, False),
        ],
    )
    def test_should_retry_matrix(
        self,
        method: str,
        status: int | None,
        exc: Exception | None,
        attempt: int,
        max_retries: int,
        idempotency_key: str | None,
        expected: bool,
    ) -> None:
        result = should_retry(
            method=method,
            status_code=status,
            error=exc,
            attempt=attempt,
            max_retries=max_retries,
            idempotency_key=idempotency_key,
        )
        assert result is expected


class TestSyncRequestor:
    @respx.mock
    def test_sync_request_success_and_headers(self) -> None:
        route = respx.get("https://api.didit.me/v3/session/").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        client = httpx.Client()
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
        )
        resp = requestor.request("GET", "/session/")
        assert resp.status_code == 200
        assert route.call_count == 1

        sent_request = route.calls[0].request
        assert sent_request.headers["x-api-key"] == "key_123"
        assert sent_request.headers["Accept"] == "application/json"
        assert "didit-sdk-python/" in sent_request.headers["User-Agent"]

    @respx.mock
    def test_sync_request_options_and_absolute_url(self) -> None:
        route = respx.post("https://api.didit.me/v3/webhook").mock(
            return_value=httpx.Response(200, json={"received": True})
        )
        client = httpx.Client()
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
        )
        opts = RequestOptions(
            idempotency_key="idem_999",
            headers={"X-Extra": "extra-value"},
            timeout=15.0,
        )
        resp = requestor.request(
            "POST",
            "https://api.didit.me/v3/webhook",
            json={"data": 1},
            options=opts,
        )
        assert resp.status_code == 200
        sent_request = route.calls[0].request
        assert sent_request.headers["Idempotency-Key"] == "idem_999"
        assert sent_request.headers["X-Extra"] == "extra-value"

    @respx.mock
    def test_sync_request_retry_recovers(self) -> None:
        # Fails once with 503, succeeds on second attempt
        route = respx.get("https://api.didit.me/v3/status").mock(
            side_effect=[
                httpx.Response(503, json={"error": "service unavailable"}),
                httpx.Response(200, json={"healthy": True}),
            ]
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        resp = requestor.request("GET", "/status")
        assert resp.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_sync_request_retry_exhausted_raises_server_error(self) -> None:
        respx.get("https://api.didit.me/v3/status").mock(
            return_value=httpx.Response(503, json={"error_code": "DOWN", "detail": "Unavailable"})
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        with pytest.raises(DiditServerError) as exc_info:
            requestor.request("GET", "/status")
        assert exc_info.value.status_code == 503
        assert exc_info.value.error_code == "DOWN"

    @respx.mock
    def test_sync_request_retry_after_within_ceiling(self) -> None:
        route = respx.get("https://api.didit.me/v3/rate").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.01"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=1, max_retry_after=60.0)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        resp = requestor.request("GET", "/rate")
        assert resp.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_sync_request_retry_after_exceeds_ceiling_aborts(self) -> None:
        respx.get("https://api.didit.me/v3/rate").mock(
            return_value=httpx.Response(
                429,
                headers={"Retry-After": "120"},
                json={"error": "Rate limit exceeded"},
            )
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=3, max_retry_after=60.0)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        with pytest.raises(DiditRateLimitError) as exc_info:
            requestor.request("GET", "/rate")
        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == 120.0

    def test_sync_request_pool_timeout_fails_fast(self) -> None:
        class SaturatedTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.PoolTimeout("All pool connections checked out")

        client = httpx.Client(transport=SaturatedTransport())
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=RetryPolicy(max_retries=3),
        )
        with pytest.raises(DiditPoolTimeoutError) as exc_info:
            requestor.request("GET", "/test")
        assert "pool" in str(exc_info.value).lower()

    def test_sync_request_connect_error(self) -> None:
        class ConnErrTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("DNS lookup failed")

        client = httpx.Client(transport=ConnErrTransport())
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        with pytest.raises(DiditConnectionError) as exc_info:
            requestor.request("GET", "/test")
        assert "connect" in str(exc_info.value).lower()

    def test_sync_request_read_timeout_retries_and_raises(self) -> None:
        class ReadTimeoutTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadTimeout("Server did not send bytes in time")

        client = httpx.Client(transport=ReadTimeoutTransport())
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        with pytest.raises(DiditTimeoutError) as exc_info:
            requestor.request("GET", "/test")
        assert "timed out" in str(exc_info.value).lower()


class TestAsyncRequestor:
    @respx.mock
    @pytest.mark.asyncio
    async def test_async_request_success_and_retries(self) -> None:
        route = respx.get("https://api.didit.me/v3/async-status").mock(
            side_effect=[
                httpx.Response(502, json={"error": "bad gateway"}),
                httpx.Response(200, json={"status": "ok"}),
            ]
        )
        client = httpx.AsyncClient()
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
            retry_policy=policy,
        )
        resp = await requestor.request("GET", "/async-status")
        assert resp.status_code == 200
        assert route.call_count == 2
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_request_pool_timeout_fails_fast(self) -> None:
        class AsyncSaturatedTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.PoolTimeout("Pool exhausted in async")

        client = httpx.AsyncClient(transport=AsyncSaturatedTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
            retry_policy=RetryPolicy(max_retries=3),
        )
        with pytest.raises(DiditPoolTimeoutError):
            await requestor.request("GET", "/async-test")
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_request_connect_and_timeout_errors(self) -> None:
        class AsyncConnErrTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("Async connection failed")

        client = httpx.AsyncClient(transport=AsyncConnErrTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
            retry_policy=RetryPolicy(max_retries=1, base_delay=0.001, jitter=False),
        )
        with pytest.raises(DiditConnectionError):
            await requestor.request("GET", "/async-test")
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_retry_after_exceeds_ceiling_aborts(self) -> None:
        respx.get("https://api.didit.me/v3/async-rate").mock(
            return_value=httpx.Response(429, headers={"Retry-After": "999"})
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
            retry_policy=RetryPolicy(max_retries=2, max_retry_after=60.0),
        )
        with pytest.raises(DiditRateLimitError):
            await requestor.request("GET", "/async-rate")
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_request_handles_http_error_on_404(self) -> None:
        from didit.errors import DiditNotFoundError

        respx.get("https://api.didit.me/v3/not-found").mock(
            return_value=httpx.Response(404, json={"error": "missing"})
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
        )
        with pytest.raises(DiditNotFoundError):
            await requestor.request("GET", "/not-found")
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_connect_error_retries_and_recovers(self) -> None:
        calls = 0

        class FlakyConnTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise httpx.ConnectError("Transient DNS failure")
                return httpx.Response(200, json={"recovered": True})

        client = httpx.AsyncClient(transport=FlakyConnTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
            retry_policy=RetryPolicy(max_retries=2, base_delay=0.001, jitter=False),
        )
        resp = await requestor.request("GET", "/async-flaky")
        assert resp.status_code == 200
        assert calls == 2
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_read_timeout_retries_and_raises(self) -> None:
        class AsyncTimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadTimeout("Server timed out in async")

        client = httpx.AsyncClient(transport=AsyncTimeoutTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="async_key",
            retry_policy=RetryPolicy(max_retries=1, base_delay=0.001, jitter=False),
        )
        with pytest.raises(DiditTimeoutError):
            await requestor.request("GET", "/async-timeout")
        await client.aclose()

    def test_build_headers_partial_options(self) -> None:
        from didit.transport import _build_headers

        h1 = _build_headers("key", RequestOptions(idempotency_key="only_key"))
        assert h1["Idempotency-Key"] == "only_key"
        assert "X-Extra" not in h1

        h2 = _build_headers("key", RequestOptions(headers={"X-Extra": "val"}))
        assert "Idempotency-Key" not in h2
        assert h2["X-Extra"] == "val"

    def test_merge_options(self) -> None:
        from didit.transport import _merge_options

        # Base is None
        opt = RequestOptions(idempotency_key="opt1")
        assert _merge_options(None, opt) is opt
        assert _merge_options(opt, None) is opt

        # Both present, override merges on top of base
        base = RequestOptions(
            idempotency_key="base_key",
            timeout=10.0,
            headers={"A": "1", "B": "2"},
        )
        override = RequestOptions(idempotency_key="new_key", headers={"B": "override", "C": "3"})
        merged = _merge_options(base, override)
        assert merged is not None
        assert merged.idempotency_key == "new_key"
        assert merged.timeout == 10.0
        assert merged.headers == {"A": "1", "B": "override", "C": "3"}

        # Override without headers preserves base headers
        override_no_hdr = RequestOptions(idempotency_key="only_key")
        merged_no_hdr = _merge_options(base, override_no_hdr)
        assert merged_no_hdr is not None
        assert merged_no_hdr.headers == {"A": "1", "B": "2"}

    def test_cross_origin_absolute_url_raises_configuration_error(self) -> None:
        client = httpx.Client()
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
        )
        with pytest.raises(DiditConfigurationError) as exc_info:
            requestor.request("GET", "https://attacker.example.com/steal-api-key")
        assert "Cross-origin absolute URLs are not allowed" in str(exc_info.value)

    @pytest.mark.parametrize("header_name", ["x-api-key", "Host", "User-Agent", "idempotency-key"])
    def test_reserved_header_override_forbidden(self, header_name: str) -> None:
        client = httpx.Client()
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
        )
        opts = RequestOptions(headers={header_name: "malicious-value"})
        with pytest.raises(DiditConfigurationError) as exc_info:
            requestor.request("GET", "/test", options=opts)
        assert "Overriding reserved header" in str(exc_info.value)

    def test_deadline_expired_before_execution(self) -> None:
        import time

        client = httpx.Client()
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
        )
        opts = RequestOptions(deadline=time.monotonic() - 1.0)
        with pytest.raises(DiditTimeoutError) as exc_info:
            requestor.request("GET", "/test", options=opts)
        assert "deadline exceeded" in str(exc_info.value).lower()

    @respx.mock
    def test_deadline_exceeded_before_retry_backoff(self) -> None:
        import time

        respx.get("https://api.didit.me/v3/retry-fail").mock(
            return_value=httpx.Response(503, json={"error": "busy"})
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=3, base_delay=5.0, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.1)
        with pytest.raises(DiditTimeoutError) as exc_info:
            requestor.request("GET", "/retry-fail", options=opts)
        assert "deadline exceeded" in str(exc_info.value).lower()

    def test_network_transmission_errors_retry_and_mapping(self) -> None:
        class FlakySocketTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ReadError("TCP connection reset by peer")
                return httpx.Response(200, json={"ok": True})

        trans = FlakySocketTransport()
        client = httpx.Client(transport=trans)
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        resp = requestor.request("GET", "/safe-endpoint")
        assert resp.status_code == 200
        assert trans.calls == 2

    def test_network_transmission_error_exhausted_raises_connection_error(self) -> None:
        class BrokenPipeTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.WriteError("Broken pipe during write")

        client = httpx.Client(transport=BrokenPipeTransport())
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        with pytest.raises(DiditConnectionError) as exc_info:
            requestor.request("POST", "/unsafe-write")
        assert "Network error" in str(exc_info.value)

    @respx.mock
    def test_sync_retry_with_deadline_within_budget(self) -> None:
        import time

        route = respx.get("https://api.didit.me/v3/deadline-ok").mock(
            side_effect=[
                httpx.Response(503, json={"error": "busy"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="key_123",
            retry_policy=policy,
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = requestor.request("GET", "/deadline-ok", options=opts)
        assert resp.status_code == 200
        assert route.call_count == 2

    def test_sync_connect_error_deadline_exceeded_before_backoff(self) -> None:
        import time

        class FlakyConnectTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("Connection refused")

        client = httpx.Client(transport=FlakyConnectTransport())
        policy = RetryPolicy(max_retries=2, base_delay=10.0, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            requestor.request("GET", "/test", options=opts)

    def test_sync_read_timeout_deadline_exceeded_before_backoff(self) -> None:
        import time

        class FlakyTimeoutTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadTimeout("Read timed out")

        client = httpx.Client(transport=FlakyTimeoutTransport())
        policy = RetryPolicy(max_retries=2, base_delay=10.0, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            requestor.request("GET", "/test", options=opts)

    def test_sync_read_error_deadline_exceeded_before_backoff(self) -> None:
        import time

        class FlakyReadErrorTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadError("Reset by peer")

        client = httpx.Client(transport=FlakyReadErrorTransport())
        policy = RetryPolicy(max_retries=2, base_delay=10.0, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            requestor.request("GET", "/test", options=opts)

    @pytest.mark.asyncio
    async def test_async_deadline_already_exceeded_before_execution(self) -> None:
        import time

        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        opts = RequestOptions(deadline=time.monotonic() - 1.0)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            await requestor.request("GET", "/test", options=opts)
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_deadline_exceeded_before_retry_backoff(self) -> None:
        import time

        respx.get("https://api.didit.me/v3/retry-fail").mock(
            return_value=httpx.Response(503, json={"error": "busy"})
        )
        client = httpx.AsyncClient()
        policy = RetryPolicy(max_retries=3, base_delay=5.0, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            await requestor.request("GET", "/retry-fail", options=opts)
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_connect_error_deadline_exceeded(self) -> None:
        import time

        class FlakyAsyncConnectTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("Connection refused")

        client = httpx.AsyncClient(transport=FlakyAsyncConnectTransport())
        policy = RetryPolicy(max_retries=2, base_delay=10.0, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            await requestor.request("GET", "/test", options=opts)
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_read_timeout_deadline_exceeded(self) -> None:
        import time

        class FlakyAsyncTimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadTimeout("Read timed out")

        client = httpx.AsyncClient(transport=FlakyAsyncTimeoutTransport())
        policy = RetryPolicy(max_retries=2, base_delay=10.0, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            await requestor.request("GET", "/test", options=opts)
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_network_transmission_error_retry_and_mapping(self) -> None:
        class FlakyAsyncSocketTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ReadError("TCP reset")
                return httpx.Response(200, json={"ok": True})

        trans = FlakyAsyncSocketTransport()
        client = httpx.AsyncClient(transport=trans)
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        resp = await requestor.request("GET", "/safe")
        assert resp.status_code == 200
        assert trans.calls == 2
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_network_transmission_error_deadline_exceeded(self) -> None:
        import time

        class BrokenPipeAsyncTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadError("Network reset")

        client = httpx.AsyncClient(transport=BrokenPipeAsyncTransport())
        policy = RetryPolicy(max_retries=2, base_delay=10.0, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 0.05)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded"):
            await requestor.request("GET", "/test", options=opts)
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_network_transmission_error_exhausted(self) -> None:
        class BrokenPipeAsyncTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.WriteError("Broken pipe")

        client = httpx.AsyncClient(transport=BrokenPipeAsyncTransport())
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        with pytest.raises(DiditConnectionError, match="Network error"):
            await requestor.request("POST", "/unsafe-write")
        await client.aclose()

    def test_sync_connect_error_deadline_within_budget(self) -> None:
        import time

        class FlakyConnectTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ConnectError("Connection refused")
                return httpx.Response(200, json={"ok": True})

        client = httpx.Client(transport=FlakyConnectTransport())
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = requestor.request("GET", "/test", options=opts)
        assert resp.status_code == 200

    def test_sync_read_timeout_deadline_within_budget(self) -> None:
        import time

        class FlakyTimeoutTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ReadTimeout("Read timed out")
                return httpx.Response(200, json={"ok": True})

        client = httpx.Client(transport=FlakyTimeoutTransport())
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = requestor.request("GET", "/test", options=opts)
        assert resp.status_code == 200

    def test_sync_read_error_deadline_within_budget(self) -> None:
        import time

        class FlakyReadErrorTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ReadError("Reset by peer")
                return httpx.Response(200, json={"ok": True})

        client = httpx.Client(transport=FlakyReadErrorTransport())
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = requestor.request("GET", "/test", options=opts)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_retry_status_503_deadline_within_budget(self) -> None:
        import time

        route = respx.get("https://api.didit.me/v3/async-deadline-ok").mock(
            side_effect=[
                httpx.Response(503, json={"error": "busy"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        client = httpx.AsyncClient()
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = await requestor.request("GET", "/async-deadline-ok", options=opts)
        assert resp.status_code == 200
        assert route.call_count == 2
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_connect_error_deadline_within_budget(self) -> None:
        import time

        class FlakyAsyncConnectTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ConnectError("Connection refused")
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=FlakyAsyncConnectTransport())
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = await requestor.request("GET", "/test", options=opts)
        assert resp.status_code == 200
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_read_timeout_deadline_within_budget(self) -> None:
        import time

        class FlakyAsyncTimeoutTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ReadTimeout("Read timed out")
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=FlakyAsyncTimeoutTransport())
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = await requestor.request("GET", "/test", options=opts)
        assert resp.status_code == 200
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_read_error_deadline_within_budget(self) -> None:
        import time

        class FlakyAsyncReadErrorTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.ReadError("Reset by peer")
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=FlakyAsyncReadErrorTransport())
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        opts = RequestOptions(deadline=time.monotonic() + 10.0)
        resp = await requestor.request("GET", "/test", options=opts)
        assert resp.status_code == 200
        await client.aclose()

    @respx.mock
    def test_sync_external_client_with_follow_redirects_does_not_leak_api_key(self) -> None:
        from didit.errors import DiditAPIError

        respx.get("https://api.didit.me/v3/redirect-target").mock(
            return_value=httpx.Response(302, headers={"Location": "https://evil.attacker.com/leak"})
        )
        evil_route = respx.get("https://evil.attacker.com/leak").mock(
            return_value=httpx.Response(200, json={"stolen": True})
        )

        client = httpx.Client(follow_redirects=True)
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="secret-key")

        with pytest.raises(DiditAPIError) as exc_info:
            requestor.request("GET", "/redirect-target")

        assert exc_info.value.status_code == 302
        assert evil_route.call_count == 0
        client.close()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_external_client_with_follow_redirects_does_not_leak_api_key(self) -> None:
        from didit.errors import DiditAPIError

        respx.get("https://api.didit.me/v3/async-redirect").mock(
            return_value=httpx.Response(
                307, headers={"Location": "https://evil.attacker.com/steal"}
            )
        )
        evil_route = respx.get("https://evil.attacker.com/steal").mock(
            return_value=httpx.Response(200, json={"stolen": True})
        )

        client = httpx.AsyncClient(follow_redirects=True)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="secret-key"
        )

        with pytest.raises(DiditAPIError) as exc_info:
            await requestor.request("GET", "/async-redirect")

        assert exc_info.value.status_code == 307
        assert evil_route.call_count == 0
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_slow_drip_outer_wall_clock_timeout(self) -> None:
        import asyncio

        class SlowDripTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                await asyncio.sleep(0.3)
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=SlowDripTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="k",
            retry_policy=RetryPolicy(max_retries=0),
            default_timeout=0.05,
        )

        with pytest.raises(DiditTimeoutError, match="Request timed out during transmission"):
            await requestor.request("GET", "/slow")

        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_request_without_wall_clock_timeout(self) -> None:
        class FastTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=FastTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="k",
            default_timeout=None,
        )

        resp = await requestor.request("GET", "/fast")
        assert resp.status_code == 200
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_request_with_httpx_timeout_read(self) -> None:
        class FastTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=FastTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="k",
            default_timeout=None,
        )

        opts = RequestOptions(timeout=httpx.Timeout(10.0, read=5.0))
        resp = await requestor.request("GET", "/fast", options=opts)
        assert resp.status_code == 200
        await client.aclose()


class TransportRecordingSink(DiditEventSink):
    def __init__(self) -> None:
        self.events: list[DiditSDKEvent] = []

    def emit(self, event: DiditSDKEvent) -> None:
        self.events.append(event)


class TestTransportRetryTelemetryReasons:
    def test_sync_retry_scheduled_reasons(self) -> None:
        sink = TransportRecordingSink()

        # Network error simulation
        class FailTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.RemoteProtocolError("corrupted frame")
                return httpx.Response(200, json={"ok": True})

        client = httpx.Client(transport=FailTransport())
        requestor = _SyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="k",
            retry_policy=RetryPolicy(base_delay=0.001, jitter=False),
            event_sink=sink,
        )

        resp = requestor.request("GET", "/test-net-err")
        assert resp.status_code == 200
        client.close()

        retry_events = [e for e in sink.events if isinstance(e, RequestRetryScheduled)]
        assert len(retry_events) == 1
        assert retry_events[0].reason == "network_error"

    @pytest.mark.asyncio
    async def test_async_retry_scheduled_reasons(self) -> None:
        sink = TransportRecordingSink()

        class AsyncFailTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                if self.calls == 1:
                    raise httpx.RemoteProtocolError("corrupted frame")
                return httpx.Response(200, json={"ok": True})

        client = httpx.AsyncClient(transport=AsyncFailTransport())
        requestor = _AsyncRequestor(
            client,
            base_url="https://api.didit.me/v3",
            api_key="k",
            retry_policy=RetryPolicy(base_delay=0.001, jitter=False),
            event_sink=sink,
        )

        resp = await requestor.request("GET", "/test-net-err-async")
        assert resp.status_code == 200
        await client.aclose()

        retry_events = [e for e in sink.events if isinstance(e, RequestRetryScheduled)]
        assert len(retry_events) == 1
        assert retry_events[0].reason == "network_error"


class TestAtomicPublishAndStreamingDownload:
    """Validate atomic non-replacing file publication and direct-to-disk streaming."""

    def test_atomic_publish_force_true(self, tmp_path: Path) -> None:
        from didit.transport import _atomic_publish

        src = tmp_path / "src.tmp"
        dest = tmp_path / "dest.txt"
        src.write_text("source content")
        dest.write_text("existing content")

        _atomic_publish(src, dest, force=True)
        assert not src.exists()
        assert dest.read_text() == "source content"

    def test_atomic_publish_force_false_dest_exists(self, tmp_path: Path) -> None:
        from didit.transport import _atomic_publish

        src = tmp_path / "src.tmp"
        dest = tmp_path / "dest.txt"
        src.write_text("source content")
        dest.write_text("existing content")

        with pytest.raises(FileExistsError, match="already exists"):
            _atomic_publish(src, dest, force=False)
        assert not src.exists()
        assert dest.read_text() == "existing content"

    def test_atomic_publish_hardlink_oserror_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from didit.transport import _atomic_publish

        src = tmp_path / "src.tmp"
        dest = tmp_path / "dest.txt"
        src.write_text("fallback content")

        def broken_link(s: Any, d: Any) -> None:
            raise OSError("Operation not supported on filesystem")

        monkeypatch.setattr(os, "link", broken_link)
        with pytest.raises(OSError, match="does not support atomic link-based publication"):
            _atomic_publish(src, dest, force=False)
        assert not src.exists()
        assert not dest.exists()

        # When force=True, replace is used safely
        src_force = tmp_path / "src_force.tmp"
        src_force.write_text("forced content")
        _atomic_publish(src_force, dest, force=True)
        assert not src_force.exists()
        assert dest.read_text() == "forced content"

    def test_atomic_publish_hardlink_oserror_fallback_when_dest_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from didit.transport import _atomic_publish

        src = tmp_path / "src.tmp"
        dest = tmp_path / "dest.txt"
        src.write_text("fallback content")
        dest.write_text("existing content")

        def broken_link(s: Any, d: Any) -> None:
            raise OSError("Cross-device link not permitted")

        monkeypatch.setattr(os, "link", broken_link)
        with pytest.raises(FileExistsError, match="already exists"):
            _atomic_publish(src, dest, force=False)
        assert not src.exists()
        assert dest.read_text() == "existing content"

    def test_sync_stream_download_dest_exists_no_force(self, tmp_path: Path) -> None:
        dest = tmp_path / "report.pdf"
        dest.write_text("existing")
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        with pytest.raises(FileExistsError, match="already exists"):
            requestor.stream_download("/pdf", dest, force=False)

    @respx.mock
    def test_sync_stream_download_http_error(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/pdf-err").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "err.pdf"
        with pytest.raises(DiditNotFoundError):
            requestor.stream_download("/pdf-err", dest)
        assert not dest.exists()

    @respx.mock
    def test_sync_stream_download_invalid_mime(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/pdf-bad-mime").mock(
            return_value=httpx.Response(
                200, content=b"%PDF-1.4 test", headers={"Content-Type": "text/html"}
            )
        )
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "bad_mime.pdf"
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            requestor.stream_download("/pdf-bad-mime", dest)
        assert not dest.exists()

    @respx.mock
    def test_sync_stream_download_invalid_header_magic(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/pdf-bad-magic").mock(
            return_value=httpx.Response(
                200, content=b"INVALID_HEADER", headers={"Content-Type": "application/pdf"}
            )
        )
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "bad_magic.pdf"
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            requestor.stream_download("/pdf-bad-magic", dest)
        assert not dest.exists()

    @respx.mock
    def test_sync_stream_download_empty_body(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/pdf-empty").mock(
            return_value=httpx.Response(
                200, content=b"", headers={"Content-Type": "application/pdf"}
            )
        )
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "empty.pdf"
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            requestor.stream_download("/pdf-empty", dest)
        assert not dest.exists()

    def test_sync_stream_download_empty_chunk_skipped_and_no_validate(self, tmp_path: Path) -> None:
        class CustomSyncStream(httpx.SyncByteStream):
            def __iter__(self) -> Any:
                yield b""
                yield b"part1 "
                yield b"part2"

        class EmptyChunkTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    stream=CustomSyncStream(),
                    headers={"Content-Type": "application/octet-stream"},
                )

        client = httpx.Client(transport=EmptyChunkTransport())
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "raw.bin"
        saved = requestor.stream_download("/raw", dest, validate_pdf=False)
        assert saved == dest.resolve()
        assert dest.read_bytes() == b"part1 part2"

    @respx.mock
    def test_sync_stream_download_cleanup_on_write_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        respx.get("https://api.didit.me/v3/pdf-write-err").mock(
            return_value=httpx.Response(
                200, content=b"%PDF-1.4 ok", headers={"Content-Type": "application/pdf"}
            )
        )
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "write_err.pdf"

        def broken_fdopen(*args: Any, **kwargs: Any) -> Any:
            raise OSError("Disk write failed")

        monkeypatch.setattr(os, "fdopen", broken_fdopen)
        with pytest.raises(OSError, match="Disk write failed"):
            requestor.stream_download("/pdf-write-err", dest)
        assert not dest.exists()

    @pytest.mark.asyncio
    async def test_async_stream_download_dest_exists_no_force(self, tmp_path: Path) -> None:
        dest = tmp_path / "async_report.pdf"
        dest.write_text("existing")
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        with pytest.raises(FileExistsError, match="already exists"):
            await requestor.astream_download("/pdf", dest, force=False)
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_stream_download_http_error(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/async-pdf-err").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_err.pdf"
        with pytest.raises(DiditNotFoundError):
            await requestor.astream_download("/async-pdf-err", dest)
        assert not dest.exists()
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_stream_download_invalid_mime(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/async-bad-mime").mock(
            return_value=httpx.Response(
                200, content=b"%PDF-1.4 test", headers={"Content-Type": "text/html"}
            )
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_bad_mime.pdf"
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            await requestor.astream_download("/async-bad-mime", dest)
        assert not dest.exists()
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_stream_download_invalid_header_magic(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/async-bad-magic").mock(
            return_value=httpx.Response(
                200, content=b"INVALID_HEADER", headers={"Content-Type": "application/pdf"}
            )
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_bad_magic.pdf"
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            await requestor.astream_download("/async-bad-magic", dest)
        assert not dest.exists()
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_stream_download_empty_body(self, tmp_path: Path) -> None:
        respx.get("https://api.didit.me/v3/async-empty").mock(
            return_value=httpx.Response(
                200, content=b"", headers={"Content-Type": "application/pdf"}
            )
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_empty.pdf"
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            await requestor.astream_download("/async-empty", dest)
        assert not dest.exists()
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_stream_download_empty_chunk_skipped_and_no_validate(
        self, tmp_path: Path
    ) -> None:
        class CustomAsyncStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                yield b""
                yield b"async part1 "
                yield b"async part2"

        class AsyncEmptyChunkTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    stream=CustomAsyncStream(),
                    headers={"Content-Type": "application/octet-stream"},
                )

        client = httpx.AsyncClient(transport=AsyncEmptyChunkTransport())
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_raw.bin"
        saved = await requestor.astream_download("/async-raw", dest, validate_pdf=False)
        assert saved == dest.resolve()
        assert dest.read_bytes() == b"async part1 async part2"
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_stream_download_cleanup_on_write_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        respx.get("https://api.didit.me/v3/async-write-err").mock(
            return_value=httpx.Response(
                200, content=b"%PDF-1.4 ok", headers={"Content-Type": "application/pdf"}
            )
        )
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_write_err.pdf"

        def broken_fdopen(*args: Any, **kwargs: Any) -> Any:
            raise OSError("Async disk write failed")

        monkeypatch.setattr(os, "fdopen", broken_fdopen)
        with pytest.raises(OSError, match="Async disk write failed"):
            await requestor.astream_download("/async-write-err", dest)
        assert not dest.exists()
        await client.aclose()

    def test_sync_stream_download_multichunk_pdf(self, tmp_path: Path) -> None:
        chunk1 = b"%PDF-1.4 header " + b"A" * 65536
        chunk2 = b"tail chunk"

        class MultiChunkSyncStream(httpx.SyncByteStream):
            def __iter__(self) -> Any:
                yield chunk1
                yield chunk2

        class MultiChunkTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    stream=MultiChunkSyncStream(),
                    headers={"Content-Type": "application/pdf"},
                )

        client = httpx.Client(transport=MultiChunkTransport())
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "multichunk.pdf"
        saved = requestor.stream_download("/pdf-multi", dest, validate_pdf=True)
        assert saved == dest.resolve()
        assert dest.read_bytes() == chunk1 + chunk2

    @pytest.mark.asyncio
    async def test_async_stream_download_multichunk_pdf(self, tmp_path: Path) -> None:
        chunk1 = b"%PDF-1.4 async header " + b"B" * 65536
        chunk2 = b"async tail chunk"

        class MultiChunkAsyncStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                yield chunk1
                yield chunk2

        class MultiChunkAsyncTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    stream=MultiChunkAsyncStream(),
                    headers={"Content-Type": "application/pdf"},
                )

        client = httpx.AsyncClient(transport=MultiChunkAsyncTransport())
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "multichunk_async.pdf"
        saved = await requestor.astream_download("/async-pdf-multi", dest, validate_pdf=True)
        assert saved == dest.resolve()
        assert dest.read_bytes() == chunk1 + chunk2
        await client.aclose()

    def test_sync_stream_download_deadline_exceeded_before_execution(self, tmp_path: Path) -> None:
        client = httpx.Client()
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "deadline_fail.pdf"
        opts = RequestOptions(deadline=time.monotonic() - 1.0)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded before execution"):
            requestor.stream_download("/pdf", dest, options=opts)

    @respx.mock
    def test_sync_stream_download_retry_on_503_and_succeed(self, tmp_path: Path) -> None:
        route = respx.get("https://api.didit.me/v3/pdf-retry").mock(
            side_effect=[
                httpx.Response(503, json={"error": "service unavailable"}),
                httpx.Response(
                    200,
                    content=b"%PDF-1.4 retried ok",
                    headers={"Content-Type": "application/pdf"},
                ),
            ]
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=2, base_delay=0.01, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        dest = tmp_path / "retried.pdf"
        saved = requestor.stream_download("/pdf-retry", dest)
        assert saved == dest.resolve()
        assert dest.read_bytes() == b"%PDF-1.4 retried ok"
        assert route.call_count == 2

    @respx.mock
    def test_sync_stream_download_retry_429_exceeds_max_retry_after_aborts(
        self, tmp_path: Path
    ) -> None:
        respx.get("https://api.didit.me/v3/pdf-429").mock(
            return_value=httpx.Response(
                429, headers={"Retry-After": "120"}, json={"error": "rate limit"}
            )
        )
        client = httpx.Client()
        policy = RetryPolicy(max_retries=2, base_delay=0.01, max_retry_after=60.0, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        dest = tmp_path / "rate_limit.pdf"
        with pytest.raises(DiditAPIError):
            requestor.stream_download("/pdf-429", dest)
        assert not dest.exists()

    def test_sync_stream_download_pool_timeout(self, tmp_path: Path) -> None:
        class PoolTimeoutTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.PoolTimeout("Pool exhausted")

        client = httpx.Client(transport=PoolTimeoutTransport())
        requestor = _SyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "pool.pdf"
        with pytest.raises(DiditPoolTimeoutError, match="Connection pool acquisition timed out"):
            requestor.stream_download("/pdf-pool", dest)
        assert not dest.exists()

    def test_sync_stream_download_network_error_retry_and_exhaustion(self, tmp_path: Path) -> None:
        class FlakyTransport(httpx.BaseTransport):
            def __init__(self) -> None:
                self.calls = 0

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                self.calls += 1
                raise httpx.ConnectError("Network is unreachable")

        transport = FlakyTransport()
        client = httpx.Client(transport=transport)
        policy = RetryPolicy(max_retries=1, base_delay=0.01, jitter=False)
        requestor = _SyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        dest = tmp_path / "flaky.pdf"
        with pytest.raises(DiditConnectionError, match="Failed to connect"):
            requestor.stream_download("/pdf-flaky", dest)
        assert transport.calls == 2
        assert not dest.exists()

    @pytest.mark.asyncio
    async def test_async_stream_download_deadline_exceeded_before_execution(
        self, tmp_path: Path
    ) -> None:
        client = httpx.AsyncClient()
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_deadline_fail.pdf"
        opts = RequestOptions(deadline=time.monotonic() - 1.0)
        with pytest.raises(DiditTimeoutError, match="deadline exceeded before execution"):
            await requestor.astream_download("/async-pdf", dest, options=opts)
        await client.aclose()

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_stream_download_retry_on_503_and_succeed(self, tmp_path: Path) -> None:
        route = respx.get("https://api.didit.me/v3/async-retry").mock(
            side_effect=[
                httpx.Response(503, json={"error": "service unavailable"}),
                httpx.Response(
                    200,
                    content=b"%PDF-1.4 async retried ok",
                    headers={"Content-Type": "application/pdf"},
                ),
            ]
        )
        client = httpx.AsyncClient()
        policy = RetryPolicy(max_retries=2, base_delay=0.01, jitter=False)
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", retry_policy=policy
        )
        dest = tmp_path / "async_retried.pdf"
        saved = await requestor.astream_download("/async-retry", dest)
        assert saved == dest.resolve()
        assert dest.read_bytes() == b"%PDF-1.4 async retried ok"
        assert route.call_count == 2
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_stream_download_slow_drip_timeout_aborts(self, tmp_path: Path) -> None:
        class SlowDripAsyncStream(httpx.AsyncByteStream):
            async def __aiter__(self) -> Any:
                yield b"%PDF-1.4 start chunk"
                await asyncio.sleep(0.5)
                yield b"never reached"

        class SlowDripTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    stream=SlowDripAsyncStream(),
                    headers={"Content-Type": "application/pdf"},
                )

        client = httpx.AsyncClient(transport=SlowDripTransport())
        requestor = _AsyncRequestor(
            client, base_url="https://api.didit.me/v3", api_key="k", default_timeout=0.05
        )
        dest = tmp_path / "slow_drip.pdf"
        opts = RequestOptions(max_retries=0)
        with pytest.raises(DiditTimeoutError):
            await requestor.astream_download("/slow-drip", dest, options=opts)
        assert not dest.exists()
        await client.aclose()

    @pytest.mark.asyncio
    async def test_async_stream_download_pool_timeout(self, tmp_path: Path) -> None:
        class AsyncPoolTimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.PoolTimeout("Async pool exhausted")

        client = httpx.AsyncClient(transport=AsyncPoolTimeoutTransport())
        requestor = _AsyncRequestor(client, base_url="https://api.didit.me/v3", api_key="k")
        dest = tmp_path / "async_pool.pdf"
        with pytest.raises(DiditPoolTimeoutError, match="Connection pool acquisition timed out"):
            await requestor.astream_download("/async-pool", dest)
        assert not dest.exists()
        await client.aclose()
