"""Unit tests for the transport engine, safe retries, and requestors."""

from __future__ import annotations

import datetime

import httpx
import pytest
import respx

from didit.errors import (
    DiditConnectionError,
    DiditPoolTimeoutError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
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
        route = respx.post("https://custom.endpoint.com/webhook").mock(
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
            "https://custom.endpoint.com/webhook",
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
