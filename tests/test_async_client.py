import json

import pytest
import respx
from httpx import Response

from didit.client import AsyncDidit
from didit.config import DiditConfig
from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
from didit.models.enums import SessionStatus
from didit.webhooks import compute_signature


@pytest.fixture
def base_url() -> str:
    return "https://verification.didit.me/v3"


@pytest.fixture
def async_client(base_url: str) -> AsyncDidit:
    return AsyncDidit(
        api_key="didit_live_key_async",
        base_url=base_url,
        webhook_secret="whsec_async_test",
        timeout=10.0,
        max_retries=0,
    )


class TestAsyncDiditClient:
    async def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        with pytest.raises(DiditConfigurationError):
            AsyncDidit()

    async def test_init_with_config_instance(self, base_url: str) -> None:
        cfg = DiditConfig(api_key="custom_cfg_key", base_url=base_url)
        c = AsyncDidit(config=cfg)
        assert c.config.api_key == "custom_cfg_key"
        await c.aclose()

    @respx.mock
    async def test_create_session_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.post(f"{base_url}/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_async_123",
                    "session_token": "tok_async",
                    "url": "https://verify.didit.me/sess_async_123",
                    "status": "In Progress",
                    "workflow_id": "wf_test",
                    "vendor_data": "usr_99",
                },
            )
        )

        resp = await async_client.sessions.create(
            vendor_data="usr_99",
            workflow_id="wf_test",
            callback="https://app.com/cb",
            language="es",
        )

        assert route.called
        req = route.calls.last.request
        assert req.headers["x-api-key"] == "didit_live_key_async"
        assert req.headers["content-type"] == "application/json"
        assert resp.session_id == "sess_async_123"
        assert resp.status == SessionStatus.IN_PROGRESS
        await async_client.aclose()

    @respx.mock
    async def test_async_create_session_with_sandbox_scenario(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        route = respx.post(f"{base_url}/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_sb_async",
                    "status": "In Progress",
                    "workflow_id": "wf_test",
                    "vendor_data": "usr_sb",
                },
            )
        )
        resp = await async_client.sessions.create(
            vendor_data="usr_sb",
            workflow_id="wf_test",
            sandbox_scenario="approve",
        )
        assert route.called
        req_json = json.loads(route.calls.last.request.content.decode("utf-8"))
        assert req_json["sandbox_scenario"] == "approve"
        assert resp.session_id == "sess_sb_async"
        await async_client.aclose()

    @respx.mock
    async def test_get_session_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.get(f"{base_url}/session/sess_456/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_456",
                    "status": "Approved",
                    "workflow_id": "wf_test",
                },
            )
        )

        resp = await async_client.sessions.get("sess_456")
        assert route.called
        assert resp.session_id == "sess_456"
        assert resp.status == SessionStatus.APPROVED
        await async_client.aclose()

    @respx.mock
    async def test_get_decision_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.get(f"{base_url}/session/sess_456/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_456",
                    "status": "Approved",
                    "workflow_id": "wf_test",
                    "document": {
                        "document_type": "passport",
                        "document_number": "PA123456",
                        "is_valid": True,
                    },
                },
            )
        )

        decision = await async_client.sessions.get_decision("sess_456")
        assert route.called
        assert decision.session_id == "sess_456"
        assert decision.status == SessionStatus.APPROVED
        assert decision.document is not None
        await async_client.aclose()

    @respx.mock
    async def test_poll_decision_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.get(f"{base_url}/session/sess_poll_async/decision/").mock(
            side_effect=[
                Response(200, json={"session_id": "sess_poll_async", "status": "In Progress"}),
                Response(200, json={"session_id": "sess_poll_async", "status": "Approved"}),
            ]
        )
        decision = await async_client.sessions.poll_decision(
            "sess_poll_async", timeout=1.0, interval=0.001
        )
        assert route.call_count == 2
        assert decision.status == SessionStatus.APPROVED
        await async_client.aclose()

    @respx.mock
    async def test_poll_decision_timeout(self, async_client: AsyncDidit, base_url: str) -> None:
        from didit.errors import DiditTimeoutError

        respx.get(f"{base_url}/session/sess_poll_to_async/decision/").mock(
            return_value=Response(
                200, json={"session_id": "sess_poll_to_async", "status": "In Progress"}
            )
        )
        with pytest.raises(DiditTimeoutError, match="timed out after"):
            await async_client.sessions.poll_decision(
                "sess_poll_to_async", timeout=0.01, interval=0.02
            )
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_stop_on_review(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_review_async/decision/").mock(
            return_value=Response(
                200, json={"session_id": "sess_review_async", "status": "In Review"}
            )
        )
        decision = await async_client.sessions.poll_decision("sess_review_async", timeout=1.0)
        assert decision.status == SessionStatus.IN_REVIEW
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_stop_when(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_custom_async/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_custom_async",
                    "status": "In Progress",
                    "id_verifications": [{"status": "Approved"}],
                },
            )
        )
        decision = await async_client.sessions.poll_decision(
            "sess_custom_async",
            stop_when=lambda d: len(d.id_verifications) > 0,
            timeout=1.0,
        )
        assert decision.status == SessionStatus.IN_PROGRESS
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_transient_error_tolerance(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        route = respx.get(f"{base_url}/session/sess_flaky_async/decision/").mock(
            side_effect=[
                Response(502, json={"error": "bad gateway"}),
                Response(200, json={"session_id": "sess_flaky_async", "status": "Approved"}),
            ]
        )
        decision = await async_client.sessions.poll_decision(
            "sess_flaky_async",
            timeout=2.0,
            interval=0.001,
            tolerate_transient_errors=True,
        )
        assert decision.status == SessionStatus.APPROVED
        assert route.call_count == 2
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_retry_after(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        route = respx.get(f"{base_url}/session/sess_rate_async/decision/").mock(
            side_effect=[
                Response(429, headers={"Retry-After": "0.001"}, json={"error": "rate limited"}),
                Response(200, json={"session_id": "sess_rate_async", "status": "Approved"}),
            ]
        )
        decision = await async_client.sessions.poll_decision(
            "sess_rate_async",
            timeout=2.0,
            interval=0.001,
            tolerate_transient_errors=True,
        )
        assert decision.status == SessionStatus.APPROVED
        assert route.call_count == 2
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_transient_error_not_tolerated(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_503_async/decision/").mock(
            return_value=Response(503, json={"error": "service down"})
        )
        with pytest.raises(DiditServerError):
            await async_client.sessions.poll_decision(
                "sess_503_async", timeout=1.0, tolerate_transient_errors=False
            )
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_non_transient_5xx_raises_immediately(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_501_async/decision/").mock(
            return_value=Response(501, json={"error": "not implemented"})
        )
        with pytest.raises(DiditServerError) as exc_info:
            await async_client.sessions.poll_decision(
                "sess_501_async", timeout=5.0, tolerate_transient_errors=True
            )
        assert exc_info.value.status_code == 501
        await async_client.aclose()

    @respx.mock
    async def test_async_poll_decision_transient_error_timeout_exhausted(
        self, async_client: AsyncDidit, base_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        respx.get(f"{base_url}/session/sess_to_async/decision/").mock(
            return_value=Response(503, json={"error": "service down"})
        )
        ticks = [100.0, 100.0, 100.0, 105.0]
        monkeypatch.setattr("time.monotonic", lambda: ticks.pop(0) if ticks else 105.0)
        with pytest.raises(DiditTimeoutError) as exc_info:
            await async_client.sessions.poll_decision(
                "sess_to_async", timeout=2.0, interval=0.01, tolerate_transient_errors=True
            )
        assert isinstance(exc_info.value.__cause__, DiditServerError)
        await async_client.aclose()

    @respx.mock
    @pytest.mark.parametrize(
        ("status_code", "exc_type"),
        [
            (401, DiditAuthenticationError),
            (403, DiditPermissionError),
            (404, DiditNotFoundError),
            (500, DiditServerError),
            (503, DiditServerError),
            (400, DiditAPIError),
        ],
    )
    async def test_http_error_mappings(
        self, async_client: AsyncDidit, base_url: str, status_code: int, exc_type: type[Exception]
    ) -> None:
        respx.get(f"{base_url}/session/s_err/").mock(
            return_value=Response(status_code, text="Error payload")
        )
        with pytest.raises(exc_type) as exc_info:
            await async_client.sessions.get("s_err")
        assert isinstance(exc_info.value, DiditAPIError)
        assert exc_info.value.status_code == status_code
        await async_client.aclose()

    @respx.mock
    async def test_http_error_capture_sensitive_response_default_and_explicit(
        self, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/s_leak_async/").mock(
            return_value=Response(
                400,
                text='{"detail": "Sensitive Biometric Payload Async"}',
                headers={"X-Request-Id": "req_leak_async_123"},
            )
        )
        # Default: capture_sensitive_response=False -> response_body is None
        client_safe = AsyncDidit(api_key="key", base_url=base_url)
        with pytest.raises(DiditAPIError) as exc_safe:
            await client_safe.sessions.get("s_leak_async")
        assert exc_safe.value.response_body is None
        assert exc_safe.value.status_code == 400
        assert exc_safe.value.request_id == "req_leak_async_123"
        await client_safe.aclose()

        # Explicit: capture_sensitive_response=True -> response_body retained
        client_sensitive = AsyncDidit(
            api_key="key", base_url=base_url, capture_sensitive_response=True
        )
        with pytest.raises(DiditAPIError) as exc_sens:
            await client_sensitive.sessions.get("s_leak_async")
        assert exc_sens.value.response_body == '{"detail": "Sensitive Biometric Payload Async"}'
        await client_sensitive.aclose()

    @respx.mock
    async def test_rate_limit_error_retry_after(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/s_rate/").mock(
            return_value=Response(
                429,
                headers={"Retry-After": "30"},
                json={"detail": "Too many requests"},
            )
        )
        with pytest.raises(DiditRateLimitError) as exc_info:
            await async_client.sessions.get("s_rate")
        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == 30.0
        await async_client.aclose()

    async def test_external_http_client_not_closed_by_didit(self, base_url: str) -> None:
        import httpx

        custom_http = httpx.AsyncClient()
        c = AsyncDidit(api_key="k", base_url=base_url, http_client=custom_http)
        assert c.http_client is custom_http
        await c.aclose()
        # external http client is NOT closed
        assert not custom_http.is_closed
        await custom_http.aclose()

    async def test_async_context_manager(self, base_url: str) -> None:
        async with AsyncDidit(api_key="k", base_url=base_url) as c:
            assert not c.http_client.is_closed
        assert c.http_client.is_closed

    async def test_verify_and_parse_webhook_convenience_methods(
        self, async_client: AsyncDidit
    ) -> None:
        import json
        import time

        payload_dict = {
            "session_id": "sess_wh_async",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = compute_signature(
            async_client.config.webhook_secret or "", payload_dict, version="v2"
        )
        headers = {"X-Signature-V2": sig}

        assert async_client.verify_webhook(raw_body, headers) is True
        parsed = async_client.parse_webhook(raw_body, headers)
        assert parsed.session_id == "sess_wh_async"
        assert parsed.status == SessionStatus.APPROVED
        await async_client.aclose()

    async def test_webhook_methods_without_secret_raise_config_error(self, base_url: str) -> None:
        c = AsyncDidit(api_key="k", base_url=base_url, webhook_secret=None)
        with pytest.raises(DiditConfigurationError, match="No webhook_secret configured"):
            c.verify_webhook(b"{}", {})
        with pytest.raises(DiditConfigurationError, match="No webhook_secret configured"):
            c.parse_webhook(b"{}", {})
        await c.aclose()

    async def test_async_requestor_property_and_with_options(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        from didit.transport import RequestOptions, _AsyncRequestor

        assert isinstance(async_client.requestor, _AsyncRequestor)

        bound = async_client.with_options(RequestOptions(timeout=15.0))
        assert bound is not async_client
        assert bound.requestor._default_options is not None
        assert bound.requestor._default_options.timeout == 15.0

        with pytest.raises(DiditConfigurationError) as exc_info:
            async_client.with_options(RequestOptions(idempotency_key="async_bound_key"))
        assert "idempotency_key cannot be set as a client-level default option" in str(
            exc_info.value
        )
        await async_client.aclose()

    @respx.mock
    async def test_async_sessions_resource_raw_client_compat(self, base_url: str) -> None:
        import httpx

        from didit.resources.sessions import AsyncSessionsResource

        raw_http = httpx.AsyncClient(
            base_url=base_url,
            headers={"x-api-key": "raw_async_key", "Accept": "application/json"},
        )
        respx.get(f"{base_url}/session/sess_async_compat/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "session_id": "sess_async_compat",
                    "status": "In Progress",
                    "workflow_id": "wf",
                    "vendor_data": "vd",
                },
            )
        )
        res = AsyncSessionsResource(raw_http)
        assert res._http is raw_http
        session = await res.get("sess_async_compat")
        assert session.session_id == "sess_async_compat"
        await raw_http.aclose()
