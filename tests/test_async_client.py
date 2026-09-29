"""Unit tests for the asynchronous Didit client."""

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
    DiditRateLimitError,
    DiditServerError,
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
    @pytest.mark.parametrize(
        ("status_code", "exc_type"),
        [
            (401, DiditAuthenticationError),
            (403, DiditAuthenticationError),
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
