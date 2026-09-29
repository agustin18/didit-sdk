"""Unit tests for the synchronous Didit client."""

import pytest
import respx
from httpx import Response

from didit.client import Didit
from didit.config import DiditConfig
from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditNotFoundError,
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
def client(base_url: str) -> Didit:
    return Didit(
        api_key="didit_live_key_123",
        base_url=base_url,
        webhook_secret="whsec_sync_test",
        timeout=10.0,
        max_retries=0,
    )


class TestDiditSyncClient:
    def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        with pytest.raises(DiditConfigurationError):
            Didit()

    def test_init_with_config_instance(self, base_url: str) -> None:
        cfg = DiditConfig(api_key="custom_cfg_key", base_url=base_url)
        c = Didit(config=cfg)
        assert c.config.api_key == "custom_cfg_key"
        c.close()

    @respx.mock
    def test_create_session_success(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_123",
                    "session_token": "tok_abc",
                    "url": "https://verify.didit.me/sess_123",
                    "status": "In Progress",
                    "workflow_id": "wf_test",
                    "vendor_data": "usr_99",
                },
            )
        )

        resp = client.sessions.create(
            vendor_data="usr_99",
            workflow_id="wf_test",
            callback="https://app.com/cb",
            language="es",
        )

        assert route.called
        req = route.calls.last.request
        assert req.headers["x-api-key"] == "didit_live_key_123"
        assert req.headers["content-type"] == "application/json"
        assert resp.session_id == "sess_123"
        assert resp.status == SessionStatus.IN_PROGRESS
        assert resp.url == "https://verify.didit.me/sess_123"

    @respx.mock
    def test_get_session_success(self, client: Didit, base_url: str) -> None:
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

        resp = client.sessions.get("sess_456")
        assert route.called
        assert resp.session_id == "sess_456"
        assert resp.status == SessionStatus.APPROVED

    @respx.mock
    def test_get_decision_success(self, client: Didit, base_url: str) -> None:
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
                    "biometrics": {
                        "face_match": True,
                        "liveness_check": True,
                        "score": 0.99,
                    },
                },
            )
        )

        decision = client.sessions.get_decision("sess_456")
        assert route.called
        assert decision.session_id == "sess_456"
        assert decision.status == SessionStatus.APPROVED
        assert decision.document is not None
        assert decision.document.document_number == "PA123456"
        assert decision.biometrics is not None
        assert decision.biometrics.face_match is True

    @respx.mock
    def test_poll_decision_success(self, client: Didit, base_url: str) -> None:
        route = respx.get(f"{base_url}/session/sess_poll/decision/").mock(
            side_effect=[
                Response(200, json={"session_id": "sess_poll", "status": "In Progress"}),
                Response(200, json={"session_id": "sess_poll", "status": "Approved"}),
            ]
        )
        decision = client.sessions.poll_decision("sess_poll", timeout=1.0, interval=0.001)
        assert route.call_count == 2
        assert decision.status == SessionStatus.APPROVED

    @respx.mock
    def test_poll_decision_timeout(self, client: Didit, base_url: str) -> None:
        from didit.errors import DiditTimeoutError

        respx.get(f"{base_url}/session/sess_poll_to/decision/").mock(
            return_value=Response(200, json={"session_id": "sess_poll_to", "status": "In Progress"})
        )
        with pytest.raises(DiditTimeoutError, match="timed out after"):
            client.sessions.poll_decision("sess_poll_to", timeout=0.01, interval=0.02)

    @respx.mock
    def test_poll_decision_stop_on_review(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/sess_review/decision/").mock(
            return_value=Response(200, json={"session_id": "sess_review", "status": "In Review"})
        )
        # Default stop_on_review=True returns immediately on In Review
        decision = client.sessions.poll_decision("sess_review", timeout=1.0)
        assert decision.status == SessionStatus.IN_REVIEW

    @respx.mock
    def test_poll_decision_stop_when_custom_predicate(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/sess_custom/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_custom",
                    "status": "In Progress",
                    "id_verifications": [{"status": "Approved"}],
                },
            )
        )
        # Custom predicate stops polling even when status is In Progress
        decision = client.sessions.poll_decision(
            "sess_custom",
            stop_when=lambda d: len(d.id_verifications) > 0,
            timeout=1.0,
        )
        assert decision.status == SessionStatus.IN_PROGRESS
        assert len(decision.id_verifications) == 1

    @respx.mock
    def test_poll_decision_transient_error_tolerance(self, client: Didit, base_url: str) -> None:
        route = respx.get(f"{base_url}/session/sess_flaky/decision/").mock(
            side_effect=[
                Response(503, json={"error": "transient unavailable"}),
                Response(429, headers={"Retry-After": "0.001"}, json={"error": "rate limit"}),
                Response(200, json={"session_id": "sess_flaky", "status": "Approved"}),
            ]
        )
        decision = client.sessions.poll_decision(
            "sess_flaky",
            timeout=2.0,
            interval=0.001,
            tolerate_transient_errors=True,
        )
        assert decision.status == SessionStatus.APPROVED
        assert route.call_count == 3

    @respx.mock
    def test_poll_decision_terminal_error_fails_fast(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/sess_404/decision/").mock(
            return_value=Response(404, json={"error": "not found"})
        )
        with pytest.raises(DiditNotFoundError):
            client.sessions.poll_decision("sess_404", timeout=5.0)

    @respx.mock
    def test_poll_decision_transient_error_not_tolerated(
        self, client: Didit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_503/decision/").mock(
            return_value=Response(503, json={"error": "service down"})
        )
        with pytest.raises(DiditServerError):
            client.sessions.poll_decision("sess_503", timeout=1.0, tolerate_transient_errors=False)

    @respx.mock
    def test_poll_decision_transient_error_timeout_exhausted(
        self, client: Didit, base_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        respx.get(f"{base_url}/session/sess_to/decision/").mock(
            return_value=Response(503, json={"error": "service down"})
        )
        ticks = [100.0, 100.0, 105.0]
        monkeypatch.setattr(
            "didit.resources.sessions.time.monotonic", lambda: ticks.pop(0) if ticks else 105.0
        )
        with pytest.raises(DiditTimeoutError) as exc_info:
            client.sessions.poll_decision(
                "sess_to", timeout=2.0, interval=0.01, tolerate_transient_errors=True
            )
        assert isinstance(exc_info.value.__cause__, DiditServerError)

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
    def test_http_error_mappings(
        self, client: Didit, base_url: str, status_code: int, exc_type: type[Exception]
    ) -> None:
        respx.get(f"{base_url}/session/s_err/").mock(
            return_value=Response(status_code, text="Error payload")
        )
        with pytest.raises(exc_type) as exc_info:
            client.sessions.get("s_err")
        assert isinstance(exc_info.value, DiditAPIError)
        assert exc_info.value.status_code == status_code

    @respx.mock
    def test_rate_limit_error_retry_after(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/s_rate/").mock(
            return_value=Response(
                429,
                headers={"Retry-After": "45"},
                json={"detail": "Too many requests"},
            )
        )
        with pytest.raises(DiditRateLimitError) as exc_info:
            client.sessions.get("s_rate")
        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == 45.0

    @respx.mock
    def test_rate_limit_error_without_retry_after(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/s_rate_no_header/").mock(
            return_value=Response(429, text="busy")
        )
        with pytest.raises(DiditRateLimitError) as exc_info:
            client.sessions.get("s_rate_no_header")
        assert exc_info.value.retry_after is None

    @respx.mock
    def test_rate_limit_error_invalid_retry_after(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/s_rate_invalid/").mock(
            return_value=Response(
                429,
                headers={"Retry-After": "not-a-number"},
                text="non json",
            )
        )
        with pytest.raises(DiditRateLimitError) as exc_info:
            client.sessions.get("s_rate_invalid")
        assert exc_info.value.retry_after is None

    @respx.mock
    def test_non_dict_json_error(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/s_non_dict/").mock(
            return_value=Response(400, json=["unexpected", "list"])
        )
        with pytest.raises(DiditAPIError) as exc_info:
            client.sessions.get("s_non_dict")
        assert exc_info.value.error_code is None

    def test_handle_http_error_on_success(self) -> None:
        from didit.resources.base import handle_http_error

        resp = Response(200, json={"ok": True})
        # Should not raise
        handle_http_error(resp)

    def test_external_http_client_not_closed_by_didit(self, base_url: str) -> None:
        import httpx

        custom_http = httpx.Client()
        c = Didit(api_key="k", base_url=base_url, http_client=custom_http)
        assert c.http_client is custom_http
        c.close()
        # external http client is NOT closed
        assert not custom_http.is_closed
        custom_http.close()

    def test_context_manager(self, base_url: str) -> None:
        with Didit(api_key="k", base_url=base_url) as c:
            assert not c.http_client.is_closed
        assert c.http_client.is_closed

    def test_verify_and_parse_webhook_convenience_methods(self, client: Didit) -> None:
        import time

        payload_dict = {
            "session_id": "sess_wh_sync",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        import json

        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = compute_signature(client.config.webhook_secret or "", payload_dict, version="v2")
        headers = {"X-Signature-V2": sig}

        # Uses secret configured on client
        assert client.verify_webhook(raw_body, headers) is True

        parsed = client.parse_webhook(raw_body, headers)
        assert parsed.session_id == "sess_wh_sync"
        assert parsed.status == SessionStatus.APPROVED

    def test_webhook_methods_without_secret_raise_config_error(self, base_url: str) -> None:
        c = Didit(api_key="k", base_url=base_url, webhook_secret=None)
        with pytest.raises(DiditConfigurationError, match="No webhook_secret configured"):
            c.verify_webhook(b"{}", {})
        with pytest.raises(DiditConfigurationError, match="No webhook_secret configured"):
            c.parse_webhook(b"{}", {})
        c.close()

    def test_requestor_property_and_with_options(self, client: Didit, base_url: str) -> None:
        from didit.transport import RequestOptions, _SyncRequestor

        assert isinstance(client.requestor, _SyncRequestor)

        bound = client.with_options(RequestOptions(idempotency_key="bound_key"))
        assert bound is not client
        assert bound.requestor._default_options is not None
        assert bound.requestor._default_options.idempotency_key == "bound_key"

    @respx.mock
    def test_sessions_resource_raw_client_compat(self, base_url: str) -> None:
        import httpx

        from didit.resources.sessions import SessionsResource

        raw_http = httpx.Client(
            base_url=base_url,
            headers={"x-api-key": "raw_key", "Accept": "application/json"},
        )
        respx.get(f"{base_url}/session/sess_compat/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_compat",
                    "status": "In Progress",
                    "workflow_id": "wf",
                    "vendor_data": "vd",
                },
            )
        )
        res = SessionsResource(raw_http)
        assert res._http is raw_http
        session = res.get("sess_compat")
        assert session.session_id == "sess_compat"
        raw_http.close()
