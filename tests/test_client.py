from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import respx
from httpx import Response

from didit.client import AsyncDidit, Didit
from didit.config import DiditConfig
from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
from didit.models.enums import SessionStatus
from didit.models.session import (
    ContactDetails,
    ExpectedDetails,
    ResubmitFeature,
    ResubmitNode,
)
from didit.transport import RequestOptions
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
    def test_create_session_with_sandbox_scenario(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_sb",
                    "status": "In Progress",
                    "workflow_id": "wf_test",
                    "vendor_data": "usr_sb",
                },
            )
        )
        resp = client.sessions.create(
            vendor_data="usr_sb",
            workflow_id="wf_test",
            sandbox_scenario="decline_face_match_low_similarity",
        )
        assert route.called
        req_json = json.loads(route.calls.last.request.content.decode("utf-8"))
        assert req_json["sandbox_scenario"] == "decline_face_match_low_similarity"
        assert resp.session_id == "sess_sb"

    @respx.mock
    def test_create_session_with_full_v3_surface(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_full_v3",
                    "status": "Not Started",
                    "workflow_id": "wf_v3",
                    "vendor_data": "usr_v3",
                },
            )
        )
        resp = client.sessions.create(
            vendor_data="usr_v3",
            workflow_id="wf_v3",
            callback="https://example.com/callback",
            callback_method="both",
            metadata={"user_tier": "enterprise", "tenant_id": 99},
            contact_details=ContactDetails(
                email="alice@example.com",
                send_notification_emails=True,
                email_lang="es",
                phone="+34600112233",
            ),
            expected_details=ExpectedDetails(
                first_name="Alice",
                last_name="Smith",
                date_of_birth="1992-04-10",
                nationality="ESP",
                expected_document_types=["P", "ID"],
            ),
            portrait_image="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
        )
        assert route.called
        req_json = json.loads(route.calls.last.request.content.decode("utf-8"))
        assert req_json["workflow_id"] == "wf_v3"
        assert req_json["vendor_data"] == "usr_v3"
        assert req_json["callback_method"] == "both"
        assert req_json["metadata"] == {"user_tier": "enterprise", "tenant_id": 99}
        assert req_json["contact_details"]["email"] == "alice@example.com"
        assert req_json["contact_details"]["phone"] == "+34600112233"
        assert req_json["expected_details"]["first_name"] == "Alice"
        assert req_json["expected_details"]["expected_document_types"] == ["P", "ID"]
        assert req_json["portrait_image"].startswith("iVBORw")
        assert resp.session_id == "sess_full_v3"

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
    def test_list_sessions_success_and_filters(self, client: Didit, base_url: str) -> None:
        from didit.models.session import SessionListPage

        route = respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 2,
                    "next": None,
                    "previous": None,
                    "results": [
                        {
                            "session_id": "sess_1",
                            "status": "Approved",
                            "workflow_id": "wf_1",
                            "vendor_data": "user_1",
                            "country": "ES",
                            "session_kind": "user",
                        },
                        {
                            "session_id": "sess_2",
                            "status": "Declined",
                            "workflow_id": "wf_1",
                            "vendor_data": "user_2",
                            "country": "FR",
                            "session_kind": "user",
                        },
                    ],
                },
            )
        )

        from datetime import datetime

        page = client.sessions.list(
            status=SessionStatus.APPROVED,
            vendor_data="user_1",
            country="ESP",
            workflow_id="wf_1",
            search="query",
            date_from=datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
            date_to=datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc),
            limit=25,
            offset=10,
        )

        assert isinstance(page, SessionListPage)
        assert route.called
        req = route.calls.last.request
        assert req.url.params["status"] == "Approved"
        assert req.url.params["session_kind"] == "user"
        assert req.url.params["vendor_data"] == "user_1"
        assert req.url.params["country"] == "ESP"
        assert req.url.params["workflow_id"] == "wf_1"
        assert req.url.params["search"] == "query"
        assert req.url.params["date_from"] == "2026-01-01T00:00:00+00:00"
        assert req.url.params["date_to"] == "2026-01-02T00:00:00+00:00"
        assert req.url.params["limit"] == "25"
        assert req.url.params["offset"] == "10"
        assert page.count == 2
        assert len(page.results) == 2
        assert page.results[0].session_id == "sess_1"
        assert page.results[0].status == SessionStatus.APPROVED

        # Also test with string dates
        client.sessions.list(
            date_from="2026-01-01T00:00:00Z",
            date_to="2026-01-02T00:00:00Z",
        )
        req2 = route.calls.last.request
        assert req2.url.params["session_kind"] == "user"

        # Test listing with pure defaults
        page_default = client.sessions.list()
        assert page_default.count == 2

    @respx.mock
    def test_reconcile_single_session_in_sync_and_drift(self, client: Didit, base_url: str) -> None:
        from didit.models.session import ObservedSessionState

        # 1. In sync scenario
        respx.get(f"{base_url}/session/sess_sync/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_sync",
                    "status": "Approved",
                    "warnings": [],
                },
            )
        )

        report_sync = client.sessions.reconcile(
            "sess_sync",
            observed=ObservedSessionState(session_id="sess_sync", status=SessionStatus.APPROVED),
        )
        assert report_sync.is_in_sync is True
        assert report_sync.status_drift is False
        assert report_sync.warning_drift is False

        # 2. Status & warning drift scenario
        respx.get(f"{base_url}/session/sess_drift/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_drift",
                    "status": "Declined",
                    "warnings": [{"code": "SUSPECTED_FRAUD", "severity": "high"}],
                },
            )
        )

        report_drift = client.sessions.reconcile(
            "sess_drift",
            observed=ObservedSessionState(
                session_id="sess_drift",
                status=SessionStatus.IN_REVIEW,
                warning_codes=["OLD_WARN"],
            ),
        )
        assert report_drift.is_in_sync is False
        assert report_drift.status_drift is True
        assert report_drift.warning_drift is True
        assert report_drift.warning_codes_added == ["SUSPECTED_FRAUD"]
        assert report_drift.warning_codes_removed == ["OLD_WARN"]

        # 3. Missing local scenario
        respx.get(f"{base_url}/session/sess_no_local/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_no_local",
                    "status": "Approved",
                },
            )
        )
        report_no_local = client.sessions.reconcile("sess_no_local", observed=None)
        assert report_no_local.local_missing is True
        assert report_no_local.is_in_sync is False

        # 4. Missing remote scenario (404)
        respx.get(f"{base_url}/session/sess_404/decision/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )
        report_404 = client.sessions.reconcile(
            "sess_404",
            observed=ObservedSessionState(session_id="sess_404", status=SessionStatus.APPROVED),
        )
        assert report_404.remote_missing is True
        assert report_404.is_in_sync is False

    @respx.mock
    def test_reconcile_range_batch(self, client: Didit, base_url: str) -> None:
        from didit.models.session import ObservedSessionState

        # Mock list sessions
        respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 4,
                    "next": None,
                    "previous": None,
                    "results": [
                        {"session_id": "sess_b1", "status": "Approved"},
                        {"session_id": "sess_b2", "status": "Declined"},
                        {"session_id": "sess_b3", "status": "Approved"},
                        {"session_id": "sess_b4", "status": "Approved"},
                    ],
                },
            )
        )
        # Mock decision for sess_b1 (in sync)
        respx.get(f"{base_url}/session/sess_b1/decision/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_b1", "status": "Approved", "warnings": []},
            )
        )
        # Mock decision for sess_b2 (drift)
        respx.get(f"{base_url}/session/sess_b2/decision/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_b2", "status": "Declined", "warnings": []},
            )
        )
        # Mock decision for sess_b3 (missing locally)
        respx.get(f"{base_url}/session/sess_b3/decision/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_b3", "status": "Approved", "warnings": []},
            )
        )
        # Mock decision for sess_b4 (missing remotely -> 404)
        respx.get(f"{base_url}/session/sess_b4/decision/").mock(
            return_value=Response(
                404,
                json={"detail": "Not found"},
            )
        )

        class MockSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                if session_id == "sess_b1":
                    return ObservedSessionState(session_id="sess_b1", status=SessionStatus.APPROVED)
                if session_id == "sess_b2":
                    return ObservedSessionState(
                        session_id="sess_b2", status=SessionStatus.IN_REVIEW
                    )
                if session_id == "sess_b3":
                    return None
                return ObservedSessionState(session_id="sess_b4", status=SessionStatus.APPROVED)

        batch_report = client.sessions.reconcile_range(
            since="2026-01-01T00:00:00Z",
            until="2026-01-02T00:00:00Z",
            source=MockSource(),
        )

        assert batch_report.total_evaluated == 4
        assert batch_report.drift_count == 1
        assert batch_report.missing_local_count == 1
        assert batch_report.missing_remote_count == 1
        assert len(batch_report.reports) == 4

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
    def test_poll_decision_non_transient_5xx_raises_immediately(
        self, client: Didit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_501/decision/").mock(
            return_value=Response(501, json={"error": "not implemented"})
        )
        with pytest.raises(DiditServerError) as exc_info:
            client.sessions.poll_decision("sess_501", timeout=5.0, tolerate_transient_errors=True)
        assert exc_info.value.status_code == 501

    @respx.mock
    def test_poll_decision_transient_error_timeout_exhausted(
        self, client: Didit, base_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        respx.get(f"{base_url}/session/sess_to/decision/").mock(
            return_value=Response(503, json={"error": "service down"})
        )
        ticks = [100.0, 100.0, 100.0, 105.0]
        monkeypatch.setattr("time.monotonic", lambda: ticks.pop(0) if ticks else 105.0)
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
            (403, DiditPermissionError),
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
    def test_http_error_capture_sensitive_response_default_and_explicit(
        self, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/s_leak/").mock(
            return_value=Response(
                400,
                text='{"detail": "Sensitive Biometric Payload"}',
                headers={"X-Request-Id": "req_leak_123"},
            )
        )
        # Default: capture_sensitive_response=False -> response_body is None
        client_safe = Didit(api_key="key", base_url=base_url)
        with pytest.raises(DiditAPIError) as exc_safe:
            client_safe.sessions.get("s_leak")
        assert exc_safe.value.response_body is None
        assert exc_safe.value.status_code == 400
        assert exc_safe.value.request_id == "req_leak_123"
        client_safe.close()

        # Explicit: capture_sensitive_response=True -> response_body retained
        client_sensitive = Didit(api_key="key", base_url=base_url, capture_sensitive_response=True)
        with pytest.raises(DiditAPIError) as exc_sens:
            client_sensitive.sessions.get("s_leak")
        assert exc_sens.value.response_body == '{"detail": "Sensitive Biometric Payload"}'
        client_sensitive.close()

        # Test exception causes suppression on connection/network error
        import httpx

        class ConnFailTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("Failed TCP connect")

        client_cause_safe = Didit(
            api_key="key",
            base_url="https://api.example.com",
            http_client=httpx.Client(transport=ConnFailTransport()),
        )
        with pytest.raises(DiditConnectionError) as conn_exc_safe:
            client_cause_safe.sessions.get("s_cause")
        assert conn_exc_safe.value.__cause__ is None
        assert conn_exc_safe.value.__suppress_context__ is True
        client_cause_safe.close()

        client_cause_sens = Didit(
            api_key="key",
            base_url="https://api.example.com",
            capture_sensitive_response=True,
            http_client=httpx.Client(transport=ConnFailTransport()),
        )
        with pytest.raises(DiditConnectionError) as conn_exc_sens:
            client_cause_sens.sessions.get("s_cause")
        assert isinstance(conn_exc_sens.value.__cause__, httpx.ConnectError)
        client_cause_sens.close()

    @pytest.mark.parametrize(
        ("kwargs",),
        [
            ({"api_key": "k"},),
            ({"base_url": "https://api.example.com"},),
            ({"timeout": 10.0},),
            ({"max_retries": 1},),
            ({"webhook_secret": "whsec"},),
            ({"capture_sensitive_response": False},),
        ],
    )
    def test_client_config_mutual_exclusivity(self, kwargs: dict[str, object]) -> None:
        cfg = DiditConfig(api_key="cfg_key")
        with pytest.deprecated_call(
            match="Passing explicit configuration arguments alongside `config`"
        ):
            client = Didit(config=cfg, **kwargs)
        assert client.config.api_key == "cfg_key"

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
        from didit.errors import DiditConfigurationError
        from didit.transport import RequestOptions, _SyncRequestor

        assert isinstance(client.requestor, _SyncRequestor)

        bound = client.with_options(RequestOptions(timeout=15.0))
        assert bound is not client
        assert bound.requestor._default_options is not None
        assert bound.requestor._default_options.timeout == 15.0

        with pytest.raises(DiditConfigurationError) as exc_info:
            client.with_options(RequestOptions(idempotency_key="bound_key"))
        assert "idempotency_key cannot be set as a client-level default option" in str(
            exc_info.value
        )

        with pytest.raises(DiditConfigurationError):
            Didit(
                api_key="test_key",
                default_options=RequestOptions(idempotency_key="client_level_key"),
            )

        with pytest.raises(DiditConfigurationError):
            AsyncDidit(
                api_key="test_key",
                default_options=RequestOptions(idempotency_key="client_level_key"),
            )

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

    @respx.mock
    def test_client_event_sink_integration(self, base_url: str) -> None:
        from didit.events import (
            DiditSDKEvent,
            RateLimitObserved,
            ReconciliationDriftObserved,
            RequestRetryScheduled,
        )
        from didit.models.session import ObservedSessionState

        events: list[DiditSDKEvent] = []

        class TestSink:
            def emit(self, event: DiditSDKEvent) -> None:
                events.append(event)

        sink = TestSink()
        client = Didit(
            api_key="key",
            base_url=base_url,
            event_sink=sink,
            max_retries=1,
        )
        assert client.event_sink is sink

        # Check with_options preserves event_sink
        cloned = client.with_options(RequestOptions())
        assert cloned.event_sink is sink

        # 1. Reconciliation drift emission
        respx.get(f"{base_url}/session/sess_sink_test/decision/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_sink_test", "status": "Approved", "warnings": []},
            )
        )
        client.sessions.reconcile(
            "sess_sink_test",
            observed=ObservedSessionState(
                session_id="sess_sink_test", status=SessionStatus.DECLINED
            ),
        )
        assert len(events) == 1
        assert isinstance(events[0], ReconciliationDriftObserved)
        assert events[0].session_id == "sess_sink_test"

        # 2. Rate limit and retry emission
        events.clear()
        route = respx.get(f"{base_url}/session/sess_rl/").mock(
            side_effect=[
                Response(429, headers={"retry-after": "0.01"}),
                Response(200, json={"session_id": "sess_rl", "status": "Approved"}),
            ]
        )
        client.sessions.get("sess_rl")
        assert route.call_count == 2
        assert len(events) == 2
        assert isinstance(events[0], RateLimitObserved)
        assert isinstance(events[1], RequestRetryScheduled)
        client.close()

    @respx.mock
    def test_reconcile_range_multi_page_pagination(self, client: Didit, base_url: str) -> None:
        from didit.models.session import ObservedSessionState

        page1_items = [{"session_id": f"sess_p1_{i}", "status": "Approved"} for i in range(50)]
        page2_items = [{"session_id": f"sess_p2_{i}", "status": "Approved"} for i in range(2)]
        respx.get(f"{base_url}/sessions/").mock(
            side_effect=[
                Response(
                    200,
                    json={
                        "count": 52,
                        "next": f"{base_url}/sessions/?offset=50&limit=50",
                        "previous": None,
                        "results": page1_items,
                    },
                ),
                Response(
                    200,
                    json={
                        "count": 52,
                        "next": None,
                        "previous": f"{base_url}/sessions/?offset=0&limit=50",
                        "results": page2_items,
                    },
                ),
            ]
        )
        for i in range(50):
            respx.get(f"{base_url}/session/sess_p1_{i}/decision/").mock(
                return_value=Response(
                    200,
                    json={"session_id": f"sess_p1_{i}", "status": "Approved", "warnings": []},
                )
            )
        for i in range(2):
            respx.get(f"{base_url}/session/sess_p2_{i}/decision/").mock(
                return_value=Response(
                    200,
                    json={"session_id": f"sess_p2_{i}", "status": "Approved", "warnings": []},
                )
            )

        class AllSyncSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        batch_report = client.sessions.reconcile_range(
            since="2026-01-01T00:00:00Z",
            until="2026-01-02T00:00:00Z",
            source=AllSyncSource(),
        )
        assert batch_report.total_evaluated == 52
        assert len(batch_report.reports) == 52
        assert batch_report.drift_count == 0
        assert batch_report.truncated is False
        assert batch_report.remote_count == 52

    @respx.mock
    def test_reconcile_range_max_sessions_cap(self, client: Didit, base_url: str) -> None:
        from didit.models.session import ObservedSessionState

        page1_items = [{"session_id": f"sess_cap_{i}", "status": "Approved"} for i in range(50)]
        respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 100,
                    "next": f"{base_url}/sessions/?offset=50&limit=50",
                    "previous": None,
                    "results": page1_items,
                },
            )
        )
        for i in range(30):
            respx.get(f"{base_url}/session/sess_cap_{i}/decision/").mock(
                return_value=Response(
                    200,
                    json={"session_id": f"sess_cap_{i}", "status": "Approved", "warnings": []},
                )
            )

        class AllSyncSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        batch_report = client.sessions.reconcile_range(
            since="2026-01-01T00:00:00Z",
            until="2026-01-02T00:00:00Z",
            source=AllSyncSource(),
            max_sessions=30,
        )
        assert batch_report.total_evaluated == 30
        assert len(batch_report.reports) == 30
        assert batch_report.truncated is True
        assert batch_report.remote_count == 100

    @respx.mock
    def test_reconcile_range_short_page_with_next_continues_pagination(
        self, client: Didit, base_url: str
    ) -> None:
        from didit.models.session import ObservedSessionState

        page1_items = [{"session_id": f"sess_short1_{i}", "status": "Approved"} for i in range(50)]
        page2_items = [{"session_id": f"sess_short2_{i}", "status": "Approved"} for i in range(20)]
        respx.get(f"{base_url}/sessions/").mock(
            side_effect=[
                Response(
                    200,
                    json={
                        "count": 70,
                        "next": f"{base_url}/sessions/?offset=50&limit=100",
                        "previous": None,
                        "results": page1_items,
                    },
                ),
                Response(
                    200,
                    json={
                        "count": 70,
                        "next": None,
                        "previous": f"{base_url}/sessions/?offset=0&limit=100",
                        "results": page2_items,
                    },
                ),
            ]
        )
        for i in range(50):
            respx.get(f"{base_url}/session/sess_short1_{i}/decision/").mock(
                return_value=Response(
                    200,
                    json={"session_id": f"sess_short1_{i}", "status": "Approved", "warnings": []},
                )
            )
        for i in range(20):
            respx.get(f"{base_url}/session/sess_short2_{i}/decision/").mock(
                return_value=Response(
                    200,
                    json={"session_id": f"sess_short2_{i}", "status": "Approved", "warnings": []},
                )
            )

        class AllSyncSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        batch_report = client.sessions.reconcile_range(
            page_size=100,
            source=AllSyncSource(),
        )
        assert batch_report.total_evaluated == 70
        assert len(batch_report.reports) == 70
        assert batch_report.drift_count == 0
        assert batch_report.truncated is False
        assert batch_report.remote_count == 70

    @respx.mock
    def test_reconcile_range_empty_results_with_next_raises_api_error(
        self, client: Didit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 10,
                    "next": f"{base_url}/sessions/?offset=0&limit=50",
                    "previous": None,
                    "results": [],
                },
            )
        )

        class DummySource:
            def get(self, session_id: str) -> None:
                return None

        with pytest.raises(
            DiditAPIError,
            match="Didit pagination returned next page metadata without progress",
        ) as exc_info:
            client.sessions.reconcile_range(source=DummySource())
        assert exc_info.value.status_code == 502

    @respx.mock
    def test_reconcile_range_inconsistent_count_without_next_raises_api_error(
        self, client: Didit, base_url: str
    ) -> None:
        from didit.models.session import ObservedSessionState

        page_items = [{"session_id": f"sess_incon_{i}", "status": "Approved"} for i in range(5)]
        respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 50,
                    "next": None,
                    "previous": None,
                    "results": page_items,
                },
            )
        )
        for i in range(5):
            respx.get(f"{base_url}/session/sess_incon_{i}/decision/").mock(
                return_value=Response(
                    200,
                    json={"session_id": f"sess_incon_{i}", "status": "Approved", "warnings": []},
                )
            )

        class AllSyncSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        with pytest.raises(
            DiditAPIError,
            match="Inconsistent pagination metadata: received 5 of 50 sessions without next page",
        ) as exc_info:
            client.sessions.reconcile_range(source=AllSyncSource())
        assert exc_info.value.status_code == 502

    @respx.mock
    def test_reconcile_range_empty_results_inconsistent_count_raises_api_error(
        self, client: Didit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 50,
                    "next": None,
                    "previous": None,
                    "results": [],
                },
            )
        )

        class DummySource:
            def get(self, session_id: str) -> None:
                return None

        with pytest.raises(
            DiditAPIError,
            match="Inconsistent pagination metadata: received 0 of 50 sessions without next page",
        ) as exc_info:
            client.sessions.reconcile_range(source=DummySource())
        assert exc_info.value.status_code == 502

    @pytest.mark.parametrize(
        ("filter_kwargs", "err_match"),
        [
            ({"session_kind": "business"}, "Unsupported session_kind 'business'"),
            ({"session_kind": None}, "Unsupported session_kind 'None'"),
            ({"country": "ES"}, "Expected 3-letter ISO 3166-1 alpha-3 code"),
            ({"country": "españa"}, "Expected 3-letter ISO 3166-1 alpha-3 code"),
            ({"limit": 0}, "limit must be between 1 and 100"),
            ({"limit": 101}, "limit must be between 1 and 100"),
            ({"offset": -1}, "offset must be non-negative"),
            ({"date_from": "2026-01-01T00:00:00"}, "must include timezone information"),
            ({"date_from": datetime(2026, 1, 1)}, "must be timezone-aware"),
            ({"date_from": 12345}, "must be a datetime or ISO-8601 string"),
            ({"date_from": "invalid-iso-string"}, "Invalid ISO-8601 timestamp string"),
            (
                {"date_from": "2026-01-02T00:00:00Z", "date_to": "2026-01-01T00:00:00Z"},
                "cannot be later than date_to",
            ),
        ],
    )
    def test_session_list_filter_validations(
        self, client: Didit, filter_kwargs: dict[str, Any], err_match: str
    ) -> None:
        with pytest.raises(ValueError, match=err_match):
            client.sessions.list(**filter_kwargs)

    @pytest.mark.parametrize(
        ("conflict_kwargs", "err_match"),
        [
            (
                {"since": "2026-01-01T00:00:00Z", "date_from": "2026-01-01T00:00:00Z"},
                "Specify either 'since' or 'date_from', not both",
            ),
            (
                {"until": "2026-01-02T00:00:00Z", "date_to": "2026-01-02T00:00:00Z"},
                "Specify either 'until' or 'date_to', not both",
            ),
            (
                {"page_size": 0},
                "page_size must be between 1 and 100",
            ),
            (
                {"limit": 101},
                "page_size must be between 1 and 100",
            ),
            (
                {"max_sessions": 0},
                "max_sessions must be greater than 0",
            ),
        ],
    )
    def test_reconcile_range_conflicting_parameters(
        self, client: Didit, conflict_kwargs: dict[str, Any], err_match: str
    ) -> None:
        class DummySource:
            def get(self, session_id: str) -> None:
                return None

        with pytest.raises(ValueError, match=err_match):
            client.sessions.reconcile_range(source=DummySource(), **conflict_kwargs)

    @respx.mock
    def test_reconcile_range_empty_results(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/sessions/").mock(
            return_value=Response(
                200,
                json={"count": 0, "next": None, "previous": None, "results": []},
            )
        )

        class DummySource:
            def get(self, session_id: str) -> None:
                return None

        report = client.sessions.reconcile_range(source=DummySource())
        assert report.total_evaluated == 0
        assert report.reports == []

    def test_reconcile_session_id_mismatch(self, client: Didit) -> None:
        from didit.models.session import ObservedSessionState

        with pytest.raises(
            ValueError,
            match="ObservedSessionState session_id mismatch: expected 'sess_target'",
        ):
            client.sessions.reconcile(
                "sess_target",
                observed=ObservedSessionState(
                    session_id="sess_other", status=SessionStatus.APPROVED
                ),
            )

    @respx.mock
    def test_reconcile_clean_missing_local_and_remote(self, client: Didit, base_url: str) -> None:
        # 1. Local missing: observed is None
        respx.get(f"{base_url}/session/sess_clean_local/decision/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_clean_local", "status": "Approved", "warnings": ["w1"]},
            )
        )
        report_local = client.sessions.reconcile("sess_clean_local", observed=None)
        assert report_local.local_missing is True
        assert report_local.remote_missing is False
        assert report_local.status_drift is False
        assert report_local.warning_codes_added == []
        assert report_local.warning_codes_removed == []
        assert report_local.is_in_sync is False

        # 2. Remote missing: 404 from upstream
        respx.get(f"{base_url}/session/sess_clean_remote/decision/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )
        from didit.models.session import ObservedSessionState

        report_remote = client.sessions.reconcile(
            "sess_clean_remote",
            observed=ObservedSessionState(
                session_id="sess_clean_remote", status=SessionStatus.APPROVED, warnings=["w1"]
            ),
        )
        assert report_remote.local_missing is False
        assert report_remote.remote_missing is True
        assert report_remote.status_drift is False
        assert report_remote.warning_codes_added == []
        assert report_remote.warning_codes_removed == []
        assert report_remote.is_in_sync is False

    @pytest.mark.parametrize("method_name", ["generate_pdf_report", "get_pdf_report"])
    @respx.mock
    def test_generate_pdf_report_success(
        self, client: Didit, base_url: str, method_name: str
    ) -> None:
        pdf_bytes = b"%PDF-1.4 simulated pdf document content \x00\x01\x02"
        respx.get(f"{base_url}/session/sess_pdf_123/generate-pdf/").mock(
            return_value=Response(
                200, content=pdf_bytes, headers={"Content-Type": "application/pdf"}
            )
        )
        fn = getattr(client.sessions, method_name)
        result = fn("sess_pdf_123")
        assert result == pdf_bytes

    @respx.mock
    def test_generate_pdf_report_not_found(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/sess_pdf_404/generate-pdf/").mock(
            return_value=Response(404, json={"detail": "Session not found"})
        )
        with pytest.raises(DiditNotFoundError):
            client.sessions.generate_pdf_report("sess_pdf_404")

    @pytest.mark.parametrize("invalid_id", ["", "   "])
    def test_generate_pdf_report_invalid_session_id(self, client: Didit, invalid_id: str) -> None:
        with pytest.raises(ValueError, match="session_id must not be empty"):
            client.sessions.generate_pdf_report(invalid_id)

    @respx.mock
    def test_generate_pdf_report_invalid_mime_and_magic(self, client: Didit, base_url: str) -> None:
        # Server returns 200 HTML error page instead of PDF
        respx.get(f"{base_url}/session/sess_bad_pdf/generate-pdf/").mock(
            return_value=Response(
                200, content=b"<html>Error occurred</html>", headers={"Content-Type": "text/html"}
            )
        )
        with pytest.raises(DiditAPIError, match="Invalid PDF report response"):
            client.sessions.generate_pdf_report("sess_bad_pdf")

    @respx.mock
    def test_generate_pdf_report_custom_timeout(self, client: Didit, base_url: str) -> None:
        from didit.transport import RequestOptions

        pdf_bytes = b"%PDF-1.4 custom timeout pdf"
        route = respx.get(f"{base_url}/session/sess_custom_timeout/generate-pdf/").mock(
            return_value=Response(
                200, content=pdf_bytes, headers={"Content-Type": "application/pdf"}
            )
        )
        opts = RequestOptions(timeout=120.0)
        res = client.sessions.generate_pdf_report("sess_custom_timeout", options=opts)
        assert res == pdf_bytes
        assert route.called

    @respx.mock
    def test_resubmit_success(self, client: Didit, base_url: str) -> None:
        route = respx.patch(f"{base_url}/session/sess_resub_1/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_resub_1",
                },
            )
        )

        res = client.sessions.resubmit("sess_resub_1")
        assert res.session_id == "sess_resub_1"
        assert route.called
        sent = json.loads(route.calls[0].request.content)
        assert sent["new_status"] == "Resubmitted"
        assert "nodes_to_resubmit" not in sent

    @respx.mock
    def test_resubmit_with_nodes(self, client: Didit, base_url: str) -> None:
        route = respx.patch(f"{base_url}/session/sess_resub_2/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_resub_2",
                },
            )
        )

        res = client.sessions.resubmit(
            "sess_resub_2",
            nodes_to_resubmit=[
                ResubmitNode(node_id="feature_ocr", feature=ResubmitFeature.OCR),
                {"node_id": "feature_liveness", "feature": "LIVENESS"},
            ],
            comment="Please redo OCR and Liveness",
            send_email=True,
            email_address="user@example.com",
            email_language="en",
        )
        assert res.session_id == "sess_resub_2"
        sent = json.loads(route.calls[0].request.content)
        assert sent["new_status"] == "Resubmitted"
        assert sent["nodes_to_resubmit"] == [
            {"node_id": "feature_ocr", "feature": "OCR"},
            {"node_id": "feature_liveness", "feature": "LIVENESS"},
        ]
        assert sent["comment"] == "Please redo OCR and Liveness"
        assert sent["send_email"] is True
        assert sent["email_address"] == "user@example.com"
        assert sent["email_language"] == "en"

    def test_resubmit_nodes_invalid_types(self, client: Didit) -> None:
        with pytest.raises(TypeError, match="must be a ResubmitNode, dict, or string"):
            client.sessions.resubmit("sess_err", nodes_to_resubmit=[12345])  # type: ignore[list-item]

        with pytest.raises(ValueError, match="must contain 'node_id' and 'feature'"):
            client.sessions.resubmit("sess_err", nodes_to_resubmit=[{"node_id": "foo"}])

        with pytest.raises(ValueError, match="must contain 'node_id' and 'feature'"):
            client.sessions.resubmit("sess_err", nodes_to_resubmit=[{"feature": "OCR"}])

    @respx.mock
    def test_resubmit_nodes_string_inference_matrix(self, client: Didit, base_url: str) -> None:
        route = respx.patch(f"{base_url}/session/sess_matrix/update-status/").mock(
            return_value=Response(200, json={"session_id": "sess_matrix"})
        )
        res = client.sessions.resubmit(
            "sess_matrix",
            nodes_to_resubmit=[
                "   ",
                "custom_node:LIVENESS",
                "live_step",
                "face_check",
                "face_match_check",
                "aml_screening",
                "poa_check",
                "address_step",
                "phone_auth",
                "email_verify",
                "doc_front",
                "ocr_back",
                "NFC",
                "unrecognized_step",
            ],
        )
        assert res.session_id == "sess_matrix"
        sent = json.loads(route.calls[0].request.content)
        expected_nodes = [
            {"node_id": "custom_node", "feature": "LIVENESS"},
            {"node_id": "live_step", "feature": "LIVENESS"},
            {"node_id": "face_check", "feature": "FACE"},
            {"node_id": "face_match_check", "feature": "FACE_MATCH"},
            {"node_id": "aml_screening", "feature": "AML"},
            {"node_id": "poa_check", "feature": "PROOF_OF_ADDRESS"},
            {"node_id": "address_step", "feature": "PROOF_OF_ADDRESS"},
            {"node_id": "phone_auth", "feature": "PHONE_VERIFICATION"},
            {"node_id": "email_verify", "feature": "EMAIL_VERIFICATION"},
            {"node_id": "doc_front", "feature": "OCR"},
            {"node_id": "ocr_back", "feature": "OCR"},
            {"node_id": "NFC", "feature": "NFC"},
            {"node_id": "unrecognized_step", "feature": "OCR"},
        ]
        assert sent["nodes_to_resubmit"] == expected_nodes

    @respx.mock
    def test_update_status_response_shapes(self, client: Didit, base_url: str) -> None:
        # Non-dict JSON response fallback
        respx.patch(f"{base_url}/session/sess_nondict/update-status/").mock(
            return_value=Response(200, json=["unexpected", "array"])
        )
        r1 = client.sessions.update_status("sess_nondict", SessionStatus.APPROVED)
        assert r1.session_id == "sess_nondict"
        assert r1.status == SessionStatus.APPROVED

        # Dict response with explicit status included upstream
        respx.patch(f"{base_url}/session/sess_explicit_status/update-status/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_explicit_status", "status": "Declined"},
            )
        )
        r2 = client.sessions.update_status("sess_explicit_status", SessionStatus.DECLINED)
        assert r2.session_id == "sess_explicit_status"
        assert r2.status == "Declined"

    def test_update_status_send_email_without_address(self, client: Didit) -> None:
        with pytest.raises(ValueError, match="email_address is required when send_email is True"):
            client.sessions.update_status(
                "sess_err",
                SessionStatus.APPROVED,
                send_email=True,
            )

    @pytest.mark.parametrize("invalid_id", ["", "   "])
    def test_resubmit_invalid_session_id(self, client: Didit, invalid_id: str) -> None:
        with pytest.raises(ValueError, match="session_id must not be empty"):
            client.sessions.resubmit(invalid_id)

    @respx.mock
    def test_update_status_custom(self, client: Didit, base_url: str) -> None:
        route = respx.patch(f"{base_url}/session/sess_custom_status/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_custom_status",
                },
            )
        )

        res = client.sessions.update_status(
            "sess_custom_status",
            SessionStatus.DECLINED,
            comment="Suspected fraud",
        )
        assert res.session_id == "sess_custom_status"
        sent = json.loads(route.calls[0].request.content)
        assert sent["new_status"] == "Declined"
        assert sent["comment"] == "Suspected fraud"

    @pytest.mark.parametrize(
        "invalid_status",
        [
            "In Review",
            "In Progress",
            SessionStatus.IN_REVIEW,
            SessionStatus.NOT_STARTED,
            SessionStatus.EXPIRED,
            "Unknown",
        ],
    )
    def test_update_status_invalid_manual_status(self, client: Didit, invalid_status: Any) -> None:
        with pytest.raises(ValueError, match="Invalid manual status transition"):
            client.sessions.update_status("sess_invalid", invalid_status)

    @respx.mock
    def test_pdf_report_options_timeout_none(self, client: Didit, base_url: str) -> None:
        from didit.transport import RequestOptions

        respx.get(f"{base_url}/session/sess_pdf_opt/generate-pdf/").mock(
            return_value=Response(
                200,
                content=b"%PDF-1.4 sample content",
                headers={"Content-Type": "application/pdf"},
            )
        )
        pdf = client.sessions.generate_pdf_report(
            "sess_pdf_opt", options=RequestOptions(timeout=None)
        )
        assert pdf.startswith(b"%PDF-")

    @respx.mock
    def test_generate_pdf_report_octet_stream(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/sess_pdf_bin/generate-pdf/").mock(
            return_value=Response(
                200,
                content=b"%PDF-1.4 binary octet",
                headers={"Content-Type": "application/octet-stream"},
            )
        )
        pdf = client.sessions.generate_pdf_report("sess_pdf_bin")
        assert pdf == b"%PDF-1.4 binary octet"

    @respx.mock
    def test_generate_pdf_report_invalid_magic_with_pdf_mime(
        self, client: Didit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_pdf_bad_magic/generate-pdf/").mock(
            return_value=Response(
                200,
                content=b"CORRUPTED_NOT_PDF_HEADER",
                headers={"Content-Type": "application/pdf"},
            )
        )
        with pytest.raises(DiditAPIError) as exc_info:
            client.sessions.generate_pdf_report("sess_pdf_bad_magic")
        assert exc_info.value.status_code == 502

    @respx.mock
    def test_generate_pdf_report_valid_magic_with_invalid_mime(
        self, client: Didit, base_url: str
    ) -> None:
        respx.get(f"{base_url}/session/sess_pdf_bad_mime/generate-pdf/").mock(
            return_value=Response(
                200,
                content=b"%PDF-1.4 valid magic header",
                headers={"Content-Type": "text/html"},
            )
        )
        with pytest.raises(DiditAPIError) as exc_info:
            client.sessions.generate_pdf_report("sess_pdf_bad_mime")
        assert exc_info.value.status_code == 502

    @respx.mock
    def test_download_pdf_report_success_and_force(
        self, client: Didit, base_url: str, tmp_path: Path
    ) -> None:
        target = tmp_path / "reports" / "compliance.pdf"
        pdf_content = b"%PDF-1.4 official compliance report binary content"
        respx.get(f"{base_url}/session/sess_pdf_dl/generate-pdf/").mock(
            return_value=Response(
                200,
                content=pdf_content,
                headers={"Content-Type": "application/pdf"},
            )
        )

        # 1. Successful download to new file
        saved = client.sessions.download_pdf_report("sess_pdf_dl", target)
        assert saved == target.resolve()
        assert target.is_file()
        assert target.read_bytes() == pdf_content

        # 2. Re-download with force=False raises FileExistsError
        with pytest.raises(FileExistsError, match="already exists"):
            client.sessions.download_pdf_report("sess_pdf_dl", target, force=False)

        # 3. Re-download with force=True succeeds and overwrites
        new_pdf_content = b"%PDF-1.4 updated compliance report binary content"
        respx.get(f"{base_url}/session/sess_pdf_dl_overwrite/generate-pdf/").mock(
            return_value=Response(
                200,
                content=new_pdf_content,
                headers={"Content-Type": "application/pdf"},
            )
        )
        saved_overwrite = client.sessions.download_pdf_report(
            "sess_pdf_dl_overwrite", target, force=True
        )
        assert saved_overwrite == target.resolve()
        assert target.read_bytes() == new_pdf_content

        # 4. Empty/whitespace session_id raises ValueError
        with pytest.raises(ValueError, match="session_id must not be empty or whitespace"):
            client.sessions.download_pdf_report("", target)
        with pytest.raises(ValueError, match="session_id must not be empty or whitespace"):
            client.sessions.download_pdf_report("   ", target)

        # 5. Options branches (timeout=None and explicit timeout)
        target_opt1 = tmp_path / "opt1.pdf"
        target_opt2 = tmp_path / "opt2.pdf"
        respx.get(f"{base_url}/session/sess_opt/generate-pdf/").mock(
            return_value=Response(
                200, content=pdf_content, headers={"Content-Type": "application/pdf"}
            )
        )
        client.sessions.download_pdf_report(
            "sess_opt", target_opt1, options=RequestOptions(idempotency_key="opt_key")
        )
        client.sessions.download_pdf_report(
            "sess_opt", target_opt2, options=RequestOptions(timeout=25.0)
        )
        assert target_opt1.is_file()
        assert target_opt2.is_file()
