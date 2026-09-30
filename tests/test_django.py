"""Targeted tests for Didit Django webhook integration."""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        SECRET_KEY="test-secret-key-for-django-settings",
        ALLOWED_HOSTS=["*"],
    )
    django.setup()

import pytest
from django.http import HttpRequest, HttpResponse, JsonResponse

from didit.dedup import (
    AsyncWebhookDedupStore,
    InMemoryWebhookDedupStore,
    InMemoryWebhookReservationStore,
    ReservationAttempt,
    ReservationState,
)
from didit.errors import DiditConfigurationError
from didit.events import (
    DiditEventSink,
    DiditSDKEvent,
    WebhookDuplicateObserved,
    WebhookLeaseDegraded,
    WebhookLeaseLost,
)
from didit.integrations.django import didit_webhook_view, parse_django_webhook
from didit.models.enums import SessionStatus
from didit.models.webhook import WebhookPayload
from didit.webhooks import compute_signature

SECRET = "whsec_test_secret_12345"


def create_signed_django_request(
    body_dict: dict[str, Any],
    secret: str = SECRET,
    timestamp: int | None = None,
    method: str = "POST",
    tamper_sig: bool = False,
    content_length: int | None = None,
) -> HttpRequest:
    data = dict(body_dict)
    data["created_at"] = timestamp if timestamp is not None else int(time.time())
    raw_body = json.dumps(data).encode("utf-8")
    sig = compute_signature(secret, data, version="v2")
    if tamper_sig:
        sig = "0" * 64

    request = HttpRequest()
    request.method = method
    request._body = raw_body
    cl = str(content_length if content_length is not None else len(raw_body))
    request.META = {
        "HTTP_X_SIGNATURE_V2": sig,
        "CONTENT_LENGTH": cl,
    }
    request.headers = {  # type: ignore[attr-defined]
        "x-signature-v2": sig,
        "content-length": cl,
    }
    return request


SAMPLE_PAYLOAD = {
    "session_id": "ses_django_123",
    "status": "Approved",
    "workflow_id": "wf_123",
    "workflow_version": 1,
}


class TestDjangoWebhookView:
    def test_missing_secret_raises_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        with pytest.raises(DiditConfigurationError, match="Missing webhook secret"):
            didit_webhook_view(secret=None)

    def test_invalid_duplicate_action_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid duplicate_action"):
            didit_webhook_view(secret=SECRET, duplicate_action="invalid")  # type: ignore[arg-type]

    def test_csrf_exempt_attribute_set(self) -> None:
        @didit_webhook_view(secret=SECRET)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        assert getattr(view, "csrf_exempt", False) is True

    def test_method_not_allowed_for_non_post(self) -> None:
        @didit_webhook_view(secret=SECRET)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        request = create_signed_django_request(SAMPLE_PAYLOAD, method="GET")
        response = view(request)
        assert response.status_code == 405

    def test_payload_exceeding_content_length_limit(self) -> None:
        @didit_webhook_view(secret=SECRET, max_body_bytes=50)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        request = create_signed_django_request(SAMPLE_PAYLOAD, content_length=500)
        response = view(request)
        assert response.status_code == 413
        assert b"exceeds maximum size limit" in response.content

    def test_payload_exceeding_body_size_limit(self) -> None:
        @didit_webhook_view(secret=SECRET, max_body_bytes=20)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        request = create_signed_django_request(SAMPLE_PAYLOAD)
        request.headers["content-length"] = "10"  # Lie about content length
        response = view(request)
        assert response.status_code == 413

    def test_invalid_signature_returns_401(self) -> None:
        @didit_webhook_view(secret=SECRET)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        request = create_signed_django_request(SAMPLE_PAYLOAD, tamper_sig=True)
        response = view(request)
        assert response.status_code == 401
        assert b"Invalid webhook signature" in response.content

    def test_malformed_json_returns_400(self) -> None:
        @didit_webhook_view(secret=SECRET)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        bad_json = b"{not: json"
        request = HttpRequest()
        request.method = "POST"
        request._body = bad_json
        request.headers = {"x-signature-v2": "0" * 64}  # type: ignore[attr-defined]

        response = view(request)
        assert response.status_code == 400
        assert b"Malformed JSON" in response.content

    def test_successful_sync_view_invocation(self) -> None:
        received_payload: list[WebhookPayload] = []

        @didit_webhook_view(secret=SECRET)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            received_payload.append(payload)
            return JsonResponse({"processed": payload.session_id})

        request = create_signed_django_request(SAMPLE_PAYLOAD)
        response = view(request)
        assert response.status_code == 200
        assert len(received_payload) == 1
        assert received_payload[0].session_id == "ses_django_123"
        assert received_payload[0].status == SessionStatus.APPROVED

    def test_handler_returning_none_defaults_to_200(self) -> None:
        @didit_webhook_view(secret=SECRET)
        def view(request: HttpRequest, payload: WebhookPayload) -> None:
            pass

        request = create_signed_django_request(SAMPLE_PAYLOAD)
        response = view(request)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_successful_async_view_invocation(self) -> None:
        received_payload: list[WebhookPayload] = []

        @didit_webhook_view(secret=SECRET)
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            received_payload.append(payload)
            return HttpResponse("async-ok", status=201)

        request = create_signed_django_request(SAMPLE_PAYLOAD)
        response = await view(request)
        assert response.status_code == 201
        assert response.content == b"async-ok"
        assert len(received_payload) == 1
        assert received_payload[0].session_id == "ses_django_123"

    def test_dedup_store_respond_ok(self) -> None:
        store = InMemoryWebhookDedupStore()

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("processed")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        res1 = view(request1)
        assert res1.status_code == 200
        assert res1.content == b"processed"

        # Replay identical event
        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        res2 = view(request2)
        assert res2.status_code == 200
        assert b"Duplicate webhook event acknowledged" in res2.content

    def test_dedup_store_raise(self) -> None:
        store = InMemoryWebhookDedupStore()

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="raise")
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("processed")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        assert view(request1).status_code == 200

        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        res2 = view(request2)
        assert res2.status_code == 409
        assert b"Duplicate webhook event" in res2.content

    def test_dedup_store_pass(self) -> None:
        store = InMemoryWebhookDedupStore()
        seen_duplicates: list[bool] = []

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="pass")
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            seen_duplicates.append(payload.is_duplicate)
            return HttpResponse("ok")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        view(request1)
        assert seen_duplicates == [False]

        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        view(request2)
        assert seen_duplicates == [False, True]

    def test_dedup_store_default_action_is_pass(self) -> None:
        store = InMemoryWebhookDedupStore()
        seen_duplicates: list[bool] = []

        @didit_webhook_view(secret=SECRET, dedup_store=store)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            seen_duplicates.append(payload.is_duplicate)
            return HttpResponse("ok")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        view(request1)
        assert seen_duplicates == [False]

        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        view(request2)
        assert seen_duplicates == [False, True]

    def test_custom_dedup_key_builder(self) -> None:
        store = InMemoryWebhookDedupStore()

        @didit_webhook_view(
            secret=SECRET,
            dedup_store=store,
            dedup_key_builder=lambda p, r: f"custom:{p.session_id}",
        )
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        request = create_signed_django_request(SAMPLE_PAYLOAD)
        assert view(request).status_code == 200
        assert store.claim("custom:ses_django_123", ttl_seconds=60) is False

    @pytest.mark.asyncio
    async def test_async_dedup_store_with_async_view(self) -> None:
        mock_store = AsyncMock(spec=AsyncWebhookDedupStore)
        mock_store.aclaim.side_effect = [True, False]

        @didit_webhook_view(secret=SECRET, dedup_store=mock_store, duplicate_action="respond_ok")
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok")

        request = create_signed_django_request(SAMPLE_PAYLOAD)
        res1 = await view(request)
        assert res1.status_code == 200

        res2 = await view(request)
        assert res2.status_code == 200
        assert b"Duplicate webhook event acknowledged" in res2.content

    def test_dedup_release_on_handler_exception(self) -> None:
        store = InMemoryWebhookDedupStore()
        call_count = 0

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Database error")
            return HttpResponse("success")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        with pytest.raises(RuntimeError, match="Database error"):
            view(request1)

        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        res = view(request2)
        assert res.status_code == 200
        assert res.content == b"success"
        assert call_count == 2

    def test_dedup_release_on_server_error_response(self) -> None:
        store = InMemoryWebhookDedupStore()
        call_count = 0

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return HttpResponse("Database down", status=503)
            return HttpResponse("success")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        res1 = view(request1)
        assert res1.status_code == 503

        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        res2 = view(request2)
        assert res2.status_code == 200
        assert res2.content == b"success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_async_dedup_release_on_exception_and_error(self) -> None:
        store = InMemoryWebhookDedupStore()
        call_count = 0

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Async DB failure")
            if call_count == 2:
                return HttpResponse("Server error", status=500)
            return HttpResponse("async success")

        request1 = create_signed_django_request(SAMPLE_PAYLOAD)
        with pytest.raises(ValueError, match="Async DB failure"):
            await view(request1)

        request2 = create_signed_django_request(SAMPLE_PAYLOAD)
        res2 = await view(request2)
        assert res2.status_code == 500

        request3 = create_signed_django_request(SAMPLE_PAYLOAD)
        res3 = await view(request3)
        assert res3.status_code == 200
        assert res3.content == b"async success"
        assert call_count == 3


class TestParseDjangoWebhook:
    def test_successful_parsing(self) -> None:
        request = create_signed_django_request(SAMPLE_PAYLOAD)
        payload = parse_django_webhook(request, secret=SECRET)
        assert payload.session_id == "ses_django_123"

    def test_content_length_exceeded(self) -> None:
        request = create_signed_django_request(SAMPLE_PAYLOAD, content_length=2000)
        with pytest.raises(ValueError, match="exceeds maximum size limit"):
            parse_django_webhook(request, secret=SECRET, max_body_bytes=50)

    def test_body_size_exceeded(self) -> None:
        request = create_signed_django_request(SAMPLE_PAYLOAD)
        with pytest.raises(ValueError, match="exceeds maximum size limit"):
            parse_django_webhook(request, secret=SECRET, max_body_bytes=10)

    def test_missing_secret_fallback_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", SECRET)
        request = create_signed_django_request(SAMPLE_PAYLOAD)
        payload = parse_django_webhook(request)
        assert payload.session_id == "ses_django_123"

    def test_missing_secret_raises_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        request = create_signed_django_request(SAMPLE_PAYLOAD)
        with pytest.raises(DiditConfigurationError, match="Missing webhook secret"):
            parse_django_webhook(request, secret=None)

    def test_invalid_content_length_header_ignored(self) -> None:
        request = create_signed_django_request(SAMPLE_PAYLOAD)
        request.headers["content-length"] = "not-a-number"  # type: ignore[attr-defined]
        payload = parse_django_webhook(request, secret=SECRET)
        assert payload.session_id == "ses_django_123"

    def test_unread_stream_request_within_limit(self) -> None:
        from unittest.mock import MagicMock

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        # Mock request without _body, but with read()
        mock_req = MagicMock(spec=HttpRequest)
        del mock_req._body
        raw_body = req.body
        mock_req.read = MagicMock(return_value=raw_body)
        mock_req.headers = dict(req.headers)
        mock_req.META = dict(req.META)
        payload = parse_django_webhook(mock_req, secret=SECRET)
        assert payload.session_id == "ses_django_123"
        assert mock_req._body == raw_body

    def test_unread_stream_request_exceeds_limit(self) -> None:
        from unittest.mock import MagicMock

        mock_req = MagicMock(spec=HttpRequest)
        del mock_req._body
        mock_req.read = MagicMock(return_value=b"x" * 50)
        mock_req.headers = {}
        mock_req.META = {}
        with pytest.raises(ValueError, match="exceeds maximum size limit"):
            parse_django_webhook(mock_req, secret=SECRET, max_body_bytes=20)


class TestDjangoWebhookReservation:
    def test_invalid_processing_action_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid processing_action 'invalid'"):
            didit_webhook_view(secret=SECRET, processing_action="invalid")  # type: ignore[arg-type]

    def test_async_reservation_store_with_sync_view_raises(self) -> None:
        class FakeAsyncResStore:
            async def areserve(self, *args: Any, **kwargs: Any) -> Any:
                pass

        with pytest.raises(
            DiditConfigurationError, match="AsyncWebhookReservationStore cannot be used"
        ):

            @didit_webhook_view(secret=SECRET, dedup_store=FakeAsyncResStore())  # type: ignore[arg-type]
            def sync_view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
                return HttpResponse("ok")

    @pytest.mark.parametrize("action", ["retry", "raise", "pass"])
    def test_sync_processing_actions(self, action: str) -> None:
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_django_res"}
        # Seed in-flight reservation
        store.reserve("evt_django_res", token="other_worker", ttl_seconds=60)

        @didit_webhook_view(
            secret=SECRET,
            dedup_store=store,
            processing_action=action,  # type: ignore[arg-type]
        )
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return JsonResponse({"duplicate": payload.is_duplicate})

        req = create_signed_django_request(payload_data)
        if action == "retry":
            resp = view(req)
            assert resp.status_code == 503
            assert resp.headers["Retry-After"] == "5"
        elif action == "raise":
            from didit.errors import DiditDuplicateWebhookError

            with pytest.raises(DiditDuplicateWebhookError) as exc_info:
                view(req)
            assert exc_info.value.state == "PROCESSING"
            assert exc_info.value.event_id == "evt_django_res"
        elif action == "pass":
            resp = view(req)
            assert resp.status_code == 200
            assert json.loads(resp.content)["duplicate"] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["retry", "raise", "pass"])
    async def test_async_processing_actions(self, action: str) -> None:
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_django_async_res"}
        store.reserve("evt_django_async_res", token="other_worker", ttl_seconds=60)

        @didit_webhook_view(
            secret=SECRET,
            dedup_store=store,
            processing_action=action,  # type: ignore[arg-type]
        )
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return JsonResponse({"duplicate": payload.is_duplicate})

        req = create_signed_django_request(payload_data)
        if action == "retry":
            resp = await view(req)
            assert resp.status_code == 503
            assert resp.headers["Retry-After"] == "5"
        elif action == "raise":
            from didit.errors import DiditDuplicateWebhookError

            with pytest.raises(DiditDuplicateWebhookError) as exc_info:
                await view(req)
            assert exc_info.value.state == "PROCESSING"
            assert exc_info.value.event_id == "evt_django_async_res"
        elif action == "pass":
            resp = await view(req)
            assert resp.status_code == 200
            assert json.loads(resp.content)["duplicate"] is True

    def test_sync_reservation_lifecycle_complete_and_release(self) -> None:
        store = InMemoryWebhookReservationStore()
        call_count = 0
        should_fail_500 = False
        should_raise = False

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            nonlocal call_count
            call_count += 1
            if should_raise:
                raise RuntimeError("Handler failed")
            if should_fail_500:
                return HttpResponse(status=500)
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)

        # 1. Exception -> releases lease so next call can acquire
        should_raise = True
        with pytest.raises(RuntimeError):
            view(req)
        assert call_count == 1

        # 2. 500 status -> releases lease so next call can acquire
        should_raise = False
        should_fail_500 = True
        resp500 = view(req)
        assert resp500.status_code == 500
        assert call_count == 2

        # 3. 200 status -> completes lease
        should_fail_500 = False
        resp200 = view(req)
        assert resp200.status_code == 200
        assert call_count == 3

        # 4. Duplicate call -> returns duplicate acknowledgment (view not invoked)
        resp_dup = view(req)
        assert resp_dup.status_code == 200
        assert b"Duplicate webhook event acknowledged" in resp_dup.content
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_async_reservation_lifecycle_complete_and_release(self) -> None:
        store = InMemoryWebhookReservationStore()
        call_count = 0
        should_fail_500 = False
        should_raise = False

        @didit_webhook_view(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            nonlocal call_count
            call_count += 1
            if should_raise:
                raise RuntimeError("Handler failed")
            if should_fail_500:
                return HttpResponse(status=500)
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)

        # 1. Exception -> releases lease
        should_raise = True
        with pytest.raises(RuntimeError):
            await view(req)

        # 2. 500 status -> releases lease
        should_raise = False
        should_fail_500 = True
        resp500 = await view(req)
        assert resp500.status_code == 500

        # 3. 200 status -> completes lease
        should_fail_500 = False
        resp200 = await view(req)
        assert resp200.status_code == 200

        # 4. Duplicate call -> duplicate acknowledged
        resp_dup = await view(req)
        assert resp_dup.status_code == 200
        assert b"Duplicate webhook event acknowledged" in resp_dup.content

    def test_default_adapter_lease_ttl_is_30_seconds(self) -> None:
        mock_store = MagicMock()
        mock_store.reserve.return_value = ReservationAttempt(state=ReservationState.ACQUIRED)

        @didit_webhook_view(secret=SECRET, dedup_store=mock_store)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        view(req)

        mock_store.reserve.assert_called_once()
        _, kwargs = mock_store.reserve.call_args
        assert kwargs.get("ttl_seconds") == 30

    def test_actual_async_redis_store_in_sync_django_raises_config_error(self) -> None:
        from didit.dedup import AsyncRedisWebhookReservationStore

        store = AsyncRedisWebhookReservationStore(client=MagicMock())

        with pytest.raises(
            DiditConfigurationError,
            match="AsyncWebhookReservationStore cannot be used with synchronous",
        ):

            @didit_webhook_view(secret=SECRET, dedup_store=store)
            def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
                return HttpResponse("ok", status=200)

    def test_django_404_releases_reservation(self) -> None:
        store = InMemoryWebhookReservationStore()
        execution_count = 0

        @didit_webhook_view(secret=SECRET, dedup_store=store)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            nonlocal execution_count
            execution_count += 1
            if execution_count == 1:
                return HttpResponse("not found", status=404)
            return HttpResponse("recovered", status=200)

        # Request 1: returns 404 -> reservation released
        req1 = create_signed_django_request(SAMPLE_PAYLOAD)
        resp1 = view(req1)
        assert resp1.status_code == 404
        assert execution_count == 1

        # Request 2 (retry with identical payload): must execute view and return 200
        req2 = create_signed_django_request(SAMPLE_PAYLOAD)
        resp2 = view(req2)
        assert resp2.status_code == 200
        assert resp2.content == b"recovered"
        assert execution_count == 2

    def test_django_legacy_store_retains_default_86400_ttl(self) -> None:
        mock_legacy = MagicMock(spec=["claim", "release"])
        mock_legacy.claim.return_value = True

        @didit_webhook_view(secret=SECRET, dedup_store=mock_legacy)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        view(req)
        mock_legacy.claim.assert_called_once()
        call_args = mock_legacy.claim.call_args
        effective_ttl = call_args.kwargs.get("ttl_seconds") or call_args.args[1]
        assert effective_ttl == 86400

    def test_django_processing_action_conflict(self) -> None:
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_conflict"}
        store.reserve("evt_conflict", token="other_worker", ttl_seconds=60)

        @didit_webhook_view(
            secret=SECRET,
            dedup_store=store,
            processing_action="conflict",
        )
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(payload_data)
        resp = view(req)
        assert resp.status_code == 409
        assert b"currently being processed" in resp.content


class RecordingSink(DiditEventSink):
    def __init__(self) -> None:
        self.events: list[DiditSDKEvent] = []

    def emit(self, event: DiditSDKEvent) -> None:
        self.events.append(event)


class TestDjangoTelemetry:
    def test_django_telemetry_normal_flow_sets_request_attributes(self) -> None:
        sink = RecordingSink()

        @didit_webhook_view(secret=SECRET, event_sink=sink)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            assert request.didit_event_sink is sink
            assert request.didit_event_id == payload.event_id
            assert request.didit_session_id == payload.session_id
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = view(req)
        assert resp.status_code == 200
        assert len(sink.events) == 0

    @pytest.mark.asyncio
    async def test_django_async_telemetry_normal_flow_sets_request_attributes(self) -> None:
        sink = RecordingSink()

        @didit_webhook_view(secret=SECRET, event_sink=sink)
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            assert request.didit_event_sink is sink
            assert request.didit_event_id == payload.event_id
            assert request.didit_session_id == payload.session_id
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = await view(req)
        assert resp.status_code == 200
        assert len(sink.events) == 0

    def test_django_telemetry_degraded_lease(self) -> None:
        sink = RecordingSink()
        store = MagicMock()
        store.reserve.return_value = ReservationAttempt(
            state=ReservationState.ACQUIRED,
            reservation=None,
            degraded=True,
        )

        @didit_webhook_view(secret=SECRET, dedup_store=store, event_sink=sink)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = view(req)
        assert resp.status_code == 200
        assert any(isinstance(e, WebhookLeaseDegraded) for e in sink.events)

    @pytest.mark.asyncio
    async def test_django_async_telemetry_degraded_lease(self) -> None:
        sink = RecordingSink()
        store = MagicMock()
        store.areserve = AsyncMock(
            return_value=ReservationAttempt(
                state=ReservationState.ACQUIRED,
                reservation=None,
                degraded=True,
            )
        )

        @didit_webhook_view(secret=SECRET, dedup_store=store, event_sink=sink)
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = await view(req)
        assert resp.status_code == 200
        assert any(isinstance(e, WebhookLeaseDegraded) for e in sink.events)

    def test_django_telemetry_duplicate_completed(self) -> None:
        sink = RecordingSink()
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_dup"}
        attempt = store.reserve("evt_dup", token="tok1")
        store.complete("evt_dup", token=attempt.reservation.token)  # type: ignore[union-attr]

        @didit_webhook_view(
            secret=SECRET, dedup_store=store, duplicate_action="respond_ok", event_sink=sink
        )
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(payload_data)
        resp = view(req)
        assert resp.status_code == 200
        assert b"acknowledged" in resp.content
        assert any(
            isinstance(e, WebhookDuplicateObserved) and e.action_taken == "respond_ok"
            for e in sink.events
        )

    @pytest.mark.asyncio
    async def test_django_async_telemetry_duplicate_completed(self) -> None:
        sink = RecordingSink()
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_async_dup"}
        attempt = store.reserve("evt_async_dup", token="tok1")
        store.complete("evt_async_dup", token=attempt.reservation.token)  # type: ignore[union-attr]

        @didit_webhook_view(
            secret=SECRET, dedup_store=store, duplicate_action="respond_ok", event_sink=sink
        )
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(payload_data)
        resp = await view(req)
        assert resp.status_code == 200
        assert b"acknowledged" in resp.content
        assert any(
            isinstance(e, WebhookDuplicateObserved) and e.action_taken == "respond_ok"
            for e in sink.events
        )

    def test_django_telemetry_duplicate_processing(self) -> None:
        sink = RecordingSink()
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_proc"}
        store.reserve("evt_proc", token="tok_in_flight", ttl_seconds=60)

        @didit_webhook_view(
            secret=SECRET, dedup_store=store, processing_action="retry", event_sink=sink
        )
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(payload_data)
        resp = view(req)
        assert resp.status_code == 503
        assert any(
            isinstance(e, WebhookDuplicateObserved) and e.action_taken == "retry"
            for e in sink.events
        )

    @pytest.mark.asyncio
    async def test_django_async_telemetry_duplicate_processing(self) -> None:
        sink = RecordingSink()
        store = InMemoryWebhookReservationStore()
        payload_data = {**SAMPLE_PAYLOAD, "event_id": "evt_async_proc"}
        store.reserve("evt_async_proc", token="tok_in_flight", ttl_seconds=60)

        @didit_webhook_view(
            secret=SECRET, dedup_store=store, processing_action="retry", event_sink=sink
        )
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(payload_data)
        resp = await view(req)
        assert resp.status_code == 503
        assert any(
            isinstance(e, WebhookDuplicateObserved) and e.action_taken == "retry"
            for e in sink.events
        )

    def test_django_telemetry_legacy_store_duplicate(self) -> None:
        sink = RecordingSink()
        mock_legacy = MagicMock(spec=["claim", "release"])
        mock_legacy.claim.return_value = False

        @didit_webhook_view(
            secret=SECRET, dedup_store=mock_legacy, duplicate_action="respond_ok", event_sink=sink
        )
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = view(req)
        assert resp.status_code == 200
        assert b"acknowledged" in resp.content
        assert any(
            isinstance(e, WebhookDuplicateObserved) and e.action_taken == "respond_ok"
            for e in sink.events
        )

    def test_django_telemetry_release_failure_during_unwind(self) -> None:
        sink = RecordingSink()
        store = MagicMock()
        store.reserve.return_value = ReservationAttempt(
            state=ReservationState.ACQUIRED,
            reservation=MagicMock(token="tok1"),
        )
        store.release.side_effect = RuntimeError("network partition on release")

        @didit_webhook_view(secret=SECRET, dedup_store=store, event_sink=sink)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            raise ValueError("Endpoint exploded")

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        with pytest.raises(ValueError, match="Endpoint exploded"):
            view(req)

        lost_events = [e for e in sink.events if isinstance(e, WebhookLeaseLost)]
        assert len(lost_events) == 1
        assert "Release failed during exception unwind" in lost_events[0].reason

    @pytest.mark.asyncio
    async def test_django_async_telemetry_release_failure_during_unwind(self) -> None:
        sink = RecordingSink()
        store = MagicMock()
        store.areserve = AsyncMock(
            return_value=ReservationAttempt(
                state=ReservationState.ACQUIRED,
                reservation=MagicMock(token="tok1"),
            )
        )
        store.arelease = AsyncMock(side_effect=RuntimeError("network partition on release"))

        @didit_webhook_view(secret=SECRET, dedup_store=store, event_sink=sink)
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            raise ValueError("Endpoint exploded")

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        with pytest.raises(ValueError, match="Endpoint exploded"):
            await view(req)

        lost_events = [e for e in sink.events if isinstance(e, WebhookLeaseLost)]
        assert len(lost_events) == 1
        assert "Release failed during exception unwind" in lost_events[0].reason

    def test_django_telemetry_cas_failure_emits_lease_lost(self) -> None:
        sink = RecordingSink()
        store = MagicMock()
        store.reserve.return_value = ReservationAttempt(
            state=ReservationState.ACQUIRED,
            reservation=MagicMock(token="tok1"),
        )
        store.complete.return_value = False

        @didit_webhook_view(secret=SECRET, dedup_store=store, event_sink=sink)
        def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = view(req)
        assert resp.status_code == 200
        lost_events = [e for e in sink.events if isinstance(e, WebhookLeaseLost)]
        assert len(lost_events) == 1
        assert lost_events[0].reason == "lease_cas_failed"

    @pytest.mark.asyncio
    async def test_django_async_telemetry_cas_failure_emits_lease_lost(self) -> None:
        sink = RecordingSink()
        store = MagicMock()
        store.areserve = AsyncMock(
            return_value=ReservationAttempt(
                state=ReservationState.ACQUIRED,
                reservation=MagicMock(token="tok1"),
            )
        )
        store.acomplete = AsyncMock(return_value=False)

        @didit_webhook_view(secret=SECRET, dedup_store=store, event_sink=sink)
        async def view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
            return HttpResponse("ok", status=200)

        req = create_signed_django_request(SAMPLE_PAYLOAD)
        resp = await view(req)
        assert resp.status_code == 200
        lost_events = [e for e in sink.events if isinstance(e, WebhookLeaseLost)]
        assert len(lost_events) == 1
        assert lost_events[0].reason == "lease_cas_failed"
