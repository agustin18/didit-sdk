"""Targeted tests for Didit Django webhook integration."""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock

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

from didit.dedup import InMemoryWebhookDedupStore
from didit.errors import DiditConfigurationError
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
        mock_store = AsyncMock()
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
