"""Targeted tests for Didit Flask webhook integration."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from flask import Flask, Response, g, jsonify

from didit.dedup import InMemoryWebhookDedupStore
from didit.errors import DiditConfigurationError, DiditSignatureError
from didit.integrations.flask import didit_webhook, parse_flask_webhook
from didit.models.enums import SessionStatus
from didit.models.webhook import WebhookPayload
from didit.webhooks import compute_signature

SECRET = "whsec_flask_test_secret_98765"


def create_signed_flask_client(
    app: Flask,
    path: str,
    body_dict: dict[str, Any],
    secret: str = SECRET,
    timestamp: int | None = None,
    method: str = "POST",
    tamper_sig: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> Any:
    data = dict(body_dict)
    data["created_at"] = timestamp if timestamp is not None else int(time.time())
    raw_body = json.dumps(data).encode("utf-8")
    sig = compute_signature(secret, data, version="v2")
    if tamper_sig:
        sig = "0" * 64

    headers = {
        "X-Signature-V2": sig,
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    client = app.test_client()
    if method == "POST":
        return client.post(path, data=raw_body, headers=headers)
    if method == "GET":
        return client.get(path, headers=headers)
    return client.open(path, method=method, data=raw_body, headers=headers)


SAMPLE_PAYLOAD = {
    "session_id": "ses_flask_123",
    "status": "Approved",
    "workflow_id": "wf_flask_1",
    "workflow_version": 1,
}


class TestFlaskWebhookIntegration:
    def test_missing_secret_raises_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        with pytest.raises(DiditConfigurationError, match="Missing webhook secret"):
            didit_webhook(secret=None)

    def test_invalid_duplicate_action_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid duplicate_action"):
            didit_webhook(secret=SECRET, duplicate_action="invalid")  # type: ignore[arg-type]

    def test_method_not_allowed_for_non_post(self) -> None:
        app = Flask(__name__)

        @app.route("/webhook", methods=["GET", "POST"])
        @didit_webhook(secret=SECRET)
        def handle():
            return "ok"

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD, method="GET")
        assert res.status_code == 405

    def test_payload_exceeding_content_length_limit(self) -> None:
        app = Flask(__name__)

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, max_body_bytes=50)
        def handle():
            return "ok"

        res = create_signed_flask_client(
            app, "/webhook", SAMPLE_PAYLOAD, extra_headers={"Content-Length": "5000"}
        )
        assert res.status_code == 413
        assert b"exceeds maximum size limit" in res.data

    def test_payload_exceeding_body_size_limit(self) -> None:
        app = Flask(__name__)

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, max_body_bytes=20)
        def handle():
            return "ok"

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res.status_code == 413

    def test_invalid_signature_returns_401(self) -> None:
        app = Flask(__name__)

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET)
        def handle():
            return "ok"

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD, tamper_sig=True)
        assert res.status_code == 401
        assert b"Invalid webhook signature" in res.data

    def test_malformed_json_returns_400(self) -> None:
        app = Flask(__name__)

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET)
        def handle():
            return "ok"

        bad_json = b"{invalid: json"
        client = app.test_client()
        res = client.post(
            "/webhook",
            data=bad_json,
            headers={"X-Signature-V2": "0" * 64, "Content-Type": "application/json"},
        )
        assert res.status_code == 400
        assert b"Malformed JSON" in res.data

    def test_successful_invocation_with_payload_arg_and_g(self) -> None:
        app = Flask(__name__)
        captured: list[WebhookPayload] = []

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET)
        def handle(payload: WebhookPayload):
            captured.append(payload)
            assert g.didit_payload == payload
            return jsonify({"status": "received", "session": payload.session_id})

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res.status_code == 200
        assert len(captured) == 1
        assert captured[0].session_id == "ses_flask_123"
        assert captured[0].status == SessionStatus.APPROVED

    def test_handler_returning_none_defaults_to_200(self) -> None:
        app = Flask(__name__)

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET)
        def handle(payload: WebhookPayload) -> None:
            pass

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res.status_code == 200

    def test_async_flask_handler(self) -> None:
        app = Flask(__name__)
        captured: list[WebhookPayload] = []

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET)
        async def handle(payload: WebhookPayload):
            captured.append(payload)
            return Response("async-ok", status=201)

        client = app.test_client()
        data = dict(SAMPLE_PAYLOAD)
        data["created_at"] = int(time.time())
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(SECRET, data, version="v2")

        res = client.post(
            "/webhook",
            data=raw_body,
            headers={"X-Signature-V2": sig, "Content-Type": "application/json"},
        )
        assert res.status_code == 201
        assert res.data == b"async-ok"
        assert len(captured) == 1

    def test_dedup_store_respond_ok(self) -> None:
        app = Flask(__name__)
        store = InMemoryWebhookDedupStore()

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def handle(payload: WebhookPayload):
            return "processed", 200

        res1 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res1.status_code == 200
        assert res1.data == b"processed"

        res2 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res2.status_code == 200
        assert b"Duplicate webhook event acknowledged" in res2.data

    def test_dedup_store_raise(self) -> None:
        app = Flask(__name__)
        store = InMemoryWebhookDedupStore()

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, dedup_store=store, duplicate_action="raise")
        def handle(payload: WebhookPayload):
            return "processed", 200

        res1 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res1.status_code == 200

        res2 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res2.status_code == 409
        assert b"Duplicate webhook event" in res2.data

    def test_dedup_store_pass(self) -> None:
        app = Flask(__name__)
        store = InMemoryWebhookDedupStore()
        seen_duplicates: list[bool] = []

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, dedup_store=store, duplicate_action="pass")
        def handle(payload: WebhookPayload):
            seen_duplicates.append(payload.is_duplicate)
            return "ok", 200

        create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert seen_duplicates == [False]

        create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert seen_duplicates == [False, True]

    def test_custom_dedup_key_builder(self) -> None:
        app = Flask(__name__)
        store = InMemoryWebhookDedupStore()

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(
            secret=SECRET,
            dedup_store=store,
            dedup_key_builder=lambda p, r: f"flask:{p.session_id}",
        )
        def handle(payload: WebhookPayload):
            return "ok"

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res.status_code == 200
        assert store.claim("flask:ses_flask_123", ttl_seconds=60) is False

    def test_dedup_release_on_handler_exception(self) -> None:
        app = Flask(__name__)
        app.testing = True
        store = InMemoryWebhookDedupStore()
        call_count = 0

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def handle(payload: WebhookPayload):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Database connection lost")
            return "success", 200

        with pytest.raises(RuntimeError, match="Database connection lost"):
            create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)

        res = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res.status_code == 200
        assert res.data == b"success"
        assert call_count == 2

    def test_dedup_release_on_handler_server_error_response(self) -> None:
        app = Flask(__name__)
        store = InMemoryWebhookDedupStore()
        call_count = 0

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        def handle(payload: WebhookPayload):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "temporary failure", 503
            return "success", 200

        res1 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res1.status_code == 503

        res2 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res2.status_code == 200
        assert res2.data == b"success"
        assert call_count == 2

    def test_async_dedup_release_on_exception_and_error(self) -> None:
        app = Flask(__name__)
        app.testing = True
        store = InMemoryWebhookDedupStore()
        call_count = 0

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, dedup_store=store, duplicate_action="respond_ok")
        async def handle(payload: WebhookPayload):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Async processing failed")
            if call_count == 2:
                return Response("Internal error", status=500)
            return "async success", 200

        with pytest.raises(ValueError, match="Async processing failed"):
            create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)

        res1 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res1.status_code == 500

        res2 = create_signed_flask_client(app, "/webhook", SAMPLE_PAYLOAD)
        assert res2.status_code == 200
        assert res2.data == b"async success"
        assert call_count == 3


class TestParseFlaskWebhook:
    def test_successful_parsing_within_request_context(self) -> None:
        app = Flask(__name__)
        data = dict(SAMPLE_PAYLOAD)
        data["created_at"] = int(time.time())
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(SECRET, data, version="v2")

        with app.test_request_context(
            "/webhook",
            method="POST",
            data=raw_body,
            headers={"X-Signature-V2": sig, "Content-Type": "application/json"},
        ):
            payload = parse_flask_webhook(secret=SECRET)
            assert payload.session_id == "ses_flask_123"

    def test_content_length_exceeded(self) -> None:
        app = Flask(__name__)
        with (
            app.test_request_context(
                "/webhook",
                method="POST",
                data=json.dumps(SAMPLE_PAYLOAD),
                environ_base={"CONTENT_LENGTH": "5000"},
            ),
            pytest.raises(ValueError, match="exceeds maximum size limit"),
        ):
            parse_flask_webhook(secret=SECRET, max_body_bytes=50)

    def test_body_size_exceeded(self) -> None:
        from unittest.mock import MagicMock

        mock_req = MagicMock()
        mock_req.content_length = None
        mock_req.headers = {}
        mock_req.get_data.return_value = b"0123456789extra_bytes"
        with pytest.raises(ValueError, match="exceeds maximum size limit"):
            parse_flask_webhook(request_obj=mock_req, secret=SECRET, max_body_bytes=5)

    def test_missing_secret_fallback_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", SECRET)
        app = Flask(__name__)
        data = dict(SAMPLE_PAYLOAD)
        data["created_at"] = int(time.time())
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(SECRET, data, version="v2")

        with app.test_request_context(
            "/webhook",
            method="POST",
            data=raw_body,
            headers={"X-Signature-V2": sig, "Content-Type": "application/json"},
        ):
            payload = parse_flask_webhook()
            assert payload.session_id == "ses_flask_123"

    def test_missing_secret_raises_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        app = Flask(__name__)
        with (
            app.test_request_context("/webhook", method="POST"),
            pytest.raises(DiditConfigurationError, match="Missing webhook secret"),
        ):
            parse_flask_webhook(secret=None)

    def test_invalid_content_length_header_ignored(self) -> None:
        from unittest.mock import MagicMock

        data = dict(SAMPLE_PAYLOAD)
        data["created_at"] = int(time.time())
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(SECRET, data, version="v2")

        mock_req = MagicMock()
        mock_req.content_length = None
        mock_req.headers = {
            "x-signature-v2": sig,
            "content-length": "not-an-int",
        }
        mock_req.get_data.return_value = raw_body

        payload = parse_flask_webhook(request_obj=mock_req, secret=SECRET)
        assert payload.session_id == "ses_flask_123"

    def test_flask_bounded_stream_without_content_length(self) -> None:
        import io

        from werkzeug.test import EnvironBuilder

        app = Flask(__name__)

        @app.route("/webhook", methods=["POST"])
        @didit_webhook(secret=SECRET, max_body_bytes=50)
        def handle(payload: WebhookPayload):
            return "ok"

        client = app.test_client()
        stream = io.BytesIO(b'{"session_id": "ses_stream", "padding": "' + b"x" * 100 + b'"}')
        b = EnvironBuilder(
            path="/webhook", method="POST", input_stream=stream, content_type="application/json"
        )
        env = b.get_environ()
        env.pop("CONTENT_LENGTH", None)
        env["wsgi.input_terminated"] = True

        res = client.open(environ_overrides=env)
        assert res.status_code == 413
        assert b"exceeds maximum size limit" in res.data

    def test_flask_bounded_stream_exact_limit_accepted(self) -> None:
        import io

        from werkzeug.test import EnvironBuilder

        app = Flask(__name__)
        exact_body = b'{"a": 1}'

        stream = io.BytesIO(exact_body)
        b = EnvironBuilder(
            path="/webhook", method="POST", input_stream=stream, content_type="application/json"
        )
        env = b.get_environ()
        env.pop("CONTENT_LENGTH", None)
        env["wsgi.input_terminated"] = True

        with app.test_request_context(environ_overrides=env), pytest.raises(DiditSignatureError):
            parse_flask_webhook(secret=SECRET, max_body_bytes=len(exact_body))

    def test_flask_exact_limit_no_stream_obj(self) -> None:
        from unittest.mock import MagicMock

        mock_req = MagicMock()
        mock_req.content_length = None
        mock_req.stream = None
        mock_req.headers = {}
        mock_req.get_data.return_value = b"12345"
        with pytest.raises(DiditSignatureError):
            parse_flask_webhook(request_obj=mock_req, secret=SECRET, max_body_bytes=5)

    def test_flask_get_data_entity_too_large_exception(self) -> None:
        from unittest.mock import MagicMock

        from werkzeug.exceptions import RequestEntityTooLarge

        mock_req = MagicMock()
        mock_req.content_length = None
        mock_req.headers = {}
        mock_req.get_data.side_effect = RequestEntityTooLarge("Too large")
        with pytest.raises(ValueError, match="exceeds maximum size limit"):
            parse_flask_webhook(request_obj=mock_req, secret="sec", max_body_bytes=100)

    def test_flask_get_data_unexpected_exception_reraises(self) -> None:
        from unittest.mock import MagicMock

        mock_req = MagicMock()
        mock_req.content_length = None
        mock_req.headers = {}
        mock_req.get_data.side_effect = RuntimeError("Disk IO failure")
        with pytest.raises(RuntimeError, match="Disk IO failure"):
            parse_flask_webhook(request_obj=mock_req, secret="sec", max_body_bytes=100)
