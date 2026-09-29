"""Tests for FastAPI webhook integration guard."""

import json
import time

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from didit.integrations.fastapi import DiditWebhookGuard
from didit.models.webhook import WebhookPayload
from didit.webhooks import compute_signature

WEBHOOK_SECRET = "whsec_fastapi_guard_test"

app = FastAPI()
guard = DiditWebhookGuard(secret=WEBHOOK_SECRET)


@app.post("/webhooks/didit")
async def didit_webhook_endpoint(
    payload: WebhookPayload = Depends(guard),
) -> dict[str, str]:
    return {"session_id": payload.session_id, "status": payload.status.value}


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestFastAPIWebhookGuard:
    def test_valid_webhook_processed(self, client: TestClient) -> None:
        data = {
            "session_id": "sess_fastapi_ok",
            "status": "Approved",
            "created_at": int(time.time()),
            "workflow_id": "wf_fastapi",
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")

        resp = client.post(
            "/webhooks/didit",
            content=raw_body,
            headers={
                "X-Signature-V2": sig,
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 200
        assert resp.json() == {"session_id": "sess_fastapi_ok", "status": "Approved"}

    def test_invalid_signature_returns_401(self, client: TestClient) -> None:
        data = {
            "session_id": "sess_tampered",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")

        resp = client.post(
            "/webhooks/didit",
            content=raw_body,
            headers={"X-Signature-V2": "invalid_sig", "Content-Type": "application/json"},
        )
        assert resp.status_code == 401
        assert "Invalid webhook signature" in resp.json()["detail"]

    def test_malformed_json_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            "/webhooks/didit",
            content=b"not json",
            headers={"X-Signature-V2": "sig", "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert "Malformed JSON" in resp.json()["detail"]

    def test_non_dict_json_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            "/webhooks/didit",
            content=b"[1, 2, 3]",
            headers={"X-Signature-V2": "sig", "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert "Malformed JSON" in resp.json()["detail"]

    def test_guard_resolves_secret_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", "env_secret")
        env_guard = DiditWebhookGuard()
        assert env_guard.secret == "env_secret"

    def test_guard_missing_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from didit.errors import DiditConfigurationError

        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        with pytest.raises(DiditConfigurationError, match="Missing webhook secret"):
            DiditWebhookGuard()

    def test_payload_too_large_content_length_returns_413(self, client: TestClient) -> None:
        resp = client.post(
            "/webhooks/didit",
            content=b"{}",
            headers={
                "X-Signature-V2": "sig",
                "Content-Type": "application/json",
                "Content-Length": "2000000",
            },
        )
        assert resp.status_code == 413
        assert "exceeds maximum size limit" in resp.json()["detail"]

    def test_payload_too_large_streaming_returns_413(self) -> None:
        small_guard = DiditWebhookGuard(secret=WEBHOOK_SECRET, max_body_bytes=50)
        custom_app = FastAPI()

        @custom_app.post("/test-limit")
        async def endpoint(payload: WebhookPayload = Depends(small_guard)) -> dict[str, str]:
            return {"ok": "true"}

        test_client = TestClient(custom_app)

        def stream_gen():
            yield b"a" * 30
            yield b"b" * 30

        resp = test_client.post(
            "/test-limit",
            content=stream_gen(),
            headers={"X-Signature-V2": "sig", "Content-Type": "application/json"},
        )
        assert resp.status_code == 413
        assert "exceeds maximum size limit" in resp.json()["detail"]

    def test_invalid_content_length_falls_through_to_stream(self) -> None:
        small_guard = DiditWebhookGuard(secret=WEBHOOK_SECRET, max_body_bytes=50)
        custom_app = FastAPI()

        @custom_app.post("/test-invalid-cl")
        async def endpoint(payload: WebhookPayload = Depends(small_guard)) -> dict[str, str]:
            return {"ok": "true"}

        test_client = TestClient(custom_app)
        resp = test_client.post(
            "/test-invalid-cl",
            content=b"not json",
            headers={
                "X-Signature-V2": "sig",
                "Content-Type": "application/json",
                "Content-Length": "invalid_number",
            },
        )
        assert resp.status_code == 400

    def test_deeply_nested_json_returns_400(self, client: TestClient) -> None:
        nested = b'{"a":' * 10000 + b"1" + b"}" * 10000
        resp = client.post(
            "/webhooks/didit",
            content=nested,
            headers={"X-Signature-V2": "sig", "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert "Malformed JSON" in resp.json()["detail"]
