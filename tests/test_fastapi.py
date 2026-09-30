import json
import time
from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from didit.integrations.fastapi import (
    DiditWebhookGuard,
    didit_webhook,
    didit_webhook_view,
)
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

        from collections.abc import Iterator

        def stream_gen() -> Iterator[bytes]:
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

    def test_invalid_duplicate_action_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid duplicate_action"):
            DiditWebhookGuard(
                secret=WEBHOOK_SECRET,
                duplicate_action="invalid_action",  # type: ignore[arg-type]
            )

    def test_guard_dedup_respond_ok_action(self) -> None:
        from didit.dedup import InMemoryWebhookDedupStore

        store = InMemoryWebhookDedupStore()
        guard_with_dedup = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
            duplicate_action="respond_ok",
        )
        dedup_app = FastAPI()

        @dedup_app.post("/webhook-dedup")
        async def endpoint(payload: WebhookPayload = Depends(guard_with_dedup)) -> dict[str, str]:
            return {"session_id": payload.session_id, "status": payload.status.value}

        test_client = TestClient(dedup_app)
        data = {
            "event_id": "evt_fastapi_dedup_1",
            "session_id": "sess_dedup_1",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        # First request succeeds normally
        resp1 = test_client.post("/webhook-dedup", content=raw_body, headers=headers)
        assert resp1.status_code == 200
        assert resp1.json() == {"session_id": "sess_dedup_1", "status": "Approved"}

        # Duplicate request returns 200 OK acknowledging duplicate without re-processing
        resp2 = test_client.post("/webhook-dedup", content=raw_body, headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["detail"] == "Duplicate webhook event acknowledged"

    def test_guard_dedup_pass_action(self) -> None:
        from didit.dedup import InMemoryWebhookDedupStore

        store = InMemoryWebhookDedupStore()
        guard_pass = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
            duplicate_action="pass",
        )
        app_pass = FastAPI()

        @app_pass.post("/webhook-pass")
        async def endpoint(payload: WebhookPayload = Depends(guard_pass)) -> dict[str, Any]:
            return {"is_duplicate": payload.is_duplicate, "session_id": payload.session_id}

        test_client = TestClient(app_pass)
        data = {
            "event_id": "evt_fastapi_pass",
            "session_id": "sess_pass",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        # First call: not duplicate
        resp1 = test_client.post("/webhook-pass", content=raw_body, headers=headers)
        assert resp1.status_code == 200
        assert resp1.json()["is_duplicate"] is False

        # Second call: passed through with is_duplicate = True
        resp2 = test_client.post("/webhook-pass", content=raw_body, headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["is_duplicate"] is True

    def test_guard_dedup_default_action_is_pass(self) -> None:
        from didit.dedup import InMemoryWebhookDedupStore

        store = InMemoryWebhookDedupStore()
        guard = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
        )
        assert guard.duplicate_action == "pass"
        app = FastAPI()

        @app.post("/webhook-default")
        async def endpoint(payload: WebhookPayload = Depends(guard)) -> dict[str, Any]:
            return {"is_duplicate": payload.is_duplicate}

        test_client = TestClient(app)
        data = {
            "event_id": "evt_fastapi_default",
            "session_id": "sess_default",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp1 = test_client.post("/webhook-default", content=raw_body, headers=headers)
        assert resp1.status_code == 200
        assert resp1.json()["is_duplicate"] is False

        resp2 = test_client.post("/webhook-default", content=raw_body, headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["is_duplicate"] is True

    def test_guard_dedup_raise_action(self) -> None:
        from didit.dedup import InMemoryWebhookDedupStore

        store = InMemoryWebhookDedupStore()
        guard_raise = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
            duplicate_action="raise",
        )
        app_raise = FastAPI()

        @app_raise.post("/webhook-raise")
        async def endpoint(payload: WebhookPayload = Depends(guard_raise)) -> dict[str, str]:
            return {"ok": "true"}

        test_client = TestClient(app_raise)
        data = {
            "event_id": "evt_fastapi_raise",
            "session_id": "sess_raise",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp1 = test_client.post("/webhook-raise", content=raw_body, headers=headers)
        assert resp1.status_code == 200

        resp2 = test_client.post("/webhook-raise", content=raw_body, headers=headers)
        assert resp2.status_code == 409
        assert "Duplicate webhook event" in resp2.json()["detail"]

    def test_guard_dedup_custom_key_builder(self) -> None:
        from didit.dedup import InMemoryWebhookDedupStore

        store = InMemoryWebhookDedupStore()
        guard_custom = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
            dedup_key_builder=lambda p, r: f"custom:{p.session_id}",
            duplicate_action="respond_ok",
        )
        app_custom = FastAPI()

        @app_custom.post("/webhook-custom")
        async def endpoint(payload: WebhookPayload = Depends(guard_custom)) -> dict[str, str]:
            return {"ok": "true"}

        test_client = TestClient(app_custom)
        data = {
            "session_id": "sess_custom_key",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp1 = test_client.post("/webhook-custom", content=raw_body, headers=headers)
        assert resp1.status_code == 200

        # Custom key was claimed
        assert store.claim("custom:sess_custom_key") is False

    def test_guard_dedup_pure_async_store(self) -> None:
        class PureAsyncStore:
            def __init__(self) -> None:
                self.calls = 0

            async def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
                self.calls += 1
                return self.calls == 1

        async_store = PureAsyncStore()
        guard_async = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=async_store,
            duplicate_action="respond_ok",
        )
        app_async = FastAPI()

        @app_async.post("/webhook-pure-async")
        async def endpoint(payload: WebhookPayload = Depends(guard_async)) -> dict[str, str]:
            return {"ok": "true"}

        test_client = TestClient(app_async)
        data = {
            "event_id": "evt_pure_async",
            "session_id": "sess_async",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp1 = test_client.post("/webhook-pure-async", content=raw_body, headers=headers)
        assert resp1.status_code == 200

        resp2 = test_client.post("/webhook-pure-async", content=raw_body, headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["detail"] == "Duplicate webhook event acknowledged"

    def test_guard_dedup_pure_sync_store(self) -> None:
        class PureSyncStore:
            def __init__(self) -> None:
                self.calls = 0

            def claim(self, key: str, ttl_seconds: int = 86400) -> bool:
                self.calls += 1
                return self.calls == 1

        sync_store = PureSyncStore()
        guard_sync = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=sync_store,
            duplicate_action="respond_ok",
        )
        app_sync = FastAPI()

        @app_sync.post("/webhook-pure-sync")
        async def endpoint(payload: WebhookPayload = Depends(guard_sync)) -> dict[str, str]:
            return {"ok": "true"}

        test_client = TestClient(app_sync)
        data = {
            "event_id": "evt_pure_sync",
            "session_id": "sess_sync",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp1 = test_client.post("/webhook-pure-sync", content=raw_body, headers=headers)
        assert resp1.status_code == 200

        resp2 = test_client.post("/webhook-pure-sync", content=raw_body, headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["detail"] == "Duplicate webhook event acknowledged"

    def test_guard_release_claim_allows_retry(self) -> None:
        from starlette.requests import Request
        from starlette.responses import Response

        from didit.dedup import InMemoryWebhookDedupStore
        from didit.integrations.fastapi import release_didit_claim

        store = InMemoryWebhookDedupStore()
        guard = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
            duplicate_action="respond_ok",
        )
        app = FastAPI()
        call_count = 0

        @app.post("/test-claim-release")
        async def endpoint(request: Request, payload: WebhookPayload = Depends(guard)) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                await guard.release_claim(request)
                return Response("Failed first time", status_code=500)
            if call_count == 2:
                await release_didit_claim(request)
                return Response("Failed second time", status_code=500)
            return {"status": "ok"}

        test_client = TestClient(app)
        data = {
            "event_id": "evt_fastapi_release",
            "session_id": "sess_rel",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp1 = test_client.post("/test-claim-release", content=raw_body, headers=headers)
        assert resp1.status_code == 500

        resp2 = test_client.post("/test-claim-release", content=raw_body, headers=headers)
        assert resp2.status_code == 500

        resp3 = test_client.post("/test-claim-release", content=raw_body, headers=headers)
        assert resp3.status_code == 200
        assert resp3.json() == {"status": "ok"}
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_guard_release_claim_no_op_branches(self) -> None:
        from starlette.requests import Request

        from didit.dedup import InMemoryWebhookDedupStore
        from didit.integrations.fastapi import release_didit_claim

        # Guard without dedup_store
        guard_none = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=None)
        req = Request({"type": "http"})
        await guard_none.release_claim(req)

        # Guard with dedup_store but request without claim
        store = InMemoryWebhookDedupStore()
        guard_with_store = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=store)
        await guard_with_store.release_claim(req)

        # release_didit_claim on uninitialized request
        await release_didit_claim(req)

    def test_guard_invalid_processing_action_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid processing_action 'unknown'"):
            DiditWebhookGuard(secret=WEBHOOK_SECRET, processing_action="unknown")  # type: ignore[arg-type]


class TestFastAPIWebhookReservation:
    @pytest.mark.parametrize("action", ["retry", "conflict", "raise", "pass"])
    def test_processing_action_outcomes(self, action: str) -> None:
        from fastapi import Request

        from didit.dedup import InMemoryWebhookReservationStore
        from didit.integrations.fastapi import complete_didit_reservation

        res_store = InMemoryWebhookReservationStore()
        # Seed an in-flight processing reservation with different token
        res_store.reserve("evt_res_test", token="other_worker", ttl_seconds=60)

        res_guard = DiditWebhookGuard(
            secret=WEBHOOK_SECRET,
            dedup_store=res_store,
            processing_action=action,  # type: ignore[arg-type]
        )
        test_app = FastAPI()

        @test_app.post("/test-res")
        async def endpoint(
            request: Request,
            payload: WebhookPayload = Depends(res_guard),
        ) -> dict[str, Any]:
            await complete_didit_reservation(request)
            await res_guard.complete_reservation(request)
            return {"duplicate": payload.is_duplicate}

        client = TestClient(test_app)
        data = {
            "event_id": "evt_res_test",
            "session_id": "sess_res",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        if action == "retry":
            resp = client.post("/test-res", content=raw_body, headers=headers)
            assert resp.status_code == 503
            assert resp.headers.get("retry-after") == "5"
            assert "currently being processed" in resp.json()["detail"]
        elif action == "conflict":
            resp = client.post("/test-res", content=raw_body, headers=headers)
            assert resp.status_code == 409
            assert "currently being processed" in resp.json()["detail"]
        elif action == "raise":
            from didit.errors import DiditDuplicateWebhookError

            with pytest.raises(DiditDuplicateWebhookError) as exc_info:
                client.post("/test-res", content=raw_body, headers=headers)
            assert exc_info.value.state == "PROCESSING"
            assert exc_info.value.event_id == "evt_res_test"
        elif action == "pass":
            resp = client.post("/test-res", content=raw_body, headers=headers)
            assert resp.status_code == 200
            assert resp.json() == {"duplicate": True}

    def test_complete_reservation_success_flow(self) -> None:
        from fastapi import Request

        from didit.dedup import InMemoryWebhookReservationStore
        from didit.integrations.fastapi import complete_didit_reservation

        res_store = InMemoryWebhookReservationStore()
        res_guard = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=res_store)
        test_app = FastAPI()
        completed_results: list[bool] = []

        @test_app.post("/test-res-complete")
        async def endpoint(
            request: Request,
            payload: WebhookPayload = Depends(res_guard),
        ) -> dict[str, str]:
            res1 = await res_guard.complete_reservation(request)
            res2 = await complete_didit_reservation(request)
            completed_results.extend([res1, res2])
            return {"status": "ok"}

        client = TestClient(test_app)
        data = {
            "event_id": "evt_comp_flow",
            "session_id": "sess_comp",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp = client.post("/test-res-complete", content=raw_body, headers=headers)
        assert resp.status_code == 200
        # First complete succeeded; second was already completed/cleared
        assert completed_results[0] is True

    @pytest.mark.asyncio
    async def test_complete_reservation_no_op_branches(self) -> None:
        from starlette.requests import Request

        from didit.dedup import InMemoryWebhookReservationStore
        from didit.integrations.fastapi import complete_didit_reservation

        guard_none = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=None)
        req = Request({"type": "http"})
        assert await guard_none.complete_reservation(req) is False

        store = InMemoryWebhookReservationStore()
        guard_with_store = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=store)
        assert await guard_with_store.complete_reservation(req) is False

        assert await complete_didit_reservation(req) is False


class TestFastAPIRouteDecoratorLifecycle:
    def test_default_adapter_lease_ttl_is_30_seconds(self) -> None:
        from unittest.mock import AsyncMock

        from didit.dedup import ReservationAttempt, ReservationState

        mock_store = AsyncMock()
        mock_store.areserve.return_value = ReservationAttempt(state=ReservationState.ACQUIRED)

        app_ttl = FastAPI()

        @app_ttl.post("/res-ttl")
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=mock_store)
        async def endpoint(payload: WebhookPayload, request: Request) -> dict[str, str]:
            return {"status": "ok"}

        client = TestClient(app_ttl)
        data = {
            "session_id": "sess_ttl",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        client.post("/res-ttl", content=raw_body, headers=headers)
        mock_store.areserve.assert_called_once()
        _, kwargs = mock_store.areserve.call_args
        assert kwargs.get("ttl_seconds") == 30

    def test_fastapi_success_auto_completion(self) -> None:
        from didit.dedup import InMemoryWebhookReservationStore

        store = InMemoryWebhookReservationStore()
        app_ac = FastAPI()

        @app_ac.post("/res-auto-complete")
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store, duplicate_action="respond_ok")
        async def endpoint(payload: WebhookPayload, request: Request) -> dict[str, str]:
            # Handler does NOT call complete_reservation manually!
            return {"status": "ok"}

        client = TestClient(app_ac)
        data = {
            "event_id": "evt_auto_comp",
            "session_id": "sess_ac",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        # Request 1 -> 200 OK; decorator automatically completes the reservation
        r1 = client.post("/res-auto-complete", content=raw_body, headers=headers)
        assert r1.status_code == 200
        assert r1.json() == {"status": "ok"}

        # Request 2 (identical event) -> acknowledged as duplicate because state is COMPLETED!
        r2 = client.post("/res-auto-complete", content=raw_body, headers=headers)
        assert r2.status_code == 200
        assert "Duplicate webhook event acknowledged" in r2.text

    def test_fastapi_exception_auto_release(self) -> None:
        from didit.dedup import InMemoryWebhookReservationStore

        store = InMemoryWebhookReservationStore()
        app_ar = FastAPI()
        should_crash = True

        @app_ar.post("/res-auto-release")
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
        async def endpoint(payload: WebhookPayload, request: Request) -> dict[str, str]:
            if should_crash:
                raise ValueError("Database failure")
            return {"status": "ok"}

        client = TestClient(app_ar, raise_server_exceptions=False)
        data = {
            "event_id": "evt_auto_rel",
            "session_id": "sess_ar",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        # Request 1 crashes -> 500; decorator automatically releases the reservation
        r1 = client.post("/res-auto-release", content=raw_body, headers=headers)
        assert r1.status_code == 500

        # Request 2 (retry by Didit) -> succeeds because lease was released
        should_crash = False
        r2 = client.post("/res-auto-release", content=raw_body, headers=headers)
        assert r2.status_code == 200
        assert r2.json() == {"status": "ok"}

    def test_fastapi_404_releases_reservation(self) -> None:
        from starlette.responses import Response as StarletteResponse

        from didit.dedup import InMemoryWebhookReservationStore

        store = InMemoryWebhookReservationStore()
        app_404 = FastAPI()
        return_404 = True

        @app_404.post("/res-404")
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
        async def endpoint(payload: WebhookPayload, request: Request) -> Any:
            if return_404:
                return StarletteResponse(content="not found", status_code=404)
            return {"status": "recovered"}

        client = TestClient(app_404)
        data = {
            "event_id": "evt_404_rel",
            "session_id": "sess_404",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        # Request 1 -> 404; non-2xx response automatically releases reservation
        r1 = client.post("/res-404", content=raw_body, headers=headers)
        assert r1.status_code == 404

        # Request 2 (retry) -> successfully acquires lease
        return_404 = False
        r2 = client.post("/res-404", content=raw_body, headers=headers)
        assert r2.status_code == 200
        assert r2.json() == {"status": "recovered"}

    def test_fastapi_processing_action_conflict(self) -> None:
        from didit.dedup import InMemoryWebhookReservationStore

        store = InMemoryWebhookReservationStore()
        store.reserve("evt_fastapi_conflict", token="other_worker", ttl_seconds=60)
        app_conf = FastAPI()

        @app_conf.post("/res-conflict")
        @didit_webhook(
            secret=WEBHOOK_SECRET,
            dedup_store=store,
            processing_action="conflict",
        )
        async def endpoint(payload: WebhookPayload, request: Request) -> dict[str, str]:
            return {"status": "ok"}

        client = TestClient(app_conf)
        data = {
            "event_id": "evt_fastapi_conflict",
            "session_id": "sess_conf",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp = client.post("/res-conflict", content=raw_body, headers=headers)
        assert resp.status_code == 409
        assert "currently being processed" in resp.json()["detail"]

    def test_actual_async_redis_store_in_sync_fastapi_raises_config_error(self) -> None:
        from unittest.mock import MagicMock

        from didit.dedup import AsyncRedisWebhookReservationStore
        from didit.errors import DiditConfigurationError

        store = AsyncRedisWebhookReservationStore(client=MagicMock())

        with pytest.raises(
            DiditConfigurationError,
            match="AsyncWebhookReservationStore cannot be used with synchronous view functions",
        ):

            @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
            def sync_endpoint(payload: WebhookPayload, request: Request) -> dict[str, str]:
                return {"status": "ok"}

    def test_decorator_validation_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from didit.errors import DiditConfigurationError

        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        with pytest.raises(DiditConfigurationError, match="Missing webhook secret"):
            didit_webhook()

        with pytest.raises(ValueError, match="Invalid duplicate_action"):
            didit_webhook(secret="sec", duplicate_action="invalid")  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="Invalid processing_action"):
            didit_webhook(secret="sec", processing_action="invalid")  # type: ignore[arg-type]

    def test_legacy_store_retains_default_86400_ttl(self) -> None:
        from unittest.mock import MagicMock

        from didit.dedup import InMemoryWebhookDedupStore

        # Default initialization: reservation lease is 30s, legacy claim is 86400s
        store = InMemoryWebhookDedupStore()
        guard = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=store)
        assert guard.effective_lease_ttl == 30
        assert guard.effective_legacy_ttl == 86400

        # When dedup_ttl_seconds is explicitly provided, legacy TTL reflects it
        guard_explicit = DiditWebhookGuard(
            secret=WEBHOOK_SECRET, dedup_store=store, dedup_ttl_seconds=120
        )
        assert guard_explicit.effective_legacy_ttl == 120
        assert guard_explicit.effective_lease_ttl == 30

        # Verify claim receives 86400 in mock legacy store
        mock_legacy = MagicMock(spec=["claim", "release"])
        mock_legacy.claim.return_value = True
        app_legacy = FastAPI()

        leg_guard = DiditWebhookGuard(secret=WEBHOOK_SECRET, dedup_store=mock_legacy)

        @app_legacy.post("/legacy-guard")
        async def leg_endpoint(
            payload: WebhookPayload = Depends(leg_guard),
        ) -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app_legacy)
        data = {
            "event_id": "evt_legacy_86400",
            "session_id": "sess_leg",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        client.post("/legacy-guard", content=raw_body, headers=headers)
        mock_legacy.claim.assert_called_once()
        call_args = mock_legacy.claim.call_args
        effective_ttl = call_args.kwargs.get("ttl_seconds") or call_args.args[1]
        assert effective_ttl == 86400

    def test_sync_endpoint_runs_in_starlette_threadpool(self) -> None:
        import threading

        from didit.dedup import InMemoryWebhookReservationStore

        store = InMemoryWebhookReservationStore()
        app_tp = FastAPI()
        recorded_threads: dict[str, int] = {}

        @app_tp.post("/sync-tp")
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
        def sync_view(payload: WebhookPayload, request: Request) -> dict[str, str]:
            recorded_threads["handler"] = threading.get_ident()
            return {"status": "ok"}

        @app_tp.post("/async-tp")
        async def async_view(request: Request) -> dict[str, str]:
            recorded_threads["loop"] = threading.get_ident()
            return {"status": "ok"}

        client = TestClient(app_tp)
        client.post("/async-tp")

        data = {
            "event_id": "evt_sync_tp",
            "session_id": "sess_tp",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp = client.post("/sync-tp", content=raw_body, headers=headers)
        assert resp.status_code == 200
        assert "handler" in recorded_threads
        assert "loop" in recorded_threads
        # Concurrency verification: sync handler must NOT block event loop thread
        assert recorded_threads["handler"] != recorded_threads["loop"]

    def test_route_status_code_404_releases_reservation(self) -> None:
        from didit.dedup import InMemoryWebhookReservationStore, ReservationState

        store = InMemoryWebhookReservationStore()
        app_404 = FastAPI()

        @app_404.post("/webhook-route-404", status_code=404)
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
        def route_404_view(payload: WebhookPayload, request: Request) -> dict[str, str]:
            return {"detail": "resource not found"}

        client = TestClient(app_404)
        data = {
            "event_id": "evt_route_404_release",
            "session_id": "sess_404",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp = client.post("/webhook-route-404", content=raw_body, headers=headers)
        assert resp.status_code == 404

        # Because route returns 404, reservation MUST be released so Didit retry succeeds
        attempt = store.reserve("evt_route_404_release")
        assert attempt.state == ReservationState.ACQUIRED

    def test_response_model_validation_failure_releases_reservation(self) -> None:
        from pydantic import BaseModel

        from didit.dedup import InMemoryWebhookReservationStore, ReservationState

        class StrictResponse(BaseModel):
            acknowledged: bool

        store = InMemoryWebhookReservationStore()
        app_model = FastAPI()

        @app_model.post("/webhook-model-fail", response_model=StrictResponse)
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
        def model_fail_view(payload: WebhookPayload, request: Request) -> dict[str, str]:
            # Invalid output schema triggers ResponseValidationError -> HTTP 500
            return {"unrelated_field": "invalid_shape"}

        client = TestClient(app_model, raise_server_exceptions=False)
        data = {
            "event_id": "evt_model_fail",
            "session_id": "sess_model_fail",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp = client.post("/webhook-model-fail", content=raw_body, headers=headers)
        assert resp.status_code == 500

        # Reservation MUST be released upon 500 response serialization failure
        attempt = store.reserve("evt_model_fail")
        assert attempt.state == ReservationState.ACQUIRED

    def test_response_status_code_mutation_releases_reservation(self) -> None:
        from fastapi import Response

        from didit.dedup import InMemoryWebhookReservationStore, ReservationState

        store = InMemoryWebhookReservationStore()
        app_resp = FastAPI()

        @app_resp.post("/webhook-resp-status")
        @didit_webhook(secret=WEBHOOK_SECRET, dedup_store=store)
        def resp_status_view(
            payload: WebhookPayload, request: Request, response: Response
        ) -> dict[str, str]:
            response.status_code = 404
            return {"error": "custom not found"}

        client = TestClient(app_resp)
        data = {
            "event_id": "evt_resp_status_404",
            "session_id": "sess_resp_status",
            "status": "Approved",
            "created_at": int(time.time()),
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(WEBHOOK_SECRET, data, version="v2")
        headers = {"X-Signature-V2": sig, "Content-Type": "application/json"}

        resp = client.post("/webhook-resp-status", content=raw_body, headers=headers)
        assert resp.status_code == 404

        # Reservation MUST be released when response.status_code is non-2xx
        attempt = store.reserve("evt_resp_status_404")
        assert attempt.state == ReservationState.ACQUIRED

    def test_didit_webhook_view_alias(self) -> None:
        assert didit_webhook_view is didit_webhook


class TestIntegrationsLazyLoading:
    def test_lazy_attribute_access_success(self) -> None:
        import didit.integrations as pkg

        assert pkg.DiditWebhookGuard is not None
        assert pkg.release_didit_claim is not None
        assert pkg.didit_webhook_view is not None
        assert pkg.parse_django_webhook is not None
        assert pkg.didit_webhook is not None
        assert pkg.parse_flask_webhook is not None

    def test_unknown_attribute_raises_attribute_error(self) -> None:
        import didit.integrations as pkg

        with pytest.raises(AttributeError, match="has no attribute 'unknown_attr'"):
            _ = pkg.unknown_attr  # type: ignore[attr-defined]

    def test_missing_fastapi_raises_informative_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        import didit.integrations as pkg

        monkeypatch.setitem(sys.modules, "didit.integrations.fastapi", None)
        monkeypatch.delattr(pkg, "fastapi", raising=False)
        with pytest.raises(ImportError, match="FastAPI is required"):
            _ = pkg.__getattr__("DiditWebhookGuard")

    def test_missing_django_raises_informative_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        import didit.integrations as pkg

        monkeypatch.setitem(sys.modules, "didit.integrations.django", None)
        monkeypatch.delattr(pkg, "django", raising=False)
        with pytest.raises(ImportError, match="Django is required"):
            _ = pkg.__getattr__("didit_webhook_view")

    def test_missing_flask_raises_informative_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        import didit.integrations as pkg

        monkeypatch.setitem(sys.modules, "didit.integrations.flask", None)
        monkeypatch.delattr(pkg, "flask", raising=False)
        with pytest.raises(ImportError, match="Flask is required"):
            _ = pkg.__getattr__("didit_webhook")
