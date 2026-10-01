"""Strict backward compatibility verification against v0.2.0 public API contract.

Ensures that v0.3.0 is purely additive and introduces zero regressions or breaking changes
for callers relying on v0.2.0 behaviors, signatures, stores, and models.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

import didit
from didit import (
    AsyncDidit,
    DecisionResponse,
    Didit,
    InMemoryWebhookDedupStore,
    SessionResponse,
    SessionStatus,
    SimulatedDidit,
    WebhookPayload,
    parse_webhook_payload,
    verify_webhook_signature,
)
from didit.webhooks import compute_signature

V020_EXPORTS = [
    "AMLData",
    "AMLScreeningResult",
    "AsyncDidit",
    "AsyncRedisWebhookDedupStore",
    "AsyncWebhookDedupStore",
    "BiometricsData",
    "CreateSessionRequest",
    "DecisionResponse",
    "DedupFailureMode",
    "Didit",
    "DiditAPIError",
    "DiditAuthenticationError",
    "DiditConfig",
    "DiditConfigurationError",
    "DiditConnectionError",
    "DiditDedupError",
    "DiditDedupSaturationError",
    "DiditError",
    "DiditNotFoundError",
    "DiditPermissionError",
    "DiditPoolTimeoutError",
    "DiditRateLimitError",
    "DiditServerError",
    "DiditSignatureError",
    "DiditTimeoutError",
    "DocumentData",
    "FaceMatchResult",
    "IdVerificationResult",
    "InMemoryWebhookDedupStore",
    "Language",
    "LivenessResult",
    "RedisWebhookDedupStore",
    "RequestOptions",
    "RetryPolicy",
    "ReviewData",
    "SessionResponse",
    "SessionStatus",
    "SimulatedAsyncDidit",
    "SimulatedDidit",
    "VerificationWarning",
    "WebhookDedupStore",
    "WebhookPayload",
    "__version__",
    "compute_dedup_key",
    "parse_webhook_payload",
    "verify_webhook_signature",
]


class TestV020Compatibility:
    """Validate 100% backward compatibility with v0.2.0 API and data contracts."""

    def test_all_v020_symbols_exported(self) -> None:
        """Verify that every single symbol present in v0.2.0 is still exported."""
        for symbol in V020_EXPORTS:
            assert hasattr(didit, symbol), f"Missing v0.2.0 export: {symbol}"
            assert symbol in didit.__all__, f"{symbol} missing from __all__"

    @respx.mock
    def test_sync_client_v020_workflow(self) -> None:
        """Verify standard v0.2.0 sync client usage pattern without any v0.3.0 parameters."""
        base_url = "https://verification.didit.me/v3"
        client = Didit(
            api_key="didit_v020_key",
            base_url=base_url,
            webhook_secret="whsec_v020",
            timeout=15.0,
        )
        assert client.config.api_key == "didit_v020_key"

        # 1. Create session (v0.2.0 signature)
        respx.post(f"{base_url}/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_v020_1",
                    "status": "Not Started",
                    "url": "https://verify.didit.me/sess_v020_1",
                },
            )
        )
        s = client.sessions.create(
            workflow_id="wf_v020",
            vendor_data="usr_v020",
            callback="https://app.example.com/callback",
        )
        assert s.session_id == "sess_v020_1"
        assert s.status == SessionStatus.NOT_STARTED

        # 2. Get session (v0.2.0 signature)
        respx.get(f"{base_url}/session/sess_v020_1/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_v020_1",
                    "status": "Approved",
                    "url": "https://verify.didit.me/sess_v020_1",
                },
            )
        )
        retrieved = client.sessions.get("sess_v020_1")
        assert retrieved.status == SessionStatus.APPROVED

        # 3. Get decision (v0.2.0 signature)
        respx.get(f"{base_url}/session/sess_v020_1/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_v020_1",
                    "status": "Approved",
                    "document": {
                        "document_type": "id_card",
                        "country": "ESP",
                        "document_number": "12345678Z",
                        "is_valid": True,
                    },
                },
            )
        )
        dec = client.sessions.get_decision("sess_v020_1")
        assert dec.status == SessionStatus.APPROVED
        assert dec.document is not None
        assert dec.document.country == "ESP"

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_client_v020_workflow(self) -> None:
        """Verify standard v0.2.0 async client usage pattern."""
        base_url = "https://verification.didit.me/v3"
        client = AsyncDidit(
            api_key="didit_async_key",
            base_url=base_url,
            timeout=10.0,
        )

        respx.get(f"{base_url}/session/sess_async_compat/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_async_compat", "status": "In Progress"},
            )
        )
        s = await client.sessions.get("sess_async_compat")
        assert s.session_id == "sess_async_compat"
        assert s.status == SessionStatus.IN_PROGRESS
        await client.aclose()

    def test_webhook_verification_v020_contract(self) -> None:
        """Verify webhook signature verification and payload parsing as documented in v0.2.0."""
        secret = "whsec_v020_secret"
        payload_bytes = b'{"session_id":"s_100","status":"Approved","timestamp":1700000000}'
        body_dict = {"session_id": "s_100", "status": "Approved", "timestamp": 1700000000}
        sig = compute_signature(secret, body_dict, version="v2")
        headers = {
            "x-signature-v2": sig,
            "x-timestamp": "1700000000",
        }

        # Legacy verify_webhook_signature call
        is_valid = verify_webhook_signature(
            payload_bytes,
            headers,
            secret,
            verify_freshness=False,
        )
        assert is_valid is True

        # Parse payload call
        parsed = parse_webhook_payload(
            payload_bytes,
            headers,
            secret,
            verify_freshness=False,
        )
        assert isinstance(parsed, WebhookPayload)
        assert parsed.session_id == "s_100"
        assert parsed.status == "Approved"

    def test_legacy_dedup_store_conformance(self) -> None:
        """Verify that InMemoryWebhookDedupStore supports legacy claim/release."""
        store = InMemoryWebhookDedupStore()

        # claim returns True on first call
        first_claim = store.claim("event_v020", ttl_seconds=60)
        assert first_claim is True

        # claim returns False on duplicate call
        dup_claim = store.claim("event_v020", ttl_seconds=60)
        assert dup_claim is False

        # release frees the key
        store.release("event_v020")
        assert store.claim("event_v020", ttl_seconds=60) is True

    def test_v020_model_instantiation(self) -> None:
        """Verify that SessionResponse and DecisionResponse work with minimal v0.2.0 dicts."""
        s = SessionResponse.model_validate(
            {
                "session_id": "sess_min",
                "status": "Not Started",
            }
        )
        assert s.session_id == "sess_min"
        assert s.status == SessionStatus.NOT_STARTED
        assert s.resubmit_info is None
        assert s.requires_resubmission is False

        d = DecisionResponse.model_validate(
            {
                "session_id": "dec_min",
                "status": "Approved",
            }
        )
        assert d.session_id == "dec_min"
        assert d.status == SessionStatus.APPROVED
        assert d.resubmit_info is None
        assert d.requires_resubmission is False

    def test_simulation_client_v020(self) -> None:
        """Verify simulated client behavior matches v0.2.0 expectations."""
        sim = SimulatedDidit()
        s = sim.sessions.create(workflow_id="wf_sim", vendor_data="u_sim")
        assert s.session_id.startswith("sim_")
        assert s.status == SessionStatus.NOT_STARTED

        retrieved = sim.sessions.get(s.session_id)
        assert retrieved.session_id == s.session_id
