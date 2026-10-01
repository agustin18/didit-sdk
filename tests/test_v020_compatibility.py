"""Strict backward compatibility verification against v0.2.0 public API contract.

Ensures that v0.3.0 is purely additive and introduces zero regressions or breaking changes
for callers relying on v0.2.0 behaviors, signatures, stores, and models.
"""

from __future__ import annotations

from typing import Any

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
        import time

        secret = "whsec_v020_secret"
        now_ts = int(time.time())
        payload_json = f'{{"session_id":"s_100","status":"Approved","timestamp":{now_ts}}}'
        payload_bytes = payload_json.encode()
        body_dict = {"session_id": "s_100", "status": "Approved", "timestamp": now_ts}
        sig = compute_signature(secret, body_dict, version="v2")
        headers = {
            "x-signature-v2": sig,
            "x-timestamp": str(now_ts),
        }

        # Exact v0.2.0 verify_webhook_signature call (no verify_freshness parameter passed)
        is_valid = verify_webhook_signature(
            payload_bytes,
            headers,
            secret,
        )
        assert is_valid is True

        # Exact v0.2.0 parse_webhook_payload call (no verify_freshness parameter passed)
        parsed = parse_webhook_payload(
            payload_bytes,
            headers,
            secret,
        )
        assert isinstance(parsed, WebhookPayload)
        assert parsed.session_id == "s_100"
        assert parsed.status == "Approved"

    def test_v020_config_with_explicit_args_precedence(self) -> None:
        """v0.2.0 allowed passing DiditConfig alongside explicit arguments without error."""
        from didit import DiditConfig

        cfg = DiditConfig(api_key="config_key", base_url="https://cfg.didit.me/v3")
        with pytest.deprecated_call(
            match="Passing explicit configuration arguments alongside `config`"
        ):
            client = Didit(config=cfg, api_key="ignored_key")
        assert client.config.api_key == "config_key"
        assert client.config.base_url == "https://cfg.didit.me/v3"

        with pytest.deprecated_call(
            match="Passing explicit configuration arguments alongside `config`"
        ):
            async_client = AsyncDidit(config=cfg, api_key="ignored_key")
        assert async_client.config.api_key == "config_key"
        assert async_client.config.base_url == "https://cfg.didit.me/v3"

    def test_public_method_signatures_v020_frozen(self) -> None:
        """Formally verify all v0.2.0 public method signatures remain backward-compatible.

        Compares parameter names, kinds, defaults, and order against the v0.2.0 frozen manifest.
        """
        import inspect

        from didit.client import AsyncDidit, Didit
        from didit.resources.sessions import AsyncSessionsResource, SessionsResource

        v020_signatures: dict[type, dict[str, list[tuple[str, inspect._ParameterKind, Any]]]] = {
            Didit: {
                "close": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty)
                ],
                "parse_webhook": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("raw_body", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("headers", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("secret", inspect.Parameter.KEYWORD_ONLY, None),
                    ("max_age_seconds", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "verify_webhook": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("raw_body", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("headers", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("secret", inspect.Parameter.KEYWORD_ONLY, None),
                    ("max_age_seconds", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "with_options": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("options", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                ],
            },
            AsyncDidit: {
                "aclose": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty)
                ],
                "parse_webhook": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("raw_body", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("headers", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("secret", inspect.Parameter.KEYWORD_ONLY, None),
                    ("max_age_seconds", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "verify_webhook": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("raw_body", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("headers", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("secret", inspect.Parameter.KEYWORD_ONLY, None),
                    ("max_age_seconds", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "with_options": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    ("options", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                ],
            },
            SessionsResource: {
                "create": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "vendor_data",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("workflow_id", inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.empty),
                    ("callback", inspect.Parameter.KEYWORD_ONLY, None),
                    ("language", inspect.Parameter.KEYWORD_ONLY, None),
                    ("sandbox_scenario", inspect.Parameter.KEYWORD_ONLY, None),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "get": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "session_id",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "get_decision": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "session_id",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "poll_decision": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "session_id",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("timeout", inspect.Parameter.KEYWORD_ONLY, 60.0),
                    ("interval", inspect.Parameter.KEYWORD_ONLY, 2.0),
                    ("max_interval", inspect.Parameter.KEYWORD_ONLY, 10.0),
                    ("backoff_multiplier", inspect.Parameter.KEYWORD_ONLY, 1.2),
                    ("stop_on_review", inspect.Parameter.KEYWORD_ONLY, True),
                    ("stop_when", inspect.Parameter.KEYWORD_ONLY, None),
                    ("tolerate_transient_errors", inspect.Parameter.KEYWORD_ONLY, True),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
            },
            AsyncSessionsResource: {
                "create": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "vendor_data",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("workflow_id", inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.empty),
                    ("callback", inspect.Parameter.KEYWORD_ONLY, None),
                    ("language", inspect.Parameter.KEYWORD_ONLY, None),
                    ("sandbox_scenario", inspect.Parameter.KEYWORD_ONLY, None),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "get": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "session_id",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "get_decision": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "session_id",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
                "poll_decision": [
                    ("self", inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                    (
                        "session_id",
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.empty,
                    ),
                    ("timeout", inspect.Parameter.KEYWORD_ONLY, 60.0),
                    ("interval", inspect.Parameter.KEYWORD_ONLY, 2.0),
                    ("max_interval", inspect.Parameter.KEYWORD_ONLY, 10.0),
                    ("backoff_multiplier", inspect.Parameter.KEYWORD_ONLY, 1.2),
                    ("stop_on_review", inspect.Parameter.KEYWORD_ONLY, True),
                    ("stop_when", inspect.Parameter.KEYWORD_ONLY, None),
                    ("tolerate_transient_errors", inspect.Parameter.KEYWORD_ONLY, True),
                    ("options", inspect.Parameter.KEYWORD_ONLY, None),
                ],
            },
        }

        for target_cls, methods in v020_signatures.items():
            for method_name, expected_params in methods.items():
                assert hasattr(target_cls, method_name), (
                    f"{target_cls.__name__}.{method_name} missing"
                )
                actual_sig = inspect.signature(getattr(target_cls, method_name))
                actual_params = list(actual_sig.parameters.values())

                for exp_name, exp_kind, exp_default in expected_params:
                    assert exp_name in actual_sig.parameters, (
                        f"{target_cls.__name__}.{method_name} dropped parameter {exp_name}"
                    )
                    param = actual_sig.parameters[exp_name]
                    assert param.kind == exp_kind, (
                        f"{target_cls.__name__}.{method_name}.{exp_name} "
                        f"kind mismatch: {param.kind} vs {exp_kind}"
                    )
                    if exp_default is not inspect.Parameter.empty:
                        assert param.default == exp_default, (
                            f"{target_cls.__name__}.{method_name}.{exp_name} "
                            f"default mismatch: {param.default} vs {exp_default}"
                        )

                exp_positional_names = [
                    p[0]
                    for p in expected_params
                    if p[1]
                    in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                ]
                actual_positional_names = [
                    p.name
                    for p in actual_params
                    if p.kind
                    in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                ]
                assert (
                    actual_positional_names[: len(exp_positional_names)] == exp_positional_names
                ), f"{target_cls.__name__}.{method_name} modified positional parameter order"

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

    def test_v020_integrations_and_dedup_frozen_contracts(self) -> None:
        """Verify that v0.2.0 integration and dedup signatures and returns are preserved."""
        import inspect

        from didit.dedup import (
            aclaim_webhook_event,
            arelease_webhook_event,
            compute_dedup_key,
            release_webhook_event,
        )
        from didit.integrations.django import didit_webhook_view, parse_django_webhook
        from didit.integrations.fastapi import (
            DiditWebhookGuard,
            didit_webhook,
            release_didit_claim,
        )
        from didit.integrations.flask import didit_webhook as didit_flask_webhook
        from didit.integrations.flask import parse_flask_webhook

        # 1. Dedup helpers signatures and None return types for v0.2.0 callers
        sig_rel = inspect.signature(release_webhook_event)
        assert "store" in sig_rel.parameters
        assert "key" in sig_rel.parameters
        assert "event_id" not in sig_rel.parameters
        assert sig_rel.return_annotation in (None, "None", type(None))

        sig_arel = inspect.signature(arelease_webhook_event)
        assert "store" in sig_arel.parameters
        assert "key" in sig_arel.parameters
        assert "event_id" not in sig_arel.parameters
        assert sig_arel.return_annotation in (None, "None", type(None))

        sig_aclaim = inspect.signature(aclaim_webhook_event)
        assert "key" in sig_aclaim.parameters
        assert sig_aclaim.parameters["ttl_seconds"].default == 86400
        assert sig_aclaim.return_annotation in (bool, "bool")

        sig_key = inspect.signature(compute_dedup_key)
        assert "payload" in sig_key.parameters
        assert sig_key.return_annotation in (str, "str")

        # 2. FastAPI integration signatures and return types
        sig_guard_init = inspect.signature(DiditWebhookGuard.__init__)
        assert "dedup_ttl_seconds" in sig_guard_init.parameters
        assert sig_guard_init.parameters["dedup_ttl_seconds"].default == 86400

        sig_guard_rel = inspect.signature(DiditWebhookGuard.release_claim)
        assert "request" in sig_guard_rel.parameters
        assert sig_guard_rel.return_annotation in (None, "None", type(None))

        sig_rel_claim = inspect.signature(release_didit_claim)
        assert "request" in sig_rel_claim.parameters
        assert sig_rel_claim.return_annotation in (None, "None", type(None))

        sig_fastapi_wh = inspect.signature(didit_webhook)
        assert "dedup_ttl_seconds" in sig_fastapi_wh.parameters
        assert sig_fastapi_wh.parameters["dedup_ttl_seconds"].default == 86400

        # 3. Django integration signatures and defaults
        sig_django_wh = inspect.signature(didit_webhook_view)
        assert "dedup_ttl_seconds" in sig_django_wh.parameters
        assert sig_django_wh.parameters["dedup_ttl_seconds"].default == 86400

        sig_django_parse = inspect.signature(parse_django_webhook)
        assert "request" in sig_django_parse.parameters
        assert sig_django_parse.return_annotation in (WebhookPayload, "WebhookPayload")

        # 4. Flask integration signatures and defaults
        sig_flask_wh = inspect.signature(didit_flask_webhook)
        assert "dedup_ttl_seconds" in sig_flask_wh.parameters
        assert sig_flask_wh.parameters["dedup_ttl_seconds"].default == 86400

        sig_flask_parse = inspect.signature(parse_flask_webhook)
        assert "request_obj" in sig_flask_parse.parameters
        assert sig_flask_parse.return_annotation in (WebhookPayload, "WebhookPayload")

    @pytest.mark.asyncio
    async def test_v020_keyword_invocation_release_webhook_event(self) -> None:
        """Verify calling release_webhook_event and arelease_webhook_event with keyword 'key'."""
        from didit.dedup import (
            InMemoryWebhookDedupStore,
            arelease_webhook_event,
            release_webhook_event,
        )

        store = InMemoryWebhookDedupStore()
        store.claim("test_key_kw", ttl_seconds=60)

        # Call synchronous release_webhook_event using keyword arguments exactly as in v0.2.0
        res = release_webhook_event(store=store, key="test_key_kw")
        assert res is None
        assert store.claim("test_key_kw", ttl_seconds=60) is True

        # Call asynchronous arelease_webhook_event using keyword arguments exactly as in v0.2.0
        res_async = await arelease_webhook_event(store=store, key="test_key_kw")
        assert res_async is None
        assert store.claim("test_key_kw", ttl_seconds=60) is True
