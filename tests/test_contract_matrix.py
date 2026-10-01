"""Contract matrix tests validating sandbox scenarios, additive schema evolution,
and warning catalog.
"""

from __future__ import annotations

from typing import Any

import pytest

from didit.models.decision import DecisionResponse, VerificationWarning
from didit.models.enums import SessionStatus
from didit.models.session import SessionResponse
from didit.models.webhook import WebhookPayload
from didit.simulation import SUPPORTED_SANDBOX_SCENARIOS, SimulatedAsyncDidit, SimulatedDidit

EXPECTED_SANDBOX_SCENARIOS: frozenset[str] = frozenset(
    {
        "approve",
        "decline_document_expired",
        "decline_could_not_recognize_document",
        "decline_mrz_validation",
        "decline_minimum_age",
        "decline_face_match_low_similarity",
        "decline_liveness_attack",
        "decline_aml_hit",
        "decline_ip_blocklist",
        "decline_poa_address_mismatch",
        "decline_nfc_chip_not_verified",
        "decline_database_no_match",
        "decline_kyb_registry_mismatch",
        "review_aml_possible_match",
        "review_face_match_borderline",
        "review_poa_partial_match",
    }
)


class TestSandboxScenarioContract:
    """Validate sandbox scenarios contract across sync and async simulation."""

    def test_sandbox_scenarios_match_independent_oracle(self) -> None:
        """Supported sandbox scenarios in simulator must exactly match 16 oracle slugs."""
        assert SUPPORTED_SANDBOX_SCENARIOS == EXPECTED_SANDBOX_SCENARIOS

    @pytest.mark.parametrize("scenario", sorted(EXPECTED_SANDBOX_SCENARIOS))
    def test_sync_sandbox_scenario_execution(self, scenario: str) -> None:
        """Every supported scenario produces a valid session and expected decision status."""
        client = SimulatedDidit()
        session = client.sessions.create(
            vendor_data=f"vendor_{scenario}",
            workflow_id="wf_matrix",
            sandbox_scenario=scenario,
        )
        assert session.session_id.startswith("sim_")
        assert session.status in (
            SessionStatus.NOT_STARTED,
            SessionStatus.IN_PROGRESS,
            SessionStatus.IN_REVIEW,
            SessionStatus.APPROVED,
            SessionStatus.DECLINED,
        )

        decision = client.sessions.get_decision(session.session_id)
        assert decision.session_id == session.session_id

        if scenario == "approve":
            assert decision.status == SessionStatus.APPROVED
        elif scenario.startswith("decline_"):
            assert decision.status == SessionStatus.DECLINED
        elif scenario.startswith("review_"):
            assert decision.status == SessionStatus.IN_REVIEW

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scenario", sorted(EXPECTED_SANDBOX_SCENARIOS))
    async def test_async_sandbox_scenario_execution(self, scenario: str) -> None:
        """Async simulated client handles sandbox scenarios identically across all 16 slugs."""
        client = SimulatedAsyncDidit()
        session = await client.sessions.create(
            vendor_data=f"async_{scenario}",
            workflow_id="wf_async_matrix",
            sandbox_scenario=scenario,
        )
        decision = await client.sessions.get_decision(session.session_id)
        if scenario == "approve":
            assert decision.status == SessionStatus.APPROVED
        elif scenario.startswith("decline_"):
            assert decision.status == SessionStatus.DECLINED
        elif scenario.startswith("review_"):
            assert decision.status == SessionStatus.IN_REVIEW


class TestAdditiveSchemaDriftContract:
    """Validate that models gracefully handle forward-compatible additive schema evolution."""

    def test_session_response_accepts_unknown_fields(self) -> None:
        raw: dict[str, Any] = {
            "session_id": "sess_future_drift",
            "status": "In Progress",
            "future_ai_score": 0.985,
            "nested_extensions": {
                "biometrics_v4": {"iris_scan": False},
                "network_signals": ["vpn_detected", "datacenter_ip"],
            },
        }
        model = SessionResponse.model_validate(raw)
        assert model.session_id == "sess_future_drift"
        assert model.status == SessionStatus.IN_PROGRESS
        assert getattr(model, "future_ai_score", None) == 0.985

    def test_decision_response_accepts_unknown_fields(self) -> None:
        raw: dict[str, Any] = {
            "session_id": "sess_decision_drift",
            "status": "Approved",
            "decision": True,
            "future_trust_tier": "TIER_A_PLUS",
            "synthetic_identity_probability": 0.001,
        }
        model = DecisionResponse.model_validate(raw)
        assert model.session_id == "sess_decision_drift"
        assert model.status == SessionStatus.APPROVED
        assert getattr(model, "future_trust_tier", None) == "TIER_A_PLUS"

    def test_webhook_payload_accepts_unknown_fields(self) -> None:
        raw: dict[str, Any] = {
            "session_id": "sess_webhook_drift",
            "status": "Approved",
            "timestamp": 1700000000,
            "webhook_type": "status.updated",
            "cloud_origin_region": "eu-west-1",
            "future_compliance_audit_id": "audit_xyz_999",
        }
        model = WebhookPayload.model_validate(raw)
        assert model.session_id == "sess_webhook_drift"
        assert model.status == "Approved"
        assert getattr(model, "cloud_origin_region", None) == "eu-west-1"

    def test_verification_warning_accepts_unknown_fields(self) -> None:
        raw: dict[str, Any] = {
            "code": "ADVANCED_FACE_MORPH",
            "future_anomaly_score": 0.992,
            "synthetic_model_id": "synth_v4",
        }
        warning = VerificationWarning.model_validate(raw)
        assert warning.warning_code == "ADVANCED_FACE_MORPH"
        assert getattr(warning, "future_anomaly_score", None) == 0.992


class TestWarningCodeCatalogContract:
    """Validate warning code catalog normalization and resilience."""

    @pytest.mark.parametrize(
        ("warning_input", "expected_code"),
        [
            ("EXPIRED_DOCUMENT", "EXPIRED_DOCUMENT"),
            ("FACE_MISMATCH_SUSPECTED", "FACE_MISMATCH_SUSPECTED"),
            ({"code": "DOC_GLARE", "severity": "low"}, "DOC_GLARE"),
            ({"risk": "PEP_CLOSE_ASSOCIATE", "severity": "medium"}, "PEP_CLOSE_ASSOCIATE"),
            ({"short_description": "MRZ_CHECKSUM_ERROR"}, "MRZ_CHECKSUM_ERROR"),
            ({"log_type": "UNSUPPORTED_HOLOGRAM"}, "UNSUPPORTED_HOLOGRAM"),
        ],
    )
    def test_warning_normalization(self, warning_input: Any, expected_code: str) -> None:
        w = VerificationWarning.model_validate(warning_input)
        assert w.warning_code == expected_code

    def test_decision_with_mixed_warnings_catalog(self) -> None:
        raw: dict[str, Any] = {
            "session_id": "sess_warnings_test",
            "status": "In Review",
            "warnings": [
                "DOCUMENT_EDGE_CROPPED",
                {"code": "SUSPICIOUS_DEVICE", "severity": "high", "details": {"ip": "1.2.3.4"}},
                {"risk": "SANCTIONS_GEO_PROXIMITY"},
            ],
        }
        decision = DecisionResponse.model_validate(raw)
        assert decision.warnings is not None
        assert len(decision.warnings) == 3
        codes = [w.warning_code for w in decision.warnings]
        assert "DOCUMENT_EDGE_CROPPED" in codes
        assert "SUSPICIOUS_DEVICE" in codes
        assert "SANCTIONS_GEO_PROXIMITY" in codes
