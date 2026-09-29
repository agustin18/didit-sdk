"""Tests for Pydantic data models and enums."""

import pytest
from pydantic import ValidationError

from didit.models.decision import (
    AMLData,
    BiometricsData,
    DecisionResponse,
    DocumentData,
    ReviewData,
)
from didit.models.enums import Language, SessionStatus
from didit.models.session import CreateSessionRequest, SessionResponse
from didit.models.webhook import WebhookPayload


class TestSessionStatus:
    @pytest.mark.parametrize(
        (
            "status",
            "is_decided",
            "is_ended_without_decision",
            "is_poll_complete",
            "requires_review",
            "requires_user_action",
        ),
        [
            (SessionStatus.NOT_STARTED, False, False, False, False, True),
            (SessionStatus.IN_PROGRESS, False, False, False, False, True),
            (SessionStatus.IN_REVIEW, False, False, False, True, False),
            (SessionStatus.APPROVED, True, False, True, False, False),
            (SessionStatus.DECLINED, True, False, True, False, False),
            (SessionStatus.EXPIRED, False, True, True, False, False),
            (SessionStatus.ABANDONED, False, True, True, False, False),
            (SessionStatus.KYC_EXPIRED, True, False, True, False, False),
            (SessionStatus.RESUBMITTED, False, False, False, False, True),
            (SessionStatus.AWAITING_USER, False, False, False, False, True),
        ],
    )
    def test_status_properties(
        self,
        status: SessionStatus,
        is_decided: bool,
        is_ended_without_decision: bool,
        is_poll_complete: bool,
        requires_review: bool,
        requires_user_action: bool,
    ) -> None:
        assert status.is_decided is is_decided
        assert status.is_ended_without_decision is is_ended_without_decision
        assert status.is_poll_complete is is_poll_complete
        assert status.requires_review is requires_review
        assert status.requires_user_action is requires_user_action
        # Backward compatibility properties
        assert status.is_in_review is requires_review
        assert status.is_closed is is_poll_complete
        assert status.is_terminal is is_poll_complete

    def test_status_string_equivalence(self) -> None:
        assert SessionStatus.APPROVED == "Approved"
        assert SessionStatus.DECLINED == "Declined"
        assert SessionStatus.EXPIRED == "Expired"
        assert SessionStatus.ABANDONED == "Abandoned"
        assert SessionStatus.KYC_EXPIRED == "Kyc Expired"
        assert SessionStatus.RESUBMITTED == "Resubmitted"
        assert SessionStatus.AWAITING_USER == "Awaiting User"
        assert SessionStatus("In Progress") == SessionStatus.IN_PROGRESS


class TestLanguageEnum:
    @pytest.mark.parametrize("code", ["en", "es", "fr", "de", "pt", "it"])
    def test_standard_languages_exist(self, code: str) -> None:
        assert Language(code).value == code


class TestCreateSessionRequest:
    def test_valid_request(self) -> None:
        req = CreateSessionRequest(
            workflow_id="wf_123",
            vendor_data="user_456",
            callback="https://example.com/cb",
            language="es",
        )
        data = req.model_dump(exclude_none=True)
        assert data == {
            "workflow_id": "wf_123",
            "vendor_data": "user_456",
            "callback": "https://example.com/cb",
            "language": "es",
        }

    def test_optional_fields_default_to_none(self) -> None:
        req = CreateSessionRequest(workflow_id="wf_123", vendor_data="user_456")
        data = req.model_dump(exclude_none=True)
        assert data == {"workflow_id": "wf_123", "vendor_data": "user_456"}

    def test_empty_workflow_or_vendor_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            CreateSessionRequest(workflow_id="", vendor_data="user_456")
        with pytest.raises(ValidationError):
            CreateSessionRequest(workflow_id="wf_123", vendor_data="")


class TestSessionResponse:
    def test_parse_valid_response(self) -> None:
        raw = {
            "session_id": "sess_abc",
            "session_token": "tok_xyz",
            "url": "https://verify.didit.me/sess_abc",
            "status": "In Progress",
            "workflow_id": "wf_123",
            "vendor_data": "usr_99",
            "callback": "https://callback.com",
            "unknown_future_field": "future_proof",
        }
        resp = SessionResponse.model_validate(raw)
        assert resp.session_id == "sess_abc"
        assert resp.session_token == "tok_xyz"
        assert resp.url == "https://verify.didit.me/sess_abc"
        assert resp.status == SessionStatus.IN_PROGRESS
        assert resp.workflow_id == "wf_123"

    def test_minimal_response(self) -> None:
        resp = SessionResponse.model_validate({"session_id": "sess_1"})
        assert resp.session_id == "sess_1"
        assert resp.status == SessionStatus.NOT_STARTED


class TestDecisionResponse:
    def test_parse_full_decision(self) -> None:
        raw = {
            "session_id": "sess_abc",
            "status": "Approved",
            "workflow_id": "wf_123",
            "vendor_data": "usr_1",
            "document": {
                "document_type": "id_card",
                "country": "ESP",
                "document_number": "12345678Z",
                "first_name": "Agustin",
                "last_name": "Saiz",
                "date_of_birth": "1995-05-15",
                "expiration_date": "2030-05-15",
                "is_valid": True,
            },
            "biometrics": {
                "face_match": True,
                "liveness_check": True,
                "score": 0.98,
            },
            "aml": {
                "pep_detected": False,
                "sanctions_detected": False,
                "adverse_media_detected": False,
            },
            "review": {
                "reviewed_by": "agent_007",
                "decision_reason": "All checks passed",
            },
        }
        decision = DecisionResponse.model_validate(raw)
        assert decision.session_id == "sess_abc"
        assert decision.status == SessionStatus.APPROVED
        assert decision.document is not None
        assert decision.document.document_number == "12345678Z"
        assert decision.document.is_valid is True
        assert decision.biometrics is not None
        assert decision.biometrics.face_match is True
        assert decision.aml is not None
        assert decision.aml.pep_detected is False
        assert decision.review is not None
        assert decision.review.reviewed_by == "agent_007"

    def test_parse_v3_plural_decision_arrays(self) -> None:
        raw = {
            "session_id": "sess_v3",
            "status": "Approved",
            "id_verifications": [
                {
                    "first_name": "José",
                    "last_name": "García",
                    "document_number": "12345678Z",
                    "country": "ESP",
                    "status": "Approved",
                }
            ],
            "liveness_checks": [{"status": "Approved", "score": 98.5}],
            "face_matches": [{"status": "Approved", "score": 99.1}],
            "aml_screenings": [{"status": "Approved", "pep_detected": False}],
            "reviews": [{"reviewed_by": "compliance_lead", "decision_reason": "Cleared"}],
            "custom_upstream_metric": 42,
        }
        decision = DecisionResponse.model_validate(raw)
        assert len(decision.id_verifications) == 1
        assert decision.id_verifications[0].first_name == "José"
        assert len(decision.liveness_checks) == 1
        assert decision.liveness_checks[0].score == 98.5
        assert len(decision.face_matches) == 1
        assert len(decision.aml_screenings) == 1
        assert len(decision.reviews) == 1

        # Test backward-compatible property accessors
        assert decision.document is not None
        assert decision.document.first_name == "José"
        assert decision.document.document_number == "12345678Z"
        assert decision.biometrics is not None
        assert decision.biometrics.face_match is True
        assert decision.biometrics.liveness_check is True
        assert decision.biometrics.score == 98.5
        assert decision.aml is not None
        assert decision.aml.pep_detected is False
        assert decision.review is not None
        assert decision.review.reviewed_by == "compliance_lead"

        # Extra fields preserved via extra="allow"
        assert getattr(decision, "custom_upstream_metric", None) == 42

    def test_decision_response_model_validate_does_not_mutate_caller_dict(self) -> None:
        import copy

        raw = {
            "session_id": "sess_immutable",
            "status": "Approved",
            "document": {
                "first_name": "John",
                "last_name": "Doe",
            },
            "biometrics": {
                "face_match": True,
            },
        }
        raw_copy = copy.deepcopy(raw)
        DecisionResponse.model_validate(raw)
        assert raw == raw_copy
        assert "document" in raw
        assert "biometrics" in raw

    def test_decision_response_read_only_accessors_and_multi_node_preservation(self) -> None:
        from didit.models.decision import IdVerificationResult

        node_a = IdVerificationResult(
            first_name="Alice", last_name="Smith", document_number="A1", status="Approved"
        )
        node_b = IdVerificationResult(
            first_name="Bob", last_name="Jones", document_number="B2", status="Approved"
        )

        decision = DecisionResponse(
            session_id="sess_multi",
            status=SessionStatus.APPROVED,
            id_verifications=[node_a, node_b],
        )

        # Accessing .document returns first node and preserves array
        assert decision.document is not None
        assert decision.document.first_name == "Alice"
        assert len(decision.id_verifications) == 2
        assert decision.id_verifications[1].first_name == "Bob"

        # Accessors are read-only to prevent destructive overwriting of V3 arrays
        with pytest.raises(AttributeError):
            decision.document = DocumentData(first_name="Mallory")  # type: ignore[misc]

        with pytest.raises(AttributeError):
            decision.biometrics = BiometricsData(face_match=True)  # type: ignore[misc]

        with pytest.raises(AttributeError):
            decision.aml = AMLData(pep_detected=False)  # type: ignore[misc]

        with pytest.raises(AttributeError):
            decision.review = ReviewData(reviewed_by="auditor")  # type: ignore[misc]

        # NFC verifications field present
        assert decision.nfc_verifications == []
        decision.nfc_verifications.append({"status": "Approved", "chip_authenticated": True})
        assert len(decision.nfc_verifications) == 1

        # Empty decision returns None for all legacy properties
        empty_dec = DecisionResponse(session_id="s_empty", status=SessionStatus.NOT_STARTED)
        assert empty_dec.document is None
        assert empty_dec.biometrics is None
        assert empty_dec.aml is None
        assert empty_dec.review is None

        # Biometrics branch variations
        from didit.models.decision import FaceMatchResult, LivenessResult

        d_face_only = DecisionResponse(
            session_id="s_face",
            status=SessionStatus.APPROVED,
            face_matches=[FaceMatchResult(status="Approved", score=0.88)],
        )
        assert d_face_only.biometrics is not None
        assert d_face_only.biometrics.face_match is True
        assert d_face_only.biometrics.liveness_check is None
        assert d_face_only.biometrics.score == 0.88

        d_live_noscore = DecisionResponse(
            session_id="s_live_noscore",
            status=SessionStatus.APPROVED,
            liveness_checks=[LivenessResult(status="Approved", score=None)],
            face_matches=[FaceMatchResult(status="Approved", score=0.77)],
        )
        assert d_live_noscore.biometrics is not None
        assert d_live_noscore.biometrics.score == 0.77

        d_live_only_noscore = DecisionResponse(
            session_id="s_live_only",
            status=SessionStatus.APPROVED,
            liveness_checks=[LivenessResult(status="Approved", score=None)],
        )
        assert d_live_only_noscore.biometrics is not None
        assert d_live_only_noscore.biometrics.score is None

        d_face_noscore = DecisionResponse(
            session_id="s_face_none",
            status=SessionStatus.APPROVED,
            face_matches=[FaceMatchResult(status=None, score=None)],
        )
        assert d_face_noscore.biometrics is not None
        assert d_face_noscore.biometrics.face_match is None
        assert d_face_noscore.biometrics.score is None

        # Migration hook with non-dict input
        assert DecisionResponse._migrate_legacy_singular_fields(42) == 42

    def test_legacy_singular_migration_branches(self) -> None:
        # None values for legacy fields
        raw_nones = {
            "session_id": "s_nones",
            "status": "Approved",
            "document": None,
            "biometrics": None,
            "aml": None,
            "review": None,
        }
        d_nones = DecisionResponse.model_validate(raw_nones)
        assert len(d_nones.id_verifications) == 0
        assert len(d_nones.liveness_checks) == 0
        assert len(d_nones.aml_screenings) == 0
        assert len(d_nones.reviews) == 0

        # Document with explicit status (skips is_valid branch)
        raw_doc_status = {
            "session_id": "s_status",
            "status": "Approved",
            "document": {"status": "Approved", "document_number": "123"},
        }
        d_doc_status = DecisionResponse.model_validate(raw_doc_status)
        assert d_doc_status.document is not None
        assert d_doc_status.document.document_number == "123"

        # Biometrics with only liveness_check (false)
        raw_live_only = {
            "session_id": "s_live",
            "status": "Approved",
            "biometrics": {"liveness_check": False, "score": 0.1},
        }
        d_live = DecisionResponse.model_validate(raw_live_only)
        assert len(d_live.liveness_checks) == 1
        assert d_live.liveness_checks[0].status == "Declined"
        assert len(d_live.face_matches) == 0

        # Biometrics with only face_match (false)
        raw_face_only = {
            "session_id": "s_face",
            "status": "Approved",
            "biometrics": {"face_match": False, "score": 0.2},
        }
        d_face = DecisionResponse.model_validate(raw_face_only)
        assert len(d_face.face_matches) == 1
        assert d_face.face_matches[0].status == "Declined"
        assert len(d_face.liveness_checks) == 0


class TestWebhookPayload:
    def test_parse_webhook_payload(self) -> None:
        raw = {
            "session_id": "sess_webhook",
            "status": "Approved",
            "timestamp": 1727630000,
            "created_at": 1727630000,
            "event_id": "evt_abc123",
            "webhook_type": "session.updated",
            "environment": "sandbox",
            "workflow_id": "wf_123",
            "workflow_version": "v1.2",
            "vendor_data": "user_789",
            "metadata": {"source": "mobile_app"},
            "decision": {
                "session_id": "sess_webhook",
                "status": "Approved",
            },
            "custom_payload_field": "preserved",
        }
        wh = WebhookPayload.model_validate(raw)
        assert wh.session_id == "sess_webhook"
        assert wh.status == SessionStatus.APPROVED
        assert wh.timestamp == 1727630000
        assert wh.created_at == 1727630000
        assert wh.event_id == "evt_abc123"
        assert wh.webhook_type == "session.updated"
        assert wh.environment == "sandbox"
        assert wh.workflow_version == "v1.2"
        assert wh.metadata == {"source": "mobile_app"}
        assert wh.decision is not None
        assert wh.decision.status == SessionStatus.APPROVED
        assert getattr(wh, "custom_payload_field", None) == "preserved"

    @pytest.mark.parametrize("wv", [4, "v1.2", None])
    def test_workflow_version_accepts_int_and_str(self, wv: int | str | None) -> None:
        raw = {
            "session_id": "sess_1",
            "status": "Approved",
            "workflow_version": wv,
        }
        wh = WebhookPayload.model_validate(raw)
        assert wh.workflow_version == wv
