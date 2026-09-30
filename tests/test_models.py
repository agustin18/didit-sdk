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

    def test_pii_safe_repr_and_redacted_dump(self) -> None:
        from didit.models.decision import (
            AMLData,
            AMLScreeningResult,
            BiometricsData,
            DocumentData,
            FaceMatchResult,
            IdVerificationResult,
            LivenessResult,
            ReviewData,
        )

        id_v = IdVerificationResult(
            first_name="VerySecretFirst",
            last_name="VerySecretLast",
            document_number="PASSPORT123456",
            status="Approved",
            document_type="passport",
        )
        # Verify IdVerificationResult repr does not leak names or document numbers
        id_repr = repr(id_v)
        assert "VerySecretFirst" not in id_repr
        assert "PASSPORT123456" not in id_repr
        assert "IdVerificationResult" in id_repr

        live = LivenessResult(node_id="live_1", status="Approved", score=99.0)
        assert repr(live) == "LivenessResult(node_id='live_1', status='Approved')"
        assert str(live) == repr(live)

        face = FaceMatchResult(node_id="face_1", status="Approved", score=98.5)
        assert repr(face) == "FaceMatchResult(node_id='face_1', status='Approved')"
        assert str(face) == repr(face)

        aml = AMLScreeningResult(node_id="aml_1", status="Approved", pep_detected=False)
        assert repr(aml) == "AMLScreeningResult(node_id='aml_1', status='Approved')"
        assert str(aml) == repr(aml)

        doc = DocumentData(document_type="id_card", country="ESP", is_valid=True)
        assert repr(doc) == "DocumentData(document_type='id_card', is_valid=True)"
        assert str(doc) == repr(doc)

        bio = BiometricsData(face_match=True, liveness_check=True, score=98.0)
        assert repr(bio) == "BiometricsData(face_match=True, liveness_check=True)"
        assert str(bio) == repr(bio)

        aml_data = AMLData(pep_detected=False, sanctions_detected=False)
        assert repr(aml_data) == "AMLData(pep_detected=False, sanctions_detected=False)"
        assert str(aml_data) == repr(aml_data)

        rev = ReviewData(reviewed_by="auditor_42", decision_reason="Verified clean")
        assert repr(rev) == "ReviewData(reviewed_by='auditor_42', has_reason=True)"
        assert str(rev) == repr(rev)

        dec = DecisionResponse(
            session_id="sess_pii_check",
            status=SessionStatus.APPROVED,
            id_verifications=[id_v],
            liveness_checks=[live],
            face_matches=[face],
            aml_screenings=[aml],
            reviews=[rev],
        )

        # Repr of DecisionResponse must be concise and free of PII
        dec_repr = repr(dec)
        assert "VerySecretFirst" not in dec_repr
        assert "PASSPORT123456" not in dec_repr
        assert "sess_pii_check" in dec_repr
        assert "id_verifications=1" in dec_repr

        # Redacted dump output structure
        redacted = dec.redacted_dump()
        assert redacted["session_id"] == "sess_pii_check"
        assert redacted["status"] == "Approved"
        assert len(redacted["id_verifications"]) == 1
        assert "first_name" not in redacted["id_verifications"][0]
        assert "document_number" not in redacted["id_verifications"][0]
        assert redacted["id_verifications"][0]["document_type"] == "passport"
        assert "reviewed_by" not in redacted["reviews"][0]
        assert redacted["reviews"][0]["has_review"] is True
        assert redacted["reviews"][0]["has_reason"] is True

        # WebhookPayload safe repr
        wh = WebhookPayload(
            session_id="sess_pii_check",
            status=SessionStatus.APPROVED,
            event_id="evt_test_123",
            webhook_type="status.updated",
        )
        wh_repr = repr(wh)
        assert "evt_test_123" in wh_repr
        assert "WebhookPayload" in wh_repr

    def test_legacy_bool_semantics_in_review_is_none(self) -> None:
        from didit.models.decision import (
            FaceMatchResult,
            IdVerificationResult,
            LivenessResult,
        )

        # In Review status must NOT map to is_valid=False or face_match=False
        node_review = IdVerificationResult(status="In Review")
        d = DecisionResponse(
            session_id="s_rev",
            status=SessionStatus.IN_REVIEW,
            id_verifications=[node_review],
            face_matches=[FaceMatchResult(status="In Review")],
            liveness_checks=[LivenessResult(status="In Review")],
        )
        assert d.document is not None
        assert d.document.is_valid is None  # Neither True nor False
        assert d.biometrics is not None
        assert d.biometrics.face_match is None  # Neither True nor False
        assert d.biometrics.liveness_check is None  # Neither True nor False

        # Declined status maps to False
        node_declined = IdVerificationResult(status="Declined")
        d_declined = DecisionResponse(
            session_id="s_dec",
            status=SessionStatus.DECLINED,
            id_verifications=[node_declined],
            face_matches=[FaceMatchResult(status="Declined")],
            liveness_checks=[LivenessResult(status="Declined")],
        )
        assert d_declined.document is not None
        assert d_declined.document.is_valid is False
        assert d_declined.biometrics is not None
        assert d_declined.biometrics.face_match is False
        assert d_declined.biometrics.liveness_check is False

    def test_shallow_copy_migration_preserves_input_dict(self) -> None:
        raw = {
            "session_id": "sess_preserve",
            "status": "Approved",
            "document": {"document_type": "passport", "first_name": "Test"},
            "biometrics": {"face_match": True, "score": 95.0},
            "aml": {"pep_detected": False},
            "review": {"reviewed_by": "agent_1"},
        }
        raw_copy = dict(raw)
        DecisionResponse.model_validate(raw)
        # Caller dict keys and values must remain unmutated
        assert "document" in raw
        assert "biometrics" in raw
        assert "aml" in raw
        assert "review" in raw
        assert raw["session_id"] == raw_copy["session_id"]

    def test_verification_warnings_model_and_methods(self) -> None:
        from didit.models.decision import IdVerificationResult, VerificationWarning

        warning = VerificationWarning(
            code="DOC_EXPIRING_SOON",
            message="Document expires in less than 30 days",
            severity="low",
            details={"days_left": 15},
        )
        assert warning.code == "DOC_EXPIRING_SOON"
        assert warning.message == "Document expires in less than 30 days"
        assert warning.severity == "low"
        assert warning.details == {"days_left": 15}
        assert "DOC_EXPIRING_SOON" in repr(warning)

        decision = DecisionResponse(
            session_id="sess_warn",
            status=SessionStatus.APPROVED,
            warnings=[warning],
        )
        assert decision.has_warning("DOC_EXPIRING_SOON") is True
        assert decision.has_warning("UNKNOWN_WARNING") is False
        assert decision.warning_codes == ["DOC_EXPIRING_SOON"]

        coerced = VerificationWarning.model_validate("STRING_WARN")
        assert coerced.code == "STRING_WARN"
        assert coerced.message == "STRING_WARN"

        # Heterogeneous warning structures in check nodes
        raw_node = IdVerificationResult()
        object.__setattr__(
            raw_node,
            "warnings",
            [
                VerificationWarning(code="OBJ_WARN", message="from obj"),
                {"code": "DICT_WARN", "message": "from dict"},
                {"code": "DICT_WARN", "message": "duplicate dict"},
                VerificationWarning(code=None, message="no code"),
                "STR_WARN",
                12345,  # Unhandled type skipped
            ],
        )
        nested_dec = DecisionResponse(
            session_id="sess_hetero",
            status=SessionStatus.APPROVED,
            id_verifications=[raw_node],
        )
        assert nested_dec.has_warning("OBJ_WARN") is True
        assert nested_dec.has_warning("DICT_WARN") is True
        assert nested_dec.has_warning("STR_WARN") is True
        assert "OBJ_WARN" in nested_dec.warning_codes
        assert "DICT_WARN" in nested_dec.warning_codes
        assert "STR_WARN" in nested_dec.warning_codes

        dump = decision.redacted_dump()
        assert "warnings" in dump
        assert len(dump["warnings"]) == 1
        assert dump["warnings"][0]["code"] == "DOC_EXPIRING_SOON"

        # Didit V3 schema with 'risk' field
        v3_warning = VerificationWarning(
            risk="LOW_LIVENESS_SCORE",
            log_type="information",
            short_description="Liveness confidence below recommended threshold",
        )
        assert v3_warning.warning_code == "LOW_LIVENESS_SCORE"
        v3_decision = DecisionResponse(
            session_id="sess_v3_warn",
            status=SessionStatus.DECLINED,
            warnings=[v3_warning],
        )
        assert v3_decision.has_warning("LOW_LIVENESS_SCORE") is True
        assert v3_decision.has_warning("information") is True
        assert v3_decision.has_warning("Liveness confidence below recommended threshold") is True
        assert "LOW_LIVENESS_SCORE" in v3_decision.warning_codes

    def test_create_session_request_sandbox_scenario(self) -> None:
        req = CreateSessionRequest(
            workflow_id="wf_1",
            vendor_data="user_1",
            sandbox_scenario="decline_document_expired",
        )
        assert req.sandbox_scenario == "decline_document_expired"


class TestSessionListAndReconciliationModels:
    def test_session_list_item_and_page_validation(self) -> None:
        from didit.models.session import SessionListItem, SessionListPage

        item = SessionListItem.model_validate(
            {
                "session_id": "sess_list_1",
                "status": "Approved",
                "workflow_id": "wf_1",
                "vendor_data": "user_100",
                "country": "ES",
                "session_kind": "user",
                "created_at": 1710000000,
            }
        )
        assert item.session_id == "sess_list_1"
        assert item.status == SessionStatus.APPROVED
        assert item.country == "ES"
        assert item.session_kind == "user"

        page = SessionListPage.model_validate(
            {
                "count": 1,
                "next": "https://verification.didit.me/v3/sessions/?offset=50&limit=50",
                "previous": None,
                "results": [item.model_dump()],
            }
        )
        assert page.count == 1
        assert page.next is not None
        assert page.previous is None
        assert len(page.results) == 1
        assert page.results[0].session_id == "sess_list_1"

    def test_observed_session_state_and_reconciliation_report(self) -> None:
        from didit.models.session import (
            BatchReconciliationReport,
            ObservedSessionState,
            SessionReconciliationReport,
        )

        observed = ObservedSessionState(
            session_id="sess_rec_1",
            status=SessionStatus.IN_REVIEW,
            warning_codes=["LOW_LIVENESS"],
        )
        assert observed.session_id == "sess_rec_1"
        assert observed.status == SessionStatus.IN_REVIEW
        assert observed.warning_codes == ["LOW_LIVENESS"]

        # In sync report
        report_ok = SessionReconciliationReport(
            session_id="sess_rec_1",
            local_status=SessionStatus.IN_REVIEW,
            remote_status=SessionStatus.IN_REVIEW,
            status_drift=False,
            warning_codes_added=[],
            warning_codes_removed=[],
        )
        assert report_ok.is_in_sync is True
        assert report_ok.warning_drift is False

        # Status drift
        report_drift = SessionReconciliationReport(
            session_id="sess_rec_1",
            local_status=SessionStatus.IN_REVIEW,
            remote_status=SessionStatus.APPROVED,
            status_drift=True,
            warning_codes_added=["DOC_EXPIRING_SOON"],
            warning_codes_removed=["LOW_LIVENESS"],
        )
        assert report_drift.is_in_sync is False
        assert report_drift.status_drift is True
        assert report_drift.warning_drift is True
        assert report_drift.warning_codes_added == ["DOC_EXPIRING_SOON"]
        assert report_drift.warning_codes_removed == ["LOW_LIVENESS"]

        # Missing local / remote
        report_missing = SessionReconciliationReport(
            session_id="sess_missing",
            local_missing=True,
        )
        assert report_missing.is_in_sync is False
        assert report_missing.local_missing is True

        batch = BatchReconciliationReport(
            total_evaluated=2,
            drift_count=1,
            missing_local_count=1,
            reports=[report_drift, report_missing],
        )
        assert batch.total_evaluated == 2
        assert batch.drift_count == 1
        assert len(batch.reports) == 2

    def test_session_state_source_protocol_conformance(self) -> None:
        from didit.models.session import (
            AsyncSessionStateSource,
            ObservedSessionState,
            SessionStateSource,
        )

        class CustomSyncSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        class CustomAsyncSource:
            async def aget(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        assert isinstance(CustomSyncSource(), SessionStateSource)
        assert isinstance(CustomAsyncSource(), AsyncSessionStateSource)
