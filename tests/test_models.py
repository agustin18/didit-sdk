"""Tests for Pydantic data models and enums."""

import pytest
from pydantic import ValidationError

from didit.models.decision import (
    DecisionResponse,
)
from didit.models.enums import Language, SessionStatus
from didit.models.session import CreateSessionRequest, SessionResponse
from didit.models.webhook import WebhookPayload


class TestSessionStatus:
    @pytest.mark.parametrize(
        ("status", "is_terminal"),
        [
            (SessionStatus.NOT_STARTED, False),
            (SessionStatus.IN_PROGRESS, False),
            (SessionStatus.IN_REVIEW, False),
            (SessionStatus.APPROVED, True),
            (SessionStatus.DECLINED, True),
        ],
    )
    def test_terminal_property(self, status: SessionStatus, is_terminal: bool) -> None:
        assert status.is_terminal is is_terminal
        assert status.is_in_review is (status == SessionStatus.IN_REVIEW)

    def test_status_string_equivalence(self) -> None:
        assert SessionStatus.APPROVED == "Approved"
        assert SessionStatus.DECLINED == "Declined"
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


class TestWebhookPayload:
    def test_parse_webhook_payload(self) -> None:
        raw = {
            "session_id": "sess_webhook",
            "status": "Approved",
            "created_at": 1727630000,
            "workflow_id": "wf_123",
            "vendor_data": "user_789",
            "decision": {
                "session_id": "sess_webhook",
                "status": "Approved",
            },
        }
        wh = WebhookPayload.model_validate(raw)
        assert wh.session_id == "sess_webhook"
        assert wh.status == SessionStatus.APPROVED
        assert wh.created_at == 1727630000
        assert wh.decision is not None
        assert wh.decision.status == SessionStatus.APPROVED
