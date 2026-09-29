"""Tests for in-memory simulated client."""

import json

import pytest

from didit.errors import DiditNotFoundError
from didit.models.decision import DocumentData
from didit.models.enums import SessionStatus
from didit.simulation import SimulatedAsyncDidit, SimulatedDidit
from didit.webhooks import verify_webhook_signature


class TestSimulatedDidit:
    def test_sync_simulation_lifecycle(self) -> None:
        client = SimulatedDidit(webhook_secret="whsec_sim")

        # 1. Create session
        session = client.sessions.create(
            vendor_data="user_sim_1",
            workflow_id="wf_sim",
            callback="https://example.com/callback",
        )
        assert session.session_id.startswith("sim_")
        assert session.status == SessionStatus.NOT_STARTED
        assert session.vendor_data == "user_sim_1"
        assert session.workflow_id == "wf_sim"

        # 2. Get session
        fetched = client.sessions.get(session.session_id)
        assert fetched.session_id == session.session_id
        assert fetched.status == SessionStatus.NOT_STARTED

        # 3. Decision before completion is in progress or not started
        decision = client.sessions.get_decision(session.session_id)
        assert decision.session_id == session.session_id
        assert decision.status == SessionStatus.NOT_STARTED

        # 4. Approve session
        doc = DocumentData(document_type="passport", document_number="P1234567")
        approved_decision = client.approve_session(session.session_id, document=doc)
        assert approved_decision.status == SessionStatus.APPROVED
        assert approved_decision.document is not None
        assert approved_decision.document.document_number == "P1234567"

        # Check get_decision reflects approval
        latest_decision = client.sessions.get_decision(session.session_id)
        assert latest_decision.status == SessionStatus.APPROVED

        # 5. Generate signed webhook for testing external receivers
        raw_body, headers = client.generate_webhook_event(session.session_id)
        assert "x-signature-v2" in headers or "X-Signature-V2" in headers
        assert verify_webhook_signature(raw_body, headers, "whsec_sim") is True

    def test_approve_session_custom_fields(self) -> None:
        from didit.models.decision import AMLData, BiometricsData, ReviewData

        client = SimulatedDidit()
        session = client.sessions.create(vendor_data="u_custom", workflow_id="wf")

        bio = BiometricsData(face_match=False, liveness_check=False, score=0.1)
        aml = AMLData(pep_detected=True, sanctions_detected=False, adverse_media_detected=False)
        review = ReviewData(reviewed_by="manual_agent", decision_reason="Flagged for manual review")

        decision = client.approve_session(
            session.session_id,
            biometrics=bio,
            aml=aml,
            review=review,
        )
        assert decision.status == SessionStatus.APPROVED
        assert len(decision.id_verifications) == 1
        assert decision.id_verifications[0].status == "Approved"
        assert len(decision.liveness_checks) == 1
        assert decision.liveness_checks[0].status == "Declined"
        assert decision.liveness_checks[0].score == 0.1
        assert len(decision.face_matches) == 1
        assert decision.face_matches[0].status == "Declined"
        assert decision.face_matches[0].score == 0.1
        assert len(decision.aml_screenings) == 1
        assert decision.aml_screenings[0].status == "Declined"
        assert len(decision.reviews) == 1
        assert decision.reviews[0].reviewed_by == "manual_agent"

    def test_decline_session(self) -> None:
        client = SimulatedDidit(webhook_secret="whsec_sim")
        session = client.sessions.create(vendor_data="user_declined", workflow_id="wf_sim")

        declined = client.decline_session(session.session_id, reason="Document expired or forged")
        assert declined.status == SessionStatus.DECLINED
        assert declined.review is not None
        assert declined.review.decision_reason == "Document expired or forged"

    def test_poll_decision_in_simulation(self) -> None:
        from didit.errors import DiditTimeoutError

        client = SimulatedDidit()
        session = client.sessions.create(vendor_data="u_poll", workflow_id="wf")
        # Pending session raises DiditTimeoutError on polling
        with pytest.raises(DiditTimeoutError, match="without terminal outcome"):
            client.sessions.poll_decision(session.session_id, timeout=0.01)

        client.approve_session(session.session_id)
        polled = client.sessions.poll_decision(session.session_id)
        assert polled.status == SessionStatus.APPROVED

    def test_not_found_session(self) -> None:
        client = SimulatedDidit(webhook_secret="whsec_sim")
        with pytest.raises(DiditNotFoundError):
            client.sessions.get("sim_non_existent")
        with pytest.raises(DiditNotFoundError):
            client.sessions.get_decision("sim_non_existent")
        with pytest.raises(DiditNotFoundError):
            client.approve_session("sim_non_existent")
        with pytest.raises(DiditNotFoundError):
            client.decline_session("sim_non_existent")
        with pytest.raises(DiditNotFoundError):
            client.generate_webhook_event("sim_non_existent")

    def test_generate_webhook_missing_secret(self) -> None:
        from didit.errors import DiditConfigurationError

        client = SimulatedDidit(webhook_secret=None)
        session = client.sessions.create(vendor_data="user_1", workflow_id="wf_1")
        with pytest.raises(DiditConfigurationError):
            client.generate_webhook_event(session.session_id)

    def test_simulation_state_immutability(self) -> None:
        client = SimulatedDidit()
        session = client.sessions.create(vendor_data="u1", workflow_id="wf1")
        session.status = SessionStatus.DECLINED
        assert client.sessions.get(session.session_id).status == SessionStatus.NOT_STARTED

    def test_generate_webhook_event_contains_v3_fields(self) -> None:
        client = SimulatedDidit(webhook_secret="whsec_v3")
        session = client.sessions.create(vendor_data="u1", workflow_id="wf1")
        client.approve_session(session.session_id)
        raw, headers = client.generate_webhook_event(session.session_id)
        parsed = json.loads(raw.decode("utf-8"))
        assert "timestamp" in parsed
        assert "event_id" in parsed
        assert parsed["event_id"].startswith("evt_")
        assert parsed["webhook_type"] == "status.updated"
        assert headers["X-Timestamp"] == str(parsed["timestamp"])


class TestSimulatedAsyncDidit:
    async def test_async_simulation_lifecycle(self) -> None:
        client = SimulatedAsyncDidit(webhook_secret="whsec_sim_async")

        session = await client.sessions.create(
            vendor_data="user_sim_async",
            workflow_id="wf_sim_async",
        )
        assert session.session_id.startswith("sim_")
        assert session.status == SessionStatus.NOT_STARTED

        fetched = await client.sessions.get(session.session_id)
        assert fetched.session_id == session.session_id

        decision = await client.sessions.get_decision(session.session_id)
        assert decision.status == SessionStatus.NOT_STARTED

        client.approve_session(session.session_id)
        latest = await client.sessions.get_decision(session.session_id)
        assert latest.status == SessionStatus.APPROVED

        # Decline session in async client
        client.decline_session(session.session_id, reason="Declined in async")
        declined_decision = await client.sessions.get_decision(session.session_id)
        assert declined_decision.status == SessionStatus.DECLINED

        raw_body, headers = client.generate_webhook_event(session.session_id)
        assert verify_webhook_signature(raw_body, headers, "whsec_sim_async") is True

    async def test_async_generate_webhook_missing_secret(self) -> None:
        from didit.errors import DiditConfigurationError

        client = SimulatedAsyncDidit(webhook_secret=None)
        session = await client.sessions.create(vendor_data="u1", workflow_id="wf1")
        with pytest.raises(DiditConfigurationError):
            client.generate_webhook_event(session.session_id)

    async def test_async_poll_decision_in_simulation(self) -> None:
        from didit.errors import DiditTimeoutError

        client = SimulatedAsyncDidit()
        session = await client.sessions.create(vendor_data="u_async_poll", workflow_id="wf")
        with pytest.raises(DiditTimeoutError, match="without terminal outcome"):
            await client.sessions.poll_decision(session.session_id, timeout=0.01)

        client.approve_session(session.session_id)
        polled = await client.sessions.poll_decision(session.session_id)
        assert polled.status == SessionStatus.APPROVED
