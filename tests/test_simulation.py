"""Tests for in-memory simulated client."""

import json
from datetime import datetime, timezone

import pytest

from didit.errors import DiditAPIError, DiditNotFoundError
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

    def test_simulation_generate_pdf_report(self) -> None:
        client = SimulatedDidit()
        s = client.sessions.create(vendor_data="pdf_sim_sync", workflow_id="wf")
        pdf = client.sessions.generate_pdf_report(s.session_id)
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF-")
        assert client.sessions.get_pdf_report(s.session_id) == pdf

        with pytest.raises(DiditNotFoundError):
            client.sessions.generate_pdf_report("nonexistent_session")

        with pytest.raises(ValueError, match="session_id must not be empty"):
            client.sessions.generate_pdf_report("")


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

    def test_simulation_biometrics_0_to_100_scale(self) -> None:
        client = SimulatedDidit()
        session = client.sessions.create(vendor_data="u_scale", workflow_id="wf")
        decision = client.approve_session(session.session_id)
        assert decision.biometrics is not None
        assert decision.biometrics.score == 99.0
        assert decision.liveness_checks[0].score == 99.0
        assert decision.face_matches[0].score == 99.0

    @pytest.mark.parametrize(
        ("scenario", "expected_status", "expected_warning_code"),
        [
            ("approve", SessionStatus.APPROVED, None),
            ("decline_document_expired", SessionStatus.DECLINED, "DOCUMENT_EXPIRED"),
            (
                "decline_could_not_recognize_document",
                SessionStatus.DECLINED,
                "COULD_NOT_RECOGNIZE_DOCUMENT",
            ),
            ("decline_mrz_validation", SessionStatus.DECLINED, "MRZ_VALIDATION_FAILED"),
            ("decline_minimum_age", SessionStatus.DECLINED, "MINIMUM_AGE_NOT_MET"),
            (
                "decline_face_match_low_similarity",
                SessionStatus.DECLINED,
                "LOW_FACE_MATCH_SIMILARITY",
            ),
            ("decline_liveness_attack", SessionStatus.DECLINED, "LIVENESS_FACE_ATTACK"),
            ("decline_aml_hit", SessionStatus.DECLINED, "AML_MATCH_CONFIRMED"),
            ("decline_ip_blocklist", SessionStatus.DECLINED, "IP_ADDRESS_IN_BLOCKLIST"),
            ("decline_poa_address_mismatch", SessionStatus.DECLINED, "POA_ADDRESS_MISMATCH"),
            ("decline_nfc_chip_not_verified", SessionStatus.DECLINED, "NFC_CHIP_FAILED"),
            ("decline_database_no_match", SessionStatus.DECLINED, "DATABASE_NO_MATCH"),
            ("review_aml_possible_match", SessionStatus.IN_REVIEW, "POSSIBLE_MATCH_FOUND"),
            ("review_face_match_borderline", SessionStatus.IN_REVIEW, "LOW_FACE_MATCH_SIMILARITY"),
            ("review_poa_partial_match", SessionStatus.IN_REVIEW, "POA_PARTIAL_MATCH"),
            ("decline_kyb_registry_mismatch", SessionStatus.DECLINED, "REGISTRY_MISMATCH"),
        ],
    )
    def test_sandbox_scenarios(
        self,
        scenario: str,
        expected_status: SessionStatus,
        expected_warning_code: str | None,
    ) -> None:
        client = SimulatedDidit()
        session = client.sessions.create(
            vendor_data="custom_user",
            workflow_id="wf_sandbox",
            sandbox_scenario=scenario,
        )
        assert session.status == expected_status
        decision = client.sessions.get_decision(session.session_id)
        assert decision.status == expected_status

        if expected_warning_code:
            assert decision.has_warning(expected_warning_code) is True
            assert expected_warning_code in decision.warning_codes

    def test_sandbox_scenario_via_vendor_data(self) -> None:
        client = SimulatedDidit()
        session = client.sessions.create(
            vendor_data="decline_document_expired",
            workflow_id="wf_sandbox",
        )
        assert session.status == SessionStatus.DECLINED
        decision = client.sessions.get_decision(session.session_id)
        assert decision.status == SessionStatus.DECLINED
        assert decision.has_warning("DOCUMENT_EXPIRED") is True

    def test_invalid_sandbox_scenario_raises(self) -> None:
        from didit.errors import DiditConfigurationError

        client = SimulatedDidit()
        with pytest.raises(DiditConfigurationError, match="Unsupported sandbox scenario"):
            client.sessions.create(
                vendor_data="user_err",
                workflow_id="wf",
                sandbox_scenario="invalid_scenario_slug",
            )

    @pytest.mark.asyncio
    async def test_async_sandbox_scenario(self) -> None:
        client = SimulatedAsyncDidit()
        session = await client.sessions.create(
            vendor_data="user_async_sb",
            workflow_id="wf",
            sandbox_scenario="review_aml_possible_match",
        )
        assert session.status == SessionStatus.IN_REVIEW
        decision = await client.sessions.get_decision(session.session_id)
        assert decision.status == SessionStatus.IN_REVIEW
        assert decision.has_warning("POSSIBLE_MATCH_FOUND") is True

    def test_simulation_list_and_reconcile(self) -> None:
        from didit.models.session import ObservedSessionState

        client = SimulatedDidit()
        s1 = client.sessions.create(vendor_data="u1", workflow_id="wf", sandbox_scenario="approve")
        s2 = client.sessions.create(
            vendor_data="u2", workflow_id="wf", sandbox_scenario="decline_document_expired"
        )

        page = client.sessions.list(workflow_id="wf", limit=10)
        assert page.count == 2
        assert len(page.results) == 2

        # Test filters with no matches
        assert client.sessions.list(status=SessionStatus.EXPIRED).count == 0
        assert client.sessions.list(vendor_data="non_existent").count == 0
        assert client.sessions.list(workflow_id="other_wf").count == 0

        # Reconcile single in sync
        rep1 = client.sessions.reconcile(
            s1.session_id,
            observed=ObservedSessionState(session_id=s1.session_id, status=SessionStatus.APPROVED),
        )
        assert rep1.is_in_sync is True

        # Reconcile single drift
        rep2 = client.sessions.reconcile(
            s2.session_id,
            observed=ObservedSessionState(session_id=s2.session_id, status=SessionStatus.IN_REVIEW),
        )
        assert rep2.status_drift is True
        assert rep2.warning_codes_added == ["DOCUMENT_EXPIRED"]

        # Reconcile 404 (non-existent session)
        rep_404 = client.sessions.reconcile(
            "sess_non_existent",
            observed=ObservedSessionState(
                session_id="sess_non_existent", status=SessionStatus.APPROVED
            ),
        )
        assert rep_404.remote_missing is True

        # Reconcile observed is None
        rep_no_local = client.sessions.reconcile(s1.session_id, observed=None)
        assert rep_no_local.local_missing is True

        # Reconcile range batch
        s3 = client.sessions.create(vendor_data="u3", workflow_id="wf", sandbox_scenario="approve")
        del client._storage.decisions[s3.session_id]

        class SimSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                if session_id == s1.session_id:
                    return ObservedSessionState(
                        session_id=s1.session_id, status=SessionStatus.APPROVED
                    )
                if session_id == s2.session_id:
                    return None
                return ObservedSessionState(session_id=s3.session_id, status=SessionStatus.APPROVED)

        batch = client.sessions.reconcile_range(source=SimSource())
        assert batch.total_evaluated == 3
        assert batch.missing_local_count == 1
        assert batch.missing_remote_count == 1

    @pytest.mark.asyncio
    async def test_async_simulation_list_and_reconcile(self) -> None:
        from didit.models.session import ObservedSessionState

        client = SimulatedAsyncDidit()
        s1 = await client.sessions.create(
            vendor_data="u_async_1", workflow_id="wf", sandbox_scenario="approve"
        )
        s2 = await client.sessions.create(
            vendor_data="u_async_2", workflow_id="wf", sandbox_scenario="decline_document_expired"
        )
        s3 = await client.sessions.create(
            vendor_data="u_async_3", workflow_id="wf", sandbox_scenario="approve"
        )
        del client._storage.decisions[s3.session_id]

        page = await client.sessions.list(vendor_data="u_async_1")
        assert page.count == 1
        assert page.results[0].session_id == s1.session_id

        rep = await client.sessions.reconcile(
            s1.session_id,
            observed=ObservedSessionState(session_id=s1.session_id, status=SessionStatus.APPROVED),
        )
        assert rep.is_in_sync is True

        # Reconcile 404 and observed=None in async
        rep_async_404 = await client.sessions.reconcile(
            "sess_non_existent",
            observed=ObservedSessionState(
                session_id="sess_non_existent", status=SessionStatus.APPROVED
            ),
        )
        assert rep_async_404.remote_missing is True

        rep_async_no_local = await client.sessions.reconcile(s1.session_id, observed=None)
        assert rep_async_no_local.local_missing is True

        class AsyncSource:
            async def aget(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        batch = await client.sessions.reconcile_range(source=AsyncSource())
        assert batch.total_evaluated == 3

        # Test sync source with .get() in async reconcile_range
        class AsyncSimSyncSource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                if session_id == s1.session_id:
                    return ObservedSessionState(
                        session_id=s1.session_id, status=SessionStatus.APPROVED
                    )
                if session_id == s2.session_id:
                    return ObservedSessionState(
                        session_id=s2.session_id, status=SessionStatus.IN_REVIEW
                    )
                return None

        batch_sync = await client.sessions.reconcile_range(source=AsyncSimSyncSource())
        assert batch_sync.drift_count >= 1
        assert batch_sync.missing_local_count >= 1
        assert batch_sync.missing_remote_count >= 1

        # Test async source with coroutine get()
        class AsyncSimCoroSource:
            async def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        batch_coro = await client.sessions.reconcile_range(source=AsyncSimCoroSource())
        assert batch_coro.total_evaluated == 3

    def test_simulation_list_filters_and_validations(self) -> None:
        client = SimulatedDidit()
        # session_kind != "user" raises ValueError matching real API validation parity
        with pytest.raises(ValueError, match="Unsupported session_kind 'business'"):
            client.sessions.list(session_kind="business")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="Unsupported session_kind 'None'"):
            client.sessions.list(session_kind=None)  # type: ignore[arg-type]

        # Shared validation parity checks
        with pytest.raises(ValueError, match="limit must be between 1 and 100"):
            client.sessions.list(limit=0)
        with pytest.raises(ValueError, match="offset must be non-negative"):
            client.sessions.list(offset=-1)
        with pytest.raises(ValueError, match="Expected 3-letter ISO 3166-1 alpha-3 code"):
            client.sessions.list(country="ES")
        with pytest.raises(ValueError, match="must be timezone-aware"):
            client.sessions.list(date_from=datetime(2026, 1, 1))

        # Create session with decision containing country
        s = client.sessions.create(
            vendor_data="user_es", workflow_id="wf", sandbox_scenario="approve"
        )

        # Test datetime vs str date_from / date_to
        now = datetime.now(timezone.utc)
        assert client.sessions.list(date_from=now).count <= 1
        assert client.sessions.list(date_from=now.isoformat()).count <= 1
        assert client.sessions.list(date_to=now).count >= 0
        assert client.sessions.list(date_to=now.isoformat()).count >= 0

        # Test future date_from and past date_to
        future_dt = datetime(2099, 1, 1, tzinfo=timezone.utc)
        past_dt = datetime(2000, 1, 1, tzinfo=timezone.utc)
        assert client.sessions.list(date_from=future_dt).count == 0
        assert client.sessions.list(date_to=past_dt).count == 0

        # Search matching vendor_data and session_id
        assert client.sessions.list(search="user_es").count == 1
        assert client.sessions.list(search=s.session_id[:8]).count == 1
        assert client.sessions.list(search="nonexistent_query").count == 0

        # Country filter
        assert client.sessions.list(country="ESP").count == 1
        assert client.sessions.list(country="FRA").count == 0

    def test_simulation_reconcile_and_range_edge_cases(self) -> None:
        from didit.models.session import ObservedSessionState

        client = SimulatedDidit()
        s = client.sessions.create(vendor_data="u1", workflow_id="wf", sandbox_scenario="approve")

        # Session mismatch error
        with pytest.raises(ValueError, match="session_id mismatch"):
            client.sessions.reconcile(
                s.session_id,
                observed=ObservedSessionState(session_id="wrong_id", status=SessionStatus.APPROVED),
            )

        class DummySource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                if session_id == s.session_id:
                    return ObservedSessionState(
                        session_id=session_id, status=SessionStatus.DECLINED
                    )
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        # Range conflict parameter errors
        with pytest.raises(ValueError, match="Specify either 'since' or 'date_from'"):
            client.sessions.reconcile_range(
                source=DummySource(), since="2026-01-01T00:00:00Z", date_from="2026-01-01T00:00:00Z"
            )
        with pytest.raises(ValueError, match="Specify either 'until' or 'date_to'"):
            client.sessions.reconcile_range(
                source=DummySource(), until="2026-01-02T00:00:00Z", date_to="2026-01-02T00:00:00Z"
            )
        with pytest.raises(ValueError, match="page_size must be between 1 and 100"):
            client.sessions.reconcile_range(source=DummySource(), page_size=0)
        with pytest.raises(ValueError, match="max_sessions must be greater than 0"):
            client.sessions.reconcile_range(source=DummySource(), max_sessions=0)

        # Range max_sessions cap and v3 URL verification
        for i in range(5):
            client.sessions.create(
                vendor_data=f"multi_{i}", workflow_id="wf", sandbox_scenario="approve"
            )

        page = client.sessions.list(limit=2)
        assert page.count == 6
        assert page.next == "https://verification.didit.me/v3/sessions/?offset=2&limit=2"
        assert page.previous is None

        cap_report = client.sessions.reconcile_range(source=DummySource(), max_sessions=2)
        assert cap_report.total_evaluated == 2
        assert cap_report.truncated is True
        assert cap_report.remote_count == 6

        full_report = client.sessions.reconcile_range(source=DummySource(), page_size=2)
        assert full_report.total_evaluated == 6
        assert full_report.truncated is False
        assert full_report.remote_count == 6

        # Multi-page pagination in reconcile_range (page_size=2)
        paginated_report = client.sessions.reconcile_range(source=DummySource(), page_size=2)
        assert paginated_report.total_evaluated == 6

        # Empty client reconcile_range
        empty_client = SimulatedDidit()
        empty_report = empty_client.sessions.reconcile_range(source=DummySource())
        assert empty_report.total_evaluated == 0

    @pytest.mark.asyncio
    async def test_async_simulation_reconcile_and_range_edge_cases(self) -> None:
        from didit.models.session import ObservedSessionState

        client = SimulatedAsyncDidit()
        s = await client.sessions.create(
            vendor_data="u_async_edges", workflow_id="wf", sandbox_scenario="approve"
        )

        # Session mismatch error
        with pytest.raises(ValueError, match="session_id mismatch"):
            await client.sessions.reconcile(
                s.session_id,
                observed=ObservedSessionState(session_id="wrong_id", status=SessionStatus.APPROVED),
            )

        class DummyAsyncSource:
            async def aget(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        # Range conflict parameter errors
        with pytest.raises(ValueError, match="Specify either 'since' or 'date_from'"):
            await client.sessions.reconcile_range(
                source=DummyAsyncSource(),
                since="2026-01-01T00:00:00Z",
                date_from="2026-01-01T00:00:00Z",
            )
        with pytest.raises(ValueError, match="Specify either 'until' or 'date_to'"):
            await client.sessions.reconcile_range(
                source=DummyAsyncSource(),
                until="2026-01-02T00:00:00Z",
                date_to="2026-01-02T00:00:00Z",
            )
        with pytest.raises(ValueError, match="page_size must be between 1 and 100"):
            await client.sessions.reconcile_range(source=DummyAsyncSource(), page_size=0)
        with pytest.raises(ValueError, match="max_sessions must be greater than 0"):
            await client.sessions.reconcile_range(source=DummyAsyncSource(), max_sessions=0)

        # Range max_sessions cap
        for i in range(5):
            await client.sessions.create(
                vendor_data=f"multi_async_{i}", workflow_id="wf", sandbox_scenario="approve"
            )

        cap_report = await client.sessions.reconcile_range(
            source=DummyAsyncSource(), max_sessions=2
        )
        assert cap_report.total_evaluated == 2

        # Multi-page pagination in reconcile_range (page_size=2)
        paginated_report = await client.sessions.reconcile_range(
            source=DummyAsyncSource(), page_size=2
        )
        assert paginated_report.total_evaluated == 6

        # Empty client reconcile_range
        empty_client = SimulatedAsyncDidit()
        empty_report = await empty_client.sessions.reconcile_range(source=DummyAsyncSource())
        assert empty_report.total_evaluated == 0

    def test_simulation_reconcile_range_inconsistent_pagination_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from didit.models.session import ObservedSessionState, SessionListPage

        client = SimulatedDidit()

        class DummySource:
            def get(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        # 1. Empty results with next != None
        monkeypatch.setattr(
            client.sessions,
            "list",
            lambda **kwargs: SessionListPage(
                count=10, next="https://test/next", previous=None, results=[]
            ),
        )
        with pytest.raises(
            DiditAPIError,
            match="Didit pagination returned next page metadata without progress",
        ) as exc_info:
            client.sessions.reconcile_range(source=DummySource())
        assert exc_info.value.status_code == 502

        # 2. Empty results with next == None and offset < page.count
        monkeypatch.setattr(
            client.sessions,
            "list",
            lambda **kwargs: SessionListPage(count=10, next=None, previous=None, results=[]),
        )
        with pytest.raises(
            DiditAPIError,
            match="Inconsistent pagination metadata: received 0 of 10 sessions without next page",
        ) as exc_info:
            client.sessions.reconcile_range(source=DummySource())
        assert exc_info.value.status_code == 502

        # 3. Non-empty results with next == None and offset < page.count
        from didit.models.session import SessionListItem

        s = client.sessions.create(vendor_data="incon", workflow_id="wf")
        item = SessionListItem(session_id=s.session_id, status=SessionStatus.APPROVED)
        monkeypatch.setattr(
            client.sessions,
            "list",
            lambda **kwargs: SessionListPage(count=10, next=None, previous=None, results=[item]),
        )
        with pytest.raises(
            DiditAPIError,
            match="Inconsistent pagination metadata: received 1 of 10 sessions without next page",
        ) as exc_info:
            client.sessions.reconcile_range(source=DummySource())
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_async_simulation_reconcile_range_inconsistent_pagination_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typing import Any

        from didit.models.session import ObservedSessionState, SessionListPage

        client = SimulatedAsyncDidit()

        class DummyAsyncSource:
            async def aget(self, session_id: str) -> ObservedSessionState | None:
                return ObservedSessionState(session_id=session_id, status=SessionStatus.APPROVED)

        # 1. Empty results with next != None
        async def mock_list_1(**kwargs: Any) -> SessionListPage:
            return SessionListPage(count=10, next="https://test/next", previous=None, results=[])

        monkeypatch.setattr(client.sessions, "list", mock_list_1)
        with pytest.raises(
            DiditAPIError,
            match="Didit pagination returned next page metadata without progress",
        ) as exc_info:
            await client.sessions.reconcile_range(source=DummyAsyncSource())
        assert exc_info.value.status_code == 502

        # 2. Empty results with next == None and offset < page.count
        async def mock_list_2(**kwargs: Any) -> SessionListPage:
            return SessionListPage(count=10, next=None, previous=None, results=[])

        monkeypatch.setattr(client.sessions, "list", mock_list_2)
        with pytest.raises(
            DiditAPIError,
            match="Inconsistent pagination metadata: received 0 of 10 sessions without next page",
        ) as exc_info:
            await client.sessions.reconcile_range(source=DummyAsyncSource())
        assert exc_info.value.status_code == 502

        # 3. Non-empty results with next == None and offset < page.count
        from didit.models.session import SessionListItem

        s = await client.sessions.create(vendor_data="incon_async", workflow_id="wf")
        item = SessionListItem(session_id=s.session_id, status=SessionStatus.APPROVED)

        async def mock_list_3(**kwargs: Any) -> SessionListPage:
            return SessionListPage(count=10, next=None, previous=None, results=[item])

        monkeypatch.setattr(client.sessions, "list", mock_list_3)
        with pytest.raises(
            DiditAPIError,
            match="Inconsistent pagination metadata: received 1 of 10 sessions without next page",
        ) as exc_info:
            await client.sessions.reconcile_range(source=DummyAsyncSource())
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_async_simulation_generate_pdf_report(self) -> None:
        client = SimulatedAsyncDidit()
        s = await client.sessions.create(vendor_data="pdf_sim_async", workflow_id="wf")
        pdf = await client.sessions.generate_pdf_report(s.session_id)
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF-")
        assert await client.sessions.get_pdf_report(s.session_id) == pdf

        with pytest.raises(DiditNotFoundError):
            await client.sessions.generate_pdf_report("nonexistent_session")

        with pytest.raises(ValueError, match="session_id must not be empty"):
            await client.sessions.generate_pdf_report("")
