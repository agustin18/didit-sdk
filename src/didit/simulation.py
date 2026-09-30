"""In-memory simulation client for offline testing and local development without credentials."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from didit.errors import (
    DiditConfigurationError,
    DiditNotFoundError,
    DiditTimeoutError,
)
from didit.models.decision import (
    AMLData,
    AMLScreeningResult,
    BiometricsData,
    DecisionResponse,
    DocumentData,
    FaceMatchResult,
    IdVerificationResult,
    LivenessResult,
    ReviewData,
    VerificationWarning,
)
from didit.models.enums import Language, SessionStatus
from didit.models.session import (
    AsyncSessionStateSource,
    BatchReconciliationReport,
    ObservedSessionState,
    SessionListItem,
    SessionListPage,
    SessionReconciliationReport,
    SessionResponse,
    SessionStateSource,
)
from didit.webhooks import compute_signature

SUPPORTED_SANDBOX_SCENARIOS: set[str] = {
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
    "review_aml_possible_match",
    "review_face_match_borderline",
    "review_poa_partial_match",
    "decline_kyb_registry_mismatch",
}


class _SimulatedStorage:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionResponse] = {}
        self.decisions: dict[str, DecisionResponse] = {}
        self.created_at: dict[str, float] = {}

    def create(
        self,
        vendor_data: str,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
        sandbox_scenario: str | None = None,
    ) -> SessionResponse:
        if sandbox_scenario is not None and sandbox_scenario not in SUPPORTED_SANDBOX_SCENARIOS:
            raise DiditConfigurationError(
                f"Unsupported sandbox scenario '{sandbox_scenario}'. "
                f"Supported: {sorted(SUPPORTED_SANDBOX_SCENARIOS)}"
            )

        scenario = sandbox_scenario or (
            vendor_data if vendor_data in SUPPORTED_SANDBOX_SCENARIOS else None
        )

        session_id = f"sim_{uuid.uuid4().hex}"
        session = SessionResponse(
            session_id=session_id,
            session_token=f"tok_{session_id}",
            url=f"https://verify.didit.me/simulated/{session_id}",
            status=SessionStatus.NOT_STARTED,
            workflow_id=workflow_id,
            vendor_data=vendor_data,
            callback=callback,
        )
        decision = DecisionResponse(
            session_id=session_id,
            status=SessionStatus.NOT_STARTED,
            workflow_id=workflow_id,
            vendor_data=vendor_data,
        )
        self.sessions[session_id] = session
        self.decisions[session_id] = decision
        self.created_at[session_id] = datetime.now(timezone.utc).timestamp()

        if scenario == "approve":
            self.approve(session_id)
        elif scenario == "decline_document_expired":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="DOCUMENT_EXPIRED",
                message="Document has expired",
                severity="high",
            )
            decision.id_verifications = [
                IdVerificationResult(
                    document_type="passport",
                    status="Declined",
                    country="ESP",
                    expiration_date="2020-01-01",
                    warnings=[warn],
                )
            ]
            decision.warnings = [warn]
            decision.reviews = [
                ReviewData(reviewed_by="system", decision_reason="Document expired")
            ]
        elif scenario == "decline_could_not_recognize_document":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="COULD_NOT_RECOGNIZE_DOCUMENT",
                message="Document could not be recognized",
                severity="high",
            )
            decision.id_verifications = [IdVerificationResult(status="Declined", warnings=[warn])]
            decision.warnings = [warn]
        elif scenario == "decline_mrz_validation":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="MRZ_VALIDATION_FAILED",
                message="MRZ checksum validation failed",
                severity="high",
            )
            decision.id_verifications = [IdVerificationResult(status="Declined", warnings=[warn])]
            decision.warnings = [warn]
        elif scenario == "decline_minimum_age":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="MINIMUM_AGE_NOT_MET",
                message="Minimum age requirement not met",
                severity="high",
            )
            decision.id_verifications = [
                IdVerificationResult(status="Declined", date_of_birth="2015-01-01", warnings=[warn])
            ]
            decision.warnings = [warn]
        elif scenario == "decline_face_match_low_similarity":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="LOW_FACE_MATCH_SIMILARITY",
                message="Facial biometric similarity below threshold",
                severity="high",
            )
            decision.face_matches = [
                FaceMatchResult(status="Declined", score=15.0, warnings=[warn])
            ]
            decision.warnings = [warn]
            decision.reviews = [ReviewData(reviewed_by="system", decision_reason="Face mismatch")]
        elif scenario == "decline_liveness_attack":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="LIVENESS_FACE_ATTACK",
                message="Liveness spoof presentation attack detected",
                severity="critical",
            )
            decision.liveness_checks = [
                LivenessResult(status="Declined", score=5.0, warnings=[warn])
            ]
            decision.warnings = [warn]
        elif scenario == "decline_aml_hit":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="AML_MATCH_CONFIRMED",
                message="Confirmed match on sanctions list",
                severity="critical",
            )
            decision.aml_screenings = [
                AMLScreeningResult(
                    status="Declined",
                    pep_detected=True,
                    sanctions_detected=True,
                    warnings=[warn],
                )
            ]
            decision.warnings = [warn]
            decision.reviews = [
                ReviewData(reviewed_by="system", decision_reason="AML screening match")
            ]
        elif scenario == "decline_ip_blocklist":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="IP_ADDRESS_IN_BLOCKLIST",
                message="Client IP address flagged on security blocklist",
                severity="high",
            )
            decision.ip_analyses = [{"status": "Declined", "risk_level": "high"}]
            decision.warnings = [warn]
        elif scenario == "decline_poa_address_mismatch":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="POA_ADDRESS_MISMATCH",
                message="Proof of address does not match provided address",
                severity="high",
            )
            decision.poa_verifications = [{"status": "Declined"}]
            decision.warnings = [warn]
        elif scenario == "decline_nfc_chip_not_verified":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="NFC_CHIP_FAILED",
                message="NFC chip cryptographic authentication failed",
                severity="high",
            )
            decision.nfc_verifications = [{"status": "Declined", "chip_authenticated": False}]
            decision.warnings = [warn]
        elif scenario == "decline_database_no_match":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="DATABASE_NO_MATCH",
                message="No record found in authoritative database",
                severity="high",
            )
            decision.database_validations = [{"status": "Declined"}]
            decision.warnings = [warn]
        elif scenario == "review_aml_possible_match":
            session.status = SessionStatus.IN_REVIEW
            decision.status = SessionStatus.IN_REVIEW
            warn = VerificationWarning(
                code="POSSIBLE_MATCH_FOUND",
                message="Potential name match on AML watchlist",
                severity="medium",
            )
            decision.aml_screenings = [
                AMLScreeningResult(status="In Review", pep_detected=True, warnings=[warn])
            ]
            decision.warnings = [warn]
            decision.reviews = [
                ReviewData(
                    reviewed_by="compliance_lead",
                    decision_reason="Potential AML hit requires human analyst review",
                )
            ]
        elif scenario == "review_face_match_borderline":
            session.status = SessionStatus.IN_REVIEW
            decision.status = SessionStatus.IN_REVIEW
            warn = VerificationWarning(
                code="LOW_FACE_MATCH_SIMILARITY",
                message="Borderline facial similarity score",
                severity="medium",
            )
            decision.face_matches = [
                FaceMatchResult(status="In Review", score=68.0, warnings=[warn])
            ]
            decision.warnings = [warn]
            decision.reviews = [
                ReviewData(
                    reviewed_by="fraud_engine",
                    decision_reason="Borderline face match requires manual inspection",
                )
            ]
        elif scenario == "review_poa_partial_match":
            session.status = SessionStatus.IN_REVIEW
            decision.status = SessionStatus.IN_REVIEW
            warn = VerificationWarning(
                code="POA_PARTIAL_MATCH",
                message="Proof of address partially matches profile",
                severity="medium",
            )
            decision.poa_verifications = [{"status": "In Review"}]
            decision.warnings = [warn]
        elif scenario == "decline_kyb_registry_mismatch":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="REGISTRY_MISMATCH",
                message="Company registry data mismatch",
                severity="high",
            )
            decision.warnings = [warn]

        return session.model_copy(deep=True)

    def get(self, session_id: str) -> SessionResponse:
        if session_id not in self.sessions:
            raise DiditNotFoundError(f"Simulated session '{session_id}' not found", status_code=404)
        return self.sessions[session_id].model_copy(deep=True)

    def get_decision(self, session_id: str) -> DecisionResponse:
        if session_id not in self.decisions:
            raise DiditNotFoundError(f"Simulated session '{session_id}' not found", status_code=404)
        return self.decisions[session_id].model_copy(deep=True)

    def approve(
        self,
        session_id: str,
        *,
        document: DocumentData | None = None,
        biometrics: BiometricsData | None = None,
        aml: AMLData | None = None,
        review: ReviewData | None = None,
    ) -> DecisionResponse:
        if session_id not in self.sessions:
            raise DiditNotFoundError(f"Simulated session '{session_id}' not found", status_code=404)
        session = self.sessions[session_id]
        decision = self.decisions[session_id]

        session.status = SessionStatus.APPROVED
        decision.status = SessionStatus.APPROVED

        doc = document or DocumentData(
            document_type="passport",
            document_number="SIM12345678",
            country="ESP",
            is_valid=True,
        )
        bio = biometrics or BiometricsData(face_match=True, liveness_check=True, score=99.0)
        aml_data = aml or AMLData(
            pep_detected=False, sanctions_detected=False, adverse_media_detected=False
        )

        id_verif = IdVerificationResult(
            document_type=doc.document_type,
            document_number=doc.document_number,
            country=doc.country,
            first_name=doc.first_name,
            last_name=doc.last_name,
            date_of_birth=doc.date_of_birth,
            expiration_date=doc.expiration_date,
            status="Approved" if doc.is_valid is not False else "Declined",
        )
        decision.id_verifications = [id_verif]

        liveness = LivenessResult(
            status="Approved" if bio.liveness_check is not False else "Declined",
            score=bio.score if bio.score is not None else (99.0 if bio.liveness_check else 0.0),
        )
        decision.liveness_checks = [liveness]

        face_match = FaceMatchResult(
            status="Approved" if bio.face_match is not False else "Declined",
            score=bio.score if bio.score is not None else (99.0 if bio.face_match else 0.0),
        )
        decision.face_matches = [face_match]

        is_aml_approved = not (
            aml_data.pep_detected or aml_data.sanctions_detected or aml_data.adverse_media_detected
        )
        aml_result = AMLScreeningResult(
            status="Approved" if is_aml_approved else "Declined",
            pep_detected=aml_data.pep_detected,
            sanctions_detected=aml_data.sanctions_detected,
            adverse_media_detected=aml_data.adverse_media_detected,
        )
        decision.aml_screenings = [aml_result]
        decision.reviews = [review] if review else []
        return decision.model_copy(deep=True)

    def decline(
        self,
        session_id: str,
        *,
        reason: str = "Verification failed by simulated policy",
    ) -> DecisionResponse:
        if session_id not in self.sessions:
            raise DiditNotFoundError(f"Simulated session '{session_id}' not found", status_code=404)
        session = self.sessions[session_id]
        decision = self.decisions[session_id]

        session.status = SessionStatus.DECLINED
        decision.status = SessionStatus.DECLINED
        decision.reviews = [ReviewData(reviewed_by="simulator", decision_reason=reason)]
        return decision.model_copy(deep=True)

    def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: str | None = "user",
        vendor_data: str | None = None,
        country: str | None = None,
        workflow_id: str | None = None,
        search: str | None = None,
        date_from: Any = None,
        date_to: Any = None,
        limit: int = 50,
        offset: int = 0,
    ) -> SessionListPage:
        if session_kind is not None and session_kind != "user":
            return SessionListPage(count=0, next=None, previous=None, results=[])

        status_filter = status.value if isinstance(status, SessionStatus) else status
        norm_country = country.strip().upper() if country is not None else None

        from_ts: float | None = None
        if date_from is not None:
            if isinstance(date_from, datetime):
                from_ts = date_from.timestamp()
            else:
                from_ts = datetime.fromisoformat(str(date_from).replace("Z", "+00:00")).timestamp()

        to_ts: float | None = None
        if date_to is not None:
            if isinstance(date_to, datetime):
                to_ts = date_to.timestamp()
            else:
                to_ts = datetime.fromisoformat(str(date_to).replace("Z", "+00:00")).timestamp()

        items: list[SessionListItem] = []
        for s in self.sessions.values():
            if status_filter is not None and s.status.value != status_filter:
                continue
            if vendor_data is not None and s.vendor_data != vendor_data:
                continue
            if workflow_id is not None and s.workflow_id != workflow_id:
                continue

            dec = self.decisions.get(s.session_id)
            s_country: str | None = None
            if dec and dec.id_verifications and dec.id_verifications[0].country:
                s_country = dec.id_verifications[0].country.upper()

            if norm_country is not None and s_country != norm_country:
                continue

            if search is not None:
                q = search.lower()
                v_text = s.vendor_data.lower() if s.vendor_data else ""
                if q not in s.session_id.lower() and q not in v_text:
                    continue

            s_created = self.created_at.get(s.session_id, 0.0)
            if from_ts is not None and s_created < from_ts - 0.1:
                continue
            if to_ts is not None and s_created > to_ts + 0.1:
                continue

            item = SessionListItem(
                session_id=s.session_id,
                session_token=s.session_token,
                url=s.url,
                status=s.status,
                workflow_id=s.workflow_id,
                vendor_data=s.vendor_data,
                callback=s.callback,
                country=s_country,
                session_kind=session_kind or "user",
                created_at=s_created,
            )
            items.append(item)

        total = len(items)
        sliced = items[offset : offset + limit]
        next_url = (
            f"https://api.didit.me/v1/sessions/?offset={offset + limit}&limit={limit}"
            if offset + limit < total
            else None
        )
        prev_url = (
            f"https://api.didit.me/v1/sessions/?offset={max(0, offset - limit)}&limit={limit}"
            if offset > 0
            else None
        )
        return SessionListPage(
            count=total,
            next=next_url,
            previous=prev_url,
            results=sliced,
        )


class SimulatedSessionsResource:
    """Synchronous in-memory sessions resource."""

    def __init__(self, storage: _SimulatedStorage) -> None:
        self._storage = storage

    def create(
        self,
        vendor_data: str,
        *,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
        sandbox_scenario: str | None = None,
    ) -> SessionResponse:
        return self._storage.create(
            vendor_data=vendor_data,
            workflow_id=workflow_id,
            callback=callback,
            language=language,
            sandbox_scenario=sandbox_scenario,
        )

    def get(self, session_id: str) -> SessionResponse:
        return self._storage.get(session_id)

    def get_decision(self, session_id: str) -> DecisionResponse:
        return self._storage.get_decision(session_id)

    def poll_decision(
        self,
        session_id: str,
        *,
        timeout: float = 60.0,
        interval: float = 2.0,
    ) -> DecisionResponse:
        decision = self.get_decision(session_id)
        if not decision.status.is_poll_complete:
            raise DiditTimeoutError(
                f"Polling simulated session '{session_id}' timed out without terminal outcome"
            )
        return decision

    def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: str | None = "user",
        vendor_data: str | None = None,
        country: str | None = None,
        workflow_id: str | None = None,
        search: str | None = None,
        date_from: Any = None,
        date_to: Any = None,
        limit: int = 50,
        offset: int = 0,
        options: Any = None,
    ) -> SessionListPage:
        return self._storage.list(
            status=status,
            session_kind=session_kind,
            vendor_data=vendor_data,
            country=country,
            workflow_id=workflow_id,
            search=search,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )

    def reconcile(
        self,
        session_id: str,
        observed: ObservedSessionState | None = None,
        *,
        options: Any = None,
    ) -> SessionReconciliationReport:
        if observed is not None and observed.session_id != session_id:
            raise ValueError(
                f"ObservedSessionState session_id mismatch: expected '{session_id}', "
                f"got '{observed.session_id}'"
            )

        try:
            decision = self.get_decision(session_id)
            remote_status: SessionStatus | str | None = decision.status
            remote_warnings = set(decision.warning_codes)
            remote_missing = False
        except DiditNotFoundError:
            remote_status = None
            remote_warnings = set()
            remote_missing = True

        if observed is None:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=None,
                remote_status=remote_status,
                status_drift=False,
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=True,
                remote_missing=remote_missing,
            )

        if remote_missing:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=observed.status,
                remote_status=None,
                status_drift=False,
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=False,
                remote_missing=True,
            )

        local_status_val = (
            observed.status.value if isinstance(observed.status, SessionStatus) else observed.status
        )
        remote_status_val = (
            remote_status.value if isinstance(remote_status, SessionStatus) else remote_status
        )
        status_drift = local_status_val != remote_status_val

        local_warnings = set(observed.warning_codes)
        warning_added = sorted(remote_warnings - local_warnings)
        warning_removed = sorted(local_warnings - remote_warnings)

        return SessionReconciliationReport(
            session_id=session_id,
            local_status=observed.status,
            remote_status=remote_status,
            status_drift=status_drift,
            warning_codes_added=warning_added,
            warning_codes_removed=warning_removed,
            local_missing=False,
            remote_missing=False,
        )

    def reconcile_range(
        self,
        *,
        source: SessionStateSource,
        since: Any = None,
        until: Any = None,
        date_from: Any = None,
        date_to: Any = None,
        status: SessionStatus | str | None = None,
        page_size: int = 50,
        max_sessions: int | None = None,
        limit: int | None = None,
        options: Any = None,
    ) -> BatchReconciliationReport:
        if since is not None and date_from is not None:
            raise ValueError("Specify either 'since' or 'date_from', not both")
        if until is not None and date_to is not None:
            raise ValueError("Specify either 'until' or 'date_to', not both")

        start = since if since is not None else date_from
        end = until if until is not None else date_to

        effective_page_size = limit if limit is not None else page_size
        if effective_page_size <= 0 or effective_page_size > 100:
            raise ValueError(f"page_size must be between 1 and 100, got {effective_page_size}")
        if max_sessions is not None and max_sessions <= 0:
            raise ValueError(f"max_sessions must be greater than 0, got {max_sessions}")

        effective_until = end if end is not None else datetime.now(timezone.utc)

        reports: list[SessionReconciliationReport] = []
        drift_count = 0
        missing_local_count = 0
        missing_remote_count = 0
        offset = 0

        while True:
            current_limit = effective_page_size
            if max_sessions is not None:
                current_limit = min(current_limit, max_sessions - len(reports))

            page = self.list(
                date_from=start,
                date_to=effective_until,
                status=status,
                limit=current_limit,
                offset=offset,
            )

            if not page.results:
                break

            for item in page.results:
                observed = source.get(item.session_id)
                report = self.reconcile(item.session_id, observed=observed)
                reports.append(report)
                if report.status_drift or report.warning_drift:
                    drift_count += 1
                if report.local_missing:
                    missing_local_count += 1
                if report.remote_missing:
                    missing_remote_count += 1
                if max_sessions is not None and len(reports) >= max_sessions:
                    break

            offset += len(page.results)
            if (
                page.next is None
                or len(page.results) < current_limit
                or (max_sessions is not None and len(reports) >= max_sessions)
            ):
                break

        return BatchReconciliationReport(
            total_evaluated=len(reports),
            drift_count=drift_count,
            missing_local_count=missing_local_count,
            missing_remote_count=missing_remote_count,
            reports=reports,
        )


class SimulatedAsyncSessionsResource:
    """Asynchronous in-memory sessions resource."""

    def __init__(self, storage: _SimulatedStorage) -> None:
        self._storage = storage

    async def create(
        self,
        vendor_data: str,
        *,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
        sandbox_scenario: str | None = None,
    ) -> SessionResponse:
        return self._storage.create(
            vendor_data=vendor_data,
            workflow_id=workflow_id,
            callback=callback,
            language=language,
            sandbox_scenario=sandbox_scenario,
        )

    async def get(self, session_id: str) -> SessionResponse:
        return self._storage.get(session_id)

    async def get_decision(self, session_id: str) -> DecisionResponse:
        return self._storage.get_decision(session_id)

    async def poll_decision(
        self,
        session_id: str,
        *,
        timeout: float = 60.0,
        interval: float = 2.0,
    ) -> DecisionResponse:
        decision = await self.get_decision(session_id)
        if not decision.status.is_poll_complete:
            raise DiditTimeoutError(
                f"Polling simulated session '{session_id}' timed out without terminal outcome"
            )
        return decision

    async def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: str | None = "user",
        vendor_data: str | None = None,
        country: str | None = None,
        workflow_id: str | None = None,
        search: str | None = None,
        date_from: Any = None,
        date_to: Any = None,
        limit: int = 50,
        offset: int = 0,
        options: Any = None,
    ) -> SessionListPage:
        return self._storage.list(
            status=status,
            session_kind=session_kind,
            vendor_data=vendor_data,
            country=country,
            workflow_id=workflow_id,
            search=search,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )

    async def reconcile(
        self,
        session_id: str,
        observed: ObservedSessionState | None = None,
        *,
        options: Any = None,
    ) -> SessionReconciliationReport:
        if observed is not None and observed.session_id != session_id:
            raise ValueError(
                f"ObservedSessionState session_id mismatch: expected '{session_id}', "
                f"got '{observed.session_id}'"
            )

        try:
            decision = await self.get_decision(session_id)
            remote_status: SessionStatus | str | None = decision.status
            remote_warnings = set(decision.warning_codes)
            remote_missing = False
        except DiditNotFoundError:
            remote_status = None
            remote_warnings = set()
            remote_missing = True

        if observed is None:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=None,
                remote_status=remote_status,
                status_drift=False,
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=True,
                remote_missing=remote_missing,
            )

        if remote_missing:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=observed.status,
                remote_status=None,
                status_drift=False,
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=False,
                remote_missing=True,
            )

        local_status_val = (
            observed.status.value if isinstance(observed.status, SessionStatus) else observed.status
        )
        remote_status_val = (
            remote_status.value if isinstance(remote_status, SessionStatus) else remote_status
        )
        status_drift = local_status_val != remote_status_val

        local_warnings = set(observed.warning_codes)
        warning_added = sorted(remote_warnings - local_warnings)
        warning_removed = sorted(local_warnings - remote_warnings)

        return SessionReconciliationReport(
            session_id=session_id,
            local_status=observed.status,
            remote_status=remote_status,
            status_drift=status_drift,
            warning_codes_added=warning_added,
            warning_codes_removed=warning_removed,
            local_missing=False,
            remote_missing=False,
        )

    async def reconcile_range(
        self,
        *,
        source: SessionStateSource | AsyncSessionStateSource,
        since: Any = None,
        until: Any = None,
        date_from: Any = None,
        date_to: Any = None,
        status: SessionStatus | str | None = None,
        page_size: int = 50,
        max_sessions: int | None = None,
        limit: int | None = None,
        options: Any = None,
    ) -> BatchReconciliationReport:
        if since is not None and date_from is not None:
            raise ValueError("Specify either 'since' or 'date_from', not both")
        if until is not None and date_to is not None:
            raise ValueError("Specify either 'until' or 'date_to', not both")

        start = since if since is not None else date_from
        end = until if until is not None else date_to

        effective_page_size = limit if limit is not None else page_size
        if effective_page_size <= 0 or effective_page_size > 100:
            raise ValueError(f"page_size must be between 1 and 100, got {effective_page_size}")
        if max_sessions is not None and max_sessions <= 0:
            raise ValueError(f"max_sessions must be greater than 0, got {max_sessions}")

        effective_until = end if end is not None else datetime.now(timezone.utc)

        reports: list[SessionReconciliationReport] = []
        drift_count = 0
        missing_local_count = 0
        missing_remote_count = 0
        offset = 0

        while True:
            current_limit = effective_page_size
            if max_sessions is not None:
                current_limit = min(current_limit, max_sessions - len(reports))

            page = await self.list(
                date_from=start,
                date_to=effective_until,
                status=status,
                limit=current_limit,
                offset=offset,
            )

            if not page.results:
                break

            for item in page.results:
                if isinstance(source, AsyncSessionStateSource):
                    observed = await source.aget(item.session_id)
                else:
                    get_fn: Any = getattr(source, "get", None)
                    if inspect.iscoroutinefunction(get_fn):
                        observed = await get_fn(item.session_id)
                    else:
                        observed = await asyncio.to_thread(source.get, item.session_id)

                report = await self.reconcile(item.session_id, observed=observed)
                reports.append(report)
                if report.status_drift or report.warning_drift:
                    drift_count += 1
                if report.local_missing:
                    missing_local_count += 1
                if report.remote_missing:
                    missing_remote_count += 1
                if max_sessions is not None and len(reports) >= max_sessions:
                    break

            offset += len(page.results)
            if (
                page.next is None
                or len(page.results) < current_limit
                or (max_sessions is not None and len(reports) >= max_sessions)
            ):
                break

        return BatchReconciliationReport(
            total_evaluated=len(reports),
            drift_count=drift_count,
            missing_local_count=missing_local_count,
            missing_remote_count=missing_remote_count,
            reports=reports,
        )


class SimulatedDidit:
    """Synchronous simulated Didit client."""

    is_simulated: bool = True

    def __init__(self, webhook_secret: str | None = None) -> None:
        self._storage = _SimulatedStorage()
        self._webhook_secret = webhook_secret
        self.sessions = SimulatedSessionsResource(self._storage)

    def approve_session(
        self,
        session_id: str,
        *,
        document: DocumentData | None = None,
        biometrics: BiometricsData | None = None,
        aml: AMLData | None = None,
        review: ReviewData | None = None,
    ) -> DecisionResponse:
        """Manually approve a session and populate verified identity data."""
        return self._storage.approve(
            session_id, document=document, biometrics=biometrics, aml=aml, review=review
        )

    def decline_session(
        self,
        session_id: str,
        *,
        reason: str = "Verification failed by simulated policy",
    ) -> DecisionResponse:
        """Manually decline a session with a review reason."""
        return self._storage.decline(session_id, reason=reason)

    def generate_webhook_event(
        self, session_id: str, secret: str | None = None
    ) -> tuple[bytes, dict[str, str]]:
        """Generate signed webhook payload and headers for local endpoint testing."""
        wh_secret = secret or self._webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "Missing webhook secret. Provide secret or initialize with webhook_secret."
            )

        session = self._storage.get(session_id)
        decision = self._storage.get_decision(session_id)
        now = int(time.time())
        payload: dict[str, Any] = {
            "session_id": session.session_id,
            "status": session.status.value,
            "timestamp": now,
            "created_at": now,
            "event_id": f"evt_{uuid.uuid4().hex}",
            "webhook_type": "status.updated",
            "environment": "sandbox",
            "workflow_id": session.workflow_id,
            "vendor_data": session.vendor_data,
            "decision": decision.model_dump(exclude_none=True),
        }
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(wh_secret, payload, version="v2")
        headers = {
            "X-Signature-V2": sig,
            "X-Timestamp": str(now),
            "Content-Type": "application/json",
        }
        return raw_body, headers


class SimulatedAsyncDidit:
    """Asynchronous simulated Didit client."""

    is_simulated: bool = True

    def __init__(self, webhook_secret: str | None = None) -> None:
        self._storage = _SimulatedStorage()
        self._webhook_secret = webhook_secret
        self.sessions = SimulatedAsyncSessionsResource(self._storage)

    def approve_session(
        self,
        session_id: str,
        *,
        document: DocumentData | None = None,
        biometrics: BiometricsData | None = None,
        aml: AMLData | None = None,
        review: ReviewData | None = None,
    ) -> DecisionResponse:
        """Manually approve a session and populate verified identity data."""
        return self._storage.approve(
            session_id, document=document, biometrics=biometrics, aml=aml, review=review
        )

    def decline_session(
        self,
        session_id: str,
        *,
        reason: str = "Verification failed by simulated policy",
    ) -> DecisionResponse:
        """Manually decline a session with a review reason."""
        return self._storage.decline(session_id, reason=reason)

    def generate_webhook_event(
        self, session_id: str, secret: str | None = None
    ) -> tuple[bytes, dict[str, str]]:
        """Generate signed webhook payload and headers for local endpoint testing."""
        wh_secret = secret or self._webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "Missing webhook secret. Provide secret or initialize with webhook_secret."
            )

        session = self._storage.get(session_id)
        decision = self._storage.get_decision(session_id)
        now = int(time.time())
        payload: dict[str, Any] = {
            "session_id": session.session_id,
            "status": session.status.value,
            "timestamp": now,
            "created_at": now,
            "event_id": f"evt_{uuid.uuid4().hex}",
            "webhook_type": "status.updated",
            "environment": "sandbox",
            "workflow_id": session.workflow_id,
            "vendor_data": session.vendor_data,
            "decision": decision.model_dump(exclude_none=True),
        }
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(wh_secret, payload, version="v2")
        headers = {
            "X-Signature-V2": sig,
            "X-Timestamp": str(now),
            "Content-Type": "application/json",
        }
        return raw_body, headers
