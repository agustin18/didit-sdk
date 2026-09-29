"""In-memory simulation client for offline testing and local development without credentials."""

from __future__ import annotations

import json
import time
import uuid
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
from didit.models.session import SessionResponse
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
                code="UNRECOGNIZED_DOCUMENT",
                message="Document could not be recognized",
                severity="high",
            )
            decision.id_verifications = [IdVerificationResult(status="Declined", warnings=[warn])]
            decision.warnings = [warn]
        elif scenario == "decline_mrz_validation":
            session.status = SessionStatus.DECLINED
            decision.status = SessionStatus.DECLINED
            warn = VerificationWarning(
                code="MRZ_CHECKSUM_FAILED",
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
                code="SPOOF_DETECTED",
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
                code="IP_RISK_HIGH",
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
