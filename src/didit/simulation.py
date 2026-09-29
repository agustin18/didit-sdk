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
)
from didit.models.enums import Language, SessionStatus
from didit.models.session import SessionResponse
from didit.webhooks import compute_signature


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
    ) -> SessionResponse:
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
        bio = biometrics or BiometricsData(face_match=True, liveness_check=True, score=0.99)
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
            score=bio.score if bio.score is not None else (0.99 if bio.liveness_check else 0.0),
        )
        decision.liveness_checks = [liveness]

        face_match = FaceMatchResult(
            status="Approved" if bio.face_match is not False else "Declined",
            score=bio.score if bio.score is not None else (0.99 if bio.face_match else 0.0),
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
    ) -> SessionResponse:
        return self._storage.create(
            vendor_data=vendor_data,
            workflow_id=workflow_id,
            callback=callback,
            language=language,
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
    ) -> SessionResponse:
        return self._storage.create(
            vendor_data=vendor_data,
            workflow_id=workflow_id,
            callback=callback,
            language=language,
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
