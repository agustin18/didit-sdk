"""Session request and response data models."""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from didit.models.enums import CallbackMethod, ManualSessionStatus, SessionStatus


class ResubmitFeature(str, Enum):
    """Schema-valid feature choices in Didit OpenAPI V3 specification.

    Note: Upstream business rules restrict executable resubmission to user verification
    steps (e.g. OCR, LIVENESS, FACE_MATCH). Organizational KYB steps (KYB_REGISTRY,
    KYB_KEY_PEOPLE, KYB) are valid in the schema but cannot be resubmitted directly.
    """

    OCR = "OCR"
    OCR_BACK = "OCR_BACK"
    NFC = "NFC"
    AML = "AML"
    FACE = "FACE"
    LIVENESS = "LIVENESS"
    FACE_MATCH = "FACE_MATCH"
    IP_ANALYSIS = "IP_ANALYSIS"
    AGE_ESTIMATION = "AGE_ESTIMATION"
    PROOF_OF_ADDRESS = "PROOF_OF_ADDRESS"
    PHONE_VERIFICATION = "PHONE_VERIFICATION"
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    FACE_SEARCH = "FACE_SEARCH"
    DATABASE_VALIDATION = "DATABASE_VALIDATION"
    QUESTIONNAIRE = "QUESTIONNAIRE"
    DOCUMENT_AI = "DOCUMENT_AI"
    KYB_DOCUMENTS = "KYB_DOCUMENTS"
    ID_VERIFICATION = "ID_VERIFICATION"
    POA = "POA"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    KYB_REGISTRY = "KYB_REGISTRY"
    KYB_KEY_PEOPLE = "KYB_KEY_PEOPLE"
    KYB = "KYB"


class ResubmitNode(BaseModel):
    """Node specification for workflow resubmission requests."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    node_id: str = Field(
        ...,
        min_length=1,
        description="Node identifier in the session's workflow definition (e.g. 'feature_ocr')",
    )
    feature: ResubmitFeature | str = Field(
        ...,
        description="Feature type of the node (e.g. 'OCR', 'LIVENESS', 'FACE_MATCH')",
    )

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        d = super().model_dump(**kwargs)
        if isinstance(d.get("feature"), Enum):
            d["feature"] = d["feature"].value
        return d


class ContactDetails(BaseModel):
    """Contact details to pre-fill or enforce during verification."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    email: str | None = Field(default=None, description="End user email address")
    send_notification_emails: bool | None = Field(
        default=None, description="Whether Didit should send transactional status emails"
    )
    email_lang: str | None = Field(
        default=None, description="Language code for notification emails (e.g. 'en')"
    )
    phone: str | None = Field(
        default=None, description="End user phone number in E.164 format (e.g. '+14155552671')"
    )


class ExpectedDetails(BaseModel):
    """Expected user or business details to cross-validate against submitted documents."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    first_name: str | None = Field(default=None, description="User first name")
    last_name: str | None = Field(default=None, description="User last name")
    date_of_birth: str | None = Field(default=None, description="User date of birth (YYYY-MM-DD)")
    gender: str | None = Field(default=None, description="User gender ('M', 'F', or None)")
    nationality: str | None = Field(
        default=None, description="ISO 3166-1 alpha-3 nationality country code"
    )
    country: str | None = Field(
        default=None, description="Fallback ISO 3166-1 alpha-3 country code"
    )
    id_country: str | None = Field(
        default=None, description="ISO 3166-1 alpha-3 expected ID document country code"
    )
    poa_country: str | None = Field(
        default=None, description="ISO 3166-1 alpha-3 expected Proof of Address country code"
    )
    address: str | None = Field(default=None, description="Full human-readable address")
    identification_number: str | None = Field(
        default=None, description="Document number, tax number, or personal ID"
    )
    ip_address: str | None = Field(default=None, description="Expected client IP address")
    expected_document_types: list[str] | None = Field(
        default=None,
        description="Allowed document types (e.g. ['P', 'ID', 'DL', 'RP', 'HIC', 'TC', 'SSC'])",
    )
    company_name: str | None = Field(
        default=None, description="Expected legal business name for KYB workflows"
    )
    registry_country: str | None = Field(
        default=None,
        description="ISO 3166-1 alpha-2 registry country code (or subdivision) for KYB",
    )
    registration_number: str | None = Field(
        default=None, description="Expected business registry registration number for KYB"
    )


class CreateSessionRequest(BaseModel):
    """Payload to create a new identity verification session."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    workflow_id: str = Field(..., min_length=1, description="Didit workflow UUID/identifier")
    vendor_data: str | None = Field(
        default=None,
        min_length=1,
        description="Internal reference ID for the user or entity being verified",
    )
    callback: str | None = Field(
        default=None,
        description="Optional redirect URL after verification completion",
    )
    callback_method: CallbackMethod | str | None = Field(
        default=None,
        description="Device receiving callback redirect ('initiator', 'completer', 'both')",
    )
    metadata: JsonValue | None = Field(
        default=None,
        description="Arbitrary JSON stored with the session and echoed back in webhooks/responses",
    )
    language: str | None = Field(
        default=None,
        description="Two-letter ISO 639-1 language code (e.g., 'es', 'en')",
    )
    contact_details: ContactDetails | dict[str, Any] | None = Field(
        default=None,
        description="Contact information to enforce or pre-fill during verification",
    )
    expected_details: ExpectedDetails | dict[str, Any] | None = Field(
        default=None,
        description="Applicant or business details to cross-validate against extracted data",
    )
    portrait_image: str | None = Field(
        default=None,
        description="Base64-encoded reference portrait image for face match workflows",
    )
    sandbox_scenario: str | None = Field(
        default=None,
        description="Optional Didit sandbox outcome slug e.g. approve, decline_document_expired",
    )


class UpdateSessionStatusRequest(BaseModel):
    """Payload for PATCH /v3/session/{sessionId}/update-status/."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    new_status: ManualSessionStatus | SessionStatus | str = Field(
        ...,
        description="Target status ('Approved', 'Declined', or 'Resubmitted')",
    )
    comment: str | None = Field(
        default=None,
        description="Free-text review reason stored on the session audit trail",
    )
    nodes_to_resubmit: list[dict[str, str]] | None = Field(
        default=None,
        description="Specific workflow nodes to resubmit as [{'node_id': ..., 'feature': ...}]",
    )
    send_email: bool | None = Field(
        default=None,
        description="Whether to email the user about the status change (requires email_address)",
    )
    email_address: str | None = Field(
        default=None,
        description="Recipient email address when send_email is True",
    )
    email_language: str | None = Field(
        default=None,
        description="Language code for notification email (e.g. 'en')",
    )


class UpdateSessionStatusResponse(BaseModel):
    """Response returned by Didit when updating session status.

    Note: Upstream Didit returns only `{"session_id": "<uuid>"}`.
    To inspect updated decision or status, fetch via client.sessions.get_decision().
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    session_id: str = Field(..., description="UUID of the updated verification session")
    status: SessionStatus | str | None = Field(
        default=None,
        description="Status confirmed upstream by Didit (None if not echoed upstream)",
    )
    requested_status: SessionStatus | str | None = Field(
        default=None,
        description="Status transition requested by client in update_status/resubmit",
    )
    resubmit_info: ResubmitInfo | None = Field(
        default=None,
        description="Optional resubmission metadata if present in response",
    )

    @property
    def requires_resubmission(self) -> bool:
        """Return True if status confirmed by Didit indicates resubmission is required."""
        return self.status in (SessionStatus.RESUBMITTED, "Resubmitted")

    @property
    def requested_resubmission(self) -> bool:
        """Return True if requested status indicates resubmission."""
        return self.requested_status in (SessionStatus.RESUBMITTED, "Resubmitted")

    def __repr__(self) -> str:
        parts = [f"session_id={self.session_id!r}"]
        if self.status is not None:
            parts.append(f"status={self.status!r}")
        if self.requested_status is not None:
            parts.append(f"requested_status={self.requested_status!r}")
        return f"UpdateSessionStatusResponse({', '.join(parts)})"

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dump preserving session identifier."""
        return {
            "session_id": self.session_id,
            "status": self.status.value if isinstance(self.status, SessionStatus) else self.status,
            "requested_status": (
                self.requested_status.value
                if isinstance(self.requested_status, SessionStatus)
                else self.requested_status
            ),
            "requires_resubmission": self.requires_resubmission,
            "resubmit_info": self.resubmit_info.redacted_dump() if self.resubmit_info else None,
        }


UpdateStatusResponse = UpdateSessionStatusResponse


class ResubmitInfo(BaseModel):
    """Metadata regarding requested verification resubmission."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    nodes: list[str] = Field(
        default_factory=list,
        description="Workflow node keys or check steps requiring resubmission",
    )
    available_attempts: int | None = Field(
        default=None,
        description="Number of remaining allowed resubmission attempts",
    )
    max_attempts: int | None = Field(
        default=None,
        description="Maximum total resubmission attempts configured",
    )

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dump preserving only structured non-PII attributes."""
        return {
            "nodes": list(self.nodes),
            "available_attempts": self.available_attempts,
            "max_attempts": self.max_attempts,
        }


class SessionResponse(BaseModel):
    """Data returned by Didit when a session is created or fetched."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    session_id: str = Field(..., description="Unique Didit session identifier")
    session_token: str | None = Field(
        default=None, description="Client token for web SDK embedding"
    )
    url: str | None = Field(default=None, description="Hosted verification flow URL for the user")
    status: SessionStatus = Field(
        default=SessionStatus.NOT_STARTED,
        description="Current verification status",
    )
    workflow_id: str | None = Field(default=None, description="Associated workflow identifier")
    vendor_data: str | None = Field(default=None, description="Echoed vendor reference")
    callback: str | None = Field(default=None, description="Echoed callback URL")
    resubmit_info: ResubmitInfo | None = Field(
        default=None,
        description="Optional typed metadata when resubmission of documents is requested",
    )

    @property
    def requires_resubmission(self) -> bool:
        """Return True if session requires user resubmission of documents/biometrics."""
        return self.status.requires_resubmission or bool(self.resubmit_info)

    def __repr__(self) -> str:
        token_repr = "'[REDACTED]'" if self.session_token else "None"
        return (
            f"SessionResponse(session_id={self.session_id!r}, "
            f"status={self.status.value!r}, "
            f"workflow_id={self.workflow_id!r}, "
            f"session_token={token_repr})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Dump model dictionary with session_token and sensitive URLs redacted.

        Uses a strict allowlist to guarantee privacy defaults.
        """
        return {
            "session_id": self.session_id,
            "status": self.status.value if isinstance(self.status, SessionStatus) else self.status,
            "session_token": "[REDACTED]" if self.session_token else None,
            "workflow_id": self.workflow_id,
            "vendor_data": self.vendor_data,
            "requires_resubmission": self.requires_resubmission,
            "resubmit_info": self.resubmit_info.redacted_dump() if self.resubmit_info else None,
        }


class SessionListItem(BaseModel):
    """Item representation in session listing response."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    session_id: str = Field(..., description="Unique Didit session identifier")
    status: SessionStatus = Field(..., description="Current verification status")
    session_token: str | None = Field(
        default=None, description="Client token for web SDK embedding"
    )
    url: str | None = Field(default=None, description="Hosted verification flow URL for the user")
    workflow_id: str | None = Field(default=None, description="Associated workflow identifier")
    vendor_data: str | None = Field(default=None, description="Echoed vendor reference")
    callback: str | None = Field(default=None, description="Echoed callback URL")
    country: str | None = Field(default=None, description="Country code of user")
    session_kind: str | None = Field(default=None, description="Session type e.g. user")
    created_at: int | float | str | None = Field(default=None, description="Creation timestamp")
    updated_at: int | float | str | None = Field(default=None, description="Update timestamp")

    def __repr__(self) -> str:
        token_repr = "'[REDACTED]'" if self.session_token else "None"
        return (
            f"SessionListItem(session_id={self.session_id!r}, status={self.status!r}, "
            f"workflow_id={self.workflow_id!r}, session_token={token_repr})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Dump model dictionary with session_token redacted using a strict allowlist."""
        return {
            "session_id": self.session_id,
            "status": self.status.value if isinstance(self.status, SessionStatus) else self.status,
            "session_token": "[REDACTED]" if self.session_token else None,
            "workflow_id": self.workflow_id,
            "country": self.country,
            "session_kind": self.session_kind,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class SessionListPage(BaseModel):
    """Paginated collection of sessions returned by Didit API."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    count: int = Field(..., description="Total count of matching sessions")
    results: list[SessionListItem] = Field(..., description="List of sessions on current page")
    next: str | None = Field(default=None, description="URL for the next page of results")
    previous: str | None = Field(default=None, description="URL for the previous page of results")

    def __repr__(self) -> str:
        return (
            f"SessionListPage(count={self.count}, results_count={len(self.results)}, "
            f"has_next={self.next is not None}, has_previous={self.previous is not None})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Dump model dictionary with session tokens redacted and without raw query URLs."""
        return {
            "count": self.count,
            "has_next": self.next is not None,
            "has_previous": self.previous is not None,
            "results": [item.redacted_dump() for item in self.results],
        }


class ObservedSessionState(BaseModel):
    """Local snapshot of a session used for drift reconciliation."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    session_id: str = Field(..., description="Unique session identifier")
    status: SessionStatus | str | None = Field(
        default=None, description="Observed local verification status"
    )
    warning_codes: list[str] = Field(
        default_factory=list, description="Observed local warning codes"
    )
    updated_at: int | float | str | None = Field(
        default=None, description="Local last update timestamp"
    )


class SessionReconciliationReport(BaseModel):
    """Result of reconciling a local session snapshot against remote Didit state."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    session_id: str = Field(..., description="Unique session identifier")
    local_status: SessionStatus | str | None = Field(
        default=None, description="Local status recorded in consumer system"
    )
    remote_status: SessionStatus | str | None = Field(
        default=None, description="Remote status retrieved from Didit"
    )
    status_drift: bool = Field(
        default=False, description="True if local and remote statuses mismatch"
    )
    warning_codes_added: list[str] = Field(
        default_factory=list,
        description="Warning codes present on remote Didit but missing locally",
    )
    warning_codes_removed: list[str] = Field(
        default_factory=list,
        description="Warning codes present locally but not found on remote Didit",
    )
    local_missing: bool = Field(
        default=False, description="True if session was missing from local state source"
    )
    remote_missing: bool = Field(
        default=False, description="True if session was not found on Didit remote (HTTP 404)"
    )

    @property
    def is_in_sync(self) -> bool:
        """Return True if local and remote states are completely aligned without drift."""
        return (
            not self.status_drift
            and not self.warning_codes_added
            and not self.warning_codes_removed
            and not self.local_missing
            and not self.remote_missing
        )

    @property
    def warning_drift(self) -> bool:
        """Return True if warning codes differ between local and remote state."""
        return bool(self.warning_codes_added or self.warning_codes_removed)


class BatchReconciliationReport(BaseModel):
    """Aggregated report from reconciling remote Didit inventory against a local state source.

    Note: Batch reconciliation scans remote Didit inventory and detects local
    missing/stale projections (one-way audit). Systemic remote missing is detected
    via single-session reconcile().
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    total_evaluated: int = Field(default=0, description="Total sessions evaluated")
    drift_count: int = Field(
        default=0, description="Count of sessions with status or warning drift"
    )
    missing_local_count: int = Field(default=0, description="Count of sessions missing locally")
    missing_remote_count: int = Field(default=0, description="Count of sessions missing remotely")
    truncated: bool = Field(
        default=False,
        description="True if range was capped by max_sessions before exhausting pages",
    )
    remote_count: int | None = Field(
        default=None,
        description="Total matching sessions count reported by remote Didit API metadata",
    )
    reports: list[SessionReconciliationReport] = Field(
        default_factory=list, description="Individual session reconciliation reports"
    )


@runtime_checkable
class SessionStateSource(Protocol):
    """Protocol for synchronous consumer data sources providing local session state."""

    def get(self, session_id: str) -> ObservedSessionState | None:
        """Retrieve local snapshot for a session ID."""
        ...


@runtime_checkable
class AsyncSessionStateSource(Protocol):
    """Protocol for asynchronous consumer data sources providing local session state."""

    async def aget(self, session_id: str) -> ObservedSessionState | None:
        """Retrieve local snapshot for a session ID asynchronously."""
        ...
