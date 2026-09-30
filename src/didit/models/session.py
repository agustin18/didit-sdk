"""Session request and response data models."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from didit.models.enums import SessionStatus


class CreateSessionRequest(BaseModel):
    """Payload to create a new identity verification session."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    workflow_id: str = Field(..., min_length=1, description="Didit workflow UUID/identifier")
    vendor_data: str = Field(
        ...,
        min_length=1,
        description="Internal reference ID for the user or entity being verified",
    )
    callback: str | None = Field(
        default=None,
        description="Optional redirect URL after verification completion",
    )
    language: str | None = Field(
        default=None,
        description="Two-letter ISO 639-1 language code (e.g., 'es', 'en')",
    )
    sandbox_scenario: str | None = Field(
        default=None,
        description="Optional Didit sandbox outcome slug e.g. approve, decline_document_expired",
    )


class SessionResponse(BaseModel):
    """Data returned by Didit when a session is created or fetched."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

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

    def redacted_dump(self) -> dict[str, Any]:
        """Dump model dictionary with session_token redacted."""
        data = self.model_dump()
        if data.get("session_token"):
            data["session_token"] = "[REDACTED]"
        return data


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

    def redacted_dump(self) -> dict[str, Any]:
        """Dump model dictionary with all contained session tokens redacted."""
        return {
            "count": self.count,
            "next": self.next,
            "previous": self.previous,
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
