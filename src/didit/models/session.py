"""Session request and response data models."""

from __future__ import annotations

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
