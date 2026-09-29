"""Webhook payload data model matching Didit V3 API contracts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from didit.models.decision import DecisionResponse
from didit.models.enums import SessionStatus


class WebhookPayload(BaseModel):
    """Event payload dispatched by Didit on verification status changes."""

    model_config = ConfigDict(extra="allow")

    session_id: str = Field(..., description="Unique session identifier")
    status: SessionStatus = Field(..., description="Updated session status")
    timestamp: int | None = Field(
        default=None, description="Signed UNIX timestamp in seconds when the event was emitted"
    )
    created_at: int | float | None = Field(
        default=None, description="UNIX timestamp in seconds when the session was created"
    )
    event_id: str | None = Field(
        default=None, description="Unique event identifier for idempotency tracking"
    )
    webhook_type: str | None = Field(
        default=None, description="Event classification e.g. session.updated"
    )
    environment: str | None = Field(
        default=None, description="Originating environment e.g. sandbox or production"
    )
    workflow_id: str | None = Field(default=None, description="Associated workflow identifier")
    workflow_version: str | None = Field(
        default=None, description="Workflow configuration version string"
    )
    vendor_data: str | None = Field(default=None, description="Echoed vendor reference")
    metadata: dict[str, Any] | None = Field(
        default=None, description="Custom metadata attached during session creation"
    )
    decision: DecisionResponse | None = Field(
        default=None, description="Embedded decision details if included in webhook"
    )
    raw_data: dict[str, Any] | None = Field(
        default=None, description="Complete unparsed JSON payload"
    )
