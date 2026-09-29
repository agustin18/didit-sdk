"""Webhook payload data model."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from didit.models.decision import DecisionResponse
from didit.models.enums import SessionStatus


class WebhookPayload(BaseModel):
    """Event payload dispatched by Didit on verification status changes."""

    model_config = ConfigDict(extra="ignore")

    session_id: str = Field(..., description="Unique session identifier")
    status: SessionStatus = Field(..., description="Updated session status")
    created_at: int | float | None = Field(
        default=None, description="UNIX timestamp in seconds when the event was emitted"
    )
    workflow_id: str | None = Field(default=None, description="Associated workflow identifier")
    vendor_data: str | None = Field(default=None, description="Echoed vendor reference")
    decision: DecisionResponse | None = Field(
        default=None, description="Embedded decision details if included in webhook"
    )
    raw_data: dict[str, Any] | None = Field(
        default=None, description="Complete unparsed JSON payload"
    )
