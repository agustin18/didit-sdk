"""System healthcheck data models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class HealthcheckResponse(BaseModel):
    """System health status response."""

    model_config = ConfigDict(extra="allow")

    status: str = Field(..., description="System health status (e.g. 'ok')")
    timestamp: str | None = Field(default=None, description="ISO-8601 timestamp of server probe")

    @property
    def is_healthy(self) -> bool:
        """Return True if system reports 'ok' status."""
        return self.status.lower() == "ok"

    def __repr__(self) -> str:
        return f"HealthcheckResponse(status={self.status!r}, timestamp={self.timestamp!r})"

    __str__ = __repr__
