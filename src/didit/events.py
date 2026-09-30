"""PII-minimized telemetry event sink definitions and event data models."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from didit.models.enums import SessionStatus


@dataclass(frozen=True)
class DiditSDKEvent:
    """Base class for all Didit SDK telemetry events. Strictly PII-minimized."""

    event_type: str
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())


@dataclass(frozen=True)
class RequestRetryScheduled(DiditSDKEvent):
    """Telemetry emitted when an HTTP request will be retried."""

    event_type: str = "request_retry_scheduled"
    method: str = ""
    url: str = ""
    attempt: int = 0
    delay: float = 0.0
    reason: str = ""


@dataclass(frozen=True)
class RateLimitObserved(DiditSDKEvent):
    """Telemetry emitted when HTTP 429 Rate Limit is observed."""

    event_type: str = "rate_limit_observed"
    path: str = ""
    retry_after: float | None = None


@dataclass(frozen=True)
class WebhookDuplicateObserved(DiditSDKEvent):
    """Telemetry emitted when a duplicate webhook delivery is detected."""

    event_type: str = "webhook_duplicate_observed"
    event_id: str | None = None
    session_id: str | None = None
    action_taken: str = ""


@dataclass(frozen=True)
class WebhookLeaseDegraded(DiditSDKEvent):
    """Telemetry emitted when dedup store fails open and degrades distributed lease."""

    event_type: str = "webhook_lease_degraded"
    event_id: str | None = None
    session_id: str | None = None
    reason: str = "dedup_store_fail_open"


@dataclass(frozen=True)
class WebhookLeaseLost(DiditSDKEvent):
    """Telemetry emitted when lease ownership token expired or release/CAS failed."""

    event_type: str = "webhook_lease_lost"
    event_id: str | None = None
    session_id: str | None = None
    reason: str = "lease_expired_or_lost"


@dataclass(frozen=True)
class ReconciliationDriftObserved(DiditSDKEvent):
    """Telemetry emitted when local state drifts from remote verification snapshot."""

    event_type: str = "reconciliation_drift_observed"
    session_id: str = ""
    local_status: SessionStatus | str | None = None
    remote_status: SessionStatus | str | None = None
    warning_codes_added: tuple[str, ...] = ()
    warning_codes_removed: tuple[str, ...] = ()


@runtime_checkable
class DiditEventSink(Protocol):
    """Protocol for telemetry event sinks. Sinks must never raise and MUST be non-blocking.

    safe_emit() isolates consumer exceptions, not latency. Sinks performing I/O
    must enqueue events asynchronously to a background worker or non-blocking buffer.
    """

    def emit(self, event: DiditSDKEvent) -> None:
        """Emit a telemetry event. Must return promptly without blocking."""
        ...


def safe_emit(sink: DiditEventSink | None, event: DiditSDKEvent) -> None:
    """Safely emit an event to a sink, suppressing any consumer exception."""
    if sink is None:
        return
    with contextlib.suppress(Exception):
        sink.emit(event)
