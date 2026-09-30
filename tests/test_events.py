"""Tests for telemetry event sinks and event models."""

from unittest.mock import MagicMock

from didit.events import (
    DiditEventSink,
    DiditSDKEvent,
    RateLimitObserved,
    ReconciliationDriftObserved,
    RequestRetryScheduled,
    WebhookDuplicateObserved,
    WebhookLeaseDegraded,
    WebhookLeaseLost,
    safe_emit,
)
from didit.models.enums import SessionStatus


class TestDiditEvents:
    def test_event_instantiation_defaults(self) -> None:
        evt = RequestRetryScheduled(
            method="GET",
            url="https://api.didit.me/v3/sessions/",
            attempt=1,
            delay=0.5,
            reason="503 Service Unavailable",
        )
        assert evt.event_type == "request_retry_scheduled"
        assert evt.attempt == 1
        assert evt.timestamp > 0.0

        rl = RateLimitObserved(path="/session/", retry_after=5.0)
        assert rl.event_type == "rate_limit_observed"
        assert rl.retry_after == 5.0

        dup = WebhookDuplicateObserved(
            event_id="evt_123", session_id="sess_123", action_taken="pass"
        )
        assert dup.event_type == "webhook_duplicate_observed"

        deg = WebhookLeaseDegraded(
            event_id="evt_123", session_id="sess_123", reason="Redis unreachable"
        )
        assert deg.event_type == "webhook_lease_degraded"

        lost = WebhookLeaseLost(
            event_id="evt_123", session_id="sess_123", reason="Lease expired before complete"
        )
        assert lost.event_type == "webhook_lease_lost"

        drift = ReconciliationDriftObserved(
            session_id="sess_123",
            local_status=SessionStatus.IN_REVIEW,
            remote_status=SessionStatus.APPROVED,
            warning_codes_added=("SUSPECTED_FRAUD",),
            warning_codes_removed=(),
        )
        assert drift.event_type == "reconciliation_drift_observed"
        assert drift.session_id == "sess_123"

    def test_event_sink_protocol_and_safe_emit(self) -> None:
        class WorkingSink:
            def __init__(self) -> None:
                self.received: list[DiditSDKEvent] = []

            def emit(self, event: DiditSDKEvent) -> None:
                self.received.append(event)

        assert isinstance(WorkingSink(), DiditEventSink)

        sink = WorkingSink()
        evt = DiditSDKEvent(event_type="test_event")
        safe_emit(sink, evt)
        assert len(sink.received) == 1
        assert sink.received[0] == evt

        # None sink is a no-op
        safe_emit(None, evt)

        # Faulty sink does not raise
        faulty_sink = MagicMock()
        faulty_sink.emit.side_effect = RuntimeError("Sink network failure")
        safe_emit(faulty_sink, evt)
        assert faulty_sink.emit.called
