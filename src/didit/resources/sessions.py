"""Sessions resource implementation for both synchronous and asynchronous clients."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from didit.errors import (
    DiditConnectionError,
    DiditNotFoundError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
from didit.events import DiditEventSink, ReconciliationDriftObserved, safe_emit
from didit.models.decision import DecisionResponse
from didit.models.enums import Language, SessionStatus
from didit.models.session import (
    AsyncSessionStateSource,
    BatchReconciliationReport,
    CreateSessionRequest,
    ObservedSessionState,
    SessionListPage,
    SessionReconciliationReport,
    SessionResponse,
    SessionStateSource,
)
from didit.transport import RequestOptions, _AsyncRequestor, _SyncRequestor

if TYPE_CHECKING:
    import httpx


class SessionsResource:
    """Synchronous resource for managing Didit verification sessions."""

    def __init__(
        self,
        requester: _SyncRequestor | httpx.Client,
        *,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        if isinstance(requester, _SyncRequestor):
            self._requestor = requester
            self._http = requester._client
        else:
            self._http = requester
            self._requestor = _SyncRequestor(
                requester,
                base_url=str(requester.base_url),
                api_key=requester.headers.get("x-api-key", ""),
            )
        self._event_sink = event_sink

    def create(
        self,
        vendor_data: str,
        *,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
        sandbox_scenario: str | None = None,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Create a new verification session.

        Args:
            vendor_data: Internal customer/user reference identifier.
            workflow_id: Didit workflow ID configuration.
            callback: Optional URL Didit will redirect the user to after completing verification.
            language: Optional UI language code for the hosted flow (e.g. 'es', 'en').
            sandbox_scenario: Optional Didit sandbox outcome slug e.g. 'approve',
                'decline_document_expired'.

        Returns:
            SessionResponse: Containing session_id, url, token, and status.
        """
        lang_str = language.value if isinstance(language, Language) else language
        payload = CreateSessionRequest(
            workflow_id=workflow_id,
            vendor_data=vendor_data,
            callback=callback,
            language=lang_str,
            sandbox_scenario=sandbox_scenario,
        ).model_dump(exclude_none=True)

        resp = self._requestor.request("POST", "/session/", json=payload, options=options)
        return SessionResponse.model_validate(resp.json())

    def get(
        self,
        session_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Retrieve details and status for an existing verification session."""
        resp = self._requestor.request("GET", f"/session/{session_id}/", options=options)
        return SessionResponse.model_validate(resp.json())

    def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: str | None = "user",
        vendor_data: str | None = None,
        country: str | None = None,
        workflow_id: str | None = None,
        search: str | None = None,
        date_from: datetime | str | None = None,
        date_to: datetime | str | None = None,
        limit: int = 50,
        offset: int = 0,
        options: RequestOptions | None = None,
    ) -> SessionListPage:
        """List verification sessions with optional filtering and pagination.

        Args:
            status: Filter by SessionStatus or status string.
            session_kind: Filter by session kind (default "user" for KYC).
            vendor_data: Filter by internal user/vendor identifier.
            country: Filter by ISO country code.
            workflow_id: Filter by workflow UUID.
            search: Search query across user attributes.
            date_from: Start timestamp filter (ISO string or datetime).
            date_to: End timestamp filter (ISO string or datetime).
            limit: Maximum records to return per page (default 50).
            offset: Number of items to skip for pagination (default 0).
            options: Optional per-request execution options.

        Returns:
            SessionListPage containing count, next, previous, and results.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if session_kind is not None:
            params["session_kind"] = session_kind
        if status is not None:
            params["status"] = status.value if isinstance(status, SessionStatus) else str(status)
        if vendor_data is not None:
            params["vendor_data"] = vendor_data
        if country is not None:
            params["country"] = country
        if workflow_id is not None:
            params["workflow_id"] = workflow_id
        if search is not None:
            params["search"] = search
        if date_from is not None:
            params["date_from"] = (
                date_from.isoformat() if isinstance(date_from, datetime) else str(date_from)
            )
        if date_to is not None:
            params["date_to"] = (
                date_to.isoformat() if isinstance(date_to, datetime) else str(date_to)
            )

        resp = self._requestor.request("GET", "/sessions/", params=params, options=options)
        return SessionListPage.model_validate(resp.json())

    def reconcile(
        self,
        session_id: str,
        observed: ObservedSessionState | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SessionReconciliationReport:
        """Reconcile a local session snapshot against remote Didit state.

        Compares verification status and warning codes between local consumer state
        and remote Didit decision snapshot without exposing or storing KYC PII.
        """
        try:
            decision = self.get_decision(session_id, options=options)
            remote_status: SessionStatus | str | None = decision.status
            remote_warnings = set(decision.warning_codes)
            remote_missing = False
        except DiditNotFoundError:
            remote_status = None
            remote_warnings = set()
            remote_missing = True

        if observed is None:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=None,
                remote_status=remote_status,
                status_drift=False,
                warning_codes_added=sorted(remote_warnings),
                warning_codes_removed=[],
                local_missing=True,
                remote_missing=remote_missing,
            )

        local_status_val = (
            observed.status.value if isinstance(observed.status, SessionStatus) else observed.status
        )
        remote_status_val = (
            remote_status.value if isinstance(remote_status, SessionStatus) else remote_status
        )
        status_drift = (remote_status_val is not None) and (local_status_val != remote_status_val)

        local_warnings = set(observed.warning_codes)
        warning_added = sorted(remote_warnings - local_warnings)
        warning_removed = sorted(local_warnings - remote_warnings)

        report = SessionReconciliationReport(
            session_id=session_id,
            local_status=observed.status,
            remote_status=remote_status,
            status_drift=status_drift,
            warning_codes_added=warning_added,
            warning_codes_removed=warning_removed,
            local_missing=False,
            remote_missing=remote_missing,
        )

        if report.status_drift or report.warning_drift:
            safe_emit(
                self._event_sink,
                ReconciliationDriftObserved(
                    session_id=session_id,
                    local_status=observed.status,
                    remote_status=remote_status,
                    warning_codes_added=tuple(warning_added),
                    warning_codes_removed=tuple(warning_removed),
                ),
            )

        return report

    def reconcile_range(
        self,
        *,
        source: SessionStateSource,
        since: datetime | str | None = None,
        until: datetime | str | None = None,
        date_from: datetime | str | None = None,
        date_to: datetime | str | None = None,
        status: SessionStatus | str | None = None,
        limit: int = 50,
        options: RequestOptions | None = None,
    ) -> BatchReconciliationReport:
        """Reconcile a range of sessions fetched from Didit against a local data source."""
        start = since if since is not None else date_from
        end = until if until is not None else date_to

        page = self.list(
            date_from=start,
            date_to=end,
            status=status,
            limit=limit,
            options=options,
        )

        reports: list[SessionReconciliationReport] = []
        drift_count = 0
        missing_local_count = 0
        missing_remote_count = 0

        for item in page.results:
            observed = source.get(item.session_id)
            report = self.reconcile(item.session_id, observed=observed, options=options)
            reports.append(report)
            if report.status_drift or report.warning_drift:
                drift_count += 1
            if report.local_missing:
                missing_local_count += 1
            if report.remote_missing:
                missing_remote_count += 1

        return BatchReconciliationReport(
            total_evaluated=len(reports),
            drift_count=drift_count,
            missing_local_count=missing_local_count,
            missing_remote_count=missing_remote_count,
            reports=reports,
        )

    def get_decision(
        self,
        session_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> DecisionResponse:
        """Retrieve the verification outcome and extracted checks (documents, biometrics, AML)."""
        resp = self._requestor.request("GET", f"/session/{session_id}/decision/", options=options)
        data = resp.json()
        decision = DecisionResponse.model_validate(data)
        decision.raw_data = data
        return decision

    def poll_decision(
        self,
        session_id: str,
        *,
        timeout: float = 60.0,
        interval: float = 2.0,
        max_interval: float = 10.0,
        backoff_multiplier: float = 1.2,
        stop_on_review: bool = True,
        stop_when: Callable[[DecisionResponse], bool] | None = None,
        tolerate_transient_errors: bool = True,
        options: RequestOptions | None = None,
    ) -> DecisionResponse:
        """Poll the decision endpoint until a terminal verification status is reached."""
        deadline = time.monotonic() + timeout
        current_interval = interval

        while True:
            now = time.monotonic()
            remaining_budget = max(0.0, deadline - now)
            if remaining_budget <= 0:
                raise DiditTimeoutError(
                    f"Polling decision for session '{session_id}' timed out after {timeout} seconds"
                )

            req_timeout = (
                options.timeout if (options and options.timeout is not None) else remaining_budget
            )
            effective_timeout = (
                min(float(req_timeout), remaining_budget)
                if isinstance(req_timeout, (int, float))
                else remaining_budget
            )

            poll_options = RequestOptions(
                idempotency_key=options.idempotency_key if options else None,
                timeout=effective_timeout,
                max_retries=0,
                headers=options.headers if options else None,
                deadline=deadline,
            )

            try:
                decision = self.get_decision(session_id, options=poll_options)
            except (
                DiditServerError,
                DiditRateLimitError,
                DiditTimeoutError,
                DiditConnectionError,
            ) as exc:
                if not tolerate_transient_errors:
                    raise
                if isinstance(exc, DiditServerError) and exc.status_code not in (
                    500,
                    502,
                    503,
                    504,
                ):
                    raise
                now = time.monotonic()
                if now >= deadline:
                    raise DiditTimeoutError(
                        f"Polling decision for session '{session_id}' "
                        f"timed out after {timeout} seconds"
                    ) from exc
                wait_time = current_interval
                if isinstance(exc, DiditRateLimitError) and exc.retry_after is not None:
                    wait_time = max(wait_time, exc.retry_after)

                sleep_duration = min(deadline - now, wait_time)
                time.sleep(sleep_duration)
                current_interval = min(max_interval, current_interval * backoff_multiplier)
                continue

            if stop_when is not None and stop_when(decision):
                return decision

            if stop_on_review and decision.status == SessionStatus.IN_REVIEW:
                return decision

            if decision.status.is_poll_complete:
                return decision

            now = time.monotonic()
            jitter_val = random.uniform(0.0, 0.1 * current_interval)
            sleep_duration = min(max(0.0, deadline - now), current_interval + jitter_val)
            time.sleep(sleep_duration)
            current_interval = min(max_interval, current_interval * backoff_multiplier)


class AsyncSessionsResource:
    """Asynchronous resource for managing Didit verification sessions."""

    def __init__(
        self,
        requester: _AsyncRequestor | httpx.AsyncClient,
        *,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        if isinstance(requester, _AsyncRequestor):
            self._requestor = requester
            self._http = requester._client
        else:
            self._http = requester
            self._requestor = _AsyncRequestor(
                requester,
                base_url=str(requester.base_url),
                api_key=requester.headers.get("x-api-key", ""),
            )
        self._event_sink = event_sink

    async def create(
        self,
        vendor_data: str,
        *,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
        sandbox_scenario: str | None = None,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Create a new verification session asynchronously."""
        lang_str = language.value if isinstance(language, Language) else language
        payload = CreateSessionRequest(
            workflow_id=workflow_id,
            vendor_data=vendor_data,
            callback=callback,
            language=lang_str,
            sandbox_scenario=sandbox_scenario,
        ).model_dump(exclude_none=True)

        resp = await self._requestor.request("POST", "/session/", json=payload, options=options)
        return SessionResponse.model_validate(resp.json())

    async def get(
        self,
        session_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Retrieve session status asynchronously."""
        resp = await self._requestor.request("GET", f"/session/{session_id}/", options=options)
        return SessionResponse.model_validate(resp.json())

    async def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: str | None = "user",
        vendor_data: str | None = None,
        country: str | None = None,
        workflow_id: str | None = None,
        search: str | None = None,
        date_from: datetime | str | None = None,
        date_to: datetime | str | None = None,
        limit: int = 50,
        offset: int = 0,
        options: RequestOptions | None = None,
    ) -> SessionListPage:
        """List verification sessions asynchronously with optional filtering and pagination."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if session_kind is not None:
            params["session_kind"] = session_kind
        if status is not None:
            params["status"] = status.value if isinstance(status, SessionStatus) else str(status)
        if vendor_data is not None:
            params["vendor_data"] = vendor_data
        if country is not None:
            params["country"] = country
        if workflow_id is not None:
            params["workflow_id"] = workflow_id
        if search is not None:
            params["search"] = search
        if date_from is not None:
            params["date_from"] = (
                date_from.isoformat() if isinstance(date_from, datetime) else str(date_from)
            )
        if date_to is not None:
            params["date_to"] = (
                date_to.isoformat() if isinstance(date_to, datetime) else str(date_to)
            )

        resp = await self._requestor.request("GET", "/sessions/", params=params, options=options)
        return SessionListPage.model_validate(resp.json())

    async def reconcile(
        self,
        session_id: str,
        observed: ObservedSessionState | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SessionReconciliationReport:
        """Reconcile a local session snapshot against remote Didit state asynchronously."""
        try:
            decision = await self.get_decision(session_id, options=options)
            remote_status: SessionStatus | str | None = decision.status
            remote_warnings = set(decision.warning_codes)
            remote_missing = False
        except DiditNotFoundError:
            remote_status = None
            remote_warnings = set()
            remote_missing = True

        if observed is None:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=None,
                remote_status=remote_status,
                status_drift=False,
                warning_codes_added=sorted(remote_warnings),
                warning_codes_removed=[],
                local_missing=True,
                remote_missing=remote_missing,
            )

        local_status_val = (
            observed.status.value if isinstance(observed.status, SessionStatus) else observed.status
        )
        remote_status_val = (
            remote_status.value if isinstance(remote_status, SessionStatus) else remote_status
        )
        status_drift = (remote_status_val is not None) and (local_status_val != remote_status_val)

        local_warnings = set(observed.warning_codes)
        warning_added = sorted(remote_warnings - local_warnings)
        warning_removed = sorted(local_warnings - remote_warnings)

        report = SessionReconciliationReport(
            session_id=session_id,
            local_status=observed.status,
            remote_status=remote_status,
            status_drift=status_drift,
            warning_codes_added=warning_added,
            warning_codes_removed=warning_removed,
            local_missing=False,
            remote_missing=remote_missing,
        )

        if report.status_drift or report.warning_drift:
            safe_emit(
                self._event_sink,
                ReconciliationDriftObserved(
                    session_id=session_id,
                    local_status=observed.status,
                    remote_status=remote_status,
                    warning_codes_added=tuple(warning_added),
                    warning_codes_removed=tuple(warning_removed),
                ),
            )

        return report

    async def reconcile_range(
        self,
        *,
        source: SessionStateSource | AsyncSessionStateSource,
        since: datetime | str | None = None,
        until: datetime | str | None = None,
        date_from: datetime | str | None = None,
        date_to: datetime | str | None = None,
        status: SessionStatus | str | None = None,
        limit: int = 50,
        options: RequestOptions | None = None,
    ) -> BatchReconciliationReport:
        """Reconcile a range of sessions fetched from Didit against a local data source
        asynchronously.
        """
        start = since if since is not None else date_from
        end = until if until is not None else date_to

        page = await self.list(
            date_from=start,
            date_to=end,
            status=status,
            limit=limit,
            options=options,
        )

        reports: list[SessionReconciliationReport] = []
        drift_count = 0
        missing_local_count = 0
        missing_remote_count = 0

        for item in page.results:
            if hasattr(source, "aget"):
                observed = await source.aget(item.session_id)
            else:
                observed = source.get(item.session_id)

            report = await self.reconcile(item.session_id, observed=observed, options=options)
            reports.append(report)
            if report.status_drift or report.warning_drift:
                drift_count += 1
            if report.local_missing:
                missing_local_count += 1
            if report.remote_missing:
                missing_remote_count += 1

        return BatchReconciliationReport(
            total_evaluated=len(reports),
            drift_count=drift_count,
            missing_local_count=missing_local_count,
            missing_remote_count=missing_remote_count,
            reports=reports,
        )

    async def get_decision(
        self,
        session_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> DecisionResponse:
        """Retrieve verification decision asynchronously."""
        resp = await self._requestor.request(
            "GET", f"/session/{session_id}/decision/", options=options
        )
        data = resp.json()
        decision = DecisionResponse.model_validate(data)
        decision.raw_data = data
        return decision

    async def poll_decision(
        self,
        session_id: str,
        *,
        timeout: float = 60.0,
        interval: float = 2.0,
        max_interval: float = 10.0,
        backoff_multiplier: float = 1.2,
        stop_on_review: bool = True,
        stop_when: Callable[[DecisionResponse], bool] | None = None,
        tolerate_transient_errors: bool = True,
        options: RequestOptions | None = None,
    ) -> DecisionResponse:
        """Poll the decision endpoint asynchronously until a terminal status is reached."""
        deadline = time.monotonic() + timeout
        current_interval = interval

        while True:
            now = time.monotonic()
            remaining_budget = max(0.0, deadline - now)
            if remaining_budget <= 0:
                raise DiditTimeoutError(
                    f"Polling decision for session '{session_id}' timed out after {timeout} seconds"
                )

            req_timeout = (
                options.timeout if (options and options.timeout is not None) else remaining_budget
            )
            effective_timeout = (
                min(float(req_timeout), remaining_budget)
                if isinstance(req_timeout, (int, float))
                else remaining_budget
            )

            poll_options = RequestOptions(
                idempotency_key=options.idempotency_key if options else None,
                timeout=effective_timeout,
                max_retries=0,
                headers=options.headers if options else None,
                deadline=deadline,
            )

            try:
                decision = await self.get_decision(session_id, options=poll_options)
            except (
                DiditServerError,
                DiditRateLimitError,
                DiditTimeoutError,
                DiditConnectionError,
            ) as exc:
                if not tolerate_transient_errors:
                    raise
                if isinstance(exc, DiditServerError) and exc.status_code not in (
                    500,
                    502,
                    503,
                    504,
                ):
                    raise
                now = time.monotonic()
                if now >= deadline:
                    raise DiditTimeoutError(
                        f"Polling decision for session '{session_id}' "
                        f"timed out after {timeout} seconds"
                    ) from exc
                wait_time = current_interval
                if isinstance(exc, DiditRateLimitError) and exc.retry_after is not None:
                    wait_time = max(wait_time, exc.retry_after)

                sleep_duration = min(deadline - now, wait_time)
                await asyncio.sleep(sleep_duration)
                current_interval = min(max_interval, current_interval * backoff_multiplier)
                continue

            if stop_when is not None and stop_when(decision):
                return decision

            if stop_on_review and decision.status == SessionStatus.IN_REVIEW:
                return decision

            if decision.status.is_poll_complete:
                return decision

            now = time.monotonic()
            jitter_val = random.uniform(0.0, 0.1 * current_interval)
            sleep_duration = min(max(0.0, deadline - now), current_interval + jitter_val)
            await asyncio.sleep(sleep_duration)
            current_interval = min(max_interval, current_interval * backoff_multiplier)
