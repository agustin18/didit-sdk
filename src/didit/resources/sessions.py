"""Sessions resource implementation for both synchronous and asynchronous clients."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import random
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from didit.errors import (
    DiditAPIError,
    DiditConnectionError,
    DiditNotFoundError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
from didit.events import DiditEventSink, ReconciliationDriftObserved, safe_emit
from didit.models.decision import DecisionResponse
from didit.models.enums import (
    ALLOWED_MANUAL_STATUSES,
    Language,
    ManualSessionStatus,
    SessionStatus,
)
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


def _validate_timestamp(val: datetime | str | None, param_name: str) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            raise ValueError(f"{param_name} datetime must be timezone-aware (tzinfo is not None)")
        return val
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception as exc:
            raise ValueError(
                f"Invalid ISO-8601 timestamp string for {param_name}: '{val}'"
            ) from exc
        if dt.tzinfo is None:
            raise ValueError(
                f"{param_name} ISO string must include timezone information (e.g. 'Z' or '+00:00')"
            )
        return dt
    raise ValueError(f"{param_name} must be a datetime or ISO-8601 string")


def _validate_manual_status(new_status: ManualSessionStatus | SessionStatus | str) -> str:
    """Validate manual status transition against allowed upstream Didit statuses."""
    if new_status not in ALLOWED_MANUAL_STATUSES:
        raise ValueError(
            f"Invalid manual status transition '{new_status}'. "
            "Allowed transitions are: Approved, Declined, Resubmitted"
        )
    return new_status.value if isinstance(new_status, SessionStatus) else str(new_status)


def _secure_write_bytes(dest_path: Path, data: bytes, *, force: bool = False) -> None:
    """Atomically write binary data to disk enforcing 0600 private permissions."""
    if dest_path.exists() and not force:
        raise FileExistsError(f"File '{dest_path}' already exists. Use --force to overwrite.")

    dest_dir = dest_path.parent
    dest_dir.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_path_str = tempfile.mkstemp(dir=dest_dir, prefix=".didit_tmp_")
    tmp_path = Path(tmp_path_str)
    fd_closed = False
    try:
        with contextlib.suppress(AttributeError, OSError):
            os.fchmod(tmp_fd, 0o600)
        with os.fdopen(tmp_fd, "wb") as f:
            fd_closed = True
            f.write(data)

        tmp_path.replace(dest_path)
        with contextlib.suppress(AttributeError, OSError):
            os.chmod(dest_path, 0o600)
    except Exception:
        if not fd_closed:
            with contextlib.suppress(OSError):
                os.close(tmp_fd)
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


def _validate_session_list_filters(
    *,
    status: SessionStatus | str | None,
    session_kind: str | None,
    country: str | None,
    limit: int,
    offset: int,
    date_from: datetime | str | None,
    date_to: datetime | str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    if session_kind != "user":
        raise ValueError(
            f"Unsupported session_kind '{session_kind}'. Only 'user' (KYC) is currently supported."
        )

    normalized_country: str | None = None
    if country is not None:
        normalized_country = country.strip().upper()
        if (
            len(normalized_country) != 3
            or not normalized_country.isalpha()
            or not normalized_country.isascii()
        ):
            raise ValueError(
                f"Invalid country code '{country}'. "
                "Expected 3-letter ISO 3166-1 alpha-3 code (e.g. 'ESP', 'USA')."
            )

    if limit <= 0 or limit > 100:
        raise ValueError(f"limit must be between 1 and 100, got {limit}")

    if offset < 0:
        raise ValueError(f"offset must be non-negative, got {offset}")

    parsed_from = _validate_timestamp(date_from, "date_from")
    parsed_to = _validate_timestamp(date_to, "date_to")
    if parsed_from is not None and parsed_to is not None and parsed_from > parsed_to:
        raise ValueError(f"date_from ({date_from}) cannot be later than date_to ({date_to})")

    date_from_str = (
        (date_from.isoformat() if isinstance(date_from, datetime) else str(date_from))
        if date_from is not None
        else None
    )

    date_to_str = (
        (date_to.isoformat() if isinstance(date_to, datetime) else str(date_to))
        if date_to is not None
        else None
    )

    status_str = (
        (status.value if isinstance(status, SessionStatus) else str(status))
        if status is not None
        else None
    )

    return status_str, normalized_country, date_from_str, date_to_str


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

    def update_status(
        self,
        session_id: str,
        new_status: ManualSessionStatus | SessionStatus | str,
        nodes_to_resubmit: list[str] | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Update status of an existing session (PATCH /v3/session/{session_id}/update-status/).

        Restricted by upstream Didit contract to manual reviewer transitions:
        'Approved', 'Declined', or 'Resubmitted'.

        Args:
            session_id: The unique identifier of the verification session.
            new_status: The target status ('Approved', 'Declined', 'Resubmitted',
                or SessionStatus enum).
            nodes_to_resubmit: Optional list of upstream workflow node IDs to resubmit.
            options: Optional per-request HTTP options.

        Returns:
            SessionResponse: The updated verification session.
        """
        if not session_id or not session_id.strip():
            raise ValueError("session_id must not be empty")

        status_val = _validate_manual_status(new_status)
        payload: dict[str, Any] = {"new_status": status_val}
        if nodes_to_resubmit is not None:
            payload["nodes_to_resubmit"] = nodes_to_resubmit

        resp = self._requestor.request(
            "PATCH",
            f"/session/{session_id.strip()}/update-status/",
            json=payload,
            options=options,
        )
        return SessionResponse.model_validate(resp.json())

    def resubmit(
        self,
        session_id: str,
        nodes_to_resubmit: list[str] | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Request document or biometric resubmission for an existing verification session.

        Invokes PATCH /v3/session/{session_id}/update-status/ with status 'Resubmitted'.

        Args:
            session_id: The unique identifier of the verification session.
            nodes_to_resubmit: Optional list of upstream workflow step node IDs to resubmit
                (e.g. ['document-verification-node', 'face-liveness-node']), matching
                workflow studio step keys or decision warnings.
            options: Optional per-request HTTP options.

        Returns:
            SessionResponse: The updated session with requires_resubmission=True.
        """
        return self.update_status(
            session_id,
            SessionStatus.RESUBMITTED,
            nodes_to_resubmit=nodes_to_resubmit,
            options=options,
        )

    def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: Literal["user"] = "user",
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
            session_kind: Filter by session kind (strictly "user" for KYC scope).
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
        status_str, norm_country, date_from_str, date_to_str = _validate_session_list_filters(
            status=status,
            session_kind=session_kind,
            country=country,
            limit=limit,
            offset=offset,
            date_from=date_from,
            date_to=date_to,
        )
        params: dict[str, Any] = {"limit": limit, "offset": offset, "session_kind": "user"}
        if status_str is not None:
            params["status"] = status_str
        if vendor_data is not None:
            params["vendor_data"] = vendor_data
        if norm_country is not None:
            params["country"] = norm_country
        if workflow_id is not None:
            params["workflow_id"] = workflow_id
        if search is not None:
            params["search"] = search
        if date_from_str is not None:
            params["date_from"] = date_from_str
        if date_to_str is not None:
            params["date_to"] = date_to_str

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
        if observed is not None and observed.session_id != session_id:
            raise ValueError(
                f"ObservedSessionState session_id mismatch: expected '{session_id}', "
                f"got '{observed.session_id}'"
            )

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
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=True,
                remote_missing=remote_missing,
            )

        if remote_missing:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=observed.status,
                remote_status=None,
                status_drift=False,
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=False,
                remote_missing=True,
            )

        local_status_val = (
            observed.status.value if isinstance(observed.status, SessionStatus) else observed.status
        )
        remote_status_val = (
            remote_status.value if isinstance(remote_status, SessionStatus) else remote_status
        )
        status_drift = local_status_val != remote_status_val

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
            remote_missing=False,
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
        page_size: int = 50,
        max_sessions: int | None = None,
        limit: int | None = None,
        options: RequestOptions | None = None,
    ) -> BatchReconciliationReport:
        """Reconcile a range of sessions fetched from Didit against a local data source."""
        if since is not None and date_from is not None:
            raise ValueError("Specify either 'since' or 'date_from', not both")
        if until is not None and date_to is not None:
            raise ValueError("Specify either 'until' or 'date_to', not both")

        start = since if since is not None else date_from
        end = until if until is not None else date_to

        effective_page_size = limit if limit is not None else page_size
        if effective_page_size <= 0 or effective_page_size > 100:
            raise ValueError(f"page_size must be between 1 and 100, got {effective_page_size}")
        if max_sessions is not None and max_sessions <= 0:
            raise ValueError(f"max_sessions must be greater than 0, got {max_sessions}")

        effective_until = end if end is not None else datetime.now(timezone.utc)

        reports: list[SessionReconciliationReport] = []
        drift_count = 0
        missing_local_count = 0
        missing_remote_count = 0
        offset = 0
        remote_count: int | None = None

        while True:
            current_limit = effective_page_size
            if max_sessions is not None:
                current_limit = min(current_limit, max_sessions - len(reports))

            page = self.list(
                date_from=start,
                date_to=effective_until,
                status=status,
                limit=current_limit,
                offset=offset,
                options=options,
            )
            if remote_count is None:
                remote_count = page.count

            if not page.results:
                if page.next is not None:
                    raise DiditAPIError(
                        "Didit pagination returned next page metadata without progress",
                        status_code=502,
                    )
                if offset < page.count and (max_sessions is None or len(reports) < max_sessions):
                    raise DiditAPIError(
                        f"Inconsistent pagination metadata: received {offset} of "
                        f"{page.count} sessions without next page",
                        status_code=502,
                    )
                break

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
                if max_sessions is not None and len(reports) >= max_sessions:
                    break

            offset += len(page.results)
            if max_sessions is not None and len(reports) >= max_sessions:
                break

            if page.next is None:
                if offset < page.count:
                    raise DiditAPIError(
                        f"Inconsistent pagination metadata: received {offset} of "
                        f"{page.count} sessions without next page",
                        status_code=502,
                    )
                break

        truncated = bool(
            max_sessions is not None
            and len(reports) >= max_sessions
            and (
                page.next is not None or (remote_count is not None and remote_count > len(reports))
            )
        )

        return BatchReconciliationReport(
            total_evaluated=len(reports),
            drift_count=drift_count,
            missing_local_count=missing_local_count,
            missing_remote_count=missing_remote_count,
            truncated=truncated,
            remote_count=remote_count,
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

    def generate_pdf_report(
        self,
        session_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> bytes:
        """Download compliance PDF report for a verification session.

        Invokes GET /v3/session/{session_id}/generate-pdf/ returning raw binary PDF content.
        Uses a default 60-second read timeout per upstream recommendation for media rendering.

        Args:
            session_id: The unique identifier of the verification session.
            options: Optional per-request HTTP options.

        Returns:
            bytes: The binary PDF file content.

        Raises:
            ValueError: If session_id is empty or whitespace.
            DiditNotFoundError: If the session does not exist.
            DiditAPIError: If the remote endpoint returns an error or invalid PDF format.
        """
        if not session_id or not session_id.strip():
            raise ValueError("session_id must not be empty")

        if options is None:
            eff_options = RequestOptions(timeout=60.0)
        elif options.timeout is None:
            eff_options = RequestOptions(
                idempotency_key=options.idempotency_key,
                timeout=60.0,
                max_retries=options.max_retries,
                headers=options.headers,
                deadline=options.deadline,
            )
        else:
            eff_options = options

        resp = self._requestor.request(
            "GET", f"/session/{session_id.strip()}/generate-pdf/", options=eff_options
        )
        magic_ok = resp.content.startswith(b"%PDF-")
        content_type_lower = resp.headers.get("content-type", "").lower()
        mime_ok = (
            "application/pdf" in content_type_lower
            or "application/octet-stream" in content_type_lower
        )
        if not (magic_ok and mime_ok):
            raise DiditAPIError(
                "Invalid PDF report response received from server",
                status_code=502,
            )
        return resp.content

    get_pdf_report = generate_pdf_report

    def download_pdf_report(
        self,
        session_id: str,
        destination: Path | str,
        *,
        force: bool = False,
        options: RequestOptions | None = None,
    ) -> Path:
        """Download compliance PDF report and save securely to disk with private permissions.

        Invokes GET /v3/session/{session_id}/generate-pdf/ and atomically writes
        binary content to destination enforcing private (0600 on POSIX) permissions.

        Args:
            session_id: The unique identifier of the verification session.
            destination: Target file path on disk.
            force: If True, overwrite target file if it already exists.
            options: Optional per-request HTTP options.

        Returns:
            Path: The resolved destination path of the saved PDF file.

        Raises:
            ValueError: If session_id is empty or whitespace.
            FileExistsError: If destination file exists and force is False.
            DiditNotFoundError: If session does not exist.
            DiditAPIError: If remote endpoint returns an error or invalid PDF format.
        """
        dest_path = Path(destination).resolve()
        pdf_bytes = self.generate_pdf_report(session_id, options=options)
        _secure_write_bytes(dest_path, pdf_bytes, force=force)
        return dest_path

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

    async def update_status(
        self,
        session_id: str,
        new_status: ManualSessionStatus | SessionStatus | str,
        nodes_to_resubmit: list[str] | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Update status of an existing session asynchronously.

        Endpoint: PATCH /v3/session/{session_id}/update-status/
        Restricted by upstream Didit contract to manual reviewer transitions:
        'Approved', 'Declined', or 'Resubmitted'.
        """
        if not session_id or not session_id.strip():
            raise ValueError("session_id must not be empty")

        status_val = _validate_manual_status(new_status)
        payload: dict[str, Any] = {"new_status": status_val}
        if nodes_to_resubmit is not None:
            payload["nodes_to_resubmit"] = nodes_to_resubmit

        resp = await self._requestor.request(
            "PATCH",
            f"/session/{session_id.strip()}/update-status/",
            json=payload,
            options=options,
        )
        return SessionResponse.model_validate(resp.json())

    async def resubmit(
        self,
        session_id: str,
        nodes_to_resubmit: list[str] | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Request document or biometric resubmission for an existing session asynchronously.

        Invokes PATCH /v3/session/{session_id}/update-status/ with status 'Resubmitted'.

        Args:
            session_id: The unique identifier of the verification session.
            nodes_to_resubmit: Optional list of upstream workflow step node IDs to resubmit
                (e.g. ['document-verification-node', 'face-liveness-node']), matching
                workflow studio step keys or decision warnings.
            options: Optional per-request HTTP options.

        Returns:
            SessionResponse: The updated session with requires_resubmission=True.
        """
        return await self.update_status(
            session_id,
            SessionStatus.RESUBMITTED,
            nodes_to_resubmit=nodes_to_resubmit,
            options=options,
        )

    async def list(
        self,
        *,
        status: SessionStatus | str | None = None,
        session_kind: Literal["user"] = "user",
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
        status_str, norm_country, date_from_str, date_to_str = _validate_session_list_filters(
            status=status,
            session_kind=session_kind,
            country=country,
            limit=limit,
            offset=offset,
            date_from=date_from,
            date_to=date_to,
        )
        params: dict[str, Any] = {"limit": limit, "offset": offset, "session_kind": "user"}
        if status_str is not None:
            params["status"] = status_str
        if vendor_data is not None:
            params["vendor_data"] = vendor_data
        if norm_country is not None:
            params["country"] = norm_country
        if workflow_id is not None:
            params["workflow_id"] = workflow_id
        if search is not None:
            params["search"] = search
        if date_from_str is not None:
            params["date_from"] = date_from_str
        if date_to_str is not None:
            params["date_to"] = date_to_str

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
        if observed is not None and observed.session_id != session_id:
            raise ValueError(
                f"ObservedSessionState session_id mismatch: expected '{session_id}', "
                f"got '{observed.session_id}'"
            )

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
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=True,
                remote_missing=remote_missing,
            )

        if remote_missing:
            return SessionReconciliationReport(
                session_id=session_id,
                local_status=observed.status,
                remote_status=None,
                status_drift=False,
                warning_codes_added=[],
                warning_codes_removed=[],
                local_missing=False,
                remote_missing=True,
            )

        local_status_val = (
            observed.status.value if isinstance(observed.status, SessionStatus) else observed.status
        )
        remote_status_val = (
            remote_status.value if isinstance(remote_status, SessionStatus) else remote_status
        )
        status_drift = local_status_val != remote_status_val

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
            remote_missing=False,
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
        page_size: int = 50,
        max_sessions: int | None = None,
        limit: int | None = None,
        options: RequestOptions | None = None,
    ) -> BatchReconciliationReport:
        """Reconcile a range of sessions fetched from Didit against a local data source
        asynchronously.
        """
        if since is not None and date_from is not None:
            raise ValueError("Specify either 'since' or 'date_from', not both")
        if until is not None and date_to is not None:
            raise ValueError("Specify either 'until' or 'date_to', not both")

        start = since if since is not None else date_from
        end = until if until is not None else date_to

        effective_page_size = limit if limit is not None else page_size
        if effective_page_size <= 0 or effective_page_size > 100:
            raise ValueError(f"page_size must be between 1 and 100, got {effective_page_size}")
        if max_sessions is not None and max_sessions <= 0:
            raise ValueError(f"max_sessions must be greater than 0, got {max_sessions}")

        effective_until = end if end is not None else datetime.now(timezone.utc)

        reports: list[SessionReconciliationReport] = []
        drift_count = 0
        missing_local_count = 0
        missing_remote_count = 0
        offset = 0
        remote_count: int | None = None

        while True:
            current_limit = effective_page_size
            if max_sessions is not None:
                current_limit = min(current_limit, max_sessions - len(reports))

            page = await self.list(
                date_from=start,
                date_to=effective_until,
                status=status,
                limit=current_limit,
                offset=offset,
                options=options,
            )
            if remote_count is None:
                remote_count = page.count

            if not page.results:
                if page.next is not None:
                    raise DiditAPIError(
                        "Didit pagination returned next page metadata without progress",
                        status_code=502,
                    )
                if offset < page.count and (max_sessions is None or len(reports) < max_sessions):
                    raise DiditAPIError(
                        f"Inconsistent pagination metadata: received {offset} of "
                        f"{page.count} sessions without next page",
                        status_code=502,
                    )
                break

            for item in page.results:
                if isinstance(source, AsyncSessionStateSource):
                    observed = await source.aget(item.session_id)
                else:
                    get_fn: Any = getattr(source, "get", None)
                    if inspect.iscoroutinefunction(get_fn):
                        observed = await get_fn(item.session_id)
                    else:
                        observed = await asyncio.to_thread(source.get, item.session_id)

                report = await self.reconcile(item.session_id, observed=observed, options=options)
                reports.append(report)
                if report.status_drift or report.warning_drift:
                    drift_count += 1
                if report.local_missing:
                    missing_local_count += 1
                if report.remote_missing:
                    missing_remote_count += 1
                if max_sessions is not None and len(reports) >= max_sessions:
                    break

            offset += len(page.results)
            if max_sessions is not None and len(reports) >= max_sessions:
                break

            if page.next is None:
                if offset < page.count:
                    raise DiditAPIError(
                        f"Inconsistent pagination metadata: received {offset} of "
                        f"{page.count} sessions without next page",
                        status_code=502,
                    )
                break

        truncated = bool(
            max_sessions is not None
            and len(reports) >= max_sessions
            and (
                page.next is not None or (remote_count is not None and remote_count > len(reports))
            )
        )

        return BatchReconciliationReport(
            total_evaluated=len(reports),
            drift_count=drift_count,
            missing_local_count=missing_local_count,
            missing_remote_count=missing_remote_count,
            truncated=truncated,
            remote_count=remote_count,
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

    async def generate_pdf_report(
        self,
        session_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> bytes:
        """Download compliance PDF report for a verification session asynchronously.

        Invokes GET /v3/session/{session_id}/generate-pdf/ returning raw binary PDF content.
        Uses a default 60-second read timeout per upstream recommendation for media rendering.

        Args:
            session_id: The unique identifier of the verification session.
            options: Optional per-request HTTP options.

        Returns:
            bytes: The binary PDF file content.

        Raises:
            ValueError: If session_id is empty or whitespace.
            DiditNotFoundError: If the session does not exist.
            DiditAPIError: If the remote endpoint returns an error or invalid PDF format.
        """
        if not session_id or not session_id.strip():
            raise ValueError("session_id must not be empty")

        if options is None:
            eff_options = RequestOptions(timeout=60.0)
        elif options.timeout is None:
            eff_options = RequestOptions(
                idempotency_key=options.idempotency_key,
                timeout=60.0,
                max_retries=options.max_retries,
                headers=options.headers,
                deadline=options.deadline,
            )
        else:
            eff_options = options

        resp = await self._requestor.request(
            "GET", f"/session/{session_id.strip()}/generate-pdf/", options=eff_options
        )
        magic_ok = resp.content.startswith(b"%PDF-")
        content_type_lower = resp.headers.get("content-type", "").lower()
        mime_ok = (
            "application/pdf" in content_type_lower
            or "application/octet-stream" in content_type_lower
        )
        if not (magic_ok and mime_ok):
            raise DiditAPIError(
                "Invalid PDF report response received from server",
                status_code=502,
            )
        return resp.content

    get_pdf_report = generate_pdf_report

    async def download_pdf_report(
        self,
        session_id: str,
        destination: Path | str,
        *,
        force: bool = False,
        options: RequestOptions | None = None,
    ) -> Path:
        """Download compliance PDF report asynchronously and save securely to disk.

        Invokes GET /v3/session/{session_id}/generate-pdf/ and atomically writes
        binary content to destination enforcing private (0600 on POSIX) permissions.

        Args:
            session_id: The unique identifier of the verification session.
            destination: Target file path on disk.
            force: If True, overwrite target file if it already exists.
            options: Optional per-request HTTP options.

        Returns:
            Path: The resolved destination path of the saved PDF file.

        Raises:
            ValueError: If session_id is empty or whitespace.
            FileExistsError: If destination file exists and force is False.
            DiditNotFoundError: If session does not exist.
            DiditAPIError: If remote endpoint returns an error or invalid PDF format.
        """
        dest_path = Path(destination).resolve()
        pdf_bytes = await self.generate_pdf_report(session_id, options=options)
        await asyncio.to_thread(_secure_write_bytes, dest_path, pdf_bytes, force=force)
        return dest_path

    adownload_pdf_report = download_pdf_report

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
