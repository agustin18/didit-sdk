"""Sessions resource implementation for both synchronous and asynchronous clients."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from didit.errors import (
    DiditConnectionError,
    DiditRateLimitError,
    DiditServerError,
    DiditTimeoutError,
)
from didit.models.decision import DecisionResponse
from didit.models.enums import Language, SessionStatus
from didit.models.session import CreateSessionRequest, SessionResponse
from didit.transport import RequestOptions, _AsyncRequestor, _SyncRequestor

if TYPE_CHECKING:
    import httpx


class SessionsResource:
    """Synchronous resource for managing Didit verification sessions."""

    def __init__(self, requester: _SyncRequestor | httpx.Client) -> None:
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
                max_retries=options.max_retries if options else None,
                headers=options.headers if options else None,
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

    def __init__(self, requester: _AsyncRequestor | httpx.AsyncClient) -> None:
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
                max_retries=options.max_retries if options else None,
                headers=options.headers if options else None,
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
