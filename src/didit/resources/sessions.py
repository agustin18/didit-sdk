"""Sessions resource implementation for both synchronous and asynchronous clients."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from didit.errors import DiditTimeoutError
from didit.models.decision import DecisionResponse
from didit.models.enums import Language
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
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Create a new verification session.

        Args:
            vendor_data: Internal customer/user reference identifier.
            workflow_id: Didit workflow ID configuration.
            callback: Optional URL Didit will redirect the user to after completing verification.
            language: Optional UI language code for the hosted flow (e.g. 'es', 'en').

        Returns:
            SessionResponse: Containing session_id, url, token, and status.
        """
        lang_str = language.value if isinstance(language, Language) else language
        payload = CreateSessionRequest(
            workflow_id=workflow_id,
            vendor_data=vendor_data,
            callback=callback,
            language=lang_str,
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
        options: RequestOptions | None = None,
    ) -> DecisionResponse:
        """Poll the decision endpoint until a terminal verification status is reached."""
        deadline = time.time() + timeout
        while True:
            decision = self.get_decision(session_id, options=options)
            if decision.status.is_poll_complete:
                return decision
            if time.time() + interval > deadline:
                raise DiditTimeoutError(
                    f"Polling decision for session '{session_id}' timed out after {timeout} seconds"
                )
            time.sleep(interval)


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
        options: RequestOptions | None = None,
    ) -> SessionResponse:
        """Create a new verification session asynchronously."""
        lang_str = language.value if isinstance(language, Language) else language
        payload = CreateSessionRequest(
            workflow_id=workflow_id,
            vendor_data=vendor_data,
            callback=callback,
            language=lang_str,
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
        options: RequestOptions | None = None,
    ) -> DecisionResponse:
        """Poll the decision endpoint asynchronously until a terminal status is reached."""
        deadline = time.time() + timeout
        while True:
            decision = await self.get_decision(session_id, options=options)
            if decision.status.is_poll_complete:
                return decision
            if time.time() + interval > deadline:
                raise DiditTimeoutError(
                    f"Polling decision for session '{session_id}' timed out after {timeout} seconds"
                )
            await asyncio.sleep(interval)
