"""Sessions resource implementation for both synchronous and asynchronous clients."""

from __future__ import annotations

from typing import TYPE_CHECKING

from didit.models.decision import DecisionResponse
from didit.models.enums import Language
from didit.models.session import CreateSessionRequest, SessionResponse
from didit.resources.base import handle_http_error

if TYPE_CHECKING:
    import httpx


class SessionsResource:
    """Synchronous resource for managing Didit verification sessions."""

    def __init__(self, http_client: httpx.Client) -> None:
        self._http = http_client

    def create(
        self,
        vendor_data: str,
        *,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
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

        resp = self._http.post("/session/", json=payload)
        handle_http_error(resp)
        return SessionResponse.model_validate(resp.json())

    def get(self, session_id: str) -> SessionResponse:
        """Retrieve details and status for an existing verification session."""
        resp = self._http.get(f"/session/{session_id}/")
        handle_http_error(resp)
        return SessionResponse.model_validate(resp.json())

    def get_decision(self, session_id: str) -> DecisionResponse:
        """Retrieve the verification outcome and extracted checks (documents, biometrics, AML)."""
        resp = self._http.get(f"/session/{session_id}/decision/")
        handle_http_error(resp)
        data = resp.json()
        decision = DecisionResponse.model_validate(data)
        decision.raw_data = data
        return decision


class AsyncSessionsResource:
    """Asynchronous resource for managing Didit verification sessions."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self._http = http_client

    async def create(
        self,
        vendor_data: str,
        *,
        workflow_id: str,
        callback: str | None = None,
        language: Language | str | None = None,
    ) -> SessionResponse:
        """Create a new verification session asynchronously."""
        lang_str = language.value if isinstance(language, Language) else language
        payload = CreateSessionRequest(
            workflow_id=workflow_id,
            vendor_data=vendor_data,
            callback=callback,
            language=lang_str,
        ).model_dump(exclude_none=True)

        resp = await self._http.post("/session/", json=payload)
        handle_http_error(resp)
        return SessionResponse.model_validate(resp.json())

    async def get(self, session_id: str) -> SessionResponse:
        """Retrieve session status asynchronously."""
        resp = await self._http.get(f"/session/{session_id}/")
        handle_http_error(resp)
        return SessionResponse.model_validate(resp.json())

    async def get_decision(self, session_id: str) -> DecisionResponse:
        """Retrieve verification decision asynchronously."""
        resp = await self._http.get(f"/session/{session_id}/decision/")
        handle_http_error(resp)
        data = resp.json()
        decision = DecisionResponse.model_validate(data)
        decision.raw_data = data
        return decision
