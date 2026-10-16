"""Risk resource implementations for synchronous and asynchronous clients."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import JsonValue

from didit.events import DiditEventSink
from didit.models.risk import (
    EmailRiskResponse,
    IPRiskResponse,
    PhoneRiskResponse,
    RiskSignals,
)
from didit.transport import RequestOptions, _AsyncRequestor, _SyncRequestor

if TYPE_CHECKING:
    import httpx


def _build_signals_payload(signals: RiskSignals | dict[str, Any] | None) -> dict[str, Any] | None:
    if signals is None:
        return None
    if isinstance(signals, RiskSignals):
        return signals.model_dump(exclude_none=True)
    if isinstance(signals, dict):
        return signals
    raise TypeError(f"signals must be a RiskSignals or dict, got {type(signals).__name__}")


class RiskResource:
    """Synchronous resource for Didit Standalone Risk APIs."""

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

    def email(
        self,
        email: str,
        *,
        country_code: str | None = None,
        signals: RiskSignals | dict[str, Any] | None = None,
        vendor_data: str | None = None,
        metadata: JsonValue | None = None,
        enable_social: bool = False,
        options: RequestOptions | None = None,
    ) -> EmailRiskResponse:
        """Perform standalone risk scoring for an email address without OTP verification."""
        if not email or not email.strip():
            raise ValueError("email must not be empty")

        payload: dict[str, Any] = {"email": email.strip()}
        if country_code is not None:
            payload["country_code"] = country_code
        sig_data = _build_signals_payload(signals)
        if sig_data is not None:
            payload["signals"] = sig_data
        if vendor_data is not None:
            payload["vendor_data"] = vendor_data
        if metadata is not None:
            payload["metadata"] = metadata
        if enable_social:
            payload["enable_social"] = True

        resp = self._requestor.request(
            "POST",
            "/email/risk/",
            json=payload,
            options=options,
        )
        return EmailRiskResponse.model_validate(resp.json())

    def phone(
        self,
        phone_number: str,
        *,
        country_code: str | None = None,
        signals: RiskSignals | dict[str, Any] | None = None,
        vendor_data: str | None = None,
        metadata: JsonValue | None = None,
        enable_social: bool = False,
        options: RequestOptions | None = None,
    ) -> PhoneRiskResponse:
        """Perform standalone risk scoring for a phone number without OTP verification."""
        if not phone_number or not phone_number.strip():
            raise ValueError("phone_number must not be empty")

        payload: dict[str, Any] = {"phone_number": phone_number.strip()}
        if country_code is not None:
            payload["country_code"] = country_code
        sig_data = _build_signals_payload(signals)
        if sig_data is not None:
            payload["signals"] = sig_data
        if vendor_data is not None:
            payload["vendor_data"] = vendor_data
        if metadata is not None:
            payload["metadata"] = metadata
        if enable_social:
            payload["enable_social"] = True

        resp = self._requestor.request(
            "POST",
            "/phone/risk/",
            json=payload,
            options=options,
        )
        return PhoneRiskResponse.model_validate(resp.json())

    def ip(
        self,
        ip_address: str,
        *,
        claimed_country: str | None = None,
        user_agent: str | None = None,
        vendor_data: str | None = None,
        metadata: JsonValue | None = None,
        options: RequestOptions | None = None,
    ) -> IPRiskResponse:
        """Perform standalone risk scoring and threat analysis for an IP address."""
        if not ip_address or not ip_address.strip():
            raise ValueError("ip_address must not be empty")

        payload: dict[str, Any] = {"ip_address": ip_address.strip()}
        if claimed_country is not None:
            payload["claimed_country"] = claimed_country
        if user_agent is not None:
            payload["user_agent"] = user_agent
        if vendor_data is not None:
            payload["vendor_data"] = vendor_data
        if metadata is not None:
            payload["metadata"] = metadata

        resp = self._requestor.request(
            "POST",
            "/ip/risk/",
            json=payload,
            options=options,
        )
        return IPRiskResponse.model_validate(resp.json())


class AsyncRiskResource:
    """Asynchronous resource for Didit Standalone Risk APIs."""

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

    async def email(
        self,
        email: str,
        *,
        country_code: str | None = None,
        signals: RiskSignals | dict[str, Any] | None = None,
        vendor_data: str | None = None,
        metadata: JsonValue | None = None,
        enable_social: bool = False,
        options: RequestOptions | None = None,
    ) -> EmailRiskResponse:
        """Asynchronously perform standalone risk scoring for an email address."""
        if not email or not email.strip():
            raise ValueError("email must not be empty")

        payload: dict[str, Any] = {"email": email.strip()}
        if country_code is not None:
            payload["country_code"] = country_code
        sig_data = _build_signals_payload(signals)
        if sig_data is not None:
            payload["signals"] = sig_data
        if vendor_data is not None:
            payload["vendor_data"] = vendor_data
        if metadata is not None:
            payload["metadata"] = metadata
        if enable_social:
            payload["enable_social"] = True

        resp = await self._requestor.request(
            "POST",
            "/email/risk/",
            json=payload,
            options=options,
        )
        return EmailRiskResponse.model_validate(resp.json())

    async def phone(
        self,
        phone_number: str,
        *,
        country_code: str | None = None,
        signals: RiskSignals | dict[str, Any] | None = None,
        vendor_data: str | None = None,
        metadata: JsonValue | None = None,
        enable_social: bool = False,
        options: RequestOptions | None = None,
    ) -> PhoneRiskResponse:
        """Asynchronously perform standalone risk scoring for a phone number."""
        if not phone_number or not phone_number.strip():
            raise ValueError("phone_number must not be empty")

        payload: dict[str, Any] = {"phone_number": phone_number.strip()}
        if country_code is not None:
            payload["country_code"] = country_code
        sig_data = _build_signals_payload(signals)
        if sig_data is not None:
            payload["signals"] = sig_data
        if vendor_data is not None:
            payload["vendor_data"] = vendor_data
        if metadata is not None:
            payload["metadata"] = metadata
        if enable_social:
            payload["enable_social"] = True

        resp = await self._requestor.request(
            "POST",
            "/phone/risk/",
            json=payload,
            options=options,
        )
        return PhoneRiskResponse.model_validate(resp.json())

    async def ip(
        self,
        ip_address: str,
        *,
        claimed_country: str | None = None,
        user_agent: str | None = None,
        vendor_data: str | None = None,
        metadata: JsonValue | None = None,
        options: RequestOptions | None = None,
    ) -> IPRiskResponse:
        """Asynchronously perform standalone risk scoring and threat analysis for an IP address."""
        if not ip_address or not ip_address.strip():
            raise ValueError("ip_address must not be empty")

        payload: dict[str, Any] = {"ip_address": ip_address.strip()}
        if claimed_country is not None:
            payload["claimed_country"] = claimed_country
        if user_agent is not None:
            payload["user_agent"] = user_agent
        if vendor_data is not None:
            payload["vendor_data"] = vendor_data
        if metadata is not None:
            payload["metadata"] = metadata

        resp = await self._requestor.request(
            "POST",
            "/ip/risk/",
            json=payload,
            options=options,
        )
        return IPRiskResponse.model_validate(resp.json())
