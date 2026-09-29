"""Synchronous and asynchronous Didit client implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from didit.config import DiditConfig
from didit.errors import DiditConfigurationError
from didit.models.webhook import WebhookPayload
from didit.resources.sessions import AsyncSessionsResource, SessionsResource
from didit.webhooks import parse_webhook_payload, verify_webhook_signature


class Didit:
    """Synchronous client for the Didit Verification API."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        webhook_secret: str | None = None,
        config: DiditConfig | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        if config is not None:
            self._config = config
        else:
            self._config = DiditConfig.from_env(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                max_retries=max_retries,
                webhook_secret=webhook_secret,
            )

        self._manage_http = http_client is None
        self._http = http_client or httpx.Client(
            base_url=self._config.base_url,
            headers={
                "x-api-key": self._config.api_key,
                "Accept": "application/json",
            },
            timeout=self._config.timeout,
        )

        self.sessions = SessionsResource(self._http)

    @property
    def config(self) -> DiditConfig:
        """Client configuration instance."""
        return self._config

    @property
    def http_client(self) -> httpx.Client:
        """Underlying httpx.Client instance."""
        return self._http

    def verify_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
    ) -> bool:
        """Verify an incoming webhook's signature and timestamp freshness."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return verify_webhook_signature(
            raw_body, headers, wh_secret, max_age_seconds=max_age_seconds
        )

    def parse_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
    ) -> WebhookPayload:
        """Verify and parse an incoming webhook payload into a WebhookPayload object."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return parse_webhook_payload(raw_body, headers, wh_secret, max_age_seconds=max_age_seconds)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._manage_http:
            self._http.close()

    def __enter__(self) -> Didit:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncDidit:
    """Asynchronous client for the Didit Verification API."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        webhook_secret: str | None = None,
        config: DiditConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if config is not None:
            self._config = config
        else:
            self._config = DiditConfig.from_env(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                max_retries=max_retries,
                webhook_secret=webhook_secret,
            )

        self._manage_http = http_client is None
        self._http = http_client or httpx.AsyncClient(
            base_url=self._config.base_url,
            headers={
                "x-api-key": self._config.api_key,
                "Accept": "application/json",
            },
            timeout=self._config.timeout,
        )

        self.sessions = AsyncSessionsResource(self._http)

    @property
    def config(self) -> DiditConfig:
        """Client configuration instance."""
        return self._config

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Underlying httpx.AsyncClient instance."""
        return self._http

    def verify_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
    ) -> bool:
        """Verify an incoming webhook's signature and timestamp freshness."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return verify_webhook_signature(
            raw_body, headers, wh_secret, max_age_seconds=max_age_seconds
        )

    def parse_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
    ) -> WebhookPayload:
        """Verify and parse an incoming webhook payload into a WebhookPayload object."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return parse_webhook_payload(raw_body, headers, wh_secret, max_age_seconds=max_age_seconds)

    async def aclose(self) -> None:
        """Close the underlying asynchronous HTTP client."""
        if self._manage_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncDidit:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
