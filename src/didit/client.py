"""Synchronous and asynchronous Didit client implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from didit.config import DiditConfig
from didit.errors import DiditConfigurationError
from didit.events import DiditEventSink
from didit.models.webhook import WebhookPayload
from didit.resources.sessions import AsyncSessionsResource, SessionsResource
from didit.transport import (
    RequestOptions,
    RetryPolicy,
    _AsyncRequestor,
    _SyncRequestor,
)
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
        capture_sensitive_response: bool | None = None,
        config: DiditConfig | None = None,
        http_client: httpx.Client | None = None,
        retry_policy: RetryPolicy | None = None,
        default_options: RequestOptions | None = None,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        if config is not None:
            if (
                api_key is not None
                or base_url is not None
                or timeout is not None
                or max_retries is not None
                or webhook_secret is not None
                or capture_sensitive_response is not None
            ):
                raise DiditConfigurationError(
                    "Cannot combine `config` with explicit configuration arguments "
                    "(api_key, base_url, timeout, max_retries, webhook_secret, "
                    "capture_sensitive_response). Pass either `config` or explicit arguments."
                )
            self._config = config
        else:
            self._config = DiditConfig.from_env(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                max_retries=max_retries,
                webhook_secret=webhook_secret,
                capture_sensitive_response=capture_sensitive_response,
            )

        self._manage_http = http_client is None
        self._http = http_client or httpx.Client(
            timeout=self._config.timeout,
        )
        if default_options and default_options.idempotency_key is not None:
            raise DiditConfigurationError(
                "idempotency_key cannot be set as a client-level default option. "
                "It must be provided per-request."
            )
        self._default_options = default_options
        self._retry_policy = retry_policy or RetryPolicy(
            max_retries=self._config.max_retries,
        )
        self._requestor = _SyncRequestor(
            self._http,
            base_url=self._config.base_url,
            api_key=self._config.api_key,
            retry_policy=self._retry_policy,
            default_timeout=self._config.timeout,
            default_options=self._default_options,
            capture_sensitive_response=self._config.capture_sensitive_response,
            event_sink=event_sink,
        )
        self._event_sink = event_sink
        self.sessions = SessionsResource(self._requestor, event_sink=self._event_sink)

    @property
    def config(self) -> DiditConfig:
        """Client configuration instance."""
        return self._config

    @property
    def event_sink(self) -> DiditEventSink | None:
        """Configured telemetry event sink."""
        return self._event_sink

    @property
    def http_client(self) -> httpx.Client:
        """Underlying httpx.Client instance."""
        return self._http

    @property
    def requestor(self) -> _SyncRequestor:
        """Underlying sync request runner."""
        return self._requestor

    def with_options(self, options: RequestOptions) -> Didit:
        """Return a new client clone with additional or overridden default options."""
        if options.idempotency_key is not None:
            raise DiditConfigurationError(
                "idempotency_key cannot be set as a client-level default option. "
                "It must be provided per-request."
            )
        return Didit(
            config=self._config,
            http_client=self._http,
            retry_policy=self._retry_policy,
            default_options=options,
            event_sink=self._event_sink,
        )

    def verify_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
        verify_freshness: bool = True,
    ) -> bool:
        """Verify an incoming webhook's signature and timestamp freshness."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return verify_webhook_signature(
            raw_body,
            headers,
            wh_secret,
            max_age_seconds=max_age_seconds,
            verify_freshness=verify_freshness,
        )

    def parse_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
        verify_freshness: bool = True,
    ) -> WebhookPayload:
        """Verify and parse an incoming webhook payload into a WebhookPayload object."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return parse_webhook_payload(
            raw_body,
            headers,
            wh_secret,
            max_age_seconds=max_age_seconds,
            verify_freshness=verify_freshness,
        )

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
        capture_sensitive_response: bool | None = None,
        config: DiditConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
        retry_policy: RetryPolicy | None = None,
        default_options: RequestOptions | None = None,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        if config is not None:
            if (
                api_key is not None
                or base_url is not None
                or timeout is not None
                or max_retries is not None
                or webhook_secret is not None
                or capture_sensitive_response is not None
            ):
                raise DiditConfigurationError(
                    "Cannot combine `config` with explicit configuration arguments "
                    "(api_key, base_url, timeout, max_retries, webhook_secret, "
                    "capture_sensitive_response). Pass either `config` or explicit arguments."
                )
            self._config = config
        else:
            self._config = DiditConfig.from_env(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                max_retries=max_retries,
                webhook_secret=webhook_secret,
                capture_sensitive_response=capture_sensitive_response,
            )

        self._manage_http = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=self._config.timeout,
        )
        if default_options and default_options.idempotency_key is not None:
            raise DiditConfigurationError(
                "idempotency_key cannot be set as a client-level default option. "
                "It must be provided per-request."
            )
        self._default_options = default_options
        self._retry_policy = retry_policy or RetryPolicy(
            max_retries=self._config.max_retries,
        )
        self._event_sink = event_sink
        self._requestor = _AsyncRequestor(
            self._http,
            base_url=self._config.base_url,
            api_key=self._config.api_key,
            retry_policy=self._retry_policy,
            default_timeout=self._config.timeout,
            default_options=self._default_options,
            capture_sensitive_response=self._config.capture_sensitive_response,
            event_sink=event_sink,
        )

        self.sessions = AsyncSessionsResource(self._requestor, event_sink=self._event_sink)

    @property
    def config(self) -> DiditConfig:
        """Client configuration instance."""
        return self._config

    @property
    def event_sink(self) -> DiditEventSink | None:
        """Configured telemetry event sink."""
        return self._event_sink

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Underlying httpx.AsyncClient instance."""
        return self._http

    @property
    def requestor(self) -> _AsyncRequestor:
        """Underlying async request runner."""
        return self._requestor

    def with_options(self, options: RequestOptions) -> AsyncDidit:
        """Return a new async client clone with additional or overridden default options."""
        if options.idempotency_key is not None:
            raise DiditConfigurationError(
                "idempotency_key cannot be set as a client-level default option. "
                "It must be provided per-request."
            )
        return AsyncDidit(
            config=self._config,
            http_client=self._http,
            retry_policy=self._retry_policy,
            default_options=options,
            event_sink=self._event_sink,
        )

    def verify_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
        verify_freshness: bool = True,
    ) -> bool:
        """Verify an incoming webhook's signature and timestamp freshness."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return verify_webhook_signature(
            raw_body,
            headers,
            wh_secret,
            max_age_seconds=max_age_seconds,
            verify_freshness=verify_freshness,
        )

    def parse_webhook(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
        *,
        secret: str | None = None,
        max_age_seconds: int | None = None,
        verify_freshness: bool = True,
    ) -> WebhookPayload:
        """Verify and parse an incoming webhook payload into a WebhookPayload object."""
        wh_secret = secret or self._config.webhook_secret
        if not wh_secret:
            raise DiditConfigurationError(
                "No webhook_secret configured on client. "
                "Provide secret parameter or configure DIDIT_WEBHOOK_SECRET."
            )
        return parse_webhook_payload(
            raw_body,
            headers,
            wh_secret,
            max_age_seconds=max_age_seconds,
            verify_freshness=verify_freshness,
        )

    async def aclose(self) -> None:
        """Close the underlying asynchronous HTTP client."""
        if self._manage_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncDidit:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
