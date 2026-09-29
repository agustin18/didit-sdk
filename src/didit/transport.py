"""HTTP transport, safe retry engine, and requestor implementations."""

from __future__ import annotations

import asyncio
import datetime
import email.utils
import random
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from didit._version import __version__
from didit.errors import (
    DiditConnectionError,
    DiditPoolTimeoutError,
    DiditTimeoutError,
)
from didit.resources.base import handle_http_error

SDK_USER_AGENT = f"didit-sdk-python/{__version__}"
SAFE_OR_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})


@dataclass(frozen=True)
class RequestOptions:
    """Per-request execution options."""

    idempotency_key: str | None = None
    timeout: float | httpx.Timeout | None = None
    max_retries: int | None = None
    headers: Mapping[str, str] | None = None


@dataclass(frozen=True)
class RetryPolicy:
    """Exponential backoff and retry policy with full jitter."""

    max_retries: int = 3
    base_delay: float = 0.5
    max_delay: float = 16.0
    backoff_factor: float = 2.0
    max_retry_after: float = 60.0
    jitter: bool = True

    def calculate_delay(self, attempt: int) -> float:
        """Calculate backoff duration for a given attempt (0-indexed)."""
        backoff = min(self.max_delay, self.base_delay * (self.backoff_factor**attempt))
        if self.jitter:
            return random.uniform(0.0, backoff)
        return backoff

    def parse_retry_after(self, retry_after_header: str | None) -> float | None:
        """Parse Retry-After header into seconds (supporting int/float and RFC 7231 date)."""
        if not retry_after_header:
            return None
        header_val = retry_after_header.strip()
        # 1. Try parsing numeric seconds
        try:
            val = float(header_val)
            return max(0.0, val)
        except ValueError:
            pass

        # 2. Try parsing HTTP-date (RFC 7231 / RFC 2822)
        try:
            dt = email.utils.parsedate_to_datetime(header_val)
            now = datetime.datetime.now(datetime.timezone.utc)
            delta = (dt - now).total_seconds()
            return max(0.0, delta)
        except Exception:
            return None


def should_retry(
    method: str,
    status_code: int | None,
    error: Exception | None,
    attempt: int,
    max_retries: int,
    idempotency_key: str | None = None,
) -> bool:
    """Determine whether an HTTP request or connection error should be retried."""
    if attempt >= max_retries:
        return False

    # Connection pool exhaustion must fail fast to avoid deadlocks
    if isinstance(error, httpx.PoolTimeout):
        return False

    # Check method idempotency or presence of idempotency key
    is_idempotent = method.upper() in SAFE_OR_IDEMPOTENT_METHODS or bool(idempotency_key)

    if error is not None:
        if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout)):
            # Safe to retry because TCP connection was not established
            return True
        if isinstance(error, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.RemoteProtocolError)):
            return is_idempotent
        return False

    if status_code is not None and status_code in (408, 429, 500, 502, 503, 504):
        return is_idempotent

    return False


def _resolve_url(base_url: str, path: str) -> str:
    """Combine base URL with path or return absolute URL unmodified."""
    if path.startswith(("http://", "https://")):
        return path
    clean_base = base_url.rstrip("/")
    clean_path = path.lstrip("/")
    return f"{clean_base}/{clean_path}"


def _build_headers(
    api_key: str,
    options: RequestOptions | None = None,
) -> dict[str, str]:
    """Construct per-request headers without mutating underlying client state."""
    headers: dict[str, str] = {
        "x-api-key": api_key,
        "Accept": "application/json",
        "User-Agent": SDK_USER_AGENT,
    }
    if options:
        if options.idempotency_key:
            headers["Idempotency-Key"] = options.idempotency_key
        if options.headers:
            headers.update(options.headers)
    return headers


def _merge_options(
    base: RequestOptions | None,
    override: RequestOptions | None,
) -> RequestOptions | None:
    """Merge client-level default options with per-request overrides."""
    if base is None:
        return override
    if override is None:
        return base
    headers = dict(base.headers or {})
    if override.headers:
        headers.update(override.headers)
    return RequestOptions(
        idempotency_key=override.idempotency_key or base.idempotency_key,
        timeout=override.timeout if override.timeout is not None else base.timeout,
        max_retries=override.max_retries if override.max_retries is not None else base.max_retries,
        headers=headers or None,
    )


class _SyncRequestor:
    """Synchronous request runner handling retries, idempotency, and error mapping."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        base_url: str,
        api_key: str,
        retry_policy: RetryPolicy | None = None,
        default_timeout: float | None = None,
        default_options: RequestOptions | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url
        self._api_key = api_key
        self._retry_policy = retry_policy or RetryPolicy()
        self._default_timeout = default_timeout
        self._default_options = default_options

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        options: RequestOptions | None = None,
    ) -> httpx.Response:
        """Execute HTTP request with safe retries and exponential backoff."""
        effective_opts = _merge_options(self._default_options, options)
        url = _resolve_url(self._base_url, path)
        headers = _build_headers(self._api_key, effective_opts)
        timeout = (
            effective_opts.timeout
            if (effective_opts and effective_opts.timeout is not None)
            else self._default_timeout
        )
        max_retries = (
            effective_opts.max_retries
            if (effective_opts and effective_opts.max_retries is not None)
            else self._retry_policy.max_retries
        )

        attempt = 0
        while True:
            try:
                response = self._client.request(
                    method=method,
                    url=url,
                    json=json,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                )
                if response.is_success:
                    return response

                if should_retry(
                    method=method,
                    status_code=response.status_code,
                    error=None,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    retry_after = self._retry_policy.parse_retry_after(
                        response.headers.get("retry-after")
                    )
                    if retry_after is not None and retry_after > self._retry_policy.max_retry_after:
                        # Exceeds max allowable wait; abort immediately
                        handle_http_error(response)

                    delay = (
                        retry_after
                        if retry_after is not None
                        else self._retry_policy.calculate_delay(attempt)
                    )
                    time.sleep(delay)
                    attempt += 1
                    continue

                handle_http_error(response)

            except httpx.PoolTimeout as exc:
                raise DiditPoolTimeoutError(
                    f"Connection pool acquisition timed out: {exc}"
                ) from exc

            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise DiditConnectionError(f"Failed to connect to Didit API: {exc}") from exc

            except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.RemoteProtocolError) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise DiditTimeoutError(f"Request timed out during transmission: {exc}") from exc


class _AsyncRequestor:
    """Asynchronous request runner handling retries, idempotency, and error mapping."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        base_url: str,
        api_key: str,
        retry_policy: RetryPolicy | None = None,
        default_timeout: float | None = None,
        default_options: RequestOptions | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url
        self._api_key = api_key
        self._retry_policy = retry_policy or RetryPolicy()
        self._default_timeout = default_timeout
        self._default_options = default_options

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        options: RequestOptions | None = None,
    ) -> httpx.Response:
        """Execute asynchronous HTTP request with safe retries and exponential backoff."""
        effective_opts = _merge_options(self._default_options, options)
        url = _resolve_url(self._base_url, path)
        headers = _build_headers(self._api_key, effective_opts)
        timeout = (
            effective_opts.timeout
            if (effective_opts and effective_opts.timeout is not None)
            else self._default_timeout
        )
        max_retries = (
            effective_opts.max_retries
            if (effective_opts and effective_opts.max_retries is not None)
            else self._retry_policy.max_retries
        )

        attempt = 0
        while True:
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    json=json,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                )
                if response.is_success:
                    return response

                if should_retry(
                    method=method,
                    status_code=response.status_code,
                    error=None,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    retry_after = self._retry_policy.parse_retry_after(
                        response.headers.get("retry-after")
                    )
                    if retry_after is not None and retry_after > self._retry_policy.max_retry_after:
                        handle_http_error(response)

                    delay = (
                        retry_after
                        if retry_after is not None
                        else self._retry_policy.calculate_delay(attempt)
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue

                handle_http_error(response)

            except httpx.PoolTimeout as exc:
                raise DiditPoolTimeoutError(
                    f"Connection pool acquisition timed out: {exc}"
                ) from exc

            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise DiditConnectionError(f"Failed to connect to Didit API: {exc}") from exc

            except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.RemoteProtocolError) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise DiditTimeoutError(f"Request timed out during transmission: {exc}") from exc
