"""HTTP transport, safe retry engine, and requestor implementations."""

from __future__ import annotations

import asyncio
import contextlib
import os
import random
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from didit._version import __version__
from didit.errors import (
    DiditAPIError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditPoolTimeoutError,
    DiditTimeoutError,
)
from didit.events import (
    DiditEventSink,
    RateLimitObserved,
    RequestRetryScheduled,
    safe_emit,
)
from didit.resources.base import handle_http_error, parse_retry_after

SDK_USER_AGENT = f"didit-sdk-python/{__version__}"
SAFE_OR_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD"})
RESERVED_HEADERS = frozenset({"x-api-key", "host", "user-agent", "idempotency-key"})


@dataclass(frozen=True)
class RequestOptions:
    """Per-request execution options."""

    idempotency_key: str | None = None
    timeout: float | httpx.Timeout | None = None
    max_retries: int | None = None
    headers: Mapping[str, str] | None = None
    deadline: float | None = None


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
        return parse_retry_after(retry_after_header)


def _resolve_cause(exc: BaseException, capture: bool) -> BaseException | None:
    """Return exc if capture is enabled, otherwise None to suppress cause."""
    return exc if capture else None


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
        if isinstance(
            error,
            (
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                asyncio.TimeoutError,
                TimeoutError,
                httpx.RemoteProtocolError,
                httpx.ReadError,
                httpx.WriteError,
                httpx.CloseError,
            ),
        ):
            return is_idempotent
        return False

    if status_code is not None and status_code in (408, 429, 500, 502, 503, 504):
        return is_idempotent

    return False


def _resolve_url(base_url: str, path: str) -> str:
    """Combine base URL with path or validate same-origin absolute URL."""
    if path.startswith(("http://", "https://")):
        base_parts = urlsplit(base_url)
        target_parts = urlsplit(path)
        if (target_parts.scheme, target_parts.netloc) != (base_parts.scheme, base_parts.netloc):
            raise DiditConfigurationError(
                f"Cross-origin absolute URLs are not allowed: {path!r} "
                f"does not match base origin {base_url!r}"
            )
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
            for k in options.headers:
                if k.lower() in RESERVED_HEADERS:
                    raise DiditConfigurationError(
                        f"Overriding reserved header {k!r} via RequestOptions.headers is forbidden."
                    )
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
        deadline=override.deadline if override.deadline is not None else base.deadline,
    )


def _atomic_publish(tmp_path: Path, dest_path: Path, *, force: bool = False) -> None:
    """Atomically publish temporary file to destination path without TOCTOU overwrite."""
    if force:
        tmp_path.replace(dest_path)
        return

    try:
        os.link(tmp_path, dest_path)
        tmp_path.unlink(missing_ok=True)
    except FileExistsError as err:
        tmp_path.unlink(missing_ok=True)
        raise FileExistsError(
            f"File '{dest_path}' already exists. Use --force to overwrite."
        ) from err
    except (AttributeError, NotImplementedError, OSError) as exc:
        tmp_path.unlink(missing_ok=True)
        if dest_path.exists():
            raise FileExistsError(
                f"File '{dest_path}' already exists. Use --force to overwrite."
            ) from exc
        raise OSError(
            f"Filesystem at '{dest_path.parent}' does not support atomic link-based publication "
            "without overwrite. Operation aborted to prevent TOCTOU overwrite race. "
            "Use force=True to allow replacement."
        ) from exc


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
        capture_sensitive_response: bool = False,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url
        self._api_key = api_key
        self._retry_policy = retry_policy or RetryPolicy()
        self._default_timeout = default_timeout
        self._default_options = default_options
        self._capture_sensitive_response = capture_sensitive_response
        self._event_sink = event_sink

    def _execute_with_retry(
        self,
        method: str,
        url: str,
        path: str,
        headers: dict[str, str],
        effective_opts: RequestOptions | None,
        fn: Any,
    ) -> httpx.Response:
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
            if effective_opts and effective_opts.deadline is not None:
                remaining = effective_opts.deadline - time.monotonic()
                if remaining <= 0:
                    raise DiditTimeoutError("Request deadline exceeded before execution.")
                eff_timeout: float | httpx.Timeout | None = (
                    min(timeout, remaining) if isinstance(timeout, (int, float)) else remaining
                )
            else:
                eff_timeout = timeout

            try:
                response: httpx.Response = fn(eff_timeout)
                if response.is_success:
                    return response

                if response.status_code == 429:
                    safe_emit(
                        self._event_sink,
                        RateLimitObserved(
                            path=path,
                            retry_after=self._retry_policy.parse_retry_after(
                                response.headers.get("retry-after")
                            ),
                        ),
                    )

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
                        handle_http_error(
                            response,
                            capture_sensitive_response=self._capture_sensitive_response,
                        )

                    delay = (
                        retry_after
                        if retry_after is not None
                        else self._retry_policy.calculate_delay(attempt)
                    )
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason=f"http_{response.status_code}",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            )

                    time.sleep(delay)
                    attempt += 1
                    continue

                handle_http_error(
                    response,
                    capture_sensitive_response=self._capture_sensitive_response,
                )

            except httpx.PoolTimeout as exc:
                raise DiditPoolTimeoutError(
                    f"Connection pool acquisition timed out: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

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
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason="connect_error",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            ) from _resolve_cause(exc, self._capture_sensitive_response)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise DiditConnectionError(
                    f"Failed to connect to Didit API: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

            except (httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason="timeout",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            ) from _resolve_cause(exc, self._capture_sensitive_response)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise DiditTimeoutError(
                    f"Request timed out during transmission: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

            except (
                httpx.RemoteProtocolError,
                httpx.ReadError,
                httpx.WriteError,
                httpx.CloseError,
            ) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason="network_error",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            ) from _resolve_cause(exc, self._capture_sensitive_response)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise DiditConnectionError(
                    f"Network error during transmission: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        options: RequestOptions | None = None,
    ) -> httpx.Response:
        """Execute HTTP request with safe retries and exponential backoff.

        Enforces follow_redirects=False to prevent cross-origin credential leaks.
        Synchronous timeouts enforce socket-level limits and monotonic deadline budgets.
        """
        effective_opts = _merge_options(self._default_options, options)
        url = _resolve_url(self._base_url, path)
        headers = _build_headers(self._api_key, effective_opts)
        return self._execute_with_retry(
            method,
            url,
            path,
            headers,
            effective_opts,
            lambda eff_to: self._client.request(
                method=method,
                url=url,
                json=json,
                params=params,
                headers=headers,
                timeout=eff_to,
                follow_redirects=False,
            ),
        )

    def stream_download(
        self,
        path: str,
        dest_path: Path,
        *,
        force: bool = False,
        options: RequestOptions | None = None,
        validate_pdf: bool = True,
    ) -> Path:
        """Stream HTTP GET response directly to disk enforcing bounded memory,
        monotonic deadlines, safe retries, and private permissions.
        """
        dest_path = dest_path.resolve()
        if dest_path.exists() and not force:
            raise FileExistsError(f"File '{dest_path}' already exists. Use --force to overwrite.")

        dest_dir = dest_path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)

        effective_opts = _merge_options(self._default_options, options)
        url = _resolve_url(self._base_url, path)
        headers = _build_headers(self._api_key, effective_opts)

        staged_paths: list[Path] = []

        def _execute_stream(eff_timeout: float | httpx.Timeout | None) -> httpx.Response:
            while staged_paths:
                staged_paths.pop().unlink(missing_ok=True)

            tmp_fd, tmp_path_str = tempfile.mkstemp(dir=dest_dir, prefix=".didit_tmp_")
            tmp_path = Path(tmp_path_str)
            staged_paths.append(tmp_path)
            fd_closed = False

            try:
                with contextlib.suppress(AttributeError, OSError):
                    os.fchmod(tmp_fd, 0o600)

                with self._client.stream(
                    "GET",
                    url,
                    headers=headers,
                    timeout=eff_timeout,
                    follow_redirects=False,
                ) as response:
                    if response.status_code >= 400:
                        response.read()
                        return response

                    if validate_pdf:
                        content_type_lower = response.headers.get("content-type", "").lower()
                        mime_ok = (
                            "application/pdf" in content_type_lower
                            or "application/octet-stream" in content_type_lower
                        )
                        if not mime_ok:
                            raise DiditAPIError(
                                "Invalid PDF report response received from server",
                                status_code=502,
                            )

                    with os.fdopen(tmp_fd, "wb") as f:
                        fd_closed = True
                        first_chunk = True
                        for chunk in response.iter_bytes(chunk_size=65536):
                            if first_chunk:
                                if validate_pdf and not chunk.startswith(b"%PDF-"):
                                    raise DiditAPIError(
                                        "Invalid PDF report response received from server",
                                        status_code=502,
                                    )
                                first_chunk = False
                            f.write(chunk)

                        if first_chunk and validate_pdf:
                            raise DiditAPIError(
                                "Invalid PDF report response received from server",
                                status_code=502,
                            )

                        f.flush()
                        with contextlib.suppress(AttributeError, OSError):
                            os.fsync(f.fileno())

                    return response
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
            finally:
                if not fd_closed:
                    with contextlib.suppress(OSError):
                        os.close(tmp_fd)

        try:
            self._execute_with_retry("GET", url, path, headers, effective_opts, _execute_stream)
            tmp_path = staged_paths[-1]
            _atomic_publish(tmp_path, dest_path, force=force)
            with contextlib.suppress(AttributeError, OSError):
                os.chmod(dest_path, 0o600)
            return dest_path
        finally:
            while staged_paths:
                staged_paths.pop().unlink(missing_ok=True)


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
        capture_sensitive_response: bool = False,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url
        self._api_key = api_key
        self._retry_policy = retry_policy or RetryPolicy()
        self._default_timeout = default_timeout
        self._default_options = default_options
        self._capture_sensitive_response = capture_sensitive_response
        self._event_sink = event_sink

    async def _aexecute_with_retry(
        self,
        method: str,
        url: str,
        path: str,
        headers: dict[str, str],
        effective_opts: RequestOptions | None,
        fn: Any,
    ) -> httpx.Response:
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
            if effective_opts and effective_opts.deadline is not None:
                remaining = effective_opts.deadline - time.monotonic()
                if remaining <= 0:
                    raise DiditTimeoutError("Request deadline exceeded before execution.")
                eff_timeout: float | httpx.Timeout | None = (
                    min(timeout, remaining) if isinstance(timeout, (int, float)) else remaining
                )
                wall_clock_timeout: float | None = remaining
            else:
                eff_timeout = timeout
                if isinstance(timeout, (int, float)):
                    wall_clock_timeout = float(timeout)
                elif isinstance(timeout, httpx.Timeout) and timeout.read is not None:
                    wall_clock_timeout = float(timeout.read)
                else:
                    wall_clock_timeout = None

            try:
                coro = fn(eff_timeout)
                if wall_clock_timeout is not None:
                    response: httpx.Response = await asyncio.wait_for(
                        coro, timeout=wall_clock_timeout
                    )
                else:
                    response = await coro

                if response.is_success:
                    return response

                if response.status_code == 429:
                    safe_emit(
                        self._event_sink,
                        RateLimitObserved(
                            path=path,
                            retry_after=self._retry_policy.parse_retry_after(
                                response.headers.get("retry-after")
                            ),
                        ),
                    )

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
                        handle_http_error(
                            response,
                            capture_sensitive_response=self._capture_sensitive_response,
                        )

                    delay = (
                        retry_after
                        if retry_after is not None
                        else self._retry_policy.calculate_delay(attempt)
                    )
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason=f"http_{response.status_code}",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            )

                    await asyncio.sleep(delay)
                    attempt += 1
                    continue

                handle_http_error(
                    response,
                    capture_sensitive_response=self._capture_sensitive_response,
                )

            except httpx.PoolTimeout as exc:
                raise DiditPoolTimeoutError(
                    f"Connection pool acquisition timed out: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

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
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason="connect_error",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            ) from _resolve_cause(exc, self._capture_sensitive_response)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise DiditConnectionError(
                    f"Failed to connect to Didit API: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

            except (
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                asyncio.TimeoutError,
                TimeoutError,
            ) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason="timeout",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            ) from _resolve_cause(exc, self._capture_sensitive_response)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise DiditTimeoutError(
                    f"Request timed out during transmission: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

            except (
                httpx.RemoteProtocolError,
                httpx.ReadError,
                httpx.WriteError,
                httpx.CloseError,
            ) as exc:
                if should_retry(
                    method=method,
                    status_code=None,
                    error=exc,
                    attempt=attempt,
                    max_retries=max_retries,
                    idempotency_key=headers.get("Idempotency-Key"),
                ):
                    delay = self._retry_policy.calculate_delay(attempt)
                    safe_emit(
                        self._event_sink,
                        RequestRetryScheduled(
                            method=method,
                            url=url,
                            attempt=attempt + 1,
                            delay=delay,
                            reason="network_error",
                        ),
                    )
                    if effective_opts and effective_opts.deadline is not None:
                        remaining = effective_opts.deadline - time.monotonic()
                        if delay >= remaining or remaining <= 0:
                            raise DiditTimeoutError(
                                "Request deadline exceeded before retry backoff."
                            ) from _resolve_cause(exc, self._capture_sensitive_response)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise DiditConnectionError(
                    f"Network error during transmission: {exc}"
                ) from _resolve_cause(exc, self._capture_sensitive_response)

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        options: RequestOptions | None = None,
    ) -> httpx.Response:
        """Execute asynchronous HTTP request with safe retries and exponential backoff.

        Enforces follow_redirects=False to prevent cross-origin credential leaks,
        and applies an outer wall-clock timeout via asyncio.wait_for to prevent slow-drip
        transmission attacks.
        """
        effective_opts = _merge_options(self._default_options, options)
        url = _resolve_url(self._base_url, path)
        headers = _build_headers(self._api_key, effective_opts)
        return await self._aexecute_with_retry(
            method,
            url,
            path,
            headers,
            effective_opts,
            lambda eff_to: self._client.request(
                method=method,
                url=url,
                json=json,
                params=params,
                headers=headers,
                timeout=eff_to,
                follow_redirects=False,
            ),
        )

    async def astream_download(
        self,
        path: str,
        dest_path: Path,
        *,
        force: bool = False,
        options: RequestOptions | None = None,
        validate_pdf: bool = True,
    ) -> Path:
        """Stream HTTP GET response asynchronously directly to disk enforcing bounded memory,
        monotonic deadlines, slow-drip protection, safe retries, and private permissions.
        """
        dest_path = dest_path.resolve()
        if dest_path.exists() and not force:
            raise FileExistsError(f"File '{dest_path}' already exists. Use --force to overwrite.")

        dest_dir = dest_path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)

        effective_opts = _merge_options(self._default_options, options)
        url = _resolve_url(self._base_url, path)
        headers = _build_headers(self._api_key, effective_opts)

        staged_paths: list[Path] = []

        async def _execute_astream(eff_timeout: float | httpx.Timeout | None) -> httpx.Response:
            while staged_paths:
                staged_paths.pop().unlink(missing_ok=True)

            tmp_fd, tmp_path_str = tempfile.mkstemp(dir=dest_dir, prefix=".didit_tmp_")
            tmp_path = Path(tmp_path_str)
            staged_paths.append(tmp_path)
            fd_closed = False

            try:
                with contextlib.suppress(AttributeError, OSError):
                    os.fchmod(tmp_fd, 0o600)

                async with self._client.stream(
                    "GET",
                    url,
                    headers=headers,
                    timeout=eff_timeout,
                    follow_redirects=False,
                ) as response:
                    if response.status_code >= 400:
                        await response.aread()
                        return response

                    if validate_pdf:
                        content_type_lower = response.headers.get("content-type", "").lower()
                        mime_ok = (
                            "application/pdf" in content_type_lower
                            or "application/octet-stream" in content_type_lower
                        )
                        if not mime_ok:
                            raise DiditAPIError(
                                "Invalid PDF report response received from server",
                                status_code=502,
                            )

                    with os.fdopen(tmp_fd, "wb") as f:
                        fd_closed = True
                        first_chunk = True
                        async for chunk in response.aiter_bytes(chunk_size=65536):
                            if first_chunk:
                                if validate_pdf and not chunk.startswith(b"%PDF-"):
                                    raise DiditAPIError(
                                        "Invalid PDF report response received from server",
                                        status_code=502,
                                    )
                                first_chunk = False
                            f.write(chunk)

                        if first_chunk and validate_pdf:
                            raise DiditAPIError(
                                "Invalid PDF report response received from server",
                                status_code=502,
                            )

                        f.flush()
                        with contextlib.suppress(AttributeError, OSError):
                            os.fsync(f.fileno())

                    return response
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
            finally:
                if not fd_closed:
                    with contextlib.suppress(OSError):
                        os.close(tmp_fd)

        try:
            await self._aexecute_with_retry(
                "GET", url, path, headers, effective_opts, _execute_astream
            )
            tmp_path = staged_paths[-1]
            await asyncio.to_thread(_atomic_publish, tmp_path, dest_path, force=force)
            with contextlib.suppress(AttributeError, OSError):
                os.chmod(dest_path, 0o600)
            return dest_path
        finally:
            while staged_paths:
                staged_paths.pop().unlink(missing_ok=True)
