"""Base utilities and error handling for Didit API resources."""

import datetime
import email.utils

import httpx

from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditRateLimitError,
    DiditServerError,
)


def parse_retry_after(retry_after_header: str | None) -> float | None:
    """Parse Retry-After header into seconds (supporting int/float and RFC 7231 date)."""
    if not retry_after_header:
        return None
    header_val = retry_after_header.strip()
    try:
        val = float(header_val)
        return max(0.0, val)
    except ValueError:
        pass

    try:
        dt = email.utils.parsedate_to_datetime(header_val)
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = (dt - now).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


SENSITIVE_HEADER_NAMES: frozenset[str] = frozenset(
    {"authorization", "x-api-key", "set-cookie", "cookie"}
)


def handle_http_error(
    response: httpx.Response,
    *,
    capture_sensitive_response: bool = False,
) -> None:
    """Inspect HTTP response and raise appropriate typed exception on non-2xx status.

    When capture_sensitive_response is False (default), response_body and details
    are set to None and sensitive headers are stripped to prevent PII and secret leaks
    into telemetry or APMs.
    """
    if response.is_success:
        return

    status = response.status_code
    body = response.text if capture_sensitive_response else None
    headers = {k: v for k, v in response.headers.items() if k.lower() not in SENSITIVE_HEADER_NAMES}

    error_code = None
    details = None
    try:
        json_data = response.json()
        if isinstance(json_data, dict):
            error_code = json_data.get("error_code") or json_data.get("code")
            if capture_sensitive_response:
                details = json_data.get("details") or json_data.get("detail")
    except Exception:
        pass

    request_id = headers.get("x-request-id") or headers.get("X-Request-Id")
    msg_parts = [f"Didit API request failed (status={status})"]
    if error_code:
        msg_parts.append(f"code={error_code}")
    if request_id:
        msg_parts.append(f"request_id={request_id}")
    message = " ".join(msg_parts)

    if status == 401:
        raise DiditAuthenticationError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            request_id=request_id,
            details=details,
        )
    if status == 403:
        raise DiditPermissionError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            request_id=request_id,
            details=details,
        )
    if status == 404:
        raise DiditNotFoundError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            request_id=request_id,
            details=details,
        )
    if status == 429:
        retry_after = parse_retry_after(headers.get("retry-after"))
        raise DiditRateLimitError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            request_id=request_id,
            retry_after=retry_after,
        )
    if status >= 500:
        raise DiditServerError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            request_id=request_id,
            details=details,
        )

    raise DiditAPIError(
        message,
        status_code=status,
        response_body=body,
        headers=headers,
        error_code=error_code,
        request_id=request_id,
        details=details,
    )
