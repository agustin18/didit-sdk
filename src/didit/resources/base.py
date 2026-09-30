"""Base utilities and error handling for Didit API resources."""

import datetime
import email.utils
import re

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


SAFE_ERROR_HEADERS: frozenset[str] = frozenset(
    {
        "x-request-id",
        "retry-after",
        "content-type",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
)

SENSITIVE_HEADER_NAMES: frozenset[str] = frozenset(
    {"authorization", "x-api-key", "set-cookie", "cookie"}
)

_ERROR_CODE_REGEX = re.compile(r"^[A-Z][A-Z0-9_.:-]{0,63}$")
_REQUEST_ID_REGEX = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def handle_http_error(
    response: httpx.Response,
    *,
    capture_sensitive_response: bool = False,
) -> None:
    """Inspect HTTP response and raise appropriate typed exception on non-2xx status.

    When capture_sensitive_response is False (default), response_body and details
    are set to None, headers are restricted to a strict allowlist (SAFE_ERROR_HEADERS),
    and error_code/request_id are strictly validated to prevent PII and secret leaks
    into telemetry or APMs.
    """
    if response.is_success:
        return

    status = response.status_code
    body = response.text if capture_sensitive_response else None

    if capture_sensitive_response:
        headers = {
            k.lower(): v
            for k, v in response.headers.items()
            if k.lower() not in SENSITIVE_HEADER_NAMES
        }
    else:
        headers = {
            k.lower(): v for k, v in response.headers.items() if k.lower() in SAFE_ERROR_HEADERS
        }

    raw_req_id = response.headers.get("x-request-id") or response.headers.get("X-Request-Id")
    request_id = None
    if isinstance(raw_req_id, str) and _REQUEST_ID_REGEX.match(raw_req_id.strip()):
        request_id = raw_req_id.strip()

    error_code = None
    details = None
    try:
        json_data = response.json()
        if isinstance(json_data, dict):
            raw_code = json_data.get("error_code") or json_data.get("code")
            if isinstance(raw_code, str) and _ERROR_CODE_REGEX.match(raw_code.strip()):
                error_code = raw_code.strip()
            if capture_sensitive_response:
                details = json_data.get("details") or json_data.get("detail")
    except Exception:
        pass

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
