"""Base utilities and error handling for Didit API resources."""

import contextlib

import httpx

from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditNotFoundError,
    DiditRateLimitError,
    DiditServerError,
)


def handle_http_error(response: httpx.Response) -> None:
    """Inspect HTTP response and raise appropriate typed exception on non-2xx status."""
    if response.is_success:
        return

    status = response.status_code
    body = response.text
    headers = dict(response.headers)

    error_code = None
    details = None
    try:
        json_data = response.json()
        if isinstance(json_data, dict):
            error_code = json_data.get("error_code") or json_data.get("code")
            details = json_data.get("details") or json_data.get("detail")
    except Exception:
        pass

    message = f"Didit API error ({status}): {body}"

    if status in (401, 403):
        raise DiditAuthenticationError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            details=details,
        )
    if status == 404:
        raise DiditNotFoundError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            details=details,
        )
    if status == 429:
        retry_after_str = headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_str:
            with contextlib.suppress(ValueError):
                retry_after = float(retry_after_str)
        raise DiditRateLimitError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            retry_after=retry_after,
        )
    if status >= 500:
        raise DiditServerError(
            message,
            status_code=status,
            response_body=body,
            headers=headers,
            error_code=error_code,
            details=details,
        )

    raise DiditAPIError(
        message,
        status_code=status,
        response_body=body,
        headers=headers,
        error_code=error_code,
        details=details,
    )
