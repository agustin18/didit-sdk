"""Exception hierarchy for didit-sdk."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class DiditError(Exception):
    """Base exception for all Didit SDK errors."""


class DiditConfigurationError(DiditError):
    """Raised when the client is configured with missing or invalid parameters."""


class DiditSignatureError(DiditError):
    """Raised when a webhook signature fails cryptographic verification or freshness check."""


class DiditTimeoutError(DiditError):
    """Raised when an operation such as polling exceeds the configured timeout limit."""


class DiditAPIError(DiditError):
    """Raised when the Didit API returns an HTTP error status code."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response_body: str | None = None,
        headers: Mapping[str, str] | None = None,
        error_code: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
        self.headers = dict(headers) if headers else {}
        self.error_code = error_code
        self.details = details

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(status_code={self.status_code}, "
            f"error_code={self.error_code!r}, message={str(self)!r})"
        )


class DiditAuthenticationError(DiditAPIError):
    """Raised on 401 Unauthorized or 403 Forbidden responses (invalid API key)."""


class DiditNotFoundError(DiditAPIError):
    """Raised on 404 Not Found responses (session or resource does not exist)."""


class DiditRateLimitError(DiditAPIError):
    """Raised on 429 Too Many Requests responses."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 429,
        response_body: str | None = None,
        headers: Mapping[str, str] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            response_body=response_body,
            headers=headers,
            error_code="RATE_LIMIT_EXCEEDED",
        )
        self.retry_after = retry_after


class DiditServerError(DiditAPIError):
    """Raised on 5xx Internal Server Error responses."""
