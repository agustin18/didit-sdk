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


class DiditDedupError(DiditError):
    """Raised when webhook deduplication storage operations fail."""


class DiditDedupSaturationError(DiditDedupError):
    """Raised when in-memory deduplication store saturates without expired entries to evict."""


class DiditTimeoutError(DiditError):
    """Raised when an operation such as polling exceeds the configured timeout limit."""


class DiditPoolTimeoutError(DiditTimeoutError):
    """Raised when connection pool acquisition times out under high concurrency."""


class DiditConnectionError(DiditError):
    """Raised on network connectivity, DNS, or socket connection errors."""

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.request_id = request_id


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
        request_id: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
        self.headers = dict(headers) if headers else {}
        self.error_code = error_code
        self.request_id = request_id
        self.details = details

    def __repr__(self) -> str:
        parts = [f"status_code={self.status_code}"]
        if self.error_code:
            parts.append(f"error_code={self.error_code!r}")
        if self.request_id:
            parts.append(f"request_id={self.request_id!r}")
        parts.append(f"message={str(self)!r}")
        return f"{self.__class__.__name__}({', '.join(parts)})"


class DiditAuthenticationError(DiditAPIError):
    """Raised on 401 Unauthorized responses (invalid or missing API key)."""


class DiditPermissionError(DiditAuthenticationError):
    """Raised on 403 Forbidden responses (insufficient permissions or inactive key)."""


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
        request_id: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            response_body=response_body,
            headers=headers,
            error_code="RATE_LIMIT_EXCEEDED",
            request_id=request_id,
        )
        self.retry_after = retry_after


class DiditServerError(DiditAPIError):
    """Raised on 5xx Internal Server Error responses."""
