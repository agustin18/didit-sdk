"""Tests for exception hierarchy."""

from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditError,
    DiditNotFoundError,
    DiditRateLimitError,
    DiditServerError,
    DiditSignatureError,
)


class TestErrors:
    def test_didit_error_inheritance(self) -> None:
        assert issubclass(DiditConfigurationError, DiditError)
        assert issubclass(DiditSignatureError, DiditError)
        assert issubclass(DiditAPIError, DiditError)
        assert issubclass(DiditAuthenticationError, DiditAPIError)
        assert issubclass(DiditNotFoundError, DiditAPIError)
        assert issubclass(DiditRateLimitError, DiditAPIError)
        assert issubclass(DiditServerError, DiditAPIError)

    def test_didit_api_error_attributes_and_repr(self) -> None:
        err = DiditAPIError(
            "Resource missing",
            status_code=404,
            response_body='{"error": "not_found"}',
            headers={"x-request-id": "req_1"},
            error_code="RESOURCE_NOT_FOUND",
            details={"field": "id"},
        )
        assert str(err) == "Resource missing"
        assert err.status_code == 404
        assert err.response_body == '{"error": "not_found"}'
        assert err.headers == {"x-request-id": "req_1"}
        assert err.error_code == "RESOURCE_NOT_FOUND"
        assert err.details == {"field": "id"}
        assert repr(err) == (
            "DiditAPIError(status_code=404, error_code='RESOURCE_NOT_FOUND', "
            "message='Resource missing')"
        )

    def test_didit_rate_limit_error_retry_after(self) -> None:
        err = DiditRateLimitError(
            "Rate limit exceeded",
            status_code=429,
            retry_after=60.0,
            headers={"retry-after": "60"},
        )
        assert err.status_code == 429
        assert err.retry_after == 60.0
        assert err.error_code == "RATE_LIMIT_EXCEEDED"
