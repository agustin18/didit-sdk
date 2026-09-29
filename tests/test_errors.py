from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditRateLimitError,
    DiditServerError,
    DiditSignatureError,
    DiditTimeoutError,
)
from didit.resources.base import handle_http_error


class TestErrors:
    def test_didit_error_inheritance(self) -> None:
        assert issubclass(DiditConfigurationError, DiditError)
        assert issubclass(DiditSignatureError, DiditError)
        assert issubclass(DiditTimeoutError, DiditError)
        assert issubclass(DiditAPIError, DiditError)
        assert issubclass(DiditAuthenticationError, DiditAPIError)
        assert issubclass(DiditPermissionError, DiditAuthenticationError)
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
            request_id="req_1",
            details={"field": "id"},
        )
        assert str(err) == "Resource missing"
        assert err.status_code == 404
        assert err.response_body == '{"error": "not_found"}'
        assert err.headers == {"x-request-id": "req_1"}
        assert err.error_code == "RESOURCE_NOT_FOUND"
        assert err.request_id == "req_1"
        assert err.details == {"field": "id"}
        assert repr(err) == (
            "DiditAPIError(status_code=404, error_code='RESOURCE_NOT_FOUND', "
            "request_id='req_1', message='Resource missing')"
        )

    def test_didit_rate_limit_error_retry_after(self) -> None:
        err = DiditRateLimitError(
            "Rate limit exceeded",
            status_code=429,
            retry_after=60.0,
            headers={"retry-after": "60"},
            request_id="req_rl",
        )
        assert err.status_code == 429
        assert err.retry_after == 60.0
        assert err.error_code == "RATE_LIMIT_EXCEEDED"
        assert err.request_id == "req_rl"

    def test_handle_http_error_pii_safe_and_403_separation(self) -> None:
        import httpx
        import pytest

        # 403 Forbidden raises DiditPermissionError with sanitized message
        res_403 = httpx.Response(
            403,
            json={"error_code": "KEY_EXPIRED", "detail": "Sensitive PII user data"},
            headers={"X-Request-Id": "req_secret_403"},
            request=httpx.Request("GET", "https://api.didit.me/v1/session/"),
        )
        with pytest.raises(DiditPermissionError) as exc_info:
            handle_http_error(res_403)
        assert "Sensitive PII" not in str(exc_info.value)
        assert "status=403" in str(exc_info.value)
        assert "code=KEY_EXPIRED" in str(exc_info.value)
        assert "request_id=req_secret_403" in str(exc_info.value)
        assert exc_info.value.response_body is not None
        assert "Sensitive PII" in exc_info.value.response_body
