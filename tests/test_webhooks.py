"""Tests for cryptographic webhook verification and payload parsing."""

import hashlib
import hmac
import json
import time

import pytest

from didit.errors import DiditSignatureError
from didit.models.enums import SessionStatus
from didit.webhooks import (
    canonical_json,
    compute_signature,
    parse_webhook_payload,
    shorten_floats,
    timestamp_is_fresh,
    verify_webhook_signature,
)


class TestShortenFloats:
    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            (True, True),
            (False, False),
            (2.0, 2),
            (2.5, 2.5),
            (0.0, 0),
            (100, 100),
            ("test", "test"),
            (None, None),
            ([1.0, 2.5, [3.0]], [1, 2.5, [3]]),
            ({"a": 4.0, "b": {"c": 5.0, "d": 5.1}}, {"a": 4, "b": {"c": 5, "d": 5.1}}),
        ],
    )
    def test_shorten_floats_cases(self, input_val: object, expected: object) -> None:
        result = shorten_floats(input_val)
        assert result == expected
        if isinstance(input_val, float) and input_val.is_integer():
            assert isinstance(result, int)
        if isinstance(input_val, bool):
            assert isinstance(result, bool)


class TestCanonicalJson:
    def test_canonical_json_sorting_and_separators(self) -> None:
        body = {"z": 1, "a": 2.0, "m": {"b": 10.0, "a": 20}}
        canonical = canonical_json(body)
        assert canonical == '{"a":2,"m":{"a":20,"b":10},"z":1}'


class TestComputeSignature:
    def test_compute_signature_v2(self) -> None:
        secret = "secret_key"
        body = {"session_id": "s1", "score": 1.0}
        sig = compute_signature(secret, body, version="v2")
        expected = hmac.new(
            secret.encode("utf-8"),
            canonical_json(body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected

        # bytes input
        body_bytes = b'{"a":1}'
        assert (
            compute_signature(secret, body_bytes, version="v2")
            == hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        )

        # str input
        body_str = '{"a":1}'
        assert (
            compute_signature(secret, body_str, version="v2")
            == hmac.new(
                secret.encode("utf-8"), body_str.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        )

    def test_compute_signature_v1(self) -> None:
        secret = "secret_key"
        body_bytes = b'{"raw":"data"}'
        sig = compute_signature(secret, body_bytes, version="v1")
        expected = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        assert sig == expected

        # str input
        assert compute_signature(secret, '{"raw":"data"}', version="v1") == expected

        # dict input
        dict_body = {"raw": "data"}
        expected_dict = hmac.new(
            secret.encode("utf-8"),
            canonical_json(dict_body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert compute_signature(secret, dict_body, version="v1") == expected_dict

    def test_compute_signature_unsupported_version(self) -> None:
        with pytest.raises(ValueError, match="Unsupported signature version"):
            compute_signature("secret", {}, version="v3")


class TestTimestampFreshness:
    @pytest.mark.parametrize(
        ("ts", "offset", "max_age", "expected"),
        [
            (None, 0, 300, True),  # uses current time
            ("invalid", 0, 300, False),
            (None, 400, 300, False),  # 400s in the past
            (None, -400, 300, False),  # 400s in future
            (None, 200, 300, True),  # 200s in past
            (None, -200, 300, True),  # 200s in future
        ],
    )
    def test_timestamp_freshness(
        self, ts: str | None, offset: int, max_age: int, expected: bool
    ) -> None:
        tested_ts = int(time.time()) - offset if ts is None else ts
        assert timestamp_is_fresh(tested_ts, max_age_seconds=max_age) is expected


class TestVerifyWebhookSignature:
    @pytest.fixture
    def secret(self) -> str:
        return "whsec_test_12345"

    @pytest.fixture
    def payload_dict(self) -> dict[str, object]:
        return {
            "session_id": "sess_123",
            "status": "Approved",
            "created_at": int(time.time()),
        }

    def test_valid_v2_signature(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = compute_signature(secret, payload_dict, version="v2")
        headers = {"X-Signature-V2": sig}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_valid_v1_legacy_signature(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = compute_signature(secret, raw_body, version="v1")
        headers = {"X-Signature": sig}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_both_signatures_present_and_v2_valid(
        self, secret: str, payload_dict: dict[str, object]
    ) -> None:
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig_v2 = compute_signature(secret, payload_dict, version="v2")
        sig_v1 = compute_signature(secret, raw_body, version="v1")
        headers = {"x-signature-v2": sig_v2, "x-signature": sig_v1}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_timestamp_from_header(self, secret: str, payload_dict: dict[str, object]) -> None:
        payload_no_ts = {"session_id": "sess_123", "status": "Approved"}
        raw_body = json.dumps(payload_no_ts).encode("utf-8")
        sig = compute_signature(secret, payload_no_ts, version="v2")
        now_ts = str(int(time.time()))
        headers = {"X-Signature-V2": sig, "X-Timestamp": now_ts}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_missing_or_empty_secret_fails(self, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict).encode("utf-8")
        assert verify_webhook_signature(raw_body, {"x-signature-v2": "any"}, "") is False

    @pytest.mark.parametrize(
        "invalid_body",
        [
            b"invalid json{",
            b"[1, 2, 3]",
            b'"string value"',
        ],
    )
    def test_invalid_json_or_non_dict_body_fails(self, secret: str, invalid_body: bytes) -> None:
        headers = {"X-Signature-V2": "any"}
        assert verify_webhook_signature(invalid_body, headers, secret) is False

    def test_expired_timestamp_fails(self, secret: str, payload_dict: dict[str, object]) -> None:
        payload_dict["created_at"] = int(time.time()) - 1000  # 1000s ago
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = compute_signature(secret, payload_dict, version="v2")
        headers = {"X-Signature-V2": sig}
        assert verify_webhook_signature(raw_body, headers, secret, max_age_seconds=300) is False

    def test_mismatched_signature_fails(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict).encode("utf-8")
        headers = {"X-Signature-V2": "deadbeef" * 8}
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_missing_signatures_fails(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict).encode("utf-8")
        assert verify_webhook_signature(raw_body, {}, secret) is False


class TestParseWebhookPayload:
    @pytest.fixture
    def secret(self) -> str:
        return "whsec_test_parse"

    def test_successful_parse(self, secret: str) -> None:
        data = {
            "session_id": "sess_parsed",
            "status": "Approved",
            "created_at": int(time.time()),
            "workflow_id": "wf_abc",
        }
        raw_body = json.dumps(data).encode("utf-8")
        sig = compute_signature(secret, data, version="v2")
        headers = {"X-Signature-V2": sig}

        payload = parse_webhook_payload(raw_body, headers, secret)
        assert payload.session_id == "sess_parsed"
        assert payload.status == SessionStatus.APPROVED
        assert payload.workflow_id == "wf_abc"
        assert payload.raw_data == data

    def test_invalid_signature_raises_didit_signature_error(self, secret: str) -> None:
        data = {"session_id": "sess_1", "status": "Declined", "created_at": int(time.time())}
        raw_body = json.dumps(data).encode("utf-8")
        headers = {"X-Signature-V2": "invalid"}

        with pytest.raises(DiditSignatureError, match="Webhook signature verification failed"):
            parse_webhook_payload(raw_body, headers, secret)

    def test_invalid_json_raises_didit_signature_error(self, secret: str) -> None:
        with pytest.raises(DiditSignatureError, match="Invalid JSON or unsupported webhook format"):
            parse_webhook_payload(b"bad json", {"X-Signature-V2": "abc"}, secret)

    def test_non_dict_json_raises_didit_signature_error(self, secret: str) -> None:
        with pytest.raises(DiditSignatureError, match="Invalid JSON or unsupported webhook format"):
            parse_webhook_payload(b"[1, 2, 3]", {"X-Signature-V2": "abc"}, secret)

    def test_fallback_to_v1_when_v2_fails(self, secret: str) -> None:
        payload = {"session_id": "sess_1", "status": "Approved", "created_at": int(time.time())}
        raw_body = json.dumps(payload).encode("utf-8")
        sig_v1 = compute_signature(secret, raw_body, version="v1")
        # v2 is invalid, but v1 is valid
        headers = {"x-signature-v2": "bad_sig", "x-signature": sig_v1}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_both_signatures_invalid_returns_false(self, secret: str) -> None:
        payload = {"session_id": "sess_1", "status": "Approved", "created_at": int(time.time())}
        raw_body = json.dumps(payload).encode("utf-8")
        headers = {"x-signature-v2": "bad_sig_v2", "x-signature": "bad_sig_v1"}
        assert verify_webhook_signature(raw_body, headers, secret) is False
