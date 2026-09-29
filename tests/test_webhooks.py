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

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ({"name": "José"}, '{"name":"José"}'),
            ({"name": "Müller-Ünlü"}, '{"name":"Müller-Ünlü"}'),
            ({"city": "北京"}, '{"city":"北京"}'),
        ],
    )
    def test_canonical_json_unicode_characters(
        self, body: dict[str, object], expected: str
    ) -> None:
        assert canonical_json(body) == expected

    def test_canonical_json_rejects_nan_and_infinity(self) -> None:
        with pytest.raises(ValueError):
            canonical_json({"val": float("nan")})
        with pytest.raises(ValueError):
            canonical_json({"val": float("inf")})


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
            "timestamp": int(time.time()),
        }

    def test_valid_v2_signature(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload_dict, version="v2")
        headers = {"X-Signature-V2": sig, "X-Timestamp": str(payload_dict["timestamp"])}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_valid_v1_legacy_signature(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, raw_body, version="v1")
        headers = {"X-Signature": sig, "X-Timestamp": str(payload_dict["timestamp"])}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_both_signatures_present_and_v2_valid(
        self, secret: str, payload_dict: dict[str, object]
    ) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        sig_v2 = compute_signature(secret, payload_dict, version="v2")
        sig_v1 = compute_signature(secret, raw_body, version="v1")
        headers = {
            "x-signature-v2": sig_v2,
            "x-signature": sig_v1,
            "x-timestamp": str(payload_dict["timestamp"]),
        }
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_replay_attack_with_refreshed_header_fails(self, secret: str) -> None:
        # H-01: payload timestamp is 1 hour old, attacker modifies only X-Timestamp header
        old_ts = int(time.time()) - 3600
        payload = {"session_id": "sess_replay", "status": "Approved", "timestamp": old_ts}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload, version="v2")

        # Forged fresh header
        headers = {
            "X-Signature-V2": sig,
            "X-Timestamp": str(int(time.time())),
        }
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_header_and_signed_timestamp_mismatch_fails(self, secret: str) -> None:
        now_ts = int(time.time())
        payload = {"session_id": "sess_1", "status": "Approved", "timestamp": now_ts}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload, version="v2")

        headers = {
            "X-Signature-V2": sig,
            "X-Timestamp": str(now_ts + 1),  # Mismatch by 1 second
        }
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_boolean_or_invalid_signed_timestamp_fails(self, secret: str) -> None:
        payload = {"session_id": "sess_bool", "status": "Approved", "timestamp": True}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload, version="v2")
        headers = {"X-Signature-V2": sig}
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_non_ascii_or_malformed_signature_does_not_raise(self, secret: str) -> None:
        # M-04: non-ASCII characters or malformed hex in signature header must not raise TypeError
        now_ts = int(time.time())
        payload = {"session_id": "sess_malformed", "status": "Approved", "timestamp": now_ts}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        headers_non_ascii = {
            "X-Signature-V2": "é" * 64,
            "X-Timestamp": str(now_ts),
        }
        assert verify_webhook_signature(raw_body, headers_non_ascii, secret) is False

        headers_bad_len = {
            "X-Signature-V2": "deadbeef",
            "X-Timestamp": str(now_ts),
        }
        assert verify_webhook_signature(raw_body, headers_bad_len, secret) is False

    def test_non_finite_json_in_webhook_fails(self, secret: str) -> None:
        raw_body = b'{"session_id": "s1", "score": NaN, "timestamp": 1700000000}'
        headers = {"X-Signature-V2": "a" * 64, "X-Timestamp": "1700000000"}
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_missing_or_empty_secret_fails(self, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
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
        payload_dict["timestamp"] = int(time.time()) - 1000  # 1000s ago
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload_dict, version="v2")
        headers = {"X-Signature-V2": sig, "X-Timestamp": str(payload_dict["timestamp"])}
        assert verify_webhook_signature(raw_body, headers, secret, max_age_seconds=300) is False

    def test_mismatched_signature_fails(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        headers = {"X-Signature-V2": "deadbeef" * 8, "X-Timestamp": str(payload_dict["timestamp"])}
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_missing_signatures_fails(self, secret: str, payload_dict: dict[str, object]) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        assert verify_webhook_signature(raw_body, {}, secret) is False

    def test_invalid_utf8_body_fails(self, secret: str) -> None:
        headers = {"X-Signature-V2": "a" * 64}
        assert verify_webhook_signature(b"\xff\xfe\x00", headers, secret) is False

    def test_malformed_header_timestamp_fails(
        self, secret: str, payload_dict: dict[str, object]
    ) -> None:
        raw_body = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload_dict, version="v2")
        headers = {"X-Signature-V2": sig, "X-Timestamp": "not-an-integer"}
        assert verify_webhook_signature(raw_body, headers, secret) is False

    def test_timestamp_is_fresh_boolean_guard(self) -> None:
        assert timestamp_is_fresh(True) is False
        assert timestamp_is_fresh(False) is False

    def test_fallback_to_created_at_when_timestamp_absent(self, secret: str) -> None:
        now_ts = int(time.time())
        payload = {"session_id": "sess_fallback", "status": "Approved", "created_at": now_ts}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload, version="v2")
        headers = {"X-Signature-V2": sig, "X-Timestamp": str(now_ts)}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_lone_surrogate_in_json_does_not_raise(self, secret: str) -> None:
        now_ts = int(time.time())
        raw = b'{"timestamp":' + str(now_ts).encode() + b',"value":"\\ud800"}'
        headers = {"X-Signature-V2": "a" * 64, "X-Timestamp": str(now_ts)}
        assert verify_webhook_signature(raw, headers, secret) is False

    def test_strict_literal_header_timestamp_matching(self, secret: str) -> None:
        now_ts = int(time.time())
        payload = {"session_id": "sess_strict", "status": "Approved", "timestamp": now_ts}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload, version="v2")

        # Non-literal integer formatting in header must be rejected
        for non_literal in [f"+{now_ts}", f"00{now_ts}", f" {now_ts} "]:
            headers = {"X-Signature-V2": sig, "X-Timestamp": non_literal}
            assert verify_webhook_signature(raw_body, headers, secret) is False

        # Exact literal match passes
        headers = {"X-Signature-V2": sig, "X-Timestamp": str(now_ts)}
        assert verify_webhook_signature(raw_body, headers, secret) is True

    def test_v2_requires_integer_timestamp(self, secret: str) -> None:
        now_ts = int(time.time())
        # Payload with float timestamp should fail under strict integer V2 contract
        payload_float = {"session_id": "s_flt", "status": "Approved", "timestamp": float(now_ts)}
        raw_body = json.dumps(payload_float, ensure_ascii=False).encode("utf-8")
        sig = compute_signature(secret, payload_float, version="v2")
        headers = {"X-Signature-V2": sig, "X-Timestamp": str(now_ts)}
        assert verify_webhook_signature(raw_body, headers, secret) is False


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
