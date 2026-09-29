"""Cryptographic webhook signature verification and payload extraction."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping
from typing import Any, NoReturn

from didit.config import DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.errors import DiditSignatureError
from didit.models.webhook import WebhookPayload

_SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")


def _reject_non_finite(value: str) -> NoReturn:
    """Disallow non-standard JSON numbers (NaN, Infinity)."""
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


def decode_webhook_json(raw_body: bytes) -> dict[str, Any]:
    """Decode raw UTF-8 body rejecting non-standard JSON constants (NaN, Infinity)."""
    try:
        decoded = raw_body.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValueError("Webhook body is not valid UTF-8") from err

    value = json.loads(decoded, parse_constant=_reject_non_finite)
    if not isinstance(value, dict):
        raise ValueError("Webhook payload must be a JSON object")
    return value


def shorten_floats(value: Any) -> Any:
    """Normalize floats to integers when they have no fractional component.

    Didit canonical JSON signature (v2) requires float numbers like 2.0 to be
    serialized as integer 2. Booleans are preserved without integer coercion.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, list):
        return [shorten_floats(item) for item in value]
    if isinstance(value, dict):
        return {key: shorten_floats(val) for key, val in value.items()}
    return value


def canonical_json(body: dict[str, Any]) -> str:
    """Serialize a dictionary to compact canonical JSON matching Didit X-Signature-V2.

    Uses ensure_ascii=False so Unicode characters are encoded directly as UTF-8,
    and allow_nan=False to reject non-finite float numbers.
    """
    normalized = shorten_floats(body)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _signature_matches(expected_hex: str, supplied_signature: str | None) -> bool:
    """Safely verify signature format and compare bytes in constant time.

    Guards against TypeError on non-ASCII input and non-hex malformed values (M-04).
    """
    if not supplied_signature or _SHA256_HEX.fullmatch(supplied_signature) is None:
        return False
    return hmac.compare_digest(
        bytes.fromhex(expected_hex),
        bytes.fromhex(supplied_signature),
    )


def compute_signature(
    secret: str,
    body: dict[str, Any] | bytes | str,
    *,
    version: str = "v2",
) -> str:
    """Compute HMAC-SHA256 signature for a payload.

    Args:
        secret: Webhook shared secret.
        body: Payload dictionary, raw bytes, or string.
        version: "v2" for canonical JSON or "v1" for raw bytes.
    """
    if version == "v2":
        if isinstance(body, dict):
            payload_bytes = canonical_json(body).encode("utf-8")
        elif isinstance(body, bytes):
            payload_bytes = body
        else:
            payload_bytes = body.encode("utf-8")
    elif version == "v1":
        if isinstance(body, bytes):
            payload_bytes = body
        elif isinstance(body, str):
            payload_bytes = body.encode("utf-8")
        else:
            payload_bytes = canonical_json(body).encode("utf-8")
    else:
        raise ValueError(f"Unsupported signature version: {version!r}. Expected 'v1' or 'v2'.")

    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def timestamp_is_fresh(
    timestamp: Any, max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS
) -> bool:
    """Validate that a webhook timestamp is within the acceptable freshness window."""
    if isinstance(timestamp, bool):
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    return abs(int(time.time()) - ts) <= max_age_seconds


def verify_webhook_signature(
    raw_body: bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    max_age_seconds: int | None = None,
) -> bool:
    """Verify cryptographic authenticity and freshness of an incoming Didit webhook.

    Enforces authoritative signed timestamp freshness (H-01), UTF-8 canonical JSON (H-02),
    and safe signature validation avoiding remote 500s (M-04).
    """
    if not secret:
        return False

    max_age = DEFAULT_WEBHOOK_MAX_AGE_SECONDS if max_age_seconds is None else max_age_seconds

    lower_headers = {k.lower(): v for k, v in headers.items()}
    signature_v2 = lower_headers.get("x-signature-v2")
    signature_v1 = lower_headers.get("x-signature")

    if not signature_v2 and not signature_v1:
        return False

    try:
        body = decode_webhook_json(raw_body)
    except (ValueError, UnicodeDecodeError):
        return False

    signed_timestamp = body.get("timestamp")
    if signed_timestamp is None:
        # Fallback to created_at only if timestamp is absent
        signed_timestamp = body.get("created_at")

    if isinstance(signed_timestamp, bool) or not isinstance(signed_timestamp, (int, float)):
        return False

    signed_ts_int = int(signed_timestamp)
    if not timestamp_is_fresh(signed_ts_int, max_age):
        return False

    # Header is defense-in-depth: if present, it must strictly match signed timestamp
    header_timestamp = lower_headers.get("x-timestamp")
    if header_timestamp is not None:
        try:
            if int(header_timestamp.strip()) != signed_ts_int:
                return False
        except ValueError:
            return False

    if signature_v2:
        expected_v2 = compute_signature(secret, body, version="v2")
        if _signature_matches(expected_v2, signature_v2):
            return True

    if signature_v1:
        expected_v1 = compute_signature(secret, raw_body, version="v1")
        if _signature_matches(expected_v1, signature_v1):
            return True

    return False


def parse_webhook_payload(
    raw_body: bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    max_age_seconds: int | None = None,
) -> WebhookPayload:
    """Verify webhook signature and return validated WebhookPayload.

    Raises:
        DiditSignatureError: If the signature is invalid, missing, expired, or JSON is malformed.
    """
    try:
        body_dict = decode_webhook_json(raw_body)
    except (ValueError, UnicodeDecodeError) as err:
        raise DiditSignatureError("Invalid JSON or unsupported webhook format") from err

    if not verify_webhook_signature(raw_body, headers, secret, max_age_seconds=max_age_seconds):
        raise DiditSignatureError("Webhook signature verification failed or timestamp is expired")

    parsed = WebhookPayload.model_validate(body_dict)
    parsed.raw_data = body_dict
    return parsed
