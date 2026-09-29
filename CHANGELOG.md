# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-09-29

### Security & Contractual Fidelity Fixes
- **NEW-HIGH-01 (`workflow_version` Contractual Compatibility):** Updated `WebhookPayload.workflow_version` to `int | str | None = Field(default=None)` to accept integer workflow versions (e.g. `workflow_version: 4` used by upstream Didit production webhooks and fixtures) without triggering Pydantic `ValidationError` and remote 500 errors.
- **NEW-MEDIUM-01 (Malformed Unicode Surrogates & JSON Depth Guard):** Guarded `verify_webhook_signature` against `UnicodeEncodeError` (caused by un-paired lone surrogate codepoints e.g. `\ud800`), `ValueError`, and `RecursionError` in the canonical JSON serialization pipeline, returning `False` gracefully instead of throwing unhandled 500 exceptions.
- **NEW-MEDIUM-02 (Read-Only Compatibility Accessors & Multi-Node Preservation):** Converted `.document`, `.biometrics`, `.aml`, and `.review` on `DecisionResponse` into read-only compatibility properties to prevent destructive overwriting of multi-node Didit V3 verification arrays.
- **NEW-MEDIUM-03 (Immutability of Caller Dictionaries):** Deep-copied input dictionaries in `DecisionResponse._migrate_legacy_singular_fields` prior to populating plural arrays, ensuring caller-supplied dictionaries are never mutated in-place.
- **NEW-MEDIUM-04 (Simulator Webhook Event Type Alignment):** Updated `SimulatedDidit.generate_webhook_event` and `SimulatedAsyncDidit.generate_webhook_event` to emit `"webhook_type": "status.updated"` matching Didit V3 webhook standards.
- **NEW-MEDIUM-05 (State Machine & Polling Precision):** Added `is_ended_without_decision` (`Expired`, `Abandoned`) and `is_poll_complete` (`is_decided or is_ended_without_decision`) to `SessionStatus`. Updated `poll_decision()` across client and simulation resources to poll until `is_poll_complete`.
- **NEW-LOW/MEDIUM-06 (NFC Verifications Support):** Added `nfc_verifications: list[dict[str, Any]] = Field(default_factory=list)` to `DecisionResponse` to capture passport/eID chip authentication nodes.
- **Strict Literal Timestamp Matching:** Enforced exact literal string equality between `X-Timestamp` header and the signed payload `timestamp` integer (`header_timestamp == str(signed_timestamp)`), rejecting leading signs, padding zeroes, and float-formatted timestamps.
- **Packaging:** Included `NOTICE` file in `sdist` distribution targets in `pyproject.toml`.

## [0.1.1] - 2026-09-29

### Security & Correctness Fixes
- **H-01 (Anti-Replay Security Fix):** Webhook freshness verification now strictly treats the signed payload `timestamp` as the authoritative source of truth. Unauthenticated modifications to the `X-Timestamp` header can no longer be used to replay expired webhook events. If `X-Timestamp` is provided, it must strictly match the signed body timestamp.
- **H-02 (Canonical JSON Unicode Fix):** Enforced `ensure_ascii=False` and `allow_nan=False` in `canonical_json()`, ensuring valid Didit V2 signatures for identities and addresses containing non-ASCII / Unicode characters (such as "José", "Müller-Ünlü", or "北京") are properly verified instead of failing HMAC validation.
- **H-03 (Didit V3 API Decision Schema Alignment):** Refactored `DecisionResponse` to model Didit V3's plural feature arrays (`id_verifications`, `liveness_checks`, `face_matches`, `aml_screenings`, `reviews`), transitioning from `extra="ignore"` to `extra="allow"` to eliminate silent data loss of valid KYC outcomes. Provided full backward-compatible property accessors (`.document`, `.biometrics`, `.aml`, `.review`).
- **H-04 (Complete Session Statuses):** Expanded `SessionStatus` to support all 10 documented Didit lifecycle states (`Not Started`, `In Progress`, `In Review`, `Approved`, `Declined`, `Expired`, `Abandoned`, `Kyc Expired`, `Resubmitted`, `Awaiting User`). Added granular status inspector properties: `is_decided`, `is_closed`, `requires_review`, `requires_user_action`, alongside backward-compatible `is_terminal`.
- **M-04 (Signature Remote 500 Prevention):** Validated signature headers against 64-character SHA256 hex format and compared digests as raw bytes in constant time, preventing remote `TypeError` crashes on non-ASCII header input.
- **M-08 (Simulator High Fidelity):** Updated in-memory simulation storage to return deep copies of session and decision models (`model_copy(deep=True)`), preventing accidental in-memory state mutations. Added `timestamp`, `event_id`, and V3 decision structure to simulated webhook generators.

### Changed
- Clarified legal positioning: removed "Official-grade" phrasing across documentation and package docstrings in favor of "Unofficial, community-maintained Python client".
- Extracted trademark notices to dedicated `NOTICE` file; restored standard clean MIT text to `LICENSE` for clean SPDX detection.

## [0.1.0] - 2026-09-29

### Added
- Synchronous client (`Didit`) powered by `httpx.Client`.
- Asynchronous client (`AsyncDidit`) powered by `httpx.AsyncClient`.
- Identity sessions resource with `create`, `get`, `get_decision`, and `poll_decision`.
- Cryptographic HMAC-SHA256 signature verifier supporting canonical JSON float normalization (`X-Signature-V2`) and legacy raw body (`X-Signature`).
- Timestamp freshness window verification mitigating replay attacks.
- FastAPI dependency guard (`DiditWebhookGuard`) with constant-time verification.
- Offline zero-network simulation clients (`SimulatedDidit`, `SimulatedAsyncDidit`) with mock webhook generation.
- Typed exception hierarchy (`DiditError`, `DiditAuthenticationError`, `DiditNotFoundError`, `DiditRateLimitError`, `DiditServerError`, `DiditSignatureError`, `DiditTimeoutError`).
- Pydantic v2 data models with forward compatibility (`extra="ignore"`).
- PEP 561 compliance marker (`py.typed`).
- 100% test coverage suite across statements and branches.
