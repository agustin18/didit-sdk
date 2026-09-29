# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
