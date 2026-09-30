# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-30

### Security & Forensic Hardening
- **Webhook Deduplication Resilience & Safe Delivery Semantics (RC2-H01):** Changed `duplicate_action` default to `"pass"` across FastAPI, Django, and Flask adapters, ensuring duplicate/retried events are passed to application handlers with `payload.is_duplicate = True` rather than silently swallowed with fake 200 OK responses if a worker crashes before completing processing. Implemented `release()` and `arelease()` methods across `WebhookDedupStore` and `AsyncWebhookDedupStore` protocols, `InMemoryWebhookDedupStore`, `RedisWebhookDedupStore`, and `AsyncRedisWebhookDedupStore`. Automatic rollback of pre-claimed deduplication keys upon uncaught handler exceptions or HTTP 5xx responses in Flask/Django (and manual helper `release_didit_claim` in FastAPI) prevents permanent suppression of genuine Didit webhook retries.
- **Cross-Origin Credential Leak Prevention (RC2-H02):** Explicitly enforced `follow_redirects=False` on all HTTP requests executed by `_SyncRequestor` and `_AsyncRequestor`. Callers supplying external `httpx.Client(follow_redirects=True)` instances can no longer leak sensitive `x-api-key` headers to external origins via 3xx redirect responses.
- **Async Socket Slow-Drip Wall-Clock Timeout (RC2-H03):** Wrapped async HTTP request executions in `asyncio.wait_for(..., timeout=wall_clock_timeout)`, guaranteeing strict wall-clock time bounds even against malicious servers streaming chunks below per-chunk timeout thresholds.
- **Verification Warning Schema Parity (RC2-H04):** Reconciled `VerificationWarning.warning_code` with Didit V3 schemas to inspect `self.code or self.risk or self.short_description or getattr(self, "log_type", None)`, ensuring `decision.has_warning(...)` correctly detects warning codes provided via the upstream `risk` field.
- **Streaming DoS Defense & Flask 3.1+ Upgrade (RC2-M01):** Bumped minimum Flask requirement to `flask>=3.1`. Enforced bounded chunked input stream inspection to reject oversized payloads with HTTP 413 even when `Content-Length` headers are absent.
- **PII Leakage Prevention & Privacy-Safe APM:** Redacted operator/reviewer usernames (`reviewed_by`) from `DecisionResponse.redacted_dump()`. Implemented allowlist-based representations for `DecisionResponse`, `IdVerificationResult`, and `WebhookPayload` to prevent accidental PII leakage in application logs.
- **Supply Chain Hardening:** Pinned GitHub Actions dependencies to immutable commit SHAs with version comments across all CI and release workflows.

### Added
- **Multi-Framework Webhook Adapters:**
  - **FastAPI:** `DiditWebhookGuard` with streaming bounded body limits (HTTP 413), constant-time signature verification, single-pass JSON parsing, and integrated deduplication.
  - **Django:** `@didit_webhook_view` decorator and `parse_django_webhook` with automatic CSRF exemption and body size capping.
  - **Flask:** `@didit_webhook` decorator and `parse_flask_webhook` with streaming chunked body bounding.
- **Resilient Transport & Retry Engine:** Full-jitter exponential backoff, RFC 7231 `Retry-After` header parser, transient error classification, idempotent retry policies, and per-request `RequestOptions(idempotency_key=..., timeout=..., max_retries=...)`.
- **Advanced Decision Polling:** Monotonic clock scheduling (`time.monotonic()`), unified deadline budgets, adaptive jittered intervals, transient error absorption, and customizable stopping predicates (`stop_when`, `stop_on_review`).
- **High-Fidelity Sandbox Parity:** Native `sandbox_scenario` configuration in session creation, support for 16 official Didit sandbox outcome slugs (`approve`, `decline_document_expired`, `decline_face_match_low_similarity`, `decline_aml_hit`, `review_face_match_borderline`, `review_aml_possible_match`, etc.), and 0–100 calibrated biometric confidence scores.
- **KYC Verification Warnings:** First-class typed `VerificationWarning` models, `decision.warnings`, and `decision.has_warning(...)` helper.
- **Redis Dedup Store Ergonomics:** Added `from_url()` convenience constructors to `RedisWebhookDedupStore` and `AsyncRedisWebhookDedupStore`.

### Changed
- Decoupled client resource operations from raw `httpx.Client` instances via clean `_SyncRequestor` and `_AsyncRequestor` transport layers. External client instances passed by callers are never modified or reconfigured.
- Refactored `DecisionResponse` singular feature properties (`.document`, `.biometrics`, `.aml`, `.review`) into read-only compatibility accessors preserving multi-node arrays.

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
