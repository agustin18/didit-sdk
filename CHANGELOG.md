# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-01

### Added
- **Direct-to-Disk PDF Report Download (`sessions.download_pdf_report()` / `sessions.adownload_pdf_report()`):**
  - Streamlined compliance PDF download directly to filesystem paths with atomic temporary-swap write and private POSIX `0600` permissions.
  - Implemented across sync, async, and in-memory simulated clients (`SimulatedDidit` / `SimulatedAsyncDidit`).
  - Supports `--force` flag for explicit file overwrite control.
- **Strict Diagnostic Probe Gate (`didit doctor --strict`):**
  - Flag for automated CI/CD and deployment pipelines that exits with code 1 (`CONNECTIVITY_UNAVAILABLE`) if Didit upstream healthcheck or latency probes are unreachable.
- **Zero-Degradation Compatibility & Live Contract Matrix:**
  - Comprehensive backward-compatibility suite (`tests/test_v020_compatibility.py`) ensuring zero breaking changes across all 46 public symbols from v0.2.0.
  - Automated sandbox contract matrix (`tests/test_contract_matrix.py`) validating all 16 Didit sandbox scenarios, additive schema drift resilience (`extra="allow"`), and warning code catalog normalization.
  - Scheduled GitHub Actions workflow (`.github/workflows/live-contract.yml`) for periodic live contract verification.
- **Contractual Precision & Upstream OpenAPI Drift Monitoring:**
  - Enforced strict enum validation on `CallbackMethod` (`INITIATOR`, `DESKTOP`, `BOTH`) and `ResubmitFeature` (`OCR`, `LIVENESS`, `FACE_MATCH`), eliminating loose string union bypasses while preserving backward-compatible case normalization.
  - Fail-closed normalization in `_normalize_nodes_to_resubmit()`: rejects unrecognized strings, malformed shorthand, and non-resubmittable organizational KYB steps across objects, dictionaries, and string shorthands.
  - Arbitrary JSON metadata typing via `JsonValue` for session creation (`client.sessions.create(metadata=...)`), supporting dictionaries, primitives, and lists.
  - Truthful `UpdateSessionStatusResponse` model preserving unconfirmed status (`status: None`) while recording intention in `requested_status` when Didit V3 returns only `{"session_id": ...}` without an immediate status confirmation.
  - Full simulation fidelity: `SimulatedDidit` and `SimulatedAsyncDidit` retain `callback_method` and `metadata` on created `SessionResponse` objects.
  - Dedicated upstream contract test suite (`tests/test_upstream_openapi_drift.py`) monitoring critical supported contracts against official live Didit OpenAPI definitions.
- **Session Lifecycle Completeness (`client.sessions.resubmit()` / `async_client.sessions.resubmit()` & `update_status()`):**
  - Request document or biometric resubmission via `PATCH /v3/session/{session_id}/update-status/` with target status `Resubmitted` and optional `nodes_to_resubmit` list.
  - Update session status via `PATCH /v3/session/{session_id}/update-status/` with runtime validation restricting transitions to manual review statuses: `Approved`, `Declined`, or `Resubmitted` (`ManualSessionStatus`).
  - Added typed `ResubmitInfo` domain model and `requires_resubmission` property on both `SessionResponse` and `DecisionResponse`.
  - Privacy safeguards: `redacted_dump()` and allowlist `__repr__` / `__str__` for `SessionResponse` redact sensitive session tokens and URLs while strictly preserving `extra="allow"` for forward-compatibility.
  - Full offline simulation parity (`SimulatedDidit` and `SimulatedAsyncDidit` support `resubmit()` and `update_status()` with state updates on sessions and decisions).
- **Compliance PDF Report Generation (`client.sessions.generate_pdf_report()` / `async_client.sessions.generate_pdf_report()`):**
  - Download official verification PDF reports via `GET /v3/session/{session_id}/generate-pdf/` as raw binary bytes.
  - 60.0s default timeout tailored to upstream document generation latencies.
  - Binary header (`%PDF-`) and MIME (`application/pdf` or `application/octet-stream`) format validation, raising `DiditAPIError(status_code=502)` on corrupt or invalid responses.
- **Developer CLI (`didit`):**
  - Production-grade CLI tool for session inspection, lifecycle operations, webhook verification, and system diagnostics.
  - Zero argv secrets: reads credentials exclusively via environment variables (`DIDIT_API_KEY`, `DIDIT_WEBHOOK_SECRET`) or secure files (`--api-key-file`, `--secret-file`).
  - Hardened webhook signature verification: accepts signed payloads via `--body-file` or `--stdin`, validates positive integer `--tolerance`, and provides fail-safe `--skip-freshness-check` with stderr warnings.
  - Atomic POSIX `0600` private file creation for PDF reports using temporary swap-files and `--force` overwrite protection, with cross-platform handle cleanup on Windows.
  - Universal JSON contract: custom `JSONAwareArgumentParser` ensures structured error envelopes (`{"status": "error", "error": {"code": ..., "message": ...}}`) even on argument parsing errors.
  - Privacy-by-default output: `session get`, `session list`, and `session create` redact sensitive tokens and URLs across text and JSON modes unless `--include-sensitive` is explicitly supplied.
  - Diagnostic `didit doctor`: probes root unauthenticated `/system/healthcheck/` for network connectivity without fail-open, authenticates credentials safely via probe without touching customer KYC data, and inspects secret configuration without character length leakage.
  - Sandbox scenario catalog explorer (`didit sandbox scenarios`) probing live scenarios from `/v1/sandbox/scenarios/` with a static 16-scenario offline fallback.
  - Full pagination controls on `didit session list` (`--limit`, `--offset`, `--all`, `--max-sessions`) with parameter validation.
- **Session Listing & Pagination (`client.sessions.list()` / `async_client.sessions.list()`):**
  - Query upstream `GET /v3/sessions/` with comprehensive filtering (`status`, `vendor_data`, `country`, `workflow_id`, `search`, `date_from`, `date_to`) and pagination (`limit`, `offset`).
  - Typed `SessionListPage` and `SessionListItem` models for ergonomic consumption.
- **Snapshot Reconciliation Engine (`sessions.reconcile()` / `sessions.reconcile_range()`):**
  - State verification against remote Didit API snapshots, detecting status drift and warning code additions/removals (`ObservedSessionState`, `SessionReconciliationReport`, `BatchReconciliationReport`).
  - Multi-page auto-pagination across full time windows with configurable `page_size` and safety `max_sessions` caps. Added `truncated: bool` and `remote_count: int | None` to `BatchReconciliationReport` for caller visibility into batch bounds.
  - Fail-explicit validation against upstream pagination corruption: raises `DiditAPIError(status_code=502)` if `next` page metadata exists without progress or if pagination terminates prematurely while received sessions are fewer than remote count.
  - Pluggable state protocols (`SessionStateSource` and `AsyncSessionStateSource`) supporting synchronous and asynchronous database adapters.
  - Strict PII-minimized design: reconciliation reports carry only identifiers, statuses, and warning codes (no discrete or speculative `missed_events`). Allowlist-based `redacted_dump()` and `__str__ = __repr__` for `SessionListItem` and `SessionListPage` redact bearer tokens and query URLs.
- **PII-Minimized Telemetry Event Sink Protocol (`DiditEventSink`):**
  - Protocol for passive observability without breaking SDK operations: `safe_emit()` isolates consumer exceptions synchronously.
  - PII-minimized typed events: `RequestRetryScheduled`, `RateLimitObserved`, `WebhookDuplicateObserved`, `WebhookLeaseDegraded`, `WebhookLeaseLost` (with fixed allowlisted reason literals: `"lease_cas_failed"`, `"lease_release_failed"`, `"lease_release_cas_failed"`), and `ReconciliationDriftObserved`.
  - Native integration with HTTP transport backoff retries, rate limits, session reconciliation drift, and webhook lease failures across FastAPI, Django, and Flask.
- **Tokenized Webhook Reservation Protocol (Distributed Redis Lease & In-Memory Parity):**
  - Distributed tokenized reservation store with atomic Lua CAS primitives (`reserve`, `complete`, `release`, `renew`) preventing concurrent processing races and duplicate execution across distributed workers.
  - Decoupled `lease_ttl_seconds` (default: 30s) from `completed_ttl_seconds` (default: 86400s), ensuring crash recovery from OOM/SIGKILL before Didit retry delivery windows.
  - Single-key Redis Cluster compatibility using keys formatted as `didit:webhook:<namespace>:<sha256(event_id)>` with explicit rejection of `{}` curly braces in namespaces to prevent hot shard bottlenecks.
  - Lua same-token TTL refresh via `redis.call('EXPIRE', KEYS[1], ARGV[2])` and In-Memory parity to enable clean recovery from ambiguous network disconnects.
  - Full automated lifecycle management across web framework adapters:
    - **FastAPI:** Route decorator `@didit_webhook` observing endpoint execution to automatically mark 2xx responses as `COMPLETED` and auto-release non-2xx responses (e.g. 404, 500) and exceptions. `DiditWebhookGuard` dependency for custom lifecycles.
    - **Django:** `@didit_webhook_view` auto-completing 2xx responses and auto-releasing non-2xx responses / exceptions.
    - **Flask:** `@didit_webhook` auto-completing 2xx responses and auto-releasing non-2xx responses / exceptions.
  - Typed `DiditDuplicateWebhookError` exception subclassing `DiditDedupError` with `event_id` and `state` context.
  - Safe `FAIL_OPEN` semantics: `reserve()` returns `ReservationAttempt(state=ACQUIRED, degraded=True)` for availability; `complete()`, `release()`, and `renew()` return `False` when Redis is unreachable to prevent false confirmation of distributed mutual exclusion extensions.
  - Exception unwinding protection: `DiditWebhookRoute` captures and emits `WebhookLeaseLost` if claim release fails during exception unwinding without shadowing the original handler exception.

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
