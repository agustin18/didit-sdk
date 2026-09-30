# didit-sdk

[![CI](https://github.com/agustin18/didit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/agustin18/didit-sdk/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/didit-sdk.svg)](https://pypi.org/project/didit-sdk/)
[![Python versions](https://img.shields.io/pypi/pyversions/didit-sdk.svg)](https://pypi.org/project/didit-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Unofficial, community-maintained Python client for the [Didit](https://didit.me) Identity Verification & KYC API.

> [!NOTE]
> **Supported Scope**: `didit-sdk` strictly targets **Verification Sessions, Decision Extraction, and KYC Webhook Ingestion**. For detailed architectural boundaries, excluded APIs (KYB, Travel Rule, etc.), and stability guarantees, see [SUPPORTED_SCOPE.md](SUPPORTED_SCOPE.md).

> [!IMPORTANT]
> **Legal Notice**: This is an independent, community-driven open-source project and is **not** officially affiliated with, endorsed by, or sponsored by Didit Protocol Inc. All trademarks, service marks, and company names are the property of their respective owners. See [NOTICE](NOTICE) for details.

---

## Highlights

- **Ergonomic Sync & Async**: Dual-client architecture built on top of high-performance `httpx`.
- **Strictly Typed & Validated**: 100% type annotations (PEP 561 compliant with `py.typed`) and robust Pydantic v2 domain models.
- **Didit V3 API Alignment**: Full fidelity to upstream V3 schemas (`id_verifications[]`, `liveness_checks[]`, `face_matches[]`, `aml_screenings[]`, `reviews[]`, `warnings[]`) with forward compatibility (`extra="allow"`), verification warnings helper (`decision.has_warning(...)`), and backward-compatible property accessors.
- **Complete Session Lifecycle**: Covers all 10 documented Didit session statuses (`Not Started`, `In Progress`, `In Review`, `Approved`, `Declined`, `Expired`, `Abandoned`, `Kyc Expired`, `Resubmitted`, `Awaiting User`) with granular state inspection (`is_decided`, `is_closed`, `requires_review`, `requires_user_action`).
- **Cryptographic Security & DoS Defense**: Constant-time HMAC-SHA256 signature verification (`X-Signature-V2` & `X-Signature`), full UTF-8 Unicode canonical JSON support (`ensure_ascii=False`, `allow_nan=False`), authoritative signed body anti-replay verification with strict header matching, and bounded body limits (HTTP 413) to prevent memory exhaustion.
- **Webhook Deduplication**: Thread-safe in-memory and atomic Redis deduplication stores (`InMemoryWebhookDedupStore`, `RedisWebhookDedupStore`, `AsyncRedisWebhookDedupStore`) with configurable duplicate actions (`respond_ok`, `pass`, `raise`).
- **Multi-Framework Integrations**: Native adapters for **FastAPI** (`DiditWebhookGuard`), **Django** (`@didit_webhook_view`), and **Flask** (`@didit_webhook`).
- **Resilient HTTP Engine**: Deterministic jittered exponential backoff retries with fail-fast budget timers for transient errors (HTTP 429, 502, 503, 504).
- **High-Fidelity Sandbox Parity**: 16 official Didit sandbox outcome simulation slugs (`approve`, `decline_document_expired`, `decline_face_match_low_similarity`, `decline_aml_hit`, `review_face_match_borderline`, `review_aml_possible_match`, etc.) and calibrated 0–100 biometric confidence scoring.

---

## Installation

```bash
# Core SDK (httpx + pydantic)
pip install didit-sdk

# With framework integrations
pip install "didit-sdk[fastapi]"
pip install "didit-sdk[django]"
pip install "didit-sdk[flask]"

# With Redis webhook deduplication store
pip install "didit-sdk[redis]"

# All optional dependencies
pip install "didit-sdk[all]"
```

---

## Quickstart

### 1. Synchronous Client

```python
from didit import Didit, SessionStatus

# Initialize client (falls back to DIDIT_API_KEY environment variable if omitted)
client = Didit(api_key="your_api_key", webhook_secret="your_webhook_secret")

# Create a verification session with sandbox outcome scenario
session = client.sessions.create(
    vendor_data="user_12345",
    workflow_id="wf_kyc_standard",
    callback="https://yourapp.com/kyc/complete",
    language="es",
    sandbox_scenario="approve",
)

print(f"Verification URL: {session.url}")
print(f"Session ID: {session.session_id}")

# Fetch verification decision immediately:
decision = client.sessions.get_decision(session.session_id)

# Or poll until a terminal outcome (Approved or Declined) is reached:
decision = client.sessions.poll_decision(session.session_id, timeout=60.0, interval=2.0)
if decision.status == SessionStatus.APPROVED:
    print(f"User approved! Document: {decision.document.document_number}")
    if decision.has_warning("DOCUMENT_POOR_QUALITY"):
        print("Note: Document quality was flagged.")
```

### 2. Asynchronous Client (`asyncio`)

```python
import asyncio
from didit import AsyncDidit, SessionStatus


async def main():
    async with AsyncDidit(api_key="your_api_key") as client:
        session = await client.sessions.create(
            vendor_data="user_987",
            workflow_id="wf_kyc_standard",
        )
        print(f"Session URL: {session.url}")

        decision = await client.sessions.poll_decision(session.session_id, timeout=30.0)
        if decision.status.is_terminal:
            print(f"Final outcome: {decision.status}")


asyncio.run(main())
```

### 3. Session Listing & Pagination

Query verification sessions from Didit V3 (`GET /v3/sessions/`) with typed pagination and multi-attribute filtering:

```python
from didit import Didit, SessionStatus

client = Didit()

# Fetch paginated verification sessions
page = client.sessions.list(
    status=SessionStatus.APPROVED,
    vendor_data="user_12345",
    country="ESP",
    limit=50,
    offset=0,
)

print(f"Total matching sessions: {page.count}")
for item in page.results:
    print(f"- Session {item.session_id}: {item.status.value} (Workflow: {item.workflow_id})")
```

### 4. Snapshot Reconciliation (Drift Detection)

Audit your local database state against upstream Didit API snapshots to detect state divergence that may result from delivery gaps, stale local state, or other synchronization failures without exposing PII:

```python
from didit import Didit, ObservedSessionState, SessionStatus

client = Didit()

# Reconcile a single session snapshot
report = client.sessions.reconcile(
    "sess_12345",
    observed=ObservedSessionState(
        session_id="sess_12345",
        status=SessionStatus.IN_REVIEW,
        warning_codes=["SUSPECTED_FRAUD"],
    ),
)

if not report.is_in_sync:
    print(f"Drift detected! Remote status is {report.remote_status} (Local: {report.local_status})")
    print(f"Warnings added remotely: {report.warning_codes_added}")
    print(f"Warnings removed remotely: {report.warning_codes_removed}")


# Batch reconcile over a time window against your database with auto-pagination
class DatabaseSessionSource:
    def get(self, session_id: str) -> ObservedSessionState | None:
        row = db.find_session(session_id)
        if not row:
            return None
        return ObservedSessionState(
            session_id=row.id, status=row.status, warning_codes=row.warnings
        )


batch_report = client.sessions.reconcile_range(
    since="2026-01-01T00:00:00Z",
    until="2026-01-02T00:00:00Z",
    source=DatabaseSessionSource(),
    page_size=50,
    max_sessions=1000,
)
print(f"Audited {batch_report.total_evaluated} sessions: {batch_report.drift_count} drifts found.")
```

### 5. PII-Minimized Telemetry Event Sink

Attach a passive `DiditEventSink` to collect structured, privacy-safe SDK operational metrics (backoff retries, rate limits, duplicate webhooks, lease degradations/losses, and reconciliation drift). The event sink is strictly non-blocking: any exception raised inside `emit()` is safely caught and suppressed by the SDK to guarantee that metric reporting never fails core business operations:

```python
from didit import Didit, DiditEventSink, DiditSDKEvent


class MetricsEventSink:
    def emit(self, event: DiditSDKEvent) -> None:
        # PII-minimized: contains only structured identifiers, status enums, and timing metrics
        statsd.increment(f"didit.sdk.{event.event_type}")


client = Didit(event_sink=MetricsEventSink())
```

---

## Webhook Integrations & Tokenized Reservation Protocol

Didit dispatches signed HTTP POST events upon verification completion. `didit-sdk` provides native, production-grade adapters with streaming body limits (HTTP 413) and a **crash-recoverable tokenized reservation protocol** using Redis Lua CAS state machines:

- **Active Lease (`PROCESSING`)**: Acquired via a unique cryptographic worker token with a short lease (default `lease_ttl_seconds=30`). If a worker crashes (`SIGKILL`, OOM, reboot), the lease automatically expires so Didit's retries can be recovered by another worker.
- **Terminal Retention (`COMPLETED`)**: Upon a 2xx response, the reservation atomically transitions to `COMPLETED` with long retention (default `completed_ttl_seconds=86400`).
- **Concurrent Protection (`processing_action="retry"`)**: If a second delivery arrives while processing is in flight, the adapter returns HTTP 503 with `Retry-After: 5` so Didit retries after the lease expires.

### FastAPI

```python
from fastapi import FastAPI, APIRouter
from didit import WebhookPayload, SessionStatus, RedisWebhookReservationStore
from didit.integrations.fastapi import didit_webhook, DiditWebhookRoute

app = FastAPI()
store = RedisWebhookReservationStore.from_url("redis://localhost:6379/0")
router = APIRouter(route_class=DiditWebhookRoute)


@router.post("/webhooks/didit")
@didit_webhook(
    secret="whsec_...",
    dedup_store=store,
    lease_ttl_seconds=30,  # Lease while processing (auto-recovered on crash)
    completed_ttl_seconds=86400,  # 24h retention after 2xx completion
    duplicate_action="pass",  # At-least-once delivery to DB transaction boundary
    processing_action="retry",  # HTTP 503 with Retry-After: 5 for concurrent in-flight deliveries
)
async def handle_webhook(payload: WebhookPayload):
    # Enforce idempotency at the database/transaction boundary:
    async with db.transaction():
        if not await is_event_unprocessed(payload.event_id):
            return {"status": "already_processed"}

        if payload.status == SessionStatus.APPROVED:
            # Idempotently process approved KYC verification
            await mark_user_verified(payload.session_id)

    return {"status": "ok"}


app.include_router(router)
```

Alternatively, use `DiditWebhookGuard` as a FastAPI `Depends(...)` dependency. When using `DiditWebhookGuard` with a reservation store, the application is responsible for explicitly completing or releasing the reservation, or configuring `route_class=DiditWebhookRoute` on your router for automated lifecycle management:

```python
from fastapi import APIRouter, Depends, Request
from didit.integrations.fastapi import DiditWebhookGuard, DiditWebhookRoute

router = APIRouter(route_class=DiditWebhookRoute)
guard = DiditWebhookGuard(secret="whsec_...", dedup_store=store)


@router.post("/webhooks/didit")
async def handle_webhook_guard(payload: WebhookPayload = Depends(guard)):
    return {"status": "ok"}


app.include_router(router)
```

When using `DiditWebhookGuard` on standard routers without `DiditWebhookRoute`, manage the lifecycle explicitly via `await guard.complete_reservation(request)` or `await guard.release_claim(request)`.

> [!NOTE]
> **FastAPI Lifecycle & Background Tasks**:
> `DiditWebhookRoute` observes response status and dependency teardown at the ASGI boundary before committing `COMPLETED` or releasing the lease. Webhook endpoints should return standard, non-streaming responses. Note that FastAPI `BackgroundTasks` execute prior to final ASGI response delivery; keep background tasks lightweight or offload to a durable queue (e.g. Celery, ARQ, SQS).

> [!TIP]
> **Deduplication Semantics (`duplicate_action`)**:
> - `"pass"` (**default, recommended**): When an event has already reached `COMPLETED`, it is passed to your handler with `payload.is_duplicate = True`. This guarantees that if a process crashed during a previous attempt before committing to the database, Didit's delivery retries will still reach your handler, and you can enforce idempotency safely at the database transaction boundary.
> - `"respond_ok"`: Short-circuits with an immediate HTTP 200 OK without invoking your handler. Use only when downstream ingestion is already durable (e.g. transactional outbox or Kafka enqueueing).
> - `"raise"`: Raises an HTTP 409 Conflict.

### Django

```python
from django.http import HttpRequest, HttpResponse
from didit import WebhookPayload, SessionStatus, RedisWebhookReservationStore
from didit.integrations.django import didit_webhook_view

store = RedisWebhookReservationStore.from_url("redis://localhost:6379/0")


@didit_webhook_view(
    secret="whsec_...",
    dedup_store=store,
    lease_ttl_seconds=30,
    completed_ttl_seconds=86400,
)
def my_webhook_view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
    if payload.status == SessionStatus.APPROVED:
        ...
    return HttpResponse(status=200)
```

### Flask

```python
from flask import Flask
from didit import WebhookPayload, SessionStatus, RedisWebhookReservationStore
from didit.integrations.flask import didit_webhook

app = Flask(__name__)
store = RedisWebhookReservationStore.from_url("redis://localhost:6379/0")


@app.route("/webhooks/didit", methods=["POST"])
@didit_webhook(
    secret="whsec_...",
    dedup_store=store,
    lease_ttl_seconds=30,
    completed_ttl_seconds=86400,
)
def handle_didit(payload: WebhookPayload):
    if payload.status == SessionStatus.APPROVED:
        ...
    return {"status": "ok"}, 200
```

---

## Testing & Offline Simulation

Developing without live credentials or mock servers? Use the built-in simulator:

```python
from didit import SimulatedDidit, SessionStatus

# Create in-memory client
sim = SimulatedDidit(webhook_secret="test_secret")

# 1. Create a simulated session
session = sim.sessions.create(vendor_data="dev_user", workflow_id="wf_dev")
assert session.session_id.startswith("sim_")

# 2. Simulate user passing identity check
sim.approve_session(session.session_id)

decision = sim.sessions.get_decision(session.session_id)
assert decision.status == SessionStatus.APPROVED

# 3. Generate signed webhook payloads to test your local receiver
raw_body, headers = sim.generate_webhook_event(session.session_id)
# headers contain valid X-Signature-V2 and fresh X-Timestamp!
```

---

## Exception Handling

All client errors inherit from `DiditError`:

```python
from didit import Didit
from didit.errors import (
    DiditAuthenticationError,
    DiditNotFoundError,
    DiditRateLimitError,
    DiditServerError,
)

client = Didit()

try:
    decision = client.sessions.get_decision("non_existent_session")
except DiditNotFoundError:
    print("Session not found")
except DiditRateLimitError as exc:
    print(f"Rate limited. Retry after {exc.retry_after} seconds.")
except DiditAuthenticationError:
    print("Invalid API key")
except DiditServerError as exc:
    print(f"Didit server error ({exc.status_code}): {exc.response_body}")
```

> [!NOTE]
> **PII-Minimized Exception Handling**: By default, `DiditAPIError` purges raw `response_body` and error detail dictionaries to protect user PII and biometrics from leaking into logs or APM dashboards (e.g. Sentry, Datadog). To retain raw response bodies in development or sandboxes, initialize `Didit(..., capture_sensitive_response=True)` or set `DIDIT_CAPTURE_SENSITIVE_RESPONSE=1`.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DIDIT_API_KEY` | *None* (Required) | Your Didit secret API key |
| `DIDIT_BASE_URL` | `https://verification.didit.me/v3` | Didit API base URL |
| `DIDIT_WEBHOOK_SECRET` | *None* | Shared webhook HMAC secret |
| `DIDIT_TIMEOUT` | `30.0` | HTTP request timeout in seconds |
| `DIDIT_MAX_RETRIES` | `2` | Maximum retry attempts for transient errors |
| `DIDIT_CAPTURE_SENSITIVE_RESPONSE` | `0` (False) | When `0`/false, error exceptions purge response bodies to prevent PII leakage to APMs/logs |

---

## Development & Testing

```bash
# Clone the repository
git clone https://github.com/agustin18/didit-sdk.git
cd didit-sdk

# Install dependencies with uv
uv sync --extra dev

# Run unit tests with 100% coverage gate
uv run pytest --cov=didit --cov-report=term-missing

# Lint & Format check
uv run ruff check .
uv run ruff format --check .

# Strict type check
uv run mypy src/didit
```

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
