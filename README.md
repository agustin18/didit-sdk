# didit-sdk

[![CI](https://github.com/agustin18/didit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/agustin18/didit-sdk/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/didit-sdk.svg)](https://pypi.org/project/didit-sdk/)
[![Python versions](https://img.shields.io/pypi/pyversions/didit-sdk.svg)](https://pypi.org/project/didit-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Unofficial, community-maintained Python client for the [Didit](https://didit.me) Identity Verification API.

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
- **High-Fidelity Sandbox Parity**: Predefined outcome simulation slugs (`approve`, `decline_document_expired`, `decline_face_mismatch`, `decline_aml_hit`, `review_suspicious`, `resubmit`) and calibrated 0–100 biometric confidence scoring.

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

---

## Webhook Integrations & Deduplication

Didit dispatches signed HTTP POST events upon verification completion. `didit-sdk` provides native, production-grade adapters with streaming body limits (HTTP 413) and distributed deduplication:

### FastAPI

```python
from fastapi import FastAPI, Depends
from didit import WebhookPayload, SessionStatus, RedisWebhookDedupStore
from didit.integrations.fastapi import DiditWebhookGuard

app = FastAPI()
guard = DiditWebhookGuard(
    secret="whsec_...",
    dedup_store=RedisWebhookDedupStore.from_url("redis://localhost:6379/0"),
    duplicate_action="respond_ok",
)


@app.post("/webhooks/didit")
async def handle_webhook(payload: WebhookPayload = Depends(guard)):
    if payload.status == SessionStatus.APPROVED:
        # Idempotently process approved KYC verification
        ...
    return {"status": "ok"}
```

### Django

```python
from django.http import HttpRequest, HttpResponse
from didit import WebhookPayload, SessionStatus
from didit.integrations.django import didit_webhook_view


@didit_webhook_view(secret="whsec_...")
def my_webhook_view(request: HttpRequest, payload: WebhookPayload) -> HttpResponse:
    if payload.status == SessionStatus.APPROVED:
        ...
    return HttpResponse(status=200)
```

### Flask

```python
from flask import Flask
from didit import WebhookPayload, SessionStatus
from didit.integrations.flask import didit_webhook

app = Flask(__name__)


@app.route("/webhooks/didit", methods=["POST"])
@didit_webhook(secret="whsec_...")
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

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DIDIT_API_KEY` | *None* (Required) | Your Didit secret API key |
| `DIDIT_BASE_URL` | `https://verification.didit.me/v3` | Didit API base URL |
| `DIDIT_WEBHOOK_SECRET` | *None* | Shared webhook HMAC secret |
| `DIDIT_TIMEOUT` | `30.0` | HTTP request timeout in seconds |
| `DIDIT_MAX_RETRIES` | `2` | Maximum retry attempts for transient errors |

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
