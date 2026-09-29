# didit-sdk

[![CI](https://github.com/agustin18/didit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/agustin18/didit-sdk/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/didit-sdk.svg)](https://pypi.org/project/didit-sdk/)
[![Python versions](https://img.shields.io/pypi/pyversions/didit-sdk.svg)](https://pypi.org/project/didit-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Official-grade, community-maintained Python SDK for [Didit](https://didit.me) Identity Verification & KYC.

> [!IMPORTANT]
> **Legal Disclaimer**: This is an independent, community-driven open-source project and is **not** officially affiliated with, endorsed by, or sponsored by Didit Protocol Inc. All trademarks, service marks, and company names are the property of their respective owners.

---

## Highlights

- **Ergonomic Sync & Async**: Dual-client architecture built on top of high-performance `httpx`.
- **Strictly Typed & Validated**: 100% type annotations (PEP 561 compliant with `py.typed`) and robust Pydantic v2 domain models.
- **Cryptographic Security**: Constant-time HMAC-SHA256 signature verification supporting canonical JSON float-normalization (`X-Signature-V2`) and replay-attack protection via timestamp freshness windows.
- **FastAPI Integration**: Plug-and-play `DiditWebhookGuard` dependency for securing webhook endpoints with zero boilerplate.
- **Zero-Network Simulation Mode**: Built-in `SimulatedDidit` and `SimulatedAsyncDidit` to run unit tests and local end-to-end user flows completely offline without live credentials.
- **Resilient Error Hierarchy**: Typed exceptions (`DiditAuthenticationError`, `DiditRateLimitError`, `DiditNotFoundError`, `DiditServerError`) with automated rate-limit retry duration parsing.

---

## Installation

```bash
# Core SDK (httpx + pydantic)
pip install didit-sdk

# With FastAPI integration
pip install "didit-sdk[fastapi]"
```

---

## Quickstart

### 1. Synchronous Client

```python
from didit import Didit, SessionStatus

# Initialize client (falls back to DIDIT_API_KEY environment variable if omitted)
client = Didit(api_key="your_api_key", webhook_secret="your_webhook_secret")

# Create a verification session
session = client.sessions.create(
    vendor_data="user_12345",
    workflow_id="wf_kyc_standard",
    callback="https://yourapp.com/kyc/complete",
    language="es",
)

print(f"Verification URL: {session.url}")
print(f"Session ID: {session.session_id}")

# Fetch verification decision
decision = client.sessions.get_decision(session.session_id)
if decision.status == SessionStatus.APPROVED:
    print(f"User approved! Document: {decision.document.document_number}")
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

        decision = await client.sessions.get_decision(session.session_id)
        if decision.status.is_terminal:
            print(f"Final outcome: {decision.status}")

asyncio.run(main())
```

---

## Securing Webhooks with FastAPI

Didit dispatches signed HTTP POST events upon verification completion. `didit-sdk` provides a dedicated FastAPI dependency to verify signatures in constant time and prevent replay attacks:

```python
from fastapi import FastAPI, Depends
from didit import WebhookPayload, SessionStatus
from didit.integrations.fastapi import DiditWebhookGuard

app = FastAPI()

# Guard reads secret from argument or DIDIT_WEBHOOK_SECRET env var
webhook_guard = DiditWebhookGuard(secret="whsec_...")

@app.post("/api/v1/webhooks/didit")
async def handle_didit_event(
    payload: WebhookPayload = Depends(webhook_guard),
):
    print(f"Received event for session: {payload.session_id}")
    
    if payload.status == SessionStatus.APPROVED:
        # Mark user verified in your database
        ...
    elif payload.status == SessionStatus.DECLINED:
        # Handle rejection
        ...

    return {"received": True}
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
