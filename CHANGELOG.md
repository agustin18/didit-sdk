# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
