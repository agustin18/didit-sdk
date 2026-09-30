# Supported Scope & Perimeter Policy — `didit-sdk`

This document defines the contractual perimeter, API boundaries, and product scope for the `didit-sdk` 1.x release line.

---

## 1. Mission Statement

`didit-sdk` is an enterprise-hardened, production-grade Python client engineered specifically for **Didit Verification Sessions and KYC/Identity Verification workflows**.

Our primary directive is **Veracity Over Speed**: providing bank-grade cryptographic guarantees, RFC 8785 canonicalization, distributed replay protection, strict typing, and zero-PII leak protection for production KYC integrations.

---

## 2. In-Scope Domain: Verification Sessions & KYC (1.x)

The 1.x line of `didit-sdk` fully supports and maintains the following functional domains:

| Domain | Supported Capabilities |
| :--- | :--- |
| **Verification Sessions** | Creation, configuration, metadata attachment, status retrieval, and resilient polling. |
| **Decisions & Warnings** | Decision retrieval (`get_decision`), risk normalization, multi-warning categorization, and review breakdown. |
| **Session Lifecycle Actions** | Session reconciliation (`reconcile`), resubmission requests, and compliance PDF report retrieval. |
| **Webhook Ingestion** | Constant-time HMAC-SHA256 signature verification, RFC 8785 canonical JSON formatting, and replay defense. |
| **Distributed Deduplication** | Tokenized Webhook Reservation Protocol backed by Redis (Lua CAS atomic leases) and thread-safe memory stores. |
| **Framework Adapters** | First-class, dependency-isolated guards for **FastAPI**, **Django 5.2+**, and **Flask 3.1+**. |
| **Sandbox & Simulation** | Offline simulation harness (`DiditSimulator`), live sandbox scenario cataloging, and test fixture builders. |
| **Security & Privacy** | Automatic PII redaction (`redacted_dump()`), zero-PII safe exceptions by default (`capture_sensitive_response=False`). |

---

## 3. Explicitly Out-of-Scope for 1.x

To guarantee strict **Semantic Versioning (SemVer)**, long-term API stability (LTS), and 100.00% statement/branch coverage, the following broader Didit platform capabilities are **explicitly out of scope** for `didit-sdk` 1.x:

- **Didit Business / KYB (Know Your Business):** Company registration checks, ultimate beneficial owner (UBO) structures, and corporate registries.
- **Consolidated User Management:** Centralized identity profiles, user merging, and persistent cross-session profile storage.
- **Transactions & Travel Rule:** AML transaction monitoring, crypto-asset transfer compliance, and VASPs messaging.
- **Payments & Wallets:** Direct on-chain identity binding, token transfers, or payment rail processing.

> [!NOTE]
> If Didit platform features outside Verification Sessions are needed in your architecture, they should be managed through custom clients or future dedicated packages (`didit-kyb`, `didit-travelrule`). The core `didit-sdk 1.x` contract will remain frozen and protected against non-KYC feature churn.

---

## 4. API Freeze and Stability Guarantees

1. **Strict SemVer Commitment:** No breaking changes will be introduced in minor (`0.x` post-v0.3.0) or patch releases.
2. **Backward Compatibility:** Upstream additive changes in Didit's API schemas will not break consumer builds (enforced via Pydantic `extra="allow"`).
3. **Deprecation Policy:** Any future deprecations will require a minimum 6-month warning window with active deprecation notices prior to any major version increment (`2.0.0`).
