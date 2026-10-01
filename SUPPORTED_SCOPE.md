# Supported Scope & Perimeter Policy — `didit-sdk`

This document defines the contractual perimeter, API boundaries, and product scope for the `didit-sdk` 1.x release line.

---

## 1. Mission Statement

`didit-sdk` is an enterprise-hardened, production-grade Python client engineered specifically for **Didit Verification Sessions and KYC/Identity Verification workflows**.

Our primary directive is **Veracity Over Speed**: providing bank-grade cryptographic guarantees, Didit X-Signature-V2 canonical JSON formatting, distributed replay protection, strict typing, and zero-PII leak protection for production KYC integrations.

---

## 2. Committed 1.x Feature Scope: Verification Sessions & KYC

The 1.x line of `didit-sdk` commits to the following functional domains, distinguishing between capabilities available today and those finalizing in the v0.3.0 milestone:

| Domain | Supported Capabilities | Milestone Status |
| :--- | :--- | :--- |
| **Verification Sessions** | Creation, configuration, metadata attachment, status retrieval, and resilient polling. | Implemented in v0.2.x |
| **Decisions & Warnings** | Decision retrieval (`get_decision`), risk normalization, multi-warning categorization, and review breakdown. | Implemented in v0.2.x |
| **Session Lifecycle Actions** | Pure snapshot session reconciliation (`reconcile`, `reconcile_range`), resubmission requests (`resubmit`), and direct-to-disk streaming compliance PDF report generation (`download_pdf_report`). | Implemented in v0.3.0 |
| **Webhook Ingestion** | Constant-time HMAC-SHA256 signature verification, Didit X-Signature-V2 canonical JSON formatting, and anti-replay defense. | Implemented in v0.2.x |
| **Distributed Deduplication & Leases** | Crash-recoverable Tokenized Webhook Reservation Protocol backed by Redis (Lua CAS atomic leases) and thread-safe memory stores. | Implemented in v0.3.0 |
| **Framework Adapters** | First-class, dependency-isolated guards for **FastAPI**, **Django 5.2+**, and **Flask 3.1+**. | Implemented in v0.2.x |
| **Sandbox & Simulation** | Offline simulation harness (`SimulatedDidit`, `SimulatedAsyncDidit`), live sandbox scenario cataloging (`GET /v1/sandbox/scenarios/`), and test fixture builders. | Implemented in v0.2.x / v0.3.0 |
| **Security & Privacy** | Automatic PII redaction (`redacted_dump()`), zero-PII safe exceptions by default (`capture_sensitive_response=False`). | Implemented in v0.2.x / v0.3.0 |
| **Live Contract Testing** | Automated periodic CI testing against live Didit sandbox endpoints with strict fail-closed credentials gate; continuous offline matrix validation. | Implemented in v0.3.0 |

---

## 3. Explicitly Out-of-Scope for 1.x

To guarantee long-term API stability (LTS), zero unnecessary dependencies, and 100.00% statement/branch coverage, the following broader Didit platform capabilities are **explicitly out of scope** for `didit-sdk` 1.x:

- **Didit Business / KYB (Know Your Business):** Company registration checks, ultimate beneficial owner (UBO) structures, and corporate registries.
- **Consolidated User Management:** Centralized identity profiles, user merging, and persistent cross-session profile storage.
- **Transactions & Travel Rule:** AML transaction monitoring, crypto-asset transfer compliance, and VASPs messaging.
- **Payments & Wallets:** Direct on-chain identity binding, token transfers, or payment rail processing.

> [!NOTE]
> If Didit platform features outside Verification Sessions are needed in your architecture, they should be managed through custom clients or future dedicated packages (`didit-kyb`, `didit-travelrule`). The core `didit-sdk 1.x` contract will remain frozen and protected against non-KYC feature churn.

---

## 4. API Freeze and Stability Guarantees

1. **Voluntary 0.x Freeze:** Although SemVer formally permits breaking changes during `0.x` initial development, `didit-sdk` voluntarily freezes its public API after `v0.3.0`. Post-v0.3.0 releases will be strictly backward-compatible.
2. **Backward Compatibility & Drift Detection:** Unknown additive fields in Didit's API schemas are safely preserved via Pydantic `extra="allow"`. Automated contract tests actively detect semantic and schema drift requiring SDK updates.
3. **Deprecation & Emergency Policy:** Under normal operations, any future deprecation will require a minimum 6-month warning window with active deprecation notices prior to any major version increment (`2.0.0`). *Security and upstream-contract emergency exception:* critical security, privacy, legal, or upstream-breaking issues may require an accelerated corrective release, with clear migration guidance published as soon as practicable.
