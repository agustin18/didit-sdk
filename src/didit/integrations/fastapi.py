"""FastAPI integration for verifying, parsing, and deduplicating Didit webhooks."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Literal

from starlette.requests import Request

from didit.config import DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.dedup import (
    AsyncWebhookDedupStore,
    AsyncWebhookReservationStore,
    ReservationState,
    WebhookDedupStore,
    WebhookReservationStore,
    acomplete_webhook_event,
    arelease_webhook_event,
    areserve_webhook_event,
    compute_dedup_key,
)
from didit.errors import DiditConfigurationError, DiditSignatureError
from didit.models.webhook import WebhookPayload
from didit.webhooks import parse_webhook_payload

DEFAULT_MAX_WEBHOOK_BYTES: int = 1_048_576  # 1 MiB


class DiditWebhookGuard:
    """FastAPI dependency for verifying, parsing, and reserving Didit webhook requests.

    Enforces streaming body bounds (HTTP 413) to prevent memory DoS attacks,
    executes single-pass cryptographic verification, and optionally deduplicates/leases
    events against a WebhookDedupStore or WebhookReservationStore.

    `duplicate_action` semantics:
    - `"pass"` (default): Duplicate events (COMPLETED) are passed to the route handler with
      `payload.is_duplicate = True`. This safe default prevents lost retries if a
      previous attempt crashed or failed before durable processing was complete.
    - `"respond_ok"`: Short-circuits with a fast 200 OK without invoking the handler.
    - `"raise"`: Raises an HTTP 409 Conflict.

    `processing_action` semantics:
    - `"retry"` (default): When another worker is actively holding the processing lease
      (PROCESSING), raises HTTP 503 Service Unavailable with `Retry-After: 5` header so Didit
      automatically retries delivery.
    - `"raise"`: Raises an HTTP 409 Conflict.
    - `"pass"`: Passes event to route handler with `payload.is_duplicate = True`.
    """

    def __init__(
        self,
        secret: str | None = None,
        *,
        max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
        max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BYTES,
        dedup_store: (
            WebhookDedupStore
            | AsyncWebhookDedupStore
            | WebhookReservationStore
            | AsyncWebhookReservationStore
            | None
        ) = None,
        dedup_ttl_seconds: int = 86400,
        duplicate_action: Literal["respond_ok", "pass", "raise"] = "pass",
        processing_action: Literal["retry", "pass", "raise"] = "retry",
        dedup_key_builder: Callable[[WebhookPayload, Request], str] | None = None,
    ) -> None:
        resolved_secret = secret or os.environ.get("DIDIT_WEBHOOK_SECRET")
        if not resolved_secret:
            raise DiditConfigurationError(
                "Missing webhook secret. "
                "Provide secret parameter or set DIDIT_WEBHOOK_SECRET environment variable."
            )
        if duplicate_action not in ("respond_ok", "pass", "raise"):
            raise ValueError(
                f"Invalid duplicate_action '{duplicate_action}'. "
                "Must be 'respond_ok', 'pass', or 'raise'."
            )
        if processing_action not in ("retry", "pass", "raise"):
            raise ValueError(
                f"Invalid processing_action '{processing_action}'. "
                "Must be 'retry', 'pass', or 'raise'."
            )

        self.secret: str = resolved_secret
        self.max_age_seconds = max_age_seconds
        self.max_body_bytes = max_body_bytes
        self.dedup_store = dedup_store
        self.dedup_ttl_seconds = dedup_ttl_seconds
        self.duplicate_action = duplicate_action
        self.processing_action = processing_action
        self.dedup_key_builder = dedup_key_builder

    async def __call__(self, request: Request) -> WebhookPayload:
        from fastapi import HTTPException

        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                cl_val = int(content_length)
                if cl_val > self.max_body_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Webhook payload exceeds maximum size limit of "
                            f"{self.max_body_bytes} bytes"
                        ),
                    )
            except ValueError:
                pass

        body_chunks = []
        bytes_received = 0
        async for chunk in request.stream():
            bytes_received += len(chunk)
            if bytes_received > self.max_body_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Webhook payload exceeds maximum size limit of {self.max_body_bytes} bytes"
                    ),
                )
            body_chunks.append(chunk)

        raw_body = b"".join(body_chunks)

        try:
            payload = parse_webhook_payload(
                raw_body,
                headers=dict(request.headers),
                secret=self.secret,
                max_age_seconds=self.max_age_seconds,
            )
        except DiditSignatureError as err:
            err_msg = str(err)
            if "Invalid JSON" in err_msg or "unsupported" in err_msg:
                raise HTTPException(
                    status_code=400, detail="Malformed JSON in webhook body"
                ) from None
            raise HTTPException(
                status_code=401,
                detail="Invalid webhook signature or expired timestamp",
            ) from None

        if self.dedup_store is not None:
            if self.dedup_key_builder is not None:
                dedup_key = self.dedup_key_builder(payload, request)
            else:
                sig = request.headers.get("x-signature-sha256") or request.headers.get(
                    "x-signature-v2"
                )
                dedup_key = compute_dedup_key(payload, signature=sig)

            attempt = await areserve_webhook_event(
                self.dedup_store, dedup_key, ttl_seconds=self.dedup_ttl_seconds
            )
            request.state.didit_dedup_key = dedup_key
            request.state.didit_dedup_store = self.dedup_store
            request.state.didit_attempt = attempt
            request.state.didit_reservation = attempt.reservation
            request.state.didit_claimed = attempt.state == ReservationState.ACQUIRED

            if attempt.state == ReservationState.COMPLETED:
                if self.duplicate_action == "respond_ok":
                    raise HTTPException(
                        status_code=200,
                        detail="Duplicate webhook event acknowledged",
                    )
                if self.duplicate_action == "raise":
                    raise HTTPException(
                        status_code=409,
                        detail="Duplicate webhook event",
                    )
                # "pass" mode
                payload.is_duplicate = True
                request.state.is_duplicate = True

            elif attempt.state == ReservationState.PROCESSING:
                if self.processing_action == "retry":
                    raise HTTPException(
                        status_code=503,
                        headers={"Retry-After": "5"},
                        detail="Webhook event currently being processed by another worker",
                    )
                if self.processing_action == "raise":
                    raise HTTPException(
                        status_code=409,
                        detail="Webhook event currently being processed",
                    )
                # "pass" mode
                payload.is_duplicate = True
                request.state.is_duplicate = True

            else:  # ACQUIRED
                payload.is_duplicate = False
                request.state.is_duplicate = False

        return payload

    async def release_claim(self, request: Request) -> None:
        """Release dedup claim or reservation associated with this request if processing failed."""
        if self.dedup_store is not None:
            key = getattr(request.state, "didit_dedup_key", None)
            claimed = getattr(request.state, "didit_claimed", False)
            res = getattr(request.state, "didit_reservation", None)
            token = res.token if res else None
            if key and claimed:
                await arelease_webhook_event(self.dedup_store, key, token=token)
                request.state.didit_claimed = False

    async def complete_reservation(self, request: Request, completed_ttl: int = 86400) -> bool:
        """Transition active reservation to COMPLETED state upon successful processing."""
        if self.dedup_store is not None:
            key = getattr(request.state, "didit_dedup_key", None)
            res = getattr(request.state, "didit_reservation", None)
            if key and res:
                success = await acomplete_webhook_event(
                    self.dedup_store, key, token=res.token, completed_ttl=completed_ttl
                )
                request.state.didit_claimed = False
                return success
        return False


async def release_didit_claim(request: Request) -> None:
    """Helper to release claim or reservation recorded on request.state if processing failed."""
    store = getattr(request.state, "didit_dedup_store", None)
    key = getattr(request.state, "didit_dedup_key", None)
    claimed = getattr(request.state, "didit_claimed", False)
    res = getattr(request.state, "didit_reservation", None)
    token = res.token if res else None
    if store and key and claimed:
        await arelease_webhook_event(store, key, token=token)
        request.state.didit_claimed = False


async def complete_didit_reservation(request: Request, completed_ttl: int = 86400) -> bool:
    """Helper to complete active reservation on request.state upon successful processing."""
    store = getattr(request.state, "didit_dedup_store", None)
    key = getattr(request.state, "didit_dedup_key", None)
    res = getattr(request.state, "didit_reservation", None)
    if store and key and res:
        success = await acomplete_webhook_event(
            store, key, token=res.token, completed_ttl=completed_ttl
        )
        request.state.didit_claimed = False
        return success
    return False
