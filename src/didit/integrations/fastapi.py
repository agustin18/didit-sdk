import os
from collections.abc import Callable
from typing import Literal

from starlette.requests import Request

from didit.config import DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.dedup import (
    AsyncWebhookDedupStore,
    WebhookDedupStore,
    aclaim_webhook_event,
    arelease_webhook_event,
    compute_dedup_key,
)
from didit.errors import DiditConfigurationError, DiditSignatureError
from didit.models.webhook import WebhookPayload
from didit.webhooks import parse_webhook_payload

DEFAULT_MAX_WEBHOOK_BYTES: int = 1_048_576  # 1 MiB


class DiditWebhookGuard:
    """FastAPI dependency for verifying, parsing, and deduplicating Didit webhook requests.

    Enforces streaming body bounds (HTTP 413) to prevent memory DoS attacks,
    executes single-pass cryptographic verification, and optionally deduplicates
    events against a WebhookDedupStore.

    `duplicate_action` semantics:
    - `"pass"` (default): Duplicate events are passed to the route handler with
      `payload.is_duplicate = True`. This safe default prevents lost retries if a
      previous attempt crashed or failed before durable processing was complete.
    - `"respond_ok"`: Short-circuits with a fast 200 OK without invoking the handler.
      Use only when claiming the event itself constitutes durable acceptance
      (e.g., immediate transactional inbox insertion).
    - `"raise"`: Raises an HTTP 409 Conflict.

    Example:
        ```python
        guard = DiditWebhookGuard(
            secret="whsec_...",
            dedup_store=InMemoryWebhookDedupStore(),
            # duplicate_action defaults to "pass" for at-least-once safe delivery
        )


        @app.post("/webhooks/didit")
        async def handle_webhook(payload: WebhookPayload = Depends(guard)):
            if payload.status == SessionStatus.APPROVED:
                # Idempotently process approved KYC verification
                ...
        ```
    """

    def __init__(
        self,
        secret: str | None = None,
        *,
        max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
        max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BYTES,
        dedup_store: WebhookDedupStore | AsyncWebhookDedupStore | None = None,
        dedup_ttl_seconds: int = 86400,
        duplicate_action: Literal["respond_ok", "pass", "raise"] = "pass",
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

        self.secret: str = resolved_secret
        self.max_age_seconds = max_age_seconds
        self.max_body_bytes = max_body_bytes
        self.dedup_store = dedup_store
        self.dedup_ttl_seconds = dedup_ttl_seconds
        self.duplicate_action = duplicate_action
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

        chunks: list[bytes] = []
        total_bytes = 0
        async for chunk in request.stream():
            total_bytes += len(chunk)
            if total_bytes > self.max_body_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Webhook payload exceeds maximum size limit of {self.max_body_bytes} bytes"
                    ),
                )
            chunks.append(chunk)

        raw_body = b"".join(chunks)

        try:
            payload = parse_webhook_payload(
                raw_body,
                request.headers,
                self.secret,
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

            is_new = await aclaim_webhook_event(
                self.dedup_store, dedup_key, ttl_seconds=self.dedup_ttl_seconds
            )
            request.state.didit_dedup_key = dedup_key
            request.state.didit_dedup_store = self.dedup_store
            request.state.didit_claimed = is_new

            if not is_new:
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

        return payload

    async def release_claim(self, request: Request) -> None:
        """Release dedup claim associated with this request if processing failed."""
        if self.dedup_store is not None:
            key = getattr(request.state, "didit_dedup_key", None)
            claimed = getattr(request.state, "didit_claimed", False)
            if key and claimed:
                await arelease_webhook_event(self.dedup_store, key)
                request.state.didit_claimed = False


async def release_didit_claim(request: Request) -> None:
    """Helper to release dedup claim recorded on request.state if processing failed."""
    store = getattr(request.state, "didit_dedup_store", None)
    key = getattr(request.state, "didit_dedup_key", None)
    claimed = getattr(request.state, "didit_claimed", False)
    if store and key and claimed:
        await arelease_webhook_event(store, key)
        request.state.didit_claimed = False
