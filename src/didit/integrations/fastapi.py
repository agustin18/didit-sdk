"""FastAPI integration utilities and webhook security guard."""

from __future__ import annotations

import os

from starlette.requests import Request

from didit.config import DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.errors import DiditConfigurationError, DiditSignatureError
from didit.models.webhook import WebhookPayload
from didit.webhooks import parse_webhook_payload

DEFAULT_MAX_WEBHOOK_BYTES: int = 1_048_576  # 1 MiB


class DiditWebhookGuard:
    """FastAPI dependency for verifying and parsing Didit webhook requests.

    Enforces streaming body bounds (HTTP 413) to prevent memory DoS attacks,
    and executes single-pass cryptographic verification and JSON parsing.

    Example:
        ```python
        guard = DiditWebhookGuard(secret="whsec_...")


        @app.post("/webhooks/didit")
        async def handle_webhook(payload: WebhookPayload = Depends(guard)):
            if payload.status == SessionStatus.APPROVED:
                # Process approved KYC verification
                ...
        ```
    """

    def __init__(
        self,
        secret: str | None = None,
        *,
        max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
        max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BYTES,
    ) -> None:
        resolved_secret = secret or os.environ.get("DIDIT_WEBHOOK_SECRET")
        if not resolved_secret:
            raise DiditConfigurationError(
                "Missing webhook secret. "
                "Provide secret parameter or set DIDIT_WEBHOOK_SECRET environment variable."
            )
        self.secret: str = resolved_secret
        self.max_age_seconds = max_age_seconds
        self.max_body_bytes = max_body_bytes

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
            return parse_webhook_payload(
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
