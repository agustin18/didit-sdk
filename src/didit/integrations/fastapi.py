"""FastAPI integration utilities and webhook security guard."""

from __future__ import annotations

import json
import os

from starlette.requests import Request

from didit.config import DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.errors import DiditConfigurationError
from didit.models.webhook import WebhookPayload
from didit.webhooks import verify_webhook_signature


class DiditWebhookGuard:
    """FastAPI dependency for verifying and parsing Didit webhook requests.

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
    ) -> None:
        resolved_secret = secret or os.environ.get("DIDIT_WEBHOOK_SECRET")
        if not resolved_secret:
            raise DiditConfigurationError(
                "Missing webhook secret. "
                "Provide secret parameter or set DIDIT_WEBHOOK_SECRET environment variable."
            )
        self.secret: str = resolved_secret
        self.max_age_seconds = max_age_seconds

    async def __call__(self, request: Request) -> WebhookPayload:
        from fastapi import HTTPException

        raw_body = await request.body()
        try:
            body_dict = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="Malformed JSON in webhook body") from None

        if not isinstance(body_dict, dict):
            raise HTTPException(status_code=400, detail="Malformed JSON in webhook body")

        is_valid = verify_webhook_signature(
            raw_body,
            request.headers,
            self.secret,
            max_age_seconds=self.max_age_seconds,
        )
        if not is_valid:
            raise HTTPException(
                status_code=401,
                detail="Invalid webhook signature or expired timestamp",
            )

        payload = WebhookPayload.model_validate(body_dict)
        payload.raw_data = body_dict
        return payload
