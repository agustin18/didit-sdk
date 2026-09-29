"""Flask integration for verifying, parsing, and deduplicating Didit webhooks."""

from __future__ import annotations

import contextlib
import functools
import inspect
import os
from collections.abc import Callable
from typing import Any, Literal

try:
    import flask  # noqa: F401
    from flask import Request, Response, g, request
except ImportError as err:  # pragma: no cover
    raise ImportError(
        "Flask is required to use didit.integrations.flask. "
        "Install it via: pip install didit-sdk[flask]"
    ) from err

from didit.config import DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.dedup import (
    AsyncWebhookDedupStore,
    WebhookDedupStore,
    aclaim_webhook_event,
    compute_dedup_key,
)
from didit.errors import DiditConfigurationError, DiditSignatureError
from didit.models.webhook import WebhookPayload
from didit.webhooks import parse_webhook_payload

DEFAULT_MAX_WEBHOOK_BYTES: int = 1_048_576  # 1 MiB


def parse_flask_webhook(
    request_obj: Request | None = None,
    secret: str | None = None,
    *,
    max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BYTES,
) -> WebhookPayload:
    """Parse and cryptographically verify a Didit webhook from a Flask request.

    Args:
        request_obj: Flask Request object. Defaults to the active flask.request context.
        secret: Webhook secret. If None, loaded from DIDIT_WEBHOOK_SECRET environment variable.
        max_age_seconds: Maximum tolerance in seconds for webhook timestamps (anti-replay).
        max_body_bytes: Maximum allowed request body size in bytes to prevent DoS.

    Returns:
        Verified and parsed WebhookPayload instance.

    Raises:
        DiditConfigurationError: If no webhook secret is provided or configured.
        ValueError: If payload exceeds max_body_bytes limit.
        DiditSignatureError: If signature verification fails or timestamp expired.
    """
    resolved_secret = secret or os.environ.get("DIDIT_WEBHOOK_SECRET")
    if not resolved_secret:
        raise DiditConfigurationError(
            "Missing webhook secret. "
            "Provide secret parameter or set DIDIT_WEBHOOK_SECRET environment variable."
        )

    req = request_obj if request_obj is not None else request

    content_length = getattr(req, "content_length", None)
    if content_length is None:
        raw_cl = req.headers.get("content-length")
        if raw_cl is not None:
            try:
                content_length = int(raw_cl)
            except ValueError:
                content_length = None

    if content_length is not None and content_length > max_body_bytes:
        raise ValueError(f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes")

    with contextlib.suppress(Exception):
        req.max_content_length = max_body_bytes

    try:
        raw_body = req.get_data(cache=False, as_text=False)
    except Exception as exc:
        if exc.__class__.__name__ == "RequestEntityTooLarge" or getattr(exc, "code", None) == 413:
            raise ValueError(
                f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
            ) from exc
        raise

    if len(raw_body) > max_body_bytes:
        raise ValueError(f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes")

    return parse_webhook_payload(
        raw_body,
        dict(req.headers),
        resolved_secret,
        max_age_seconds=max_age_seconds,
    )


def didit_webhook(
    secret: str | None = None,
    *,
    max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BYTES,
    dedup_store: WebhookDedupStore | AsyncWebhookDedupStore | None = None,
    dedup_ttl_seconds: int = 86400,
    duplicate_action: Literal["respond_ok", "pass", "raise"] = "respond_ok",
    dedup_key_builder: Callable[[WebhookPayload, Request], str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Flask view decorator for verifying, parsing, and deduplicating Didit webhooks.

    Enforces POST method, bounds request body memory (HTTP 413), verifies HMAC-SHA256
    signatures, prevents duplicate processing via WebhookDedupStore, assigns the payload to
    `flask.g.didit_payload`, and injects `payload: WebhookPayload` into the route handler.

    Example:
        ```python
        @app.route("/webhooks/didit", methods=["POST"])
        @didit_webhook(secret="whsec_...")
        def handle_didit(payload: WebhookPayload):
            if payload.status == SessionStatus.APPROVED:
                ...
            return {"status": "ok"}, 200
        ```
    """
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

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        is_async = inspect.iscoroutinefunction(view_func)

        if (
            not is_async
            and dedup_store is not None
            and hasattr(dedup_store, "aclaim")
            and not hasattr(dedup_store, "claim")
        ):
            raise DiditConfigurationError(
                "AsyncWebhookDedupStore cannot be used with synchronous Flask view functions. "
                "Use WebhookDedupStore."
            )

        if is_async:

            @functools.wraps(view_func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if request.method != "POST":
                    return Response("Method not allowed", status=405, mimetype="text/plain")

                try:
                    payload = parse_flask_webhook(
                        request,
                        resolved_secret,
                        max_age_seconds=max_age_seconds,
                        max_body_bytes=max_body_bytes,
                    )
                except ValueError:
                    return Response(
                        f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes",
                        status=413,
                        mimetype="text/plain",
                    )
                except DiditSignatureError as err:
                    err_msg = str(err)
                    if "Invalid JSON" in err_msg or "unsupported" in err_msg:
                        return Response(
                            "Malformed JSON in webhook body", status=400, mimetype="text/plain"
                        )
                    return Response(
                        "Invalid webhook signature or expired timestamp",
                        status=401,
                        mimetype="text/plain",
                    )

                g.didit_payload = payload

                if dedup_store is not None:
                    if dedup_key_builder is not None:
                        dedup_key = dedup_key_builder(payload, request)
                    else:
                        sig = request.headers.get("x-signature-sha256") or request.headers.get(
                            "x-signature-v2"
                        )
                        dedup_key = compute_dedup_key(payload, signature=sig)

                    is_new = await aclaim_webhook_event(
                        dedup_store, dedup_key, ttl_seconds=dedup_ttl_seconds
                    )

                    if not is_new:
                        if duplicate_action == "respond_ok":
                            return Response(
                                "Duplicate webhook event acknowledged",
                                status=200,
                                mimetype="text/plain",
                            )
                        if duplicate_action == "raise":
                            return Response(
                                "Duplicate webhook event",
                                status=409,
                                mimetype="text/plain",
                            )
                        payload.is_duplicate = True

                sig_params = inspect.signature(view_func).parameters
                if "payload" in sig_params or len(sig_params) > len(args):
                    result = await view_func(payload, *args, **kwargs)
                else:
                    result = await view_func(*args, **kwargs)

                if result is None:
                    return Response(status=200)
                return result

            return async_wrapper

        @functools.wraps(view_func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if request.method != "POST":
                return Response("Method not allowed", status=405, mimetype="text/plain")

            try:
                payload = parse_flask_webhook(
                    request,
                    resolved_secret,
                    max_age_seconds=max_age_seconds,
                    max_body_bytes=max_body_bytes,
                )
            except ValueError:
                return Response(
                    f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes",
                    status=413,
                    mimetype="text/plain",
                )
            except DiditSignatureError as err:
                err_msg = str(err)
                if "Invalid JSON" in err_msg or "unsupported" in err_msg:
                    return Response(
                        "Malformed JSON in webhook body", status=400, mimetype="text/plain"
                    )
                return Response(
                    "Invalid webhook signature or expired timestamp",
                    status=401,
                    mimetype="text/plain",
                )

            g.didit_payload = payload

            if dedup_store is not None:
                if dedup_key_builder is not None:
                    dedup_key = dedup_key_builder(payload, request)
                else:
                    sig = request.headers.get("x-signature-sha256") or request.headers.get(
                        "x-signature-v2"
                    )
                    dedup_key = compute_dedup_key(payload, signature=sig)

                claim_fn = getattr(dedup_store, "claim", None)
                if claim_fn is None:
                    raise DiditConfigurationError(
                        "AsyncWebhookDedupStore cannot be used with "
                        "synchronous Flask view functions. Use WebhookDedupStore."
                    )
                claim_res = claim_fn(dedup_key, ttl_seconds=dedup_ttl_seconds)
                if inspect.isawaitable(claim_res):
                    if inspect.iscoroutine(claim_res):
                        claim_res.close()
                    raise DiditConfigurationError(
                        "dedup_store.claim returned a coroutine in a synchronous Flask view. "
                        "Provide a synchronous WebhookDedupStore."
                    )
                is_new = bool(claim_res)
                if not is_new:
                    if duplicate_action == "respond_ok":
                        return Response(
                            "Duplicate webhook event acknowledged",
                            status=200,
                            mimetype="text/plain",
                        )
                    if duplicate_action == "raise":
                        return Response(
                            "Duplicate webhook event",
                            status=409,
                            mimetype="text/plain",
                        )
                    payload.is_duplicate = True

            sig_params = inspect.signature(view_func).parameters
            if "payload" in sig_params or len(sig_params) > len(args):
                result = view_func(payload, *args, **kwargs)
            else:
                result = view_func(*args, **kwargs)

            if result is None:
                return Response(status=200)
            return result

        return sync_wrapper

    return decorator
