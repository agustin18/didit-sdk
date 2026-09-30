"""Flask integration for verifying, parsing, and deduplicating Didit webhooks."""

from __future__ import annotations

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
    AsyncWebhookReservationStore,
    ReservationState,
    WebhookDedupStore,
    WebhookReservationStore,
    acomplete_webhook_event,
    arelease_webhook_event,
    areserve_webhook_event,
    complete_webhook_event,
    compute_dedup_key,
    release_webhook_event,
    reserve_webhook_event,
)
from didit.errors import (
    DiditConfigurationError,
    DiditSignatureError,
)
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

    req.max_content_length = max_body_bytes

    try:
        raw_body = req.get_data(cache=False, as_text=False)
        if len(raw_body) > max_body_bytes:
            raise ValueError(
                f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
            )
        if len(raw_body) == max_body_bytes:
            stream_obj = getattr(req, "stream", None)
            underlying = getattr(stream_obj, "_stream", None) or stream_obj
            if underlying is not None and hasattr(underlying, "read") and underlying.read(1):
                raise ValueError(
                    f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
                )
    except Exception as exc:
        if exc.__class__.__name__ == "RequestEntityTooLarge" or getattr(exc, "code", None) == 413:
            raise ValueError(
                f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
            ) from exc
        raise

    return parse_webhook_payload(
        raw_body,
        dict(req.headers),
        resolved_secret,
        max_age_seconds=max_age_seconds,
    )


def _extract_status_code(res: Any) -> int:
    """Extract HTTP status code from a Flask view result (tuple, Response, or default 200)."""
    if isinstance(res, tuple) and len(res) >= 2 and isinstance(res[1], int):
        return res[1]
    if hasattr(res, "status_code") and isinstance(res.status_code, int):
        return res.status_code
    return 200


def didit_webhook(
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
    lease_ttl_seconds: int = 30,
    completed_ttl_seconds: int = 86400,
    dedup_ttl_seconds: int | None = None,
    duplicate_action: Literal["respond_ok", "pass", "raise"] = "pass",
    processing_action: Literal["retry", "pass", "raise", "conflict"] = "retry",
    dedup_key_builder: Callable[[WebhookPayload, Request], str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Flask view decorator for verifying, parsing, and deduplicating Didit webhooks.

    Enforces POST method, bounds request body memory (HTTP 413), verifies HMAC-SHA256
    signatures, prevents duplicate processing via WebhookDedupStore or WebhookReservationStore,
    assigns the payload to `flask.g.didit_payload`, and injects `payload: WebhookPayload`
    into the route handler.
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
    if processing_action not in ("retry", "pass", "raise", "conflict"):
        raise ValueError(
            f"Invalid processing_action '{processing_action}'. "
            "Must be 'retry', 'pass', 'raise', or 'conflict'."
        )

    effective_lease_ttl = dedup_ttl_seconds if dedup_ttl_seconds is not None else lease_ttl_seconds
    effective_completed_ttl = completed_ttl_seconds

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        is_async = inspect.iscoroutinefunction(view_func)

        if (
            not is_async
            and dedup_store is not None
            and hasattr(dedup_store, "areserve")
            and not hasattr(dedup_store, "reserve")
        ):
            raise DiditConfigurationError(
                "AsyncWebhookReservationStore cannot be used with synchronous Flask view "
                "functions. Use WebhookReservationStore."
            )

        if (
            not is_async
            and dedup_store is not None
            and hasattr(dedup_store, "aclaim")
            and not hasattr(dedup_store, "claim")
            and not hasattr(dedup_store, "reserve")
        ):
            raise DiditConfigurationError(
                "AsyncWebhookDedupStore cannot be used with synchronous Flask view functions. "
                "Use WebhookDedupStore or WebhookReservationStore."
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

                is_new = False
                dedup_key = ""
                res_token: str | None = None
                if dedup_store is not None:
                    if dedup_key_builder is not None:
                        dedup_key = dedup_key_builder(payload, request)
                    else:
                        sig = request.headers.get("x-signature-sha256") or request.headers.get(
                            "x-signature-v2"
                        )
                        dedup_key = compute_dedup_key(payload, signature=sig)

                    attempt = await areserve_webhook_event(
                        dedup_store, dedup_key, ttl_seconds=effective_lease_ttl
                    )
                    is_new = attempt.state == ReservationState.ACQUIRED
                    if attempt.reservation is not None:
                        res_token = attempt.reservation.token
                        g.didit_reservation = attempt.reservation

                    if attempt.state == ReservationState.COMPLETED:
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

                    elif attempt.state == ReservationState.PROCESSING:
                        if processing_action == "retry":
                            resp = Response(
                                "Webhook event currently being processed by another worker",
                                status=503,
                                mimetype="text/plain",
                            )
                            resp.headers["Retry-After"] = "5"
                            return resp
                        if processing_action in ("raise", "conflict"):
                            return Response(
                                "Webhook event currently being processed",
                                status=409,
                                mimetype="text/plain",
                            )
                        payload.is_duplicate = True

                try:
                    sig_params = inspect.signature(view_func).parameters
                    if "payload" in sig_params or len(sig_params) > len(args):
                        result = await view_func(payload, *args, **kwargs)
                    else:
                        result = await view_func(*args, **kwargs)
                except Exception:
                    if dedup_store is not None and is_new:
                        await arelease_webhook_event(dedup_store, dedup_key, token=res_token)
                    raise

                if dedup_store is not None and is_new:
                    status_code = _extract_status_code(result)
                    if 200 <= status_code < 300:
                        if res_token is not None:
                            await acomplete_webhook_event(
                                dedup_store,
                                dedup_key,
                                token=res_token,
                                completed_ttl=effective_completed_ttl,
                            )
                    else:
                        await arelease_webhook_event(dedup_store, dedup_key, token=res_token)

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

            is_new = False
            dedup_key = ""
            res_token: str | None = None
            if dedup_store is not None:
                if hasattr(dedup_store, "areserve") and not hasattr(dedup_store, "reserve"):
                    raise DiditConfigurationError(
                        "AsyncWebhookReservationStore cannot be used with "
                        "synchronous Flask view functions. Use WebhookReservationStore."
                    )
                if (
                    hasattr(dedup_store, "aclaim")
                    and not hasattr(dedup_store, "claim")
                    and not hasattr(dedup_store, "reserve")
                ):
                    raise DiditConfigurationError(
                        "AsyncWebhookDedupStore cannot be used with "
                        "synchronous Flask view functions. Use WebhookDedupStore."
                    )

                if dedup_key_builder is not None:
                    dedup_key = dedup_key_builder(payload, request)
                else:
                    sig = request.headers.get("x-signature-sha256") or request.headers.get(
                        "x-signature-v2"
                    )
                    dedup_key = compute_dedup_key(payload, signature=sig)

                effective_legacy_ttl = (
                    dedup_ttl_seconds if dedup_ttl_seconds is not None else completed_ttl_seconds
                )
                claim_fn = getattr(dedup_store, "claim", None)
                if claim_fn is not None and not hasattr(dedup_store, "reserve"):
                    claim_res = claim_fn(dedup_key, ttl_seconds=effective_legacy_ttl)
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
                else:
                    attempt = reserve_webhook_event(
                        dedup_store, dedup_key, ttl_seconds=effective_lease_ttl
                    )
                    is_new = attempt.state == ReservationState.ACQUIRED
                    if attempt.reservation is not None:
                        res_token = attempt.reservation.token
                        g.didit_reservation = attempt.reservation

                    if attempt.state == ReservationState.COMPLETED:
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

                    elif attempt.state == ReservationState.PROCESSING:
                        if processing_action == "retry":
                            resp = Response(
                                "Webhook event currently being processed by another worker",
                                status=503,
                                mimetype="text/plain",
                            )
                            resp.headers["Retry-After"] = "5"
                            return resp
                        if processing_action in ("raise", "conflict"):
                            return Response(
                                "Webhook event currently being processed",
                                status=409,
                                mimetype="text/plain",
                            )
                        payload.is_duplicate = True

            try:
                sig_params = inspect.signature(view_func).parameters
                if "payload" in sig_params or len(sig_params) > len(args):
                    result = view_func(payload, *args, **kwargs)
                else:
                    result = view_func(*args, **kwargs)
            except Exception:
                if dedup_store is not None and is_new:
                    release_webhook_event(dedup_store, dedup_key, token=res_token)
                raise

            if dedup_store is not None and is_new:
                status_code = _extract_status_code(result)
                if 200 <= status_code < 300:
                    if res_token is not None:
                        complete_webhook_event(
                            dedup_store,
                            dedup_key,
                            token=res_token,
                            completed_ttl=effective_completed_ttl,
                        )
                else:
                    release_webhook_event(dedup_store, dedup_key, token=res_token)

            if result is None:
                return Response(status=200)
            return result

        return sync_wrapper

    return decorator
