"""Django integration for verifying, parsing, and deduplicating Didit webhooks."""

from __future__ import annotations

import functools
import inspect
import os
from collections.abc import Callable
from typing import Any, Literal, cast

try:
    import django  # type: ignore[import-untyped]  # noqa: F401
    from django.http import (  # type: ignore[import-untyped]
        HttpRequest,
        HttpResponse,
        HttpResponseBadRequest,
    )
except ImportError as err:  # pragma: no cover
    raise ImportError(
        "Django is required to use didit.integrations.django. "
        "Install it via: pip install didit-sdk[django]"
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
from didit.errors import DiditConfigurationError, DiditSignatureError
from didit.models.webhook import WebhookPayload
from didit.webhooks import parse_webhook_payload

DEFAULT_MAX_WEBHOOK_BYTES: int = 1_048_576  # 1 MiB


def parse_django_webhook(
    request: HttpRequest,
    secret: str | None = None,
    *,
    max_age_seconds: int = DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BYTES,
) -> WebhookPayload:
    """Parse and cryptographically verify a Didit webhook from a Django HttpRequest.

    Args:
        request: The incoming Django HttpRequest object.
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

    content_length = getattr(request, "headers", {}).get("content-length") or request.META.get(
        "CONTENT_LENGTH"
    )
    if content_length is not None:
        try:
            cl_val = int(content_length)
        except ValueError:
            cl_val = None
        if cl_val is not None and cl_val > max_body_bytes:
            raise ValueError(
                f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
            )

    if not hasattr(request, "_body") and hasattr(request, "read"):
        chunk = request.read(max_body_bytes + 1)
        if len(chunk) > max_body_bytes:
            raise ValueError(
                f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
            )
        request._body = chunk
        raw_body = chunk
    else:
        raw_body = request.body
        if len(raw_body) > max_body_bytes:
            raise ValueError(
                f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
            )

    headers_mapping: dict[str, str] = {}
    if hasattr(request, "headers"):
        headers_mapping = dict(request.headers)
    else:  # pragma: no cover
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").lower()
                headers_mapping[header_name] = str(value)
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                header_name = key.replace("_", "-").lower()
                headers_mapping[header_name] = str(value)

    return parse_webhook_payload(
        raw_body,
        headers=headers_mapping,
        secret=resolved_secret,
        max_age_seconds=max_age_seconds,
    )


def didit_webhook_view(
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
    dedup_key_builder: Callable[[WebhookPayload, HttpRequest], str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Django view decorator for verifying, parsing, and reserving Didit webhooks.

    Automatically applies @csrf_exempt, enforces POST method, bounds request body
    memory, validates cryptographic signatures, handles deduplication/leasing, and passes
    the parsed WebhookPayload into the decorated view function. Supports both synchronous
    and asynchronous Django view functions.
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
    if processing_action not in ("retry", "pass", "raise"):
        raise ValueError(
            f"Invalid processing_action '{processing_action}'. Must be 'retry', 'pass', or 'raise'."
        )

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        is_async = inspect.iscoroutinefunction(view_func)

        if (
            not is_async
            and dedup_store is not None
            and hasattr(dedup_store, "areserve")
            and not hasattr(dedup_store, "reserve")
        ):
            raise DiditConfigurationError(
                "AsyncWebhookReservationStore cannot be used with synchronous Django view "
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
                "AsyncWebhookDedupStore cannot be used with synchronous Django view functions. "
                "Use WebhookDedupStore or WebhookReservationStore."
            )

        if is_async:

            @functools.wraps(view_func)
            async def async_wrapper(
                request: HttpRequest, *args: Any, **kwargs: Any
            ) -> HttpResponse:
                if request.method != "POST":
                    return HttpResponse("Method not allowed", status=405, content_type="text/plain")

                try:
                    payload = parse_django_webhook(
                        request,
                        resolved_secret,
                        max_age_seconds=max_age_seconds,
                        max_body_bytes=max_body_bytes,
                    )
                except ValueError:
                    return HttpResponse(
                        f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes",
                        status=413,
                        content_type="text/plain",
                    )
                except DiditSignatureError as err:
                    err_msg = str(err)
                    if "Invalid JSON" in err_msg or "unsupported" in err_msg:
                        return HttpResponseBadRequest("Malformed JSON in webhook body")
                    return HttpResponse(
                        "Invalid webhook signature or expired timestamp",
                        status=401,
                        content_type="text/plain",
                    )

                is_new = False
                dedup_key = ""
                res_token: str | None = None
                if dedup_store is not None:
                    if dedup_key_builder is not None:
                        dedup_key = dedup_key_builder(payload, request)
                    else:
                        sig = getattr(request, "headers", {}).get("x-signature-sha256") or getattr(
                            request, "headers", {}
                        ).get("x-signature-v2")
                        dedup_key = compute_dedup_key(payload, signature=sig)

                    attempt = await areserve_webhook_event(
                        dedup_store, dedup_key, ttl_seconds=dedup_ttl_seconds
                    )
                    is_new = attempt.state == ReservationState.ACQUIRED
                    if attempt.reservation is not None:
                        res_token = attempt.reservation.token
                        request.didit_reservation = attempt.reservation

                    if attempt.state == ReservationState.COMPLETED:
                        if duplicate_action == "respond_ok":
                            return HttpResponse(
                                "Duplicate webhook event acknowledged",
                                status=200,
                                content_type="text/plain",
                            )
                        if duplicate_action == "raise":
                            return HttpResponse(
                                "Duplicate webhook event",
                                status=409,
                                content_type="text/plain",
                            )
                        payload.is_duplicate = True

                    elif attempt.state == ReservationState.PROCESSING:
                        if processing_action == "retry":
                            resp = HttpResponse(
                                "Webhook event currently being processed by another worker",
                                status=503,
                                content_type="text/plain",
                            )
                            resp["Retry-After"] = "5"
                            return resp
                        if processing_action == "raise":
                            return HttpResponse(
                                "Webhook event currently being processed",
                                status=409,
                                content_type="text/plain",
                            )
                        payload.is_duplicate = True

                try:
                    sig_params = inspect.signature(view_func).parameters
                    if len(sig_params) >= 2 or "payload" in sig_params:
                        result = await view_func(request, payload, *args, **kwargs)
                    else:  # pragma: no cover
                        result = await view_func(request, *args, **kwargs)
                except Exception:
                    if dedup_store is not None and is_new:
                        await arelease_webhook_event(dedup_store, dedup_key, token=res_token)
                    raise

                if dedup_store is not None and is_new:
                    status_code = getattr(result, "status_code", None)
                    if isinstance(status_code, int) and status_code >= 500:
                        await arelease_webhook_event(dedup_store, dedup_key, token=res_token)
                    elif res_token is not None:
                        await acomplete_webhook_event(dedup_store, dedup_key, token=res_token)

                if result is None:
                    return HttpResponse(status=200)
                return cast(HttpResponse, result)

            async_wrapper.csrf_exempt = True  # type: ignore[attr-defined]
            return cast(Callable[..., Any], async_wrapper)

        @functools.wraps(view_func)
        def sync_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            if request.method != "POST":
                return HttpResponse("Method not allowed", status=405, content_type="text/plain")

            try:
                payload = parse_django_webhook(
                    request,
                    resolved_secret,
                    max_age_seconds=max_age_seconds,
                    max_body_bytes=max_body_bytes,
                )
            except ValueError:
                return HttpResponse(
                    f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes",
                    status=413,
                    content_type="text/plain",
                )
            except DiditSignatureError as err:
                err_msg = str(err)
                if "Invalid JSON" in err_msg or "unsupported" in err_msg:
                    return HttpResponseBadRequest("Malformed JSON in webhook body")
                return HttpResponse(
                    "Invalid webhook signature or expired timestamp",
                    status=401,
                    content_type="text/plain",
                )

            is_new = False
            dedup_key = ""
            res_token: str | None = None
            if dedup_store is not None:
                if hasattr(dedup_store, "areserve") and not hasattr(dedup_store, "reserve"):
                    raise DiditConfigurationError(
                        "AsyncWebhookReservationStore cannot be used with "
                        "synchronous Django view functions. Use WebhookReservationStore."
                    )
                if (
                    hasattr(dedup_store, "aclaim")
                    and not hasattr(dedup_store, "claim")
                    and not hasattr(dedup_store, "reserve")
                ):
                    raise DiditConfigurationError(
                        "AsyncWebhookDedupStore cannot be used with "
                        "synchronous Django view functions. Use WebhookDedupStore."
                    )

                if dedup_key_builder is not None:
                    dedup_key = dedup_key_builder(payload, request)
                else:
                    sig = getattr(request, "headers", {}).get("x-signature-sha256") or getattr(
                        request, "headers", {}
                    ).get("x-signature-v2")
                    dedup_key = compute_dedup_key(payload, signature=sig)

                claim_fn = getattr(dedup_store, "claim", None)
                if claim_fn is not None and not hasattr(dedup_store, "reserve"):
                    claim_res = claim_fn(dedup_key, ttl_seconds=dedup_ttl_seconds)
                    if inspect.isawaitable(claim_res):
                        if inspect.iscoroutine(claim_res):
                            claim_res.close()
                        raise DiditConfigurationError(
                            "dedup_store.claim returned a coroutine in a synchronous Django view. "
                            "Provide a synchronous WebhookDedupStore."
                        )
                    is_new = bool(claim_res)
                    if not is_new:
                        if duplicate_action == "respond_ok":
                            return HttpResponse(
                                "Duplicate webhook event acknowledged",
                                status=200,
                                content_type="text/plain",
                            )
                        if duplicate_action == "raise":
                            return HttpResponse(
                                "Duplicate webhook event",
                                status=409,
                                content_type="text/plain",
                            )
                        payload.is_duplicate = True
                else:
                    attempt = reserve_webhook_event(
                        dedup_store, dedup_key, ttl_seconds=dedup_ttl_seconds
                    )
                    is_new = attempt.state == ReservationState.ACQUIRED
                    if attempt.reservation is not None:
                        res_token = attempt.reservation.token
                        request.didit_reservation = attempt.reservation

                    if attempt.state == ReservationState.COMPLETED:
                        if duplicate_action == "respond_ok":
                            return HttpResponse(
                                "Duplicate webhook event acknowledged",
                                status=200,
                                content_type="text/plain",
                            )
                        if duplicate_action == "raise":
                            return HttpResponse(
                                "Duplicate webhook event",
                                status=409,
                                content_type="text/plain",
                            )
                        payload.is_duplicate = True

                    elif attempt.state == ReservationState.PROCESSING:
                        if processing_action == "retry":
                            resp = HttpResponse(
                                "Webhook event currently being processed by another worker",
                                status=503,
                                content_type="text/plain",
                            )
                            resp["Retry-After"] = "5"
                            return resp
                        if processing_action == "raise":
                            return HttpResponse(
                                "Webhook event currently being processed",
                                status=409,
                                content_type="text/plain",
                            )
                        payload.is_duplicate = True

            try:
                sig_params = inspect.signature(view_func).parameters
                if len(sig_params) >= 2 or "payload" in sig_params:
                    result = view_func(request, payload, *args, **kwargs)
                else:  # pragma: no cover
                    result = view_func(request, *args, **kwargs)
            except Exception:
                if dedup_store is not None and is_new:
                    release_webhook_event(dedup_store, dedup_key, token=res_token)
                raise

            if dedup_store is not None and is_new:
                status_code = getattr(result, "status_code", None)
                if isinstance(status_code, int) and status_code >= 500:
                    release_webhook_event(dedup_store, dedup_key, token=res_token)
                elif res_token is not None:
                    complete_webhook_event(dedup_store, dedup_key, token=res_token)

            if result is None:
                return HttpResponse(status=200)
            return cast(HttpResponse, result)

        sync_wrapper.csrf_exempt = True  # type: ignore[attr-defined]
        return cast(Callable[..., Any], sync_wrapper)

    return decorator
