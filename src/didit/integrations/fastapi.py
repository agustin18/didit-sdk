"""FastAPI integration for verifying, parsing, and deduplicating Didit webhooks."""

from __future__ import annotations

import functools
import inspect
import os
from collections.abc import Callable
from typing import Any, Literal

from starlette.requests import Request
from starlette.responses import Response as StarletteResponse
from starlette.types import Message, Receive, Scope, Send

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
from didit.errors import (
    DiditConfigurationError,
    DiditDuplicateWebhookError,
    DiditSignatureError,
)
from didit.events import (
    DiditEventSink,
    WebhookDuplicateObserved,
    WebhookLeaseDegraded,
    WebhookLeaseLost,
    safe_emit,
)
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
        lease_ttl_seconds: int = 30,
        completed_ttl_seconds: int = 86400,
        dedup_ttl_seconds: int | None = None,
        duplicate_action: Literal["respond_ok", "pass", "raise"] = "pass",
        processing_action: Literal["retry", "pass", "raise", "conflict"] = "retry",
        dedup_key_builder: Callable[[WebhookPayload, Request], str] | None = None,
        event_sink: DiditEventSink | None = None,
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
        if processing_action not in ("retry", "pass", "raise", "conflict"):
            raise ValueError(
                f"Invalid processing_action '{processing_action}'. "
                "Must be 'retry', 'pass', 'raise', or 'conflict'."
            )

        self.secret: str = resolved_secret
        self.max_age_seconds = max_age_seconds
        self.max_body_bytes = max_body_bytes
        self.dedup_store = dedup_store
        self.lease_ttl_seconds = lease_ttl_seconds
        self.completed_ttl_seconds = completed_ttl_seconds
        self.dedup_ttl_seconds = dedup_ttl_seconds
        self.effective_lease_ttl = lease_ttl_seconds
        self.effective_legacy_ttl = dedup_ttl_seconds if dedup_ttl_seconds is not None else 86400
        self.effective_completed_ttl = completed_ttl_seconds
        self.duplicate_action = duplicate_action
        self.processing_action = processing_action
        self.dedup_key_builder = dedup_key_builder
        self.event_sink = event_sink

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

        sink = (
            self.event_sink
            or getattr(getattr(request, "state", None), "didit_event_sink", None)
            or getattr(
                getattr(getattr(request, "app", None), "state", None), "didit_event_sink", None
            )
        )
        request.state.didit_event_sink = sink
        request.state.didit_event_id = payload.event_id
        request.state.didit_session_id = payload.session_id

        if self.dedup_store is not None:
            if self.dedup_key_builder is not None:
                dedup_key = self.dedup_key_builder(payload, request)
            else:
                sig = request.headers.get("x-signature-sha256") or request.headers.get(
                    "x-signature-v2"
                )
                dedup_key = compute_dedup_key(payload, signature=sig)

            attempt = await areserve_webhook_event(
                self.dedup_store,
                dedup_key,
                ttl_seconds=self.effective_lease_ttl,
                legacy_ttl_seconds=self.effective_legacy_ttl,
            )
            request.state.didit_dedup_key = dedup_key
            request.state.didit_dedup_store = self.dedup_store
            request.state.didit_attempt = attempt
            request.state.didit_reservation = attempt.reservation
            request.state.didit_claimed = attempt.state == ReservationState.ACQUIRED
            request.state.didit_completed_ttl = self.effective_completed_ttl

            if attempt.degraded:
                safe_emit(
                    sink,
                    WebhookLeaseDegraded(
                        event_id=payload.event_id,
                        session_id=payload.session_id,
                        reason="dedup_store_fail_open",
                    ),
                )

            if attempt.state == ReservationState.COMPLETED:
                safe_emit(
                    sink,
                    WebhookDuplicateObserved(
                        event_id=payload.event_id,
                        session_id=payload.session_id,
                        action_taken=self.duplicate_action,
                    ),
                )
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
                safe_emit(
                    sink,
                    WebhookDuplicateObserved(
                        event_id=payload.event_id,
                        session_id=payload.session_id,
                        action_taken=self.processing_action,
                    ),
                )
                if self.processing_action == "retry":
                    raise HTTPException(
                        status_code=503,
                        headers={"Retry-After": "5"},
                        detail="Webhook event currently being processed by another worker",
                    )
                if self.processing_action == "conflict":
                    raise HTTPException(
                        status_code=409,
                        detail="Webhook event currently being processed",
                    )
                if self.processing_action == "raise":
                    raise DiditDuplicateWebhookError(
                        "Webhook event currently being processed by another worker",
                        event_id=payload.event_id,
                        state="PROCESSING",
                    )
                # "pass" mode
                payload.is_duplicate = True
                request.state.is_duplicate = True

            else:  # ACQUIRED
                payload.is_duplicate = False
                request.state.is_duplicate = False

        return payload

    async def release_claim(self, request: Request) -> bool:
        """Release dedup claim or reservation associated with this request if processing failed."""
        if self.dedup_store is not None:
            key = getattr(request.state, "didit_dedup_key", None)
            claimed = getattr(request.state, "didit_claimed", False)
            res = getattr(request.state, "didit_reservation", None)
            token = res.token if res else None
            if key and claimed:
                released = await arelease_webhook_event(self.dedup_store, key, token=token)
                request.state.didit_claimed = False
                if not released:
                    sink = (
                        self.event_sink
                        or getattr(getattr(request, "state", None), "didit_event_sink", None)
                        or getattr(
                            getattr(getattr(request, "app", None), "state", None),
                            "didit_event_sink",
                            None,
                        )
                    )
                    safe_emit(
                        sink,
                        WebhookLeaseLost(
                            event_id=getattr(getattr(request, "state", None), "didit_event_id", ""),
                            session_id=getattr(
                                getattr(request, "state", None), "didit_session_id", None
                            ),
                            reason="lease_release_cas_failed",
                        ),
                    )
                return released
        return True

    async def complete_reservation(
        self, request: Request, completed_ttl: int | None = None
    ) -> bool:
        """Transition active reservation to COMPLETED state upon successful processing."""
        if self.dedup_store is not None:
            key = getattr(request.state, "didit_dedup_key", None)
            res = getattr(request.state, "didit_reservation", None)
            if key and res:
                ttl = completed_ttl if completed_ttl is not None else self.effective_completed_ttl
                success = await acomplete_webhook_event(
                    self.dedup_store, key, token=res.token, completed_ttl=ttl
                )
                request.state.didit_claimed = False
                return success
        return False


async def release_didit_claim(request: Request) -> bool:
    """Helper to release claim or reservation recorded on request.state if processing failed."""
    store = getattr(request.state, "didit_dedup_store", None)
    key = getattr(request.state, "didit_dedup_key", None)
    claimed = getattr(request.state, "didit_claimed", False)
    res = getattr(request.state, "didit_reservation", None)
    token = res.token if res else None
    if store and key and claimed:
        released = await arelease_webhook_event(store, key, token=token)
        request.state.didit_claimed = False
        request.state.didit_reservation = None
        if not released:
            sink = getattr(getattr(request, "state", None), "didit_event_sink", None) or getattr(
                getattr(getattr(request, "app", None), "state", None), "didit_event_sink", None
            )
            safe_emit(
                sink,
                WebhookLeaseLost(
                    event_id=getattr(getattr(request, "state", None), "didit_event_id", ""),
                    session_id=getattr(getattr(request, "state", None), "didit_session_id", None),
                    reason="lease_release_cas_failed",
                ),
            )
        return released
    return True


async def complete_didit_reservation(request: Request, completed_ttl: int = 86400) -> bool:
    """Helper to complete active reservation on request.state upon successful processing."""
    store = getattr(request.state, "didit_dedup_store", None)
    key = getattr(request.state, "didit_dedup_key", None)
    claimed = getattr(request.state, "didit_claimed", False)
    res = getattr(request.state, "didit_reservation", None)
    ttl = getattr(request.state, "didit_completed_ttl", completed_ttl)
    if store and key and claimed and res:
        success = await acomplete_webhook_event(store, key, token=res.token, completed_ttl=ttl)
        request.state.didit_claimed = False
        request.state.didit_reservation = None
        if not success:
            sink = getattr(getattr(request, "state", None), "didit_event_sink", None) or getattr(
                getattr(getattr(request, "app", None), "state", None), "didit_event_sink", None
            )
            safe_emit(
                sink,
                WebhookLeaseLost(
                    event_id=getattr(getattr(request, "state", None), "didit_event_id", ""),
                    session_id=getattr(getattr(request, "state", None), "didit_session_id", None),
                    reason="lease_cas_failed",
                ),
            )
        return success
    return False


class _ResponseCapture:
    """ASGI Send capture buffer to inspect HTTP status code before committing reservation."""

    def __init__(self, send: Send, request: Request) -> None:
        self.send = send
        self.request = request
        self.pass_through = False
        self.status_code: int = 500
        self.messages: list[Message] = []

    async def capture_send(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.status_code = message.get("status", 500)
            if not getattr(self.request.state, "didit_claimed", False):
                self.pass_through = True
        if self.pass_through:
            await self.send(message)
        else:
            self.messages.append(message)

    async def flush(self) -> None:
        if not self.pass_through:
            for msg in self.messages:
                await self.send(msg)


try:
    from fastapi.routing import APIRoute
except ImportError:  # pragma: no cover

    class APIRoute:  # type: ignore[no-redef]
        pass


class DiditWebhookRoute(APIRoute):
    """FastAPI APIRoute subclass that manages Didit webhook reservation lifecycles
    at the final ASGI response boundary.

    Wraps route execution at the ASGI boundary to observe the complete request lifecycle,
    including endpoint execution, response validation, serialization, rendering,
    and dependency teardown (e.g. database transaction commit):
    - If route handler, response rendering, or dependency teardown raises an exception:
      automatically releases any active reservation recorded on request.state.
    - If the final response status is 2xx (200-299):
      automatically completes the active reservation.
    - If the final response status is non-2xx (e.g. 404, 500):
      automatically releases the active reservation so retries succeed.

    Note:
        DiditWebhookRoute is intended for short, non-streaming webhook responses. Streaming
        responses on claimed webhooks are buffered until completion before acknowledgment.
        Any FastAPI BackgroundTasks execute prior to final ASGI response flush; keep background
        tasks light or enqueue to a durable background worker/broker.
    """

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await super().handle(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        capture = _ResponseCapture(send, request)
        try:
            await super().handle(scope, receive, capture.capture_send)
        except Exception:
            sink = getattr(getattr(request, "state", None), "didit_event_sink", None) or getattr(
                getattr(getattr(request, "app", None), "state", None), "didit_event_sink", None
            )
            try:
                await release_didit_claim(request)
            except Exception:
                safe_emit(
                    sink,
                    WebhookLeaseLost(
                        event_id=getattr(getattr(request, "state", None), "didit_event_id", ""),
                        session_id=getattr(
                            getattr(request, "state", None), "didit_session_id", None
                        ),
                        reason="lease_release_failed",
                    ),
                )
            raise

        if 200 <= capture.status_code < 300:
            await complete_didit_reservation(request)
        else:
            await release_didit_claim(request)

        await capture.flush()


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
    event_sink: DiditEventSink | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """FastAPI route decorator for verifying, parsing, and managing webhook lifecycle.

    Observes route execution and automatically manages the reservation lifecycle:
    - 2xx response (200-299): Automatically marks reservation as COMPLETED.
    - Non-2xx response (e.g. 404, 500): Automatically releases reservation so retries succeed.
    - Unhandled exception: Automatically releases reservation and re-raises exception.
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

    effective_lease_ttl = lease_ttl_seconds
    effective_legacy_ttl = dedup_ttl_seconds if dedup_ttl_seconds is not None else 86400
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
                "AsyncWebhookReservationStore cannot be used with synchronous view functions. "
                "Use WebhookReservationStore."
            )

        if (
            not is_async
            and dedup_store is not None
            and hasattr(dedup_store, "aclaim")
            and not hasattr(dedup_store, "claim")
            and not hasattr(dedup_store, "reserve")
        ):
            raise DiditConfigurationError(
                "AsyncWebhookDedupStore cannot be used with synchronous view functions. "
                "Use WebhookDedupStore or WebhookReservationStore."
            )

        @functools.wraps(view_func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            from fastapi import HTTPException

            request: Request | None = kwargs.get("request")
            if request is None:
                for a in args:
                    if isinstance(a, Request):
                        request = a
                        break

            if request is None:
                raise DiditConfigurationError(
                    "FastAPI request object not found in endpoint arguments."
                )

            route = (
                request.scope.get("route") if hasattr(request, "scope") and request.scope else None
            )

            is_reservation_store = dedup_store is not None and (
                isinstance(dedup_store, (WebhookReservationStore, AsyncWebhookReservationStore))
                or hasattr(dedup_store, "reserve")
                or hasattr(dedup_store, "areserve")
            )

            if is_reservation_store and not isinstance(route, DiditWebhookRoute):
                raise DiditConfigurationError(
                    "Tokenized reservation auto-lifecycle on FastAPI requires DiditWebhookRoute. "
                    "Mount your webhook endpoint on an APIRouter configured with "
                    "'route_class=DiditWebhookRoute'."
                )

            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    cl_val = int(content_length)
                    if cl_val > max_body_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail=(
                                f"Webhook payload exceeds maximum size limit of "
                                f"{max_body_bytes} bytes"
                            ),
                        )
                except ValueError:
                    pass

            body_chunks = []
            bytes_received = 0
            async for chunk in request.stream():
                bytes_received += len(chunk)
                if bytes_received > max_body_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Webhook payload exceeds maximum size limit of {max_body_bytes} bytes"
                        ),
                    )
                body_chunks.append(chunk)

            raw_body = b"".join(body_chunks)

            try:
                payload = parse_webhook_payload(
                    raw_body,
                    headers=dict(request.headers),
                    secret=resolved_secret,
                    max_age_seconds=max_age_seconds,
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

            sink = (
                event_sink
                or getattr(getattr(request, "state", None), "didit_event_sink", None)
                or getattr(
                    getattr(getattr(request, "app", None), "state", None), "didit_event_sink", None
                )
            )
            request.state.didit_event_sink = sink
            request.state.didit_event_id = payload.event_id
            request.state.didit_session_id = payload.session_id

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
                    dedup_store,
                    dedup_key,
                    ttl_seconds=effective_lease_ttl,
                    legacy_ttl_seconds=effective_legacy_ttl,
                )
                is_new = attempt.state == ReservationState.ACQUIRED
                request.state.didit_dedup_store = dedup_store
                request.state.didit_dedup_key = dedup_key
                request.state.didit_claimed = is_new
                request.state.didit_reservation = attempt.reservation
                request.state.didit_completed_ttl = effective_completed_ttl
                if attempt.reservation is not None:
                    res_token = attempt.reservation.token

                if attempt.degraded:
                    safe_emit(
                        sink,
                        WebhookLeaseDegraded(
                            event_id=payload.event_id,
                            session_id=payload.session_id,
                            reason="dedup_store_fail_open",
                        ),
                    )

                if attempt.state == ReservationState.COMPLETED:
                    safe_emit(
                        sink,
                        WebhookDuplicateObserved(
                            event_id=payload.event_id,
                            session_id=payload.session_id,
                            action_taken=duplicate_action,
                        ),
                    )
                    if duplicate_action == "respond_ok":
                        return StarletteResponse(
                            content="Duplicate webhook event acknowledged",
                            media_type="text/plain",
                            status_code=200,
                        )
                    if duplicate_action == "raise":
                        raise HTTPException(
                            status_code=409,
                            detail="Duplicate webhook event",
                        )
                    payload.is_duplicate = True

                elif attempt.state == ReservationState.PROCESSING:
                    safe_emit(
                        sink,
                        WebhookDuplicateObserved(
                            event_id=payload.event_id,
                            session_id=payload.session_id,
                            action_taken=processing_action,
                        ),
                    )
                    if processing_action == "retry":
                        raise HTTPException(
                            status_code=503,
                            headers={"Retry-After": "5"},
                            detail="Webhook event currently being processed by another worker",
                        )
                    if processing_action == "conflict":
                        raise HTTPException(
                            status_code=409,
                            detail="Webhook event currently being processed",
                        )
                    if processing_action == "raise":
                        raise DiditDuplicateWebhookError(
                            "Webhook event currently being processed by another worker",
                            event_id=payload.event_id,
                            state="PROCESSING",
                        )
                    payload.is_duplicate = True

            func_sig = inspect.signature(view_func)
            call_kwargs = {k: v for k, v in kwargs.items() if k in func_sig.parameters}
            if "payload" in func_sig.parameters:
                call_kwargs["payload"] = payload
            elif any(p.annotation is WebhookPayload for p in func_sig.parameters.values()):
                for p_name, p in func_sig.parameters.items():
                    if p.annotation is WebhookPayload:
                        call_kwargs[p_name] = payload
                        break

            route = (
                request.scope.get("route") if hasattr(request, "scope") and request.scope else None
            )

            try:
                if is_async:
                    result = await view_func(*args, **call_kwargs)
                else:
                    from starlette.concurrency import run_in_threadpool

                    result = await run_in_threadpool(view_func, *args, **call_kwargs)
            except Exception:
                if dedup_store is not None and is_new and not isinstance(route, DiditWebhookRoute):
                    req_state = getattr(request, "state", None)
                    event_sink_to_use = getattr(req_state, "didit_event_sink", None) or sink
                    evt_id = getattr(req_state, "didit_event_id", payload.event_id)
                    sess_id = getattr(req_state, "didit_session_id", payload.session_id)
                    try:
                        released = await arelease_webhook_event(
                            dedup_store, dedup_key, token=res_token
                        )
                        request.state.didit_claimed = False
                        request.state.didit_reservation = None
                        if not released:
                            safe_emit(
                                event_sink_to_use,
                                WebhookLeaseLost(
                                    event_id=evt_id,
                                    session_id=sess_id,
                                    reason="lease_release_cas_failed",
                                ),
                            )
                    except Exception:
                        safe_emit(
                            event_sink_to_use,
                            WebhookLeaseLost(
                                event_id=evt_id,
                                session_id=sess_id,
                                reason="lease_release_failed",
                            ),
                        )
                raise

            if isinstance(result, StarletteResponse):
                final_response = result
            else:
                route_status = getattr(route, "status_code", None)
                response_param = kwargs.get("response")
                resp_status = (
                    getattr(response_param, "status_code", None)
                    if response_param is not None
                    else None
                )
                result_status = getattr(result, "status_code", None)

                status_code: int = 200
                if isinstance(result_status, int):
                    status_code = result_status
                elif isinstance(resp_status, int):
                    status_code = resp_status
                elif isinstance(route_status, int):
                    status_code = route_status

                from fastapi.datastructures import DefaultPlaceholder
                from fastapi.responses import JSONResponse

                raw_resp_cls = getattr(route, "response_class", None) if route else None
                if raw_resp_cls is None or isinstance(raw_resp_cls, DefaultPlaceholder):
                    resp_cls = JSONResponse
                else:
                    resp_cls = raw_resp_cls

                content = result
                if route is not None and getattr(route, "response_field", None) is not None:
                    from fastapi.routing import serialize_response

                    try:
                        content = await serialize_response(
                            field=route.response_field,
                            response_content=result,
                            include=getattr(route, "response_model_include", None),
                            exclude=getattr(route, "response_model_exclude", None),
                            by_alias=getattr(route, "response_model_by_alias", True),
                            exclude_unset=getattr(route, "response_model_exclude_unset", False),
                            exclude_defaults=getattr(
                                route, "response_model_exclude_defaults", False
                            ),
                            exclude_none=getattr(route, "response_model_exclude_none", False),
                        )
                    except Exception:
                        if dedup_store is not None and is_new:
                            rel = await arelease_webhook_event(
                                dedup_store, dedup_key, token=res_token
                            )
                            request.state.didit_claimed = False
                            request.state.didit_reservation = None
                            if not rel:
                                safe_emit(
                                    sink,
                                    WebhookLeaseLost(
                                        event_id=payload.event_id,
                                        session_id=payload.session_id,
                                        reason="lease_release_cas_failed",
                                    ),
                                )
                        raise

                try:
                    final_response = resp_cls(content, status_code=status_code)
                    if (
                        response_param is not None
                        and hasattr(final_response, "headers")
                        and hasattr(response_param, "headers")
                    ):
                        final_response.headers.raw.extend(response_param.headers.raw)
                except Exception:
                    if dedup_store is not None and is_new:
                        rel = await arelease_webhook_event(dedup_store, dedup_key, token=res_token)
                        request.state.didit_claimed = False
                        request.state.didit_reservation = None
                        if not rel:
                            safe_emit(
                                sink,
                                WebhookLeaseLost(
                                    event_id=payload.event_id,
                                    session_id=payload.session_id,
                                    reason="lease_release_cas_failed",
                                ),
                            )
                    raise

            # If the route is managed by DiditWebhookRoute, the route's ASGI wrapper
            # manages final completion or release after dependency teardown.
            if dedup_store is not None and is_new and not isinstance(route, DiditWebhookRoute):
                if 200 <= final_response.status_code < 300:
                    if res_token is not None:
                        success = await acomplete_webhook_event(
                            dedup_store,
                            dedup_key,
                            token=res_token,
                            completed_ttl=effective_completed_ttl,
                        )
                        request.state.didit_claimed = False
                        request.state.didit_reservation = None
                        if not success:
                            safe_emit(
                                sink,
                                WebhookLeaseLost(
                                    event_id=payload.event_id,
                                    session_id=payload.session_id,
                                    reason="lease_cas_failed",
                                ),
                            )
                else:
                    rel = await arelease_webhook_event(dedup_store, dedup_key, token=res_token)
                    request.state.didit_claimed = False
                    request.state.didit_reservation = None
                    if not rel:
                        safe_emit(
                            sink,
                            WebhookLeaseLost(
                                event_id=payload.event_id,
                                session_id=payload.session_id,
                                reason="lease_release_cas_failed",
                            ),
                        )

            return final_response

        func_sig = inspect.signature(view_func)
        new_params = []
        has_req = False
        has_resp = False
        for param in func_sig.parameters.values():
            if param.name == "payload" or param.annotation is WebhookPayload:
                continue
            if param.name == "request" or param.annotation is Request:
                has_req = True
            if (
                param.name == "response"
                or param.annotation is StarletteResponse
                or getattr(param.annotation, "__name__", "") == "Response"
            ):
                has_resp = True
            new_params.append(param)
        if not has_req:
            new_params.insert(
                0,
                inspect.Parameter(
                    "request",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Request,
                ),
            )
        if not has_resp:
            new_params.append(
                inspect.Parameter(
                    "response",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=None,
                    annotation=StarletteResponse,
                ),
            )
        wrapper.__signature__ = func_sig.replace(parameters=new_params)  # type: ignore[attr-defined]
        return wrapper

    return decorator


didit_webhook_view = didit_webhook
