"""Web framework integrations for Didit SDK."""

from __future__ import annotations

from typing import Any

__all__ = [
    "DiditWebhookGuard",
    "didit_webhook",
    "didit_webhook_view",
    "parse_django_webhook",
    "parse_flask_webhook",
    "release_didit_claim",
]


def __getattr__(name: str) -> Any:
    if name in ("DiditWebhookGuard", "release_didit_claim"):
        try:
            from didit.integrations.fastapi import (
                DiditWebhookGuard,
                release_didit_claim,
            )

            if name == "DiditWebhookGuard":
                return DiditWebhookGuard
            return release_didit_claim
        except ImportError as e:
            raise ImportError(
                "FastAPI is required for FastAPI integrations. "
                "Install it with 'pip install didit-sdk[fastapi]'."
            ) from e
    if name in ("didit_webhook_view", "parse_django_webhook"):
        try:
            from didit.integrations.django import (
                didit_webhook_view,
                parse_django_webhook,
            )

            if name == "didit_webhook_view":
                return didit_webhook_view
            return parse_django_webhook
        except ImportError as e:
            raise ImportError(
                "Django is required for Django integrations. "
                "Install it with 'pip install didit-sdk[django]'."
            ) from e
    if name in ("didit_webhook", "parse_flask_webhook"):
        try:
            from didit.integrations.flask import (
                didit_webhook,
                parse_flask_webhook,
            )

            if name == "didit_webhook":
                return didit_webhook
            return parse_flask_webhook
        except ImportError as e:
            raise ImportError(
                "Flask is required for Flask integrations. "
                "Install it with 'pip install didit-sdk[flask]'."
            ) from e
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
