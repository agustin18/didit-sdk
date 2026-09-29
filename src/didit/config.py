"""Configuration and global defaults for Didit SDK."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_BASE_URL: str = "https://verification.didit.me/v3"
DEFAULT_TIMEOUT: float = 30.0
DEFAULT_MAX_RETRIES: int = 2
DEFAULT_WEBHOOK_MAX_AGE_SECONDS: int = 300  # 5 minutes


@dataclass(frozen=True)
class DiditConfig:
    """Immutable client configuration."""

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    timeout: float = DEFAULT_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES
    webhook_secret: str | None = None

    @classmethod
    def from_env(
        cls,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        webhook_secret: str | None = None,
    ) -> DiditConfig:
        """Resolve configuration falling back to environment variables."""
        resolved_key = api_key or os.environ.get("DIDIT_API_KEY")
        if not resolved_key:
            from didit.errors import DiditConfigurationError

            raise DiditConfigurationError(
                "Missing Didit API key. "
                "Provide api_key or set the DIDIT_API_KEY environment variable."
            )

        resolved_base_url = (
            base_url or os.environ.get("DIDIT_BASE_URL") or DEFAULT_BASE_URL
        ).rstrip("/")

        resolved_timeout = (
            timeout
            if timeout is not None
            else float(os.environ.get("DIDIT_TIMEOUT", DEFAULT_TIMEOUT))
        )

        resolved_retries = (
            max_retries
            if max_retries is not None
            else int(os.environ.get("DIDIT_MAX_RETRIES", DEFAULT_MAX_RETRIES))
        )

        resolved_secret = webhook_secret or os.environ.get("DIDIT_WEBHOOK_SECRET")

        return cls(
            api_key=resolved_key,
            base_url=resolved_base_url,
            timeout=resolved_timeout,
            max_retries=resolved_retries,
            webhook_secret=resolved_secret,
        )
