"""Enumerations for Didit verification statuses and configurations."""

from __future__ import annotations

from enum import Enum


class SessionStatus(str, Enum):
    """Case-sensitive session statuses defined by Didit's Sessions API."""

    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    IN_REVIEW = "In Review"
    APPROVED = "Approved"
    DECLINED = "Declined"

    @property
    def is_terminal(self) -> bool:
        """Return True if the verification workflow has finished (Approved or Declined)."""
        return self in (SessionStatus.APPROVED, SessionStatus.DECLINED)

    @property
    def is_in_review(self) -> bool:
        """Return True if the verification requires manual human review."""
        return self == SessionStatus.IN_REVIEW


class Language(str, Enum):
    """Supported UI languages for Didit hosted verification pages."""

    EN = "en"
    ES = "es"
    FR = "fr"
    DE = "de"
    IT = "it"
    PT = "pt"
    CA = "ca"
    EU = "eu"
    GL = "gl"
