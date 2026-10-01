"""Enumerations for Didit verification statuses and configurations."""

from __future__ import annotations

from enum import Enum
from typing import Literal


class SessionStatus(str, Enum):
    """Case-sensitive session statuses defined by Didit's Sessions API.

    Didit documents 10 lifecycle statuses:
    - Not Started: Initial state before user begins verification.
    - In Progress: User is actively submitting documents/biometrics.
    - In Review: Submission requires manual compliance or fraud analyst review.
    - Approved: All verification checks succeeded.
    - Declined: Verification failed one or more security or policy checks.
    - Expired: Session expired before completion.
    - Abandoned: User dropped off without completing the session.
    - Kyc Expired: Verification succeeded previously but KYC validity has elapsed.
    - Resubmitted: User resubmitted data after an initial issue.
    - Awaiting User: Waiting for additional user action or document retry.
    """

    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    IN_REVIEW = "In Review"
    APPROVED = "Approved"
    DECLINED = "Declined"
    EXPIRED = "Expired"
    ABANDONED = "Abandoned"
    KYC_EXPIRED = "Kyc Expired"
    RESUBMITTED = "Resubmitted"
    AWAITING_USER = "Awaiting User"

    @property
    def is_decided(self) -> bool:
        """Return True if an identity decision has been reached."""
        return self in (
            SessionStatus.APPROVED,
            SessionStatus.DECLINED,
            SessionStatus.KYC_EXPIRED,
        )

    @property
    def is_ended_without_decision(self) -> bool:
        """Return True if session expired or was abandoned before completion."""
        return self in (
            SessionStatus.EXPIRED,
            SessionStatus.ABANDONED,
        )

    @property
    def is_poll_complete(self) -> bool:
        """Return True if polling cycle has concluded (decided or ended without decision)."""
        return self.is_decided or self.is_ended_without_decision

    @property
    def is_closed(self) -> bool:
        """Return True if the session lifecycle has concluded."""
        return self.is_poll_complete

    @property
    def requires_review(self) -> bool:
        """Return True if manual compliance analyst intervention is required."""
        return self == SessionStatus.IN_REVIEW

    @property
    def requires_user_action(self) -> bool:
        """Return True if the workflow is waiting for the end user to take action."""
        return self in (
            SessionStatus.NOT_STARTED,
            SessionStatus.IN_PROGRESS,
            SessionStatus.RESUBMITTED,
            SessionStatus.AWAITING_USER,
        )

    @property
    def requires_resubmission(self) -> bool:
        """Return True if session requires user resubmission of documents/biometrics."""
        return self == SessionStatus.RESUBMITTED

    @property
    def is_terminal(self) -> bool:
        """Backward-compatible alias for ``is_closed``."""
        return self.is_closed

    @property
    def is_in_review(self) -> bool:
        """Backward-compatible alias for ``requires_review``."""
        return self.requires_review


ManualSessionStatus = Literal[
    SessionStatus.APPROVED,
    SessionStatus.DECLINED,
    SessionStatus.RESUBMITTED,
    "Approved",
    "Declined",
    "Resubmitted",
]

ALLOWED_MANUAL_STATUSES: set[SessionStatus | str] = {
    SessionStatus.APPROVED,
    SessionStatus.DECLINED,
    SessionStatus.RESUBMITTED,
    "Approved",
    "Declined",
    "Resubmitted",
}


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
