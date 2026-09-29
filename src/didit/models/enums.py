"""Enumerations for Didit verification statuses and configurations."""

from __future__ import annotations

from enum import Enum


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
    def is_closed(self) -> bool:
        """Return True if the session lifecycle has concluded."""
        return self in (
            SessionStatus.APPROVED,
            SessionStatus.DECLINED,
            SessionStatus.EXPIRED,
            SessionStatus.ABANDONED,
            SessionStatus.KYC_EXPIRED,
        )

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
    def is_terminal(self) -> bool:
        """Backward-compatible alias for ``is_closed``."""
        return self.is_closed

    @property
    def is_in_review(self) -> bool:
        """Backward-compatible alias for ``requires_review``."""
        return self.requires_review


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
