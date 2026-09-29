"""Unofficial, community-maintained Python client for the Didit Identity Verification API.

Notice:
    This is an independent open-source library and is not officially affiliated
    with or endorsed by Didit Protocol Inc. See the NOTICE file for details.
"""

from didit.client import AsyncDidit, Didit
from didit.config import DiditConfig
from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditError,
    DiditNotFoundError,
    DiditRateLimitError,
    DiditServerError,
    DiditSignatureError,
    DiditTimeoutError,
)
from didit.models.decision import (
    AMLData,
    AMLScreeningResult,
    BiometricsData,
    DecisionResponse,
    DocumentData,
    FaceMatchResult,
    IdVerificationResult,
    LivenessResult,
    ReviewData,
)
from didit.models.enums import Language, SessionStatus
from didit.models.session import CreateSessionRequest, SessionResponse
from didit.models.webhook import WebhookPayload
from didit.simulation import SimulatedAsyncDidit, SimulatedDidit
from didit.webhooks import parse_webhook_payload, verify_webhook_signature

__version__ = "0.1.2"

__all__ = [
    "AMLData",
    "AMLScreeningResult",
    "AsyncDidit",
    "BiometricsData",
    "CreateSessionRequest",
    "DecisionResponse",
    "Didit",
    "DiditAPIError",
    "DiditAuthenticationError",
    "DiditConfig",
    "DiditConfigurationError",
    "DiditError",
    "DiditNotFoundError",
    "DiditRateLimitError",
    "DiditServerError",
    "DiditSignatureError",
    "DiditTimeoutError",
    "DocumentData",
    "FaceMatchResult",
    "IdVerificationResult",
    "Language",
    "LivenessResult",
    "ReviewData",
    "SessionResponse",
    "SessionStatus",
    "SimulatedAsyncDidit",
    "SimulatedDidit",
    "WebhookPayload",
    "__version__",
    "parse_webhook_payload",
    "verify_webhook_signature",
]
