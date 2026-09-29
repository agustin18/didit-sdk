"""Official-grade Python SDK for Didit Identity Verification & KYC.

Disclaimer:
    This is an independent open-source library and is not officially affiliated
    with or endorsed by Didit Protocol Inc.
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
    BiometricsData,
    DecisionResponse,
    DocumentData,
    ReviewData,
)
from didit.models.enums import Language, SessionStatus
from didit.models.session import CreateSessionRequest, SessionResponse
from didit.models.webhook import WebhookPayload
from didit.simulation import SimulatedAsyncDidit, SimulatedDidit
from didit.webhooks import parse_webhook_payload, verify_webhook_signature

__version__ = "0.1.0"

__all__ = [
    "AMLData",
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
    "Language",
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
