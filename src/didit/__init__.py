"""Unofficial, community-maintained Python client for the Didit Identity Verification API.

Notice:
    This is an independent open-source library and is not officially affiliated
    with or endorsed by Didit Protocol Inc. See the NOTICE file for details.
"""

from didit._version import __version__
from didit.client import AsyncDidit, Didit
from didit.config import DiditConfig
from didit.dedup import (
    AsyncRedisWebhookDedupStore,
    AsyncWebhookDedupStore,
    DedupFailureMode,
    InMemoryWebhookDedupStore,
    RedisWebhookDedupStore,
    WebhookDedupStore,
    compute_dedup_key,
)
from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditDedupError,
    DiditDedupSaturationError,
    DiditError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditPoolTimeoutError,
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
from didit.transport import RequestOptions, RetryPolicy
from didit.webhooks import parse_webhook_payload, verify_webhook_signature

__all__ = [
    "AMLData",
    "AMLScreeningResult",
    "AsyncDidit",
    "AsyncRedisWebhookDedupStore",
    "AsyncWebhookDedupStore",
    "BiometricsData",
    "CreateSessionRequest",
    "DecisionResponse",
    "DedupFailureMode",
    "Didit",
    "DiditAPIError",
    "DiditAuthenticationError",
    "DiditConfig",
    "DiditConfigurationError",
    "DiditConnectionError",
    "DiditDedupError",
    "DiditDedupSaturationError",
    "DiditError",
    "DiditNotFoundError",
    "DiditPermissionError",
    "DiditPoolTimeoutError",
    "DiditRateLimitError",
    "DiditServerError",
    "DiditSignatureError",
    "DiditTimeoutError",
    "DocumentData",
    "FaceMatchResult",
    "IdVerificationResult",
    "InMemoryWebhookDedupStore",
    "Language",
    "LivenessResult",
    "RedisWebhookDedupStore",
    "RequestOptions",
    "RetryPolicy",
    "ReviewData",
    "SessionResponse",
    "SessionStatus",
    "SimulatedAsyncDidit",
    "SimulatedDidit",
    "WebhookDedupStore",
    "WebhookPayload",
    "__version__",
    "compute_dedup_key",
    "parse_webhook_payload",
    "verify_webhook_signature",
]
