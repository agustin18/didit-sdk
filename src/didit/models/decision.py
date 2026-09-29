"""Decision and verification result data models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from didit.models.enums import SessionStatus


class DocumentData(BaseModel):
    """Document extraction and validation data."""

    model_config = ConfigDict(extra="ignore")

    document_type: str | None = Field(
        default=None, description="e.g. passport, id_card, drivers_license"
    )
    country: str | None = Field(default=None, description="ISO-3 country code")
    document_number: str | None = Field(default=None, description="Masked or raw document number")
    first_name: str | None = Field(default=None, description="Given names")
    last_name: str | None = Field(default=None, description="Family names")
    date_of_birth: str | None = Field(default=None, description="YYYY-MM-DD format")
    expiration_date: str | None = Field(default=None, description="YYYY-MM-DD format")
    is_valid: bool | None = Field(
        default=None, description="Whether document authenticity checks passed"
    )


class BiometricsData(BaseModel):
    """Facial matching and liveness assessment."""

    model_config = ConfigDict(extra="ignore")

    face_match: bool | None = Field(default=None, description="Face match against document photo")
    liveness_check: bool | None = Field(
        default=None, description="Active or passive liveness check"
    )
    score: float | None = Field(
        default=None, description="Biometric confidence score between 0.0 and 1.0"
    )


class AMLData(BaseModel):
    """Anti-Money Laundering and Watchlist screening results."""

    model_config = ConfigDict(extra="ignore")

    pep_detected: bool | None = Field(
        default=None, description="Politically Exposed Person detection"
    )
    sanctions_detected: bool | None = Field(
        default=None, description="International sanctions list match"
    )
    adverse_media_detected: bool | None = Field(default=None, description="Adverse media match")


class ReviewData(BaseModel):
    """Manual or compliance agent review information."""

    model_config = ConfigDict(extra="ignore")

    reviewed_by: str | None = Field(default=None, description="Identifier of the reviewer")
    decision_reason: str | None = Field(default=None, description="Reviewer explanation or notes")


class DecisionResponse(BaseModel):
    """Complete verification decision returned by Didit."""

    model_config = ConfigDict(extra="ignore")

    session_id: str = Field(..., description="Unique session identifier")
    status: SessionStatus = Field(..., description="Final or current verification status")
    workflow_id: str | None = Field(default=None, description="Associated workflow identifier")
    vendor_data: str | None = Field(default=None, description="Echoed vendor reference")
    document: DocumentData | None = Field(default=None, description="Document verification details")
    biometrics: BiometricsData | None = Field(
        default=None, description="Biometric matching details"
    )
    aml: AMLData | None = Field(default=None, description="AML / Watchlist screening details")
    review: ReviewData | None = Field(default=None, description="Human review details")
    raw_data: dict[str, Any] | None = Field(
        default=None, description="Raw JSON payload received from Didit"
    )
