"""Decision and verification result data models matching Didit V3 API contracts."""

from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from didit.models.enums import SessionStatus


class IdVerificationResult(BaseModel):
    """Identity document verification details."""

    model_config = ConfigDict(extra="allow")

    node_id: str | None = Field(default=None, description="Workflow step identifier")
    status: str | None = Field(default=None, description="Check outcome e.g. Approved, Declined")
    first_name: str | None = Field(default=None, description="Extracted given names")
    last_name: str | None = Field(default=None, description="Extracted family names")
    document_number: str | None = Field(default=None, description="Masked or raw document number")
    country: str | None = Field(default=None, description="ISO-3 country code of document")
    document_type: str | None = Field(
        default=None, description="e.g. passport, id_card, drivers_license"
    )
    date_of_birth: str | None = Field(default=None, description="YYYY-MM-DD format")
    expiration_date: str | None = Field(default=None, description="YYYY-MM-DD format")


class LivenessResult(BaseModel):
    """Facial liveness verification assessment."""

    model_config = ConfigDict(extra="allow")

    node_id: str | None = Field(default=None, description="Workflow step identifier")
    status: str | None = Field(default=None, description="Check outcome e.g. Approved, Declined")
    score: float | None = Field(default=None, description="Liveness confidence score")


class FaceMatchResult(BaseModel):
    """Facial match assessment comparing document photo against selfie."""

    model_config = ConfigDict(extra="allow")

    node_id: str | None = Field(default=None, description="Workflow step identifier")
    status: str | None = Field(default=None, description="Check outcome e.g. Approved, Declined")
    score: float | None = Field(default=None, description="Facial comparison score")


class AMLScreeningResult(BaseModel):
    """Anti-Money Laundering, PEP, and sanctions screening result."""

    model_config = ConfigDict(extra="allow")

    node_id: str | None = Field(default=None, description="Workflow step identifier")
    status: str | None = Field(default=None, description="Check outcome e.g. Approved, Declined")
    pep_detected: bool | None = Field(
        default=None, description="Politically Exposed Person detection"
    )
    sanctions_detected: bool | None = Field(
        default=None, description="International sanctions list match"
    )
    adverse_media_detected: bool | None = Field(default=None, description="Adverse media match")


class DocumentData(BaseModel):
    """Backward-compatible document extraction view."""

    model_config = ConfigDict(extra="allow")

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
    """Backward-compatible biometrics assessment view."""

    model_config = ConfigDict(extra="allow")

    face_match: bool | None = Field(default=None, description="Face match against document photo")
    liveness_check: bool | None = Field(
        default=None, description="Active or passive liveness check"
    )
    score: float | None = Field(
        default=None, description="Biometric confidence score between 0.0 and 1.0"
    )


class AMLData(BaseModel):
    """Backward-compatible AML and Watchlist screening view."""

    model_config = ConfigDict(extra="allow")

    pep_detected: bool | None = Field(
        default=None, description="Politically Exposed Person detection"
    )
    sanctions_detected: bool | None = Field(
        default=None, description="International sanctions list match"
    )
    adverse_media_detected: bool | None = Field(default=None, description="Adverse media match")


class ReviewData(BaseModel):
    """Manual or compliance agent review information."""

    model_config = ConfigDict(extra="allow")

    reviewed_by: str | None = Field(default=None, description="Identifier of the reviewer")
    decision_reason: str | None = Field(default=None, description="Reviewer explanation or notes")


class DecisionResponse(BaseModel):
    """Complete verification decision returned by Didit V3 API.

    Uses ``extra='allow'`` to preserve all upstream fields without silent data loss.
    Provides backward-compatible read-only singular accessors for legacy code.
    """

    model_config = ConfigDict(extra="allow")

    session_id: str = Field(..., description="Unique session identifier")
    status: SessionStatus = Field(..., description="Final or current verification status")
    workflow_id: str | None = Field(default=None, description="Associated workflow identifier")
    vendor_data: str | None = Field(default=None, description="Echoed vendor reference")

    id_verifications: list[IdVerificationResult] = Field(
        default_factory=list, description="Document verification results"
    )
    liveness_checks: list[LivenessResult] = Field(
        default_factory=list, description="Liveness check results"
    )
    face_matches: list[FaceMatchResult] = Field(
        default_factory=list, description="Facial comparison results"
    )
    aml_screenings: list[AMLScreeningResult] = Field(
        default_factory=list, description="AML and sanctions screening results"
    )
    nfc_verifications: list[dict[str, Any]] = Field(
        default_factory=list, description="NFC chip verification results"
    )
    phone_verifications: list[dict[str, Any]] = Field(
        default_factory=list, description="Phone verification results"
    )
    email_verifications: list[dict[str, Any]] = Field(
        default_factory=list, description="Email verification results"
    )
    poa_verifications: list[dict[str, Any]] = Field(
        default_factory=list, description="Proof of address verification results"
    )
    database_validations: list[dict[str, Any]] = Field(
        default_factory=list, description="Database validation results"
    )
    ip_analyses: list[dict[str, Any]] = Field(
        default_factory=list, description="IP risk analysis results"
    )
    reviews: list[ReviewData] = Field(
        default_factory=list, description="Human or agent review records"
    )
    raw_data: dict[str, Any] | None = Field(
        default=None, description="Raw JSON payload received from Didit"
    )

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_singular_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Deep copy to ensure caller input dictionary is never mutated in-place
        migrated = copy.deepcopy(data)

        # Normalize legacy document field
        if "document" in migrated and "id_verifications" not in migrated:
            doc = migrated.pop("document")
            if doc and isinstance(doc, dict):
                if "status" not in doc and "is_valid" in doc:
                    doc["status"] = "Approved" if doc["is_valid"] else "Declined"
                migrated["id_verifications"] = [doc]

        # Normalize legacy biometrics field
        if "biometrics" in migrated:
            bio = migrated.pop("biometrics")
            if bio and isinstance(bio, dict):
                if "liveness_checks" not in migrated and "liveness_check" in bio:
                    migrated["liveness_checks"] = [
                        {
                            "status": "Approved" if bio["liveness_check"] else "Declined",
                            "score": bio.get("score"),
                        }
                    ]
                if "face_matches" not in migrated and "face_match" in bio:
                    migrated["face_matches"] = [
                        {
                            "status": "Approved" if bio["face_match"] else "Declined",
                            "score": bio.get("score"),
                        }
                    ]

        # Normalize legacy aml field
        if "aml" in migrated and "aml_screenings" not in migrated:
            aml = migrated.pop("aml")
            if aml and isinstance(aml, dict):
                migrated["aml_screenings"] = [aml]

        # Normalize legacy review field
        if "review" in migrated and "reviews" not in migrated:
            rev = migrated.pop("review")
            if rev and isinstance(rev, dict):
                migrated["reviews"] = [rev]

        return migrated

    @property
    def document(self) -> DocumentData | None:
        """Backward-compatible read-only view of first document verification."""
        if not self.id_verifications:
            return None
        v = self.id_verifications[0]
        is_valid = (
            (v.status == "Approved") if v.status is not None else getattr(v, "is_valid", None)
        )
        return DocumentData(
            first_name=v.first_name,
            last_name=v.last_name,
            document_number=v.document_number,
            country=v.country,
            document_type=v.document_type,
            date_of_birth=v.date_of_birth,
            expiration_date=v.expiration_date,
            is_valid=is_valid,
        )

    @property
    def biometrics(self) -> BiometricsData | None:
        """Backward-compatible read-only view of biometric matching."""
        if not self.liveness_checks and not self.face_matches:
            return None
        live = self.liveness_checks[0] if self.liveness_checks else None
        face = self.face_matches[0] if self.face_matches else None
        score = live.score if (live and live.score is not None) else (face.score if face else None)
        return BiometricsData(
            face_match=(face.status == "Approved") if (face and face.status) else None,
            liveness_check=(live.status == "Approved") if (live and live.status) else None,
            score=score,
        )

    @property
    def aml(self) -> AMLData | None:
        """Backward-compatible read-only view of AML screening."""
        if not self.aml_screenings:
            return None
        s = self.aml_screenings[0]
        return AMLData(
            pep_detected=s.pep_detected,
            sanctions_detected=s.sanctions_detected,
            adverse_media_detected=s.adverse_media_detected,
        )

    @property
    def review(self) -> ReviewData | None:
        """Backward-compatible read-only view of review data."""
        return self.reviews[0] if self.reviews else None
