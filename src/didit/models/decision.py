"""Decision and verification result data models matching Didit V3 API contracts."""

from __future__ import annotations

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
    Provides backward-compatible singular accessors for legacy code.
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

        # Normalize legacy document field
        if "document" in data and "id_verifications" not in data:
            doc = data.pop("document")
            if doc and isinstance(doc, dict):
                if "status" not in doc and "is_valid" in doc:
                    doc["status"] = "Approved" if doc["is_valid"] else "Declined"
                data["id_verifications"] = [doc]

        # Normalize legacy biometrics field
        if "biometrics" in data:
            bio = data.pop("biometrics")
            if bio and isinstance(bio, dict):
                if "liveness_checks" not in data and "liveness_check" in bio:
                    data["liveness_checks"] = [
                        {
                            "status": "Approved" if bio["liveness_check"] else "Declined",
                            "score": bio.get("score"),
                        }
                    ]
                if "face_matches" not in data and "face_match" in bio:
                    data["face_matches"] = [
                        {
                            "status": "Approved" if bio["face_match"] else "Declined",
                            "score": bio.get("score"),
                        }
                    ]

        # Normalize legacy aml field
        if "aml" in data and "aml_screenings" not in data:
            aml = data.pop("aml")
            if aml and isinstance(aml, dict):
                data["aml_screenings"] = [aml]

        # Normalize legacy review field
        if "review" in data and "reviews" not in data:
            rev = data.pop("review")
            if rev and isinstance(rev, dict):
                data["reviews"] = [rev]

        return data

    @property
    def document(self) -> DocumentData | None:
        """Backward-compatible view of first document verification."""
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

    @document.setter
    def document(self, val: DocumentData | None) -> None:
        if val is None:
            self.id_verifications = []
        else:
            self.id_verifications = [
                IdVerificationResult(
                    first_name=val.first_name,
                    last_name=val.last_name,
                    document_number=val.document_number,
                    country=val.country,
                    document_type=val.document_type,
                    date_of_birth=val.date_of_birth,
                    expiration_date=val.expiration_date,
                    status=(
                        "Approved"
                        if val.is_valid
                        else ("Declined" if val.is_valid is False else None)
                    ),
                )
            ]

    @property
    def biometrics(self) -> BiometricsData | None:
        """Backward-compatible view of biometric matching."""
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

    @biometrics.setter
    def biometrics(self, val: BiometricsData | None) -> None:
        if val is None:
            self.liveness_checks = []
            self.face_matches = []
        else:
            if val.liveness_check is not None or val.score is not None:
                self.liveness_checks = [
                    LivenessResult(
                        status="Approved" if val.liveness_check else "Declined",
                        score=val.score,
                    )
                ]
            else:
                self.liveness_checks = []
            if val.face_match is not None:
                self.face_matches = [
                    FaceMatchResult(
                        status="Approved" if val.face_match else "Declined",
                        score=val.score,
                    )
                ]
            else:
                self.face_matches = []

    @property
    def aml(self) -> AMLData | None:
        """Backward-compatible view of AML screening."""
        if not self.aml_screenings:
            return None
        s = self.aml_screenings[0]
        return AMLData(
            pep_detected=s.pep_detected,
            sanctions_detected=s.sanctions_detected,
            adverse_media_detected=s.adverse_media_detected,
        )

    @aml.setter
    def aml(self, val: AMLData | None) -> None:
        if val is None:
            self.aml_screenings = []
        else:
            self.aml_screenings = [
                AMLScreeningResult(
                    status=(
                        "Declined"
                        if (
                            val.pep_detected or val.sanctions_detected or val.adverse_media_detected
                        )
                        else "Approved"
                    ),
                    pep_detected=val.pep_detected,
                    sanctions_detected=val.sanctions_detected,
                    adverse_media_detected=val.adverse_media_detected,
                )
            ]

    @property
    def review(self) -> ReviewData | None:
        """Backward-compatible view of review data."""
        return self.reviews[0] if self.reviews else None

    @review.setter
    def review(self, val: ReviewData | None) -> None:
        if val is None:
            self.reviews = []
        else:
            self.reviews = [val]
