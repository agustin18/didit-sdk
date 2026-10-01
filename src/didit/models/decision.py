"""Decision and verification result data models matching Didit V3 API contracts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from didit.models.enums import SessionStatus
from didit.models.session import ResubmitInfo


def _legacy_bool(status: str | None) -> bool | None:
    """Map Didit status to legacy boolean, returning None for non-decided states."""
    if status == "Approved":
        return True
    if status == "Declined":
        return False
    return None


class VerificationWarning(BaseModel):
    """Diagnostic warning or non-fatal issue encountered during verification."""

    model_config = ConfigDict(extra="allow")

    code: str | None = Field(
        default=None, description="Machine-readable warning code e.g. DOC_EXPIRING_SOON"
    )
    message: str | None = Field(default=None, description="Human-readable explanation of warning")
    risk: str | None = Field(default=None, description="Risk assessment")
    log_type: str | None = Field(default=None, description="Log type identifier")
    short_description: str | None = Field(default=None, description="Short summary")
    long_description: str | None = Field(default=None, description="Detailed explanation")
    severity: str | None = Field(
        default=None, description="Warning severity e.g. low, medium, high"
    )
    details: dict[str, Any] | None = Field(default=None, description="Detailed diagnostic context")

    @model_validator(mode="before")
    @classmethod
    def _coerce_warning(cls, data: Any) -> Any:
        if isinstance(data, str):
            return {"code": data, "message": data}
        return data

    @property
    def warning_code(self) -> str | None:
        """Normalized warning code identifier."""
        return self.code or self.risk or self.short_description or getattr(self, "log_type", None)

    def __repr__(self) -> str:
        return (
            f"VerificationWarning(code={self.warning_code or self.code!r}, "
            f"severity={self.severity!r})"
        )

    __str__ = __repr__


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
    warnings: list[VerificationWarning] = Field(
        default_factory=list, description="Step-level warnings"
    )

    def __repr__(self) -> str:
        return (
            f"IdVerificationResult(node_id={self.node_id!r}, "
            f"status={self.status!r}, "
            f"document_type={self.document_type!r})"
        )

    __str__ = __repr__


class LivenessResult(BaseModel):
    """Facial liveness verification assessment."""

    model_config = ConfigDict(extra="allow")

    node_id: str | None = Field(default=None, description="Workflow step identifier")
    status: str | None = Field(default=None, description="Check outcome e.g. Approved, Declined")
    score: float | None = Field(default=None, description="Liveness confidence score")
    warnings: list[VerificationWarning] = Field(
        default_factory=list, description="Step-level warnings"
    )

    def __repr__(self) -> str:
        return f"LivenessResult(node_id={self.node_id!r}, status={self.status!r})"

    __str__ = __repr__


class FaceMatchResult(BaseModel):
    """Facial match assessment comparing document photo against selfie."""

    model_config = ConfigDict(extra="allow")

    node_id: str | None = Field(default=None, description="Workflow step identifier")
    status: str | None = Field(default=None, description="Check outcome e.g. Approved, Declined")
    score: float | None = Field(default=None, description="Facial comparison score")
    warnings: list[VerificationWarning] = Field(
        default_factory=list, description="Step-level warnings"
    )

    def __repr__(self) -> str:
        return f"FaceMatchResult(node_id={self.node_id!r}, status={self.status!r})"

    __str__ = __repr__


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
    warnings: list[VerificationWarning] = Field(
        default_factory=list, description="Step-level warnings"
    )

    def __repr__(self) -> str:
        return f"AMLScreeningResult(node_id={self.node_id!r}, status={self.status!r})"

    __str__ = __repr__


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

    def __repr__(self) -> str:
        return f"DocumentData(document_type={self.document_type!r}, is_valid={self.is_valid})"

    __str__ = __repr__


class BiometricsData(BaseModel):
    """Backward-compatible biometrics assessment view."""

    model_config = ConfigDict(extra="allow")

    face_match: bool | None = Field(default=None, description="Face match against document photo")
    liveness_check: bool | None = Field(
        default=None, description="Active or passive liveness check"
    )
    score: float | None = Field(
        default=None, description="Biometric confidence score between 0.0 and 100.0"
    )

    def __repr__(self) -> str:
        return f"BiometricsData(face_match={self.face_match}, liveness_check={self.liveness_check})"

    __str__ = __repr__


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

    def __repr__(self) -> str:
        return (
            f"AMLData(pep_detected={self.pep_detected}, "
            f"sanctions_detected={self.sanctions_detected})"
        )

    __str__ = __repr__


class ReviewData(BaseModel):
    """Manual or compliance agent review information."""

    model_config = ConfigDict(extra="allow")

    reviewed_by: str | None = Field(default=None, description="Identifier of the reviewer")
    decision_reason: str | None = Field(default=None, description="Reviewer explanation or notes")

    def __repr__(self) -> str:
        return (
            f"ReviewData(reviewed_by={self.reviewed_by!r}, has_reason={bool(self.decision_reason)})"
        )

    __str__ = __repr__


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
    warnings: list[VerificationWarning] = Field(
        default_factory=list, description="Non-fatal verification warnings and diagnostics"
    )
    resubmit_info: ResubmitInfo | None = Field(
        default=None, description="Optional metadata when resubmission of documents is requested"
    )
    raw_data: dict[str, Any] | None = Field(
        default=None, description="Raw JSON payload received from Didit"
    )

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_singular_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Shallow copy to avoid mutating caller dict while avoiding full deepcopy overhead
        migrated = dict(data)

        # Normalize legacy document field
        if "document" in migrated and "id_verifications" not in migrated:
            doc = migrated.pop("document")
            if doc and isinstance(doc, dict):
                doc_copy = dict(doc)
                if "status" not in doc_copy and "is_valid" in doc_copy:
                    doc_copy["status"] = "Approved" if doc_copy["is_valid"] else "Declined"
                migrated["id_verifications"] = [doc_copy]

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
                migrated["aml_screenings"] = [dict(aml)]

        # Normalize legacy review field
        if "review" in migrated and "reviews" not in migrated:
            rev = migrated.pop("review")
            if rev and isinstance(rev, dict):
                migrated["reviews"] = [dict(rev)]

        return migrated

    def __repr__(self) -> str:
        return (
            f"DecisionResponse(session_id={self.session_id!r}, "
            f"status={self.status.value!r}, "
            f"id_verifications={len(self.id_verifications)}, "
            f"liveness_checks={len(self.liveness_checks)}, "
            f"face_matches={len(self.face_matches)}, "
            f"aml_screenings={len(self.aml_screenings)}, "
            f"reviews={len(self.reviews)})"
        )

    __str__ = __repr__

    @property
    def requires_resubmission(self) -> bool:
        """Return True if decision requires user resubmission of documents/biometrics."""
        return self.status.requires_resubmission or bool(self.resubmit_info)

    def redacted_dump(self, *, include_scores: bool = False) -> dict[str, Any]:
        """Return a privacy-sanitized dictionary omitting PII for telemetry/logging."""
        return {
            "session_id": self.session_id,
            "status": self.status.value,
            "workflow_id": self.workflow_id,
            "requires_resubmission": self.requires_resubmission,
            "resubmit_info": self.resubmit_info.redacted_dump() if self.resubmit_info else None,
            "id_verifications": [
                {
                    "node_id": v.node_id,
                    "status": v.status,
                    "document_type": v.document_type,
                }
                for v in self.id_verifications
            ],
            "liveness_checks": [
                {
                    "node_id": check.node_id,
                    "status": check.status,
                    **(
                        {"score": check.score} if include_scores and check.score is not None else {}
                    ),
                }
                for check in self.liveness_checks
            ],
            "face_matches": [
                {
                    "node_id": f.node_id,
                    "status": f.status,
                    **({"score": f.score} if include_scores and f.score is not None else {}),
                }
                for f in self.face_matches
            ],
            "aml_screenings": [
                {
                    "node_id": a.node_id,
                    "status": a.status,
                }
                for a in self.aml_screenings
            ],
            "reviews": [
                {"has_review": True, "has_reason": bool(r.decision_reason)} for r in self.reviews
            ],
            "warnings": [
                {
                    "code": w.warning_code or w.code,
                    "severity": w.severity,
                }
                for w in self.iter_warnings()
            ],
            "warning_codes": self.warning_codes,
        }

    def iter_warnings(self) -> list[VerificationWarning]:
        """Collect all warnings from top-level and nested check nodes."""
        all_warnings: list[VerificationWarning] = list(self.warnings)
        for node_list in (
            self.id_verifications,
            self.liveness_checks,
            self.face_matches,
            self.aml_screenings,
        ):
            for item in node_list:
                node_warns = getattr(item, "warnings", None)
                if node_warns and isinstance(node_warns, list):
                    for w in node_warns:
                        if isinstance(w, VerificationWarning):
                            all_warnings.append(w)
                        elif isinstance(w, dict):
                            all_warnings.append(VerificationWarning.model_validate(w))
                        elif isinstance(w, str):
                            all_warnings.append(VerificationWarning(code=w, message=w))
        return all_warnings

    def has_warning(self, code: str) -> bool:
        """Check whether a specific warning code is present across any decision or check node."""
        return any(
            (
                w.code == code
                or w.risk == code
                or w.warning_code == code
                or w.short_description == code
                or getattr(w, "log_type", None) == code
            )
            for w in self.iter_warnings()
        )

    @property
    def warning_codes(self) -> list[str]:
        """List of all warning codes emitted across the decision and all verification steps."""
        codes: list[str] = []
        for w in self.iter_warnings():
            c = w.warning_code or w.code
            if c and c not in codes:
                codes.append(c)
        return codes

    @property
    def document(self) -> DocumentData | None:
        """Backward-compatible read-only view of first document verification."""
        if not self.id_verifications:
            return None
        v = self.id_verifications[0]
        is_valid = _legacy_bool(v.status) if v.status is not None else getattr(v, "is_valid", None)
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
            face_match=_legacy_bool(face.status) if (face and face.status) else None,
            liveness_check=_legacy_bool(live.status) if (live and live.status) else None,
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
