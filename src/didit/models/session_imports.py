"""Data models for Didit Session Imports API.

Provides models for verification import jobs, row error details, and error pagination.
SessionImportError protects end-user privacy by redacting raw_row data from logs
and __repr__ strings.
"""

from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from didit.models.enums import SessionImportFormat, SessionImportStatus, SessionImportType


class SessionImportJob(BaseModel):
    """Asynchronous import job for historical sessions, status rules, or transactions."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    uuid: str = Field(..., description="Unique import job identifier")
    status: SessionImportStatus = Field(..., description="Current lifecycle status of the job")
    import_type: SessionImportType = Field(..., description="Target entity type being imported")
    source_format: SessionImportFormat = Field(..., description="File format (csv or ndjson)")
    source_filename: str = Field(..., description="Name of the uploaded or resolved source file")
    total_rows: int = Field(default=0, description="Total number of rows detected in source")
    processed_rows: int = Field(default=0, description="Total rows processed so far")
    checkpoint_row: int = Field(default=0, description="Latest checkpoint row persisted")
    created_count: int = Field(default=0, description="Number of new records successfully created")
    updated_count: int = Field(default=0, description="Number of existing records updated")
    skipped_count: int = Field(default=0, description="Number of records skipped")
    failed_count: int = Field(default=0, description="Number of rows that failed validation")
    total_media_bytes: int = Field(default=0, description="Total size of media bytes processed")
    last_error: str | None = Field(default=None, description="Terminal or latest error message")
    created_at: str = Field(..., description="ISO 8601 timestamp when job was created")
    updated_at: str = Field(..., description="ISO 8601 timestamp when job was last updated")
    started_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when execution began"
    )
    completed_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when job reached terminal state"
    )

    @property
    def is_completed(self) -> bool:
        """Return True if job completed successfully without fatal failure."""
        return self.status == SessionImportStatus.COMPLETED

    @property
    def is_terminal(self) -> bool:
        """Return True if job has finished processing (completed, failed, or cancelled)."""
        return self.status.is_terminal

    def __repr__(self) -> str:
        return (
            f"SessionImportJob(uuid={self.uuid!r}, status={self.status.value!r}, "
            f"type={self.import_type.value!r}, processed={self.processed_rows}/{self.total_rows}, "
            f"failed={self.failed_count})"
        )

    __str__ = __repr__


class SessionImportError(BaseModel):
    """Validation or ingestion failure for an individual row in an import job."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    uuid: str = Field(..., description="Unique error record identifier")
    row_number: int = Field(..., description="One-based index of the failed row in source")
    external_id: str | None = Field(
        default=None, description="Caller-supplied idempotency key for this row"
    )
    error: str = Field(..., description="Diagnostic error message explaining the failure")
    raw_row: dict[str, Any] | None = Field(
        default_factory=dict, description="Raw dictionary containing the rejected row data"
    )
    created_at: str = Field(..., description="ISO 8601 timestamp when error was recorded")

    def __repr__(self) -> str:
        # Exclude raw_row to prevent PII exposure in logs and terminal representations
        return (
            f"SessionImportError(uuid={self.uuid!r}, row_number={self.row_number}, "
            f"external_id={self.external_id!r}, error={self.error!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump redacting the raw row data containing potential PII."""
        data = copy.deepcopy(self.model_dump())
        if "raw_row" in data and data["raw_row"] is not None:
            data["raw_row"] = "[REDACTED]"
        return data


class SessionImportErrorPage(BaseModel):
    """Paginated collection of import row errors."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    count: int = Field(..., description="Total error count reported by server")
    next: str | None = Field(default=None, description="URL to the next page of errors")
    previous: str | None = Field(default=None, description="URL to the previous page of errors")
    results: list[SessionImportError] = Field(
        default_factory=list, description="List of import row errors on this page"
    )

    def __repr__(self) -> str:
        return f"SessionImportErrorPage(count={self.count}, page_items={len(self.results)})"

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump redacting raw_row in all error items."""
        return {
            "count": self.count,
            "next": self.next,
            "previous": self.previous,
            "results": [item.redacted_dump() for item in self.results],
        }
