"""Session Imports resource implementations for synchronous and asynchronous clients.

Enables migration and batch ingestion of historical sessions, status rules,
and transaction monitoring records.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from didit.events import DiditEventSink
from didit.models.enums import SessionImportFormat, SessionImportType
from didit.models.session_imports import (
    SessionImportErrorPage,
    SessionImportJob,
)
from didit.transport import RequestOptions, _AsyncRequestor, _SyncRequestor

if TYPE_CHECKING:
    import httpx


def _normalize_import_type(import_type: SessionImportType | str) -> str:
    if isinstance(import_type, SessionImportType):
        return import_type.value
    return str(import_type)


def _normalize_source_format(
    source_format: SessionImportFormat | str | None, filename: str | None = None
) -> str | None:
    if source_format is not None:
        if isinstance(source_format, SessionImportFormat):
            return source_format.value
        return str(source_format)
    if filename:
        lower = filename.lower()
        if lower.endswith(".ndjson"):
            return "ndjson"
        if lower.endswith(".csv"):
            return "csv"
    return None


def _extract_stream_filename(file: Any, fallback: str = "import.csv") -> str:

    obj_name = getattr(file, "name", None)
    if isinstance(obj_name, Path):
        return obj_name.name
    if obj_name:
        return str(obj_name)
    return fallback


class SessionImportsResource:
    """Synchronous resource for Didit Session Imports API."""

    def __init__(
        self,
        requester: _SyncRequestor | httpx.Client,
        *,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        if isinstance(requester, _SyncRequestor):
            self._requestor = requester
            self._http = requester._client
        else:
            self._http = requester
            self._requestor = _SyncRequestor(
                requester,
                base_url=str(requester.base_url),
                api_key=requester.headers.get("x-api-key", ""),
            )
        self._event_sink = event_sink

    def create(
        self,
        *,
        import_type: SessionImportType | str = SessionImportType.USER_VERIFICATION,
        workflow_id: str | None = None,
        file: str | Path | BinaryIO | bytes | None = None,
        filename: str | None = None,
        source_file_url: str | None = None,
        source_format: SessionImportFormat | str | None = None,
        options: RequestOptions | None = None,
    ) -> SessionImportJob:
        """Create an asynchronous verification import job.

        Mutually exclusive: Provide either `file` (multipart upload up to 25 MB)
        or `source_file_url` (public HTTPS URL for bigger files).
        """
        if file is None and source_file_url is None:
            raise ValueError("Provide either 'file' or 'source_file_url'")
        if file is not None and source_file_url is not None:
            raise ValueError("Cannot provide both 'file' and 'source_file_url'")

        type_str = _normalize_import_type(import_type)

        if source_file_url is not None:
            clean_url = source_file_url.strip()
            if not clean_url:
                raise ValueError("source_file_url must not be empty")
            json_body: dict[str, Any] = {
                "import_type": type_str,
                "source_file_url": clean_url,
            }
            if workflow_id:
                json_body["workflow_id"] = workflow_id.strip()
            fmt = _normalize_source_format(source_format, filename=clean_url)
            if fmt:
                json_body["source_format"] = fmt

            resp = self._requestor.request(
                "POST",
                "/session/imports/",
                json=json_body,
                options=options,
            )
            return SessionImportJob.model_validate(resp.json())

        # File upload mode
        data: dict[str, Any] = {"import_type": type_str}
        if workflow_id:
            data["workflow_id"] = workflow_id.strip()

        file_content: bytes
        target_filename: str

        if isinstance(file, (str, Path)):
            p = Path(file).resolve()
            if not p.is_file():
                raise FileNotFoundError(f"Import file '{p}' not found")
            target_filename = filename or p.name
            file_content = p.read_bytes()
        elif isinstance(file, bytes):
            target_filename = filename or "import.csv"
            file_content = file
        elif file is not None and hasattr(file, "read"):
            target_filename = filename or _extract_stream_filename(file)
            raw_data = file.read()
            file_content = raw_data.encode("utf-8") if isinstance(raw_data, str) else raw_data

        else:
            raise TypeError(f"Unsupported file type: {type(file).__name__}")

        fmt = _normalize_source_format(source_format, filename=target_filename)
        if fmt:
            data["source_format"] = fmt

        files = {"file": (target_filename, file_content, "application/octet-stream")}

        resp = self._requestor.request(
            "POST",
            "/session/imports/",
            data=data,
            files=files,
            options=options,
        )
        return SessionImportJob.model_validate(resp.json())

    def get(
        self,
        import_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> SessionImportJob:
        """Retrieve progress counters and status for an import job."""
        if not import_id or not import_id.strip():
            raise ValueError("import_id must not be empty")
        clean_id = import_id.strip()
        resp = self._requestor.request(
            "GET",
            f"/session/imports/{clean_id}/",
            options=options,
        )
        return SessionImportJob.model_validate(resp.json())

    def list_errors(
        self,
        import_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
        options: RequestOptions | None = None,
    ) -> SessionImportErrorPage:
        """List row-level validation errors for an import job ordered by row_number."""
        if not import_id or not import_id.strip():
            raise ValueError("import_id must not be empty")
        clean_id = import_id.strip()
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        resp = self._requestor.request(
            "GET",
            f"/session/imports/{clean_id}/errors/",
            params=params,
            options=options,
        )
        return SessionImportErrorPage.model_validate(resp.json())

    def get_template(
        self,
        *,
        import_type: SessionImportType | str = SessionImportType.USER_VERIFICATION,
        options: RequestOptions | None = None,
    ) -> str:
        """Download canonical CSV template header and structure for an import type."""
        type_str = _normalize_import_type(import_type)
        params = {"import_type": type_str}
        resp = self._requestor.request(
            "GET",
            "/session/imports/template/",
            params=params,
            options=options,
        )
        return resp.text


class AsyncSessionImportsResource:
    """Asynchronous resource for Didit Session Imports API."""

    def __init__(
        self,
        requester: _AsyncRequestor | httpx.AsyncClient,
        *,
        event_sink: DiditEventSink | None = None,
    ) -> None:
        if isinstance(requester, _AsyncRequestor):
            self._requestor = requester
            self._http = requester._client
        else:
            self._http = requester
            self._requestor = _AsyncRequestor(
                requester,
                base_url=str(requester.base_url),
                api_key=requester.headers.get("x-api-key", ""),
            )
        self._event_sink = event_sink

    async def create(
        self,
        *,
        import_type: SessionImportType | str = SessionImportType.USER_VERIFICATION,
        workflow_id: str | None = None,
        file: str | Path | BinaryIO | bytes | None = None,
        filename: str | None = None,
        source_file_url: str | None = None,
        source_format: SessionImportFormat | str | None = None,
        options: RequestOptions | None = None,
    ) -> SessionImportJob:
        """Asynchronously create a verification import job."""
        if file is None and source_file_url is None:
            raise ValueError("Provide either 'file' or 'source_file_url'")
        if file is not None and source_file_url is not None:
            raise ValueError("Cannot provide both 'file' and 'source_file_url'")

        type_str = _normalize_import_type(import_type)

        if source_file_url is not None:
            clean_url = source_file_url.strip()
            if not clean_url:
                raise ValueError("source_file_url must not be empty")
            json_body: dict[str, Any] = {
                "import_type": type_str,
                "source_file_url": clean_url,
            }
            if workflow_id:
                json_body["workflow_id"] = workflow_id.strip()
            fmt = _normalize_source_format(source_format, filename=clean_url)
            if fmt:
                json_body["source_format"] = fmt

            resp = await self._requestor.request(
                "POST",
                "/session/imports/",
                json=json_body,
                options=options,
            )
            return SessionImportJob.model_validate(resp.json())

        # File upload mode
        data: dict[str, Any] = {"import_type": type_str}
        if workflow_id:
            data["workflow_id"] = workflow_id.strip()

        file_content: bytes
        target_filename: str

        if isinstance(file, (str, Path)):
            p = Path(file).resolve()
            if not p.is_file():
                raise FileNotFoundError(f"Import file '{p}' not found")
            target_filename = filename or p.name
            file_content = p.read_bytes()
        elif isinstance(file, bytes):
            target_filename = filename or "import.csv"
            file_content = file
        elif file is not None and hasattr(file, "read"):
            target_filename = filename or _extract_stream_filename(file)
            raw_data = file.read()
            file_content = raw_data.encode("utf-8") if isinstance(raw_data, str) else raw_data

        else:
            raise TypeError(f"Unsupported file type: {type(file).__name__}")

        fmt = _normalize_source_format(source_format, filename=target_filename)
        if fmt:
            data["source_format"] = fmt

        files = {"file": (target_filename, file_content, "application/octet-stream")}

        resp = await self._requestor.request(
            "POST",
            "/session/imports/",
            data=data,
            files=files,
            options=options,
        )
        return SessionImportJob.model_validate(resp.json())

    async def get(
        self,
        import_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> SessionImportJob:
        """Asynchronously retrieve progress counters and status for an import job."""
        if not import_id or not import_id.strip():
            raise ValueError("import_id must not be empty")
        clean_id = import_id.strip()
        resp = await self._requestor.request(
            "GET",
            f"/session/imports/{clean_id}/",
            options=options,
        )
        return SessionImportJob.model_validate(resp.json())

    async def list_errors(
        self,
        import_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
        options: RequestOptions | None = None,
    ) -> SessionImportErrorPage:
        """Asynchronously list row-level validation errors for an import job."""
        if not import_id or not import_id.strip():
            raise ValueError("import_id must not be empty")
        clean_id = import_id.strip()
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        resp = await self._requestor.request(
            "GET",
            f"/session/imports/{clean_id}/errors/",
            params=params,
            options=options,
        )
        return SessionImportErrorPage.model_validate(resp.json())

    async def get_template(
        self,
        *,
        import_type: SessionImportType | str = SessionImportType.USER_VERIFICATION,
        options: RequestOptions | None = None,
    ) -> str:
        """Asynchronously download canonical CSV template header for an import type."""
        type_str = _normalize_import_type(import_type)
        params = {"import_type": type_str}
        resp = await self._requestor.request(
            "GET",
            "/session/imports/template/",
            params=params,
            options=options,
        )
        return resp.text
