"""Comprehensive tests for Didit Session Imports API.

Validates data models, PII-safe representations, synchronous and asynchronous
client resources, file and URL creation modes, simulation parity, and CLI subcommands.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import respx

from didit.cli import main
from didit.client import AsyncDidit, Didit
from didit.models.enums import SessionImportFormat, SessionImportStatus, SessionImportType
from didit.models.session_imports import (
    SessionImportError,
    SessionImportErrorPage,
    SessionImportJob,
)
from didit.simulation import SimulatedAsyncDidit, SimulatedDidit


@pytest.fixture
def base_url() -> str:
    return "https://verification.didit.me/v3"


@pytest.fixture
def client(base_url: str) -> Didit:
    return Didit(
        api_key="didit_live_key_test",
        base_url=base_url,
        timeout=10.0,
        max_retries=0,
    )


@pytest.fixture
def async_client(base_url: str) -> AsyncDidit:
    return AsyncDidit(
        api_key="didit_live_key_test",
        base_url=base_url,
        timeout=10.0,
        max_retries=0,
    )


# =========================================================================
# Model Tests
# =========================================================================


class TestSessionImportModels:
    def test_session_import_job_properties_and_repr(self) -> None:
        job = SessionImportJob(
            uuid="3f9c1a2b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
            status=SessionImportStatus.PENDING,
            import_type=SessionImportType.USER_VERIFICATION,
            source_format=SessionImportFormat.NDJSON,
            source_filename="sessions.ndjson",
            total_rows=100,
            processed_rows=50,
            checkpoint_row=50,
            created_count=45,
            updated_count=0,
            skipped_count=0,
            failed_count=5,
            total_media_bytes=5120,
            last_error="row 51 failed",
            created_at="2026-05-17T08:42:11Z",
            updated_at="2026-05-17T08:43:00Z",
            started_at="2026-05-17T08:42:15Z",
            completed_at=None,
        )
        assert job.is_completed is False
        assert job.is_terminal is False
        assert "3f9c1a2b" in repr(job)
        assert "50/100" in repr(job)
        assert str(job) == repr(job)

        completed_job = job.model_copy(update={"status": SessionImportStatus.COMPLETED})
        assert completed_job.is_completed is True
        assert completed_job.is_terminal is True

        failed_job = job.model_copy(update={"status": SessionImportStatus.FAILED})
        assert failed_job.is_completed is False
        assert failed_job.is_terminal is True

    def test_session_import_error_privacy_and_redaction(self) -> None:
        err = SessionImportError(
            uuid="5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d",
            row_number=17,
            external_id="ext-000017",
            error="status: invalid value 'unknown_status'",
            raw_row={
                "external_id": "ext-000017",
                "status": "unknown_status",
                "first_name": "Jane",
                "email": "jane@example.com",
            },
            created_at="2026-05-17T08:44:02Z",
        )
        assert err.row_number == 17
        assert err.external_id == "ext-000017"

        # Verify __repr__ does NOT expose raw_row PII
        repr_str = repr(err)
        assert "jane@example.com" not in repr_str
        assert "Jane" not in repr_str
        assert "ext-000017" in repr_str
        assert str(err) == repr_str

        # Verify redacted_dump masks raw_row completely
        dump = err.redacted_dump()
        assert dump["raw_row"] == "[REDACTED]"
        assert dump["error"] == "status: invalid value 'unknown_status'"

    def test_session_import_error_page_redacted_dump(self) -> None:
        err1 = SessionImportError(
            uuid="err-1",
            row_number=1,
            external_id="ext-1",
            error="bad row",
            raw_row={"secret": "pii_data"},
            created_at="2026-05-17T08:44:02Z",
        )
        page = SessionImportErrorPage(
            count=1,
            next=None,
            previous=None,
            results=[err1],
        )
        assert "1" in repr(page)
        assert str(page) == repr(page)

        dump = page.redacted_dump()
        assert dump["count"] == 1
        assert dump["results"][0]["raw_row"] == "[REDACTED]"
        assert "pii_data" not in str(dump)

    def test_helper_normalizers(self) -> None:
        from didit.resources.session_imports import (
            _normalize_import_type,
            _normalize_source_format,
        )

        assert _normalize_import_type(SessionImportType.USER_VERIFICATION) == "user_verification"
        assert _normalize_import_type("custom_type") == "custom_type"

        assert _normalize_source_format(SessionImportFormat.CSV) == "csv"
        assert _normalize_source_format("ndjson") == "ndjson"
        assert _normalize_source_format(None, "data.csv") == "csv"
        assert _normalize_source_format(None, "data.NDJSON") == "ndjson"
        assert _normalize_source_format(None, "data.unknown") is None
        assert _normalize_source_format(None, None) is None
        assert _normalize_source_format(None, "") is None

        from didit.resources.session_imports import _extract_stream_filename

        bio_no_name = io.BytesIO(b"abc")
        assert _extract_stream_filename(bio_no_name) == "import.csv"

        bio_with_str = io.BytesIO(b"abc")
        bio_with_str.name = "custom.csv"  # type: ignore[attr-defined]
        assert _extract_stream_filename(bio_with_str) == "custom.csv"

        bio_with_path = io.BytesIO(b"abc")
        bio_with_path.name = Path("path.csv")  # type: ignore[attr-defined]
        assert _extract_stream_filename(bio_with_path) == "path.csv"


# =========================================================================
# Synchronous Resource Tests
# =========================================================================


class TestSyncSessionImportsResource:
    @respx.mock
    def test_create_via_url(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/session/imports/").respond(
            201,
            json={
                "uuid": "job-url-123",
                "status": "PENDING",
                "import_type": "user_verification",
                "source_format": "ndjson",
                "source_filename": "sessions.ndjson",
                "total_rows": 0,
                "processed_rows": 0,
                "checkpoint_row": 0,
                "created_count": 0,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )

        job = client.session_imports.create(
            import_type=SessionImportType.USER_VERIFICATION,
            workflow_id="wf-123",
            source_file_url="https://files.example.com/exports/sessions.ndjson",
        )
        assert job.uuid == "job-url-123"
        assert job.status == SessionImportStatus.PENDING

        req = route.calls[0].request
        req_json = json.loads(req.content)
        assert req_json["import_type"] == "user_verification"
        assert req_json["workflow_id"] == "wf-123"
        assert req_json["source_file_url"] == "https://files.example.com/exports/sessions.ndjson"
        assert req_json["source_format"] == "ndjson"

    @respx.mock
    def test_create_via_local_file_path_and_bytes(
        self, client: Didit, base_url: str, tmp_path: Path
    ) -> None:
        respx.post(f"{base_url}/session/imports/").respond(
            201,
            json={
                "uuid": "job-file-123",
                "status": "PENDING",
                "import_type": "transactions",
                "source_format": "csv",
                "source_filename": "data.csv",
                "total_rows": 0,
                "processed_rows": 0,
                "checkpoint_row": 0,
                "created_count": 0,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )

        test_file = tmp_path / "data.csv"
        test_file.write_text("external_id,amount\ntx1,100\n", encoding="utf-8")

        job = client.session_imports.create(
            import_type="transactions",
            file=test_file,
        )
        assert job.uuid == "job-file-123"

        # Test passing raw bytes and BinaryIO
        job_bytes = client.session_imports.create(
            import_type=SessionImportType.TRANSACTIONS,
            file=b"external_id,amount\ntx2,200\n",
            filename="bytes.csv",
        )
        assert job_bytes.uuid == "job-file-123"

        bio = io.BytesIO(b"external_id,amount\ntx3,300\n")
        bio.name = "stream.csv"  # type: ignore[attr-defined]
        job_bio = client.session_imports.create(
            import_type="transactions",
            workflow_id="wf-sync-1",
            file=bio,
            source_format="csv",
        )
        assert job_bio.uuid == "job-file-123"

        sio = io.StringIO("external_id,amount\ntx4,400\n")
        job_sio = client.session_imports.create(
            import_type=SessionImportType.TRANSACTIONS,
            file=sio,  # type: ignore[arg-type]
            filename="stringio.csv",
        )
        assert job_sio.uuid == "job-file-123"

        # Unrecognized extension and no format specified (both branches covered)
        job_unknown_ext = client.session_imports.create(
            import_type=SessionImportType.TRANSACTIONS,
            source_file_url="https://example.com/data.bin",
        )
        assert job_unknown_ext.uuid == "job-file-123"

        bio_path = io.BytesIO(b"data")
        bio_path.name = Path("test.bin")  # type: ignore[attr-defined]
        job_bio_path = client.session_imports.create(
            import_type=SessionImportType.TRANSACTIONS,
            file=bio_path,
        )
        assert job_bio_path.uuid == "job-file-123"

        # Async unrecognized extension
        # and async stream without recognized format
        pass

    def test_create_validation_errors(self, client: Didit) -> None:
        with pytest.raises(ValueError, match="Provide either 'file' or 'source_file_url'"):
            client.session_imports.create()

        with pytest.raises(ValueError, match="Cannot provide both 'file' and 'source_file_url'"):
            client.session_imports.create(
                file=b"data", source_file_url="https://example.com/data.csv"
            )

        with pytest.raises(ValueError, match="source_file_url must not be empty"):
            client.session_imports.create(source_file_url="   ")

        with pytest.raises(FileNotFoundError, match="not found"):
            client.session_imports.create(file=Path("/nonexistent/file.csv"))

        with pytest.raises(TypeError, match="Unsupported file type"):
            client.session_imports.create(file=12345)  # type: ignore[arg-type]

    @respx.mock
    def test_get_import_job(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/imports/job-456/").respond(
            200,
            json={
                "uuid": "job-456",
                "status": "COMPLETED",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "sessions.csv",
                "total_rows": 10,
                "processed_rows": 10,
                "checkpoint_row": 10,
                "created_count": 9,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 1,
                "total_media_bytes": 1024,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:45:00Z",
            },
        )
        job = client.session_imports.get("job-456")
        assert job.uuid == "job-456"
        assert job.status == SessionImportStatus.COMPLETED

        with pytest.raises(ValueError, match="import_id must not be empty"):
            client.session_imports.get("")

    @respx.mock
    def test_list_errors(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/imports/job-456/errors/").respond(
            200,
            json={
                "count": 1,
                "next": None,
                "previous": None,
                "results": [
                    {
                        "uuid": "err-1",
                        "row_number": 5,
                        "external_id": "ext-5",
                        "error": "invalid format",
                        "raw_row": {"col": "val"},
                        "created_at": "2026-05-17T08:44:02Z",
                    }
                ],
            },
        )
        page = client.session_imports.list_errors("job-456", limit=10, offset=0)
        assert page.count == 1
        assert len(page.results) == 1
        assert page.results[0].row_number == 5

        with pytest.raises(ValueError, match="import_id must not be empty"):
            client.session_imports.list_errors("   ")

    @respx.mock
    def test_get_template(self, client: Didit, base_url: str) -> None:
        respx.get(f"{base_url}/session/imports/template/").respond(
            200,
            text="external_id,workflow_id,vendor_data\n",
        )
        tmpl = client.session_imports.get_template(import_type=SessionImportType.USER_VERIFICATION)
        assert "external_id,workflow_id" in tmpl


# =========================================================================
# Asynchronous Resource Tests
# =========================================================================


class TestAsyncSessionImportsResource:
    @pytest.mark.asyncio
    @respx.mock
    async def test_async_session_imports_crud(
        self, async_client: AsyncDidit, base_url: str, tmp_path: Path
    ) -> None:
        respx.post(f"{base_url}/session/imports/").respond(
            201,
            json={
                "uuid": "job-async-1",
                "status": "PENDING",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "data.csv",
                "total_rows": 0,
                "processed_rows": 0,
                "checkpoint_row": 0,
                "created_count": 0,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )
        respx.get(f"{base_url}/session/imports/job-async-1/").respond(
            200,
            json={
                "uuid": "job-async-1",
                "status": "COMPLETED",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "data.csv",
                "total_rows": 1,
                "processed_rows": 1,
                "checkpoint_row": 1,
                "created_count": 1,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )
        respx.get(f"{base_url}/session/imports/job-async-1/errors/").respond(
            200,
            json={"count": 0, "next": None, "previous": None, "results": []},
        )
        respx.get(f"{base_url}/session/imports/template/").respond(
            200,
            text="external_id,col\n",
        )

        # Create via URL
        j1 = await async_client.session_imports.create(
            import_type="user_verification",
            source_file_url="https://files.example.com/data.csv",
        )
        assert j1.uuid == "job-async-1"

        # Create via file
        tf = tmp_path / "data.csv"
        tf.write_text("external_id\n1\n", encoding="utf-8")
        j2 = await async_client.session_imports.create(file=tf)
        assert j2.uuid == "job-async-1"

        # Get
        j_get = await async_client.session_imports.get("job-async-1")
        assert j_get.is_completed is True

        # Errors
        errs = await async_client.session_imports.list_errors("job-async-1")
        assert errs.count == 0

        # Template
        tmpl = await async_client.session_imports.get_template()
        assert "external_id" in tmpl

    @pytest.mark.asyncio
    async def test_async_validations(self, async_client: AsyncDidit) -> None:
        with pytest.raises(ValueError, match="Provide either 'file' or 'source_file_url'"):
            await async_client.session_imports.create()

        with pytest.raises(ValueError, match="Cannot provide both 'file' and 'source_file_url'"):
            await async_client.session_imports.create(file=b"1", source_file_url="https://url")

        with pytest.raises(ValueError, match="source_file_url must not be empty"):
            await async_client.session_imports.create(source_file_url="")

        with pytest.raises(FileNotFoundError):
            await async_client.session_imports.create(file=Path("/nonexistent/file.csv"))

        with pytest.raises(TypeError):
            await async_client.session_imports.create(file=123)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="import_id must not be empty"):
            await async_client.session_imports.get("")

        with pytest.raises(ValueError, match="import_id must not be empty"):
            await async_client.session_imports.list_errors("")

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_all_optional_branches(
        self, async_client: AsyncDidit, base_url: str, tmp_path: Path
    ) -> None:
        respx.post(f"{base_url}/session/imports/").respond(
            201,
            json={
                "uuid": "job-async-branches",
                "status": "PENDING",
                "import_type": "status_rules",
                "source_format": "ndjson",
                "source_filename": "rules.ndjson",
                "total_rows": 0,
                "processed_rows": 0,
                "checkpoint_row": 0,
                "created_count": 0,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )

        # 1. Async URL with workflow_id and explicit SessionImportFormat
        j1 = await async_client.session_imports.create(
            import_type=SessionImportType.STATUS_RULES,
            workflow_id="wf-async-1",
            source_file_url="https://example.com/rules.ndjson",
            source_format=SessionImportFormat.NDJSON,
        )
        assert j1.uuid == "job-async-branches"

        # 2. Async file with workflow_id and explicit format string
        tf = tmp_path / "rules.ndjson"
        tf.write_text('{"rule": 1}\n', encoding="utf-8")
        j2 = await async_client.session_imports.create(
            import_type="status_rules",
            workflow_id="wf-async-2",
            file=tf,
            source_format="ndjson",
        )
        assert j2.uuid == "job-async-branches"

        # 3. Async file using raw bytes
        j3 = await async_client.session_imports.create(
            import_type="status_rules",
            file=b'{"rule": 2}\n',
            filename="bytes.ndjson",
        )
        assert j3.uuid == "job-async-branches"

        # 4. Async file using BinaryIO with Path name
        bio = io.BytesIO(b'{"rule": 3}\n')
        bio.name = Path("stream_path.ndjson")  # type: ignore[attr-defined]
        j4 = await async_client.session_imports.create(
            import_type="status_rules",
            file=bio,
        )
        assert j4.uuid == "job-async-branches"

        # 5. Async file using TextIO
        sio = io.StringIO('{"rule": 4}\n')
        j5 = await async_client.session_imports.create(
            import_type="status_rules",
            file=sio,  # type: ignore[arg-type]
            filename="text.ndjson",
        )
        assert j5.uuid == "job-async-branches"

        # 6. Async URL with unrecognized extension and no format
        j6 = await async_client.session_imports.create(
            import_type=SessionImportType.STATUS_RULES,
            source_file_url="https://example.com/rules.bin",
        )
        assert j6.uuid == "job-async-branches"

        # 7. Async file with unrecognized extension and no format
        bio_bin = io.BytesIO(b'{"rule": 7}\n')
        bio_bin.name = Path("test.bin")  # type: ignore[attr-defined]
        j7 = await async_client.session_imports.create(
            import_type=SessionImportType.STATUS_RULES,
            file=bio_bin,
        )
        assert j7.uuid == "job-async-branches"

    def test_resources_init_with_raw_httpx_client(self, base_url: str) -> None:
        import httpx

        from didit.resources.session_imports import (
            AsyncSessionImportsResource,
            SessionImportsResource,
        )

        with httpx.Client(base_url=base_url) as raw_client:
            res = SessionImportsResource(raw_client)
            assert res._http is raw_client

        raw_async = httpx.AsyncClient(base_url=base_url)
        ares = AsyncSessionImportsResource(raw_async)
        assert ares._http is raw_async


# =========================================================================
# Simulation Tests
# =========================================================================


class TestSimulationSessionImports:
    def test_sync_simulation_session_imports(self, tmp_path: Path) -> None:
        from didit.errors import DiditNotFoundError

        sim = SimulatedDidit()

        # Validation errors in create
        with pytest.raises(ValueError, match="Provide either 'file' or 'source_file_url'"):
            sim.session_imports.create()
        with pytest.raises(ValueError, match="Cannot provide both 'file' and 'source_file_url'"):
            sim.session_imports.create(file=b"data", source_file_url="https://example.com/data.csv")
        with pytest.raises(ValueError, match="source_file_url must not be empty"):
            sim.session_imports.create(source_file_url="   ")
        with pytest.raises(FileNotFoundError, match="not found"):
            sim.session_imports.create(file=Path("/nonexistent/file.csv"))
        with pytest.raises(TypeError, match="Unsupported file type"):
            sim.session_imports.create(file=123)  # type: ignore[arg-type]

        # Create via URL
        job_url = sim.session_imports.create(
            source_file_url="https://example.com/import.ndjson",
            import_type=SessionImportType.USER_VERIFICATION,
        )
        assert job_url.status == SessionImportStatus.COMPLETED
        assert job_url.source_format == SessionImportFormat.NDJSON

        # Create via bytes
        job_file = sim.session_imports.create(
            file=b"header\nrow1\n",
            filename="test.csv",
        )
        assert job_file.status == SessionImportStatus.COMPLETED
        assert job_file.source_format == SessionImportFormat.CSV

        # Create via existing Path
        real_file = tmp_path / "sim_upload.csv"
        real_file.write_text("header\nval1\n", encoding="utf-8")
        job_path = sim.session_imports.create(file=real_file)
        assert job_path.source_filename == "sim_upload.csv"

        # Create via stream with Path name
        bio = io.BytesIO(b"data\n")
        bio.name = Path("stream.ndjson")  # type: ignore[attr-defined]
        job_bio = sim.session_imports.create(file=bio)
        assert job_bio.source_filename == "stream.ndjson"

        # Create via stream without Path name
        bio_str = io.BytesIO(b"data\n")
        job_bio_str = sim.session_imports.create(file=bio_str)
        assert job_bio_str.source_filename == "import.csv"

        # Create via stream with string name
        bio_custom = io.BytesIO(b"data\n")
        bio_custom.name = "custom_stream.ndjson"  # type: ignore[attr-defined]
        job_custom = sim.session_imports.create(file=bio_custom)
        assert job_custom.source_filename == "custom_stream.ndjson"

        # Get
        retrieved = sim.session_imports.get(job_url.uuid)
        assert retrieved.uuid == job_url.uuid

        with pytest.raises(DiditNotFoundError):
            sim.session_imports.get("nonexistent-job")
        with pytest.raises(ValueError, match="import_id must not be empty"):
            sim.session_imports.get("")
        with pytest.raises(ValueError, match="import_id must not be empty"):
            sim.session_imports.get("   ")

        # List errors
        errors = sim.session_imports.list_errors(job_url.uuid)
        assert errors.count == 1
        assert errors.results[0].row_number == 5

        with pytest.raises(DiditNotFoundError):
            sim.session_imports.list_errors("nonexistent-job")
        with pytest.raises(ValueError, match="import_id must not be empty"):
            sim.session_imports.list_errors("")
        with pytest.raises(ValueError, match="import_id must not be empty"):
            sim.session_imports.list_errors("   ")

        # Template
        tmpl = sim.session_imports.get_template(import_type="transactions")
        assert "Template for transactions" in tmpl

    @pytest.mark.asyncio
    async def test_async_simulation_session_imports(self) -> None:
        from didit.errors import DiditNotFoundError

        sim = SimulatedAsyncDidit()

        job = await sim.session_imports.create(
            source_file_url="https://example.com/data.csv",
            import_type="user_verification",
        )
        assert job.is_completed is True

        retrieved = await sim.session_imports.get(job.uuid)
        assert retrieved.uuid == job.uuid

        with pytest.raises(ValueError, match="import_id must not be empty"):
            await sim.session_imports.get("")
        with pytest.raises(DiditNotFoundError):
            await sim.session_imports.get("nonexistent")

        errs = await sim.session_imports.list_errors(job.uuid)
        assert errs.count == 1

        with pytest.raises(ValueError, match="import_id must not be empty"):
            await sim.session_imports.list_errors("")
        with pytest.raises(DiditNotFoundError):
            await sim.session_imports.list_errors("nonexistent")

        tmpl = await sim.session_imports.get_template()
        assert "external_id" in tmpl


# =========================================================================
# CLI Subcommand Tests
# =========================================================================


class TestSessionImportsCLI:
    @respx.mock
    def test_cli_session_imports_create_url_and_text(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/session/imports/").respond(
            201,
            json={
                "uuid": "job-cli-1",
                "status": "PENDING",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "data.csv",
                "total_rows": 100,
                "processed_rows": 20,
                "checkpoint_row": 20,
                "created_count": 18,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 2,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )

        exit_code = main(
            [
                "session-imports",
                "create",
                "--url",
                "https://example.com/data.csv",
                "--type",
                "user_verification",
            ]
        )
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Import Job ID:  job-cli-1" in out
        assert "Status:         PENDING" in out

    @respx.mock
    def test_cli_session_imports_create_json_and_arguments_validation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/session/imports/").respond(
            201,
            json={
                "uuid": "job-cli-json",
                "status": "PENDING",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "data.csv",
                "total_rows": 0,
                "processed_rows": 0,
                "checkpoint_row": 0,
                "created_count": 0,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )

        exit_code = main(
            [
                "--json",
                "session-imports",
                "create",
                "--url",
                "https://example.com/data.csv",
            ]
        )
        assert exit_code == 0
        out, _ = capsys.readouterr()
        data = json.loads(out)
        assert data["uuid"] == "job-cli-json"

        # Missing both file and url
        exit_code_missing = main(["--json", "session-imports", "create"])
        assert exit_code_missing == 2
        out_err, _ = capsys.readouterr()
        assert "INVALID_ARGUMENT" in out_err

        # Providing both file and url
        exit_code_both = main(
            [
                "--json",
                "session-imports",
                "create",
                "--file",
                "file.csv",
                "--url",
                "https://example.com",
            ]
        )
        assert exit_code_both == 2
        out_err2, _ = capsys.readouterr()
        assert "INVALID_ARGUMENT" in out_err2

        # Nonexistent local file
        exit_code_nofile = main(
            [
                "--json",
                "session-imports",
                "create",
                "--file",
                "nonexistent_file_123.csv",
            ]
        )
        assert exit_code_nofile == 1
        out_err3, _ = capsys.readouterr()
        assert "FILE_NOT_FOUND" in out_err3

    @respx.mock
    def test_cli_session_imports_get(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.get(f"{base_url}/session/imports/job-123/").respond(
            200,
            json={
                "uuid": "job-123",
                "status": "FAILED",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "data.csv",
                "total_rows": 10,
                "processed_rows": 1,
                "checkpoint_row": 1,
                "created_count": 0,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 1,
                "total_media_bytes": 0,
                "last_error": "Fatal format failure",
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )

        exit_code = main(["session-imports", "get", "job-123"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Import Job ID:  job-123" in out
        assert "Last Error:     Fatal format failure" in out

        # Text mode with no last_error
        respx.get(f"{base_url}/session/imports/job-clean/").respond(
            200,
            json={
                "uuid": "job-clean",
                "status": "COMPLETED",
                "import_type": "user_verification",
                "source_format": "csv",
                "source_filename": "clean.csv",
                "total_rows": 5,
                "processed_rows": 5,
                "checkpoint_row": 5,
                "created_count": 5,
                "updated_count": 0,
                "skipped_count": 0,
                "failed_count": 0,
                "total_media_bytes": 0,
                "last_error": None,
                "created_at": "2026-05-17T08:42:11Z",
                "updated_at": "2026-05-17T08:42:11Z",
            },
        )
        exit_code_clean = main(["session-imports", "get", "job-clean"])
        assert exit_code_clean == 0
        out_clean, _ = capsys.readouterr()
        assert "Import Job ID:  job-clean" in out_clean
        assert "Last Error:" not in out_clean

        # JSON mode
        exit_code_json = main(["--json", "session-imports", "get", "job-123"])
        assert exit_code_json == 0
        out_json, _ = capsys.readouterr()
        data = json.loads(out_json)
        assert data["uuid"] == "job-123"

    @respx.mock
    def test_cli_session_imports_errors(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.get(f"{base_url}/session/imports/job-123/errors/").respond(
            200,
            json={
                "count": 1,
                "next": None,
                "previous": None,
                "results": [
                    {
                        "uuid": "err-1",
                        "row_number": 3,
                        "external_id": "ext-3",
                        "error": "country invalid",
                        "raw_row": {"first_name": "Alice"},
                        "created_at": "2026-05-17T08:42:11Z",
                    }
                ],
            },
        )

        exit_code = main(["session-imports", "errors", "job-123"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Total Errors: 1" in out
        assert "Row 3 [external_id=ext-3]: country invalid" in out

        # JSON mode without sensitive
        exit_code_json = main(["--json", "session-imports", "errors", "job-123"])
        assert exit_code_json == 0
        out_json, _ = capsys.readouterr()
        data = json.loads(out_json)
        assert data["results"][0]["raw_row"] == "[REDACTED]"

        # JSON mode with include-sensitive
        exit_code_sens = main(
            ["--json", "--include-sensitive", "session-imports", "errors", "job-123"]
        )
        assert exit_code_sens == 0
        out_sens, _ = capsys.readouterr()
        data_sens = json.loads(out_sens)
        assert data_sens["results"][0]["raw_row"] == {"first_name": "Alice"}

    @respx.mock
    def test_cli_session_imports_template(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        base_url: str,
        tmp_path: Path,
    ) -> None:

        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.get(f"{base_url}/session/imports/template/").respond(
            200,
            text="external_id,vendor_data\n",
        )

        # stdout mode
        exit_code = main(["session-imports", "template", "--type", "transactions"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "external_id,vendor_data" in out

        # JSON stdout mode
        exit_code_json = main(["--json", "session-imports", "template", "--type", "transactions"])
        assert exit_code_json == 0
        out_json, _ = capsys.readouterr()
        data = json.loads(out_json)
        assert "external_id,vendor_data" in data["template_csv"]

        # file output mode
        out_csv = tmp_path / "tmpl.csv"
        exit_code_file = main(
            [
                "session-imports",
                "template",
                "--type",
                "transactions",
                "-o",
                str(out_csv),
            ]
        )
        assert exit_code_file == 0
        assert out_csv.read_text(encoding="utf-8") == "external_id,vendor_data\n"
        capsys.readouterr()

        # file output JSON mode
        out_csv2 = tmp_path / "tmpl2.csv"
        exit_code_file_json = main(
            [
                "--json",
                "session-imports",
                "template",
                "-o",
                str(out_csv2),
            ]
        )
        assert exit_code_file_json == 0
        out_file_json, _ = capsys.readouterr()
        data_file = json.loads(out_file_json)
        assert data_file["saved_to"] == str(out_csv2)

        # stdout mode when response does not end with newline
        respx.get(f"{base_url}/session/imports/template/").mock(
            return_value=respx.MockResponse(200, text="header_no_newline")
        )
        exit_code_nonl = main(["session-imports", "template", "--type", "user_verification"])
        assert exit_code_nonl == 0
        out_nonl, _ = capsys.readouterr()
        assert out_nonl == "header_no_newline\n"
