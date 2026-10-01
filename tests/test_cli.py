"""Comprehensive unit tests for the Didit developer CLI utilities."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import respx
from httpx import ConnectError, Response

from didit._version import __version__
from didit.cli import _secure_write_bytes, main
from didit.errors import (
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditSignatureError,
)
from didit.webhooks import canonical_json, compute_signature


class TestDiditCLI:
    """Test suite covering the `didit` command line interface."""

    def test_cli_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["--version"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert f"didit-sdk {__version__}" in captured.out

    def test_cli_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--help"]) == 0
        captured = capsys.readouterr()
        assert "usage: didit" in captured.out

        assert main([]) == 0
        captured_empty = capsys.readouterr()
        assert "usage: didit" in captured_empty.out

    # -------------------------------------------------------------------------
    # Credentials & Resolution
    # -------------------------------------------------------------------------

    def test_cli_missing_api_key(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Missing Didit API key" in captured.err

    def test_cli_missing_api_key_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["doctor", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "MISSING_API_KEY"

    def test_cli_api_key_file_resolution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        key_file = tmp_path / "didit.key"
        key_file.write_text("file_api_key_xyz\n", encoding="utf-8")

        with respx.mock:
            respx.get("https://verification.didit.me/system/healthcheck/").mock(
                return_value=Response(200, json={"status": "ok"})
            )
            respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
                return_value=Response(404, json={"detail": "Not found"})
            )
            exit_code = main(["--api-key-file", str(key_file), "doctor"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "[OK] Authentication: API key verified" in captured.out

    def test_cli_api_key_file_unreadable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["--api-key-file", "/nonexistent/path/didit.key", "doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error reading API key file" in captured.err

    def test_cli_secret_file_unreadable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        exit_code = main(["doctor", "--secret-file", "/nonexistent/wh.sec"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error reading webhook secret file" in captured.err

    # -------------------------------------------------------------------------
    # didit doctor
    # -------------------------------------------------------------------------

    @respx.mock
    def test_cli_doctor_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        secret_file = tmp_path / "whsec.key"
        secret_file.write_text("whsec_test_secret_123", encoding="utf-8")
        monkeypatch.setenv("DIDIT_API_KEY", "test_api_key_123")

        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["doctor", "--secret-file", str(secret_file)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] API Connection" in captured.out
        assert "[OK] Authentication: API key verified" in captured.out
        assert "[OK] Webhook Secret: Configured" in captured.out
        assert "chars" not in captured.out

    @respx.mock
    def test_cli_doctor_success_without_secret_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_api_key_123")
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)

        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["doctor", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["authenticated"] is True
        assert data["webhook_secret_configured"] is False
        assert "latency_ms" in data

    @respx.mock
    def test_cli_doctor_connection_failure(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "valid_key")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            side_effect=ConnectError("Connection refused")
        )

        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Failed to connect to Didit system" in captured.err

    @respx.mock
    def test_cli_doctor_connection_failure_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "valid_key")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            side_effect=ConnectError("Connection refused")
        )

        exit_code = main(["doctor", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "CONNECTION_ERROR"

    @respx.mock
    def test_cli_doctor_auth_failure_401(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "invalid_key")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )

        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid or unauthorized API key (HTTP 401)" in captured.err

    @respx.mock
    def test_cli_doctor_permission_denied_403(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "key_no_session_perms")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            return_value=Response(403, json={"detail": "Forbidden"})
        )

        exit_code = main(["doctor", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "PERMISSION_DENIED"

    @respx.mock
    def test_cli_doctor_healthcheck_fallback_to_list(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        # Healthcheck endpoint returns 404 (custom gateway without healthcheck)
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["doctor"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[WARN] API Connection: Healthcheck unavailable" in captured.out
        assert "[OK] Authentication: API key verified" in captured.out

    # -------------------------------------------------------------------------
    # didit webhook verify
    # -------------------------------------------------------------------------

    def test_cli_webhook_verify_missing_secret(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                "sig_123",
                "--timestamp",
                "1700000000",
                "--stdin",
            ]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Missing webhook secret" in captured.err

    def test_cli_webhook_verify_missing_body_input(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", "whsec_test")
        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                "sig_123",
                "--timestamp",
                "1700000000",
            ]
        )
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Must provide webhook body via --body-file or --stdin" in captured.err

    def test_cli_webhook_verify_invalid_tolerance(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", "whsec_test")
        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                "sig_123",
                "--timestamp",
                "1700000000",
                "--stdin",
                "--tolerance",
                "0",
            ]
        )
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "--tolerance must be a positive integer" in captured.err

    def test_cli_webhook_verify_from_file_and_secret_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        secret = "secret_file_key_123"
        secret_file = tmp_path / "secret.key"
        secret_file.write_text(secret, encoding="utf-8")

        now_ts = int(time.time())
        body_dict = {
            "event_id": "evt_file_1",
            "session_id": "sess_file_1",
            "status": "Approved",
            "timestamp": now_ts,
        }
        body_str = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        body_file = tmp_path / "payload.json"
        body_file.write_text(body_str, encoding="utf-8")

        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret-file",
                str(secret_file),
                "--signature",
                sig,
                "--timestamp",
                str(now_ts),
                "--body-file",
                str(body_file),
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] Webhook signature verified successfully" in captured.out
        assert "evt_file_1" in captured.out

    def test_cli_webhook_verify_via_stdin(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        secret = "secret_stdin_key"
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", secret)

        now_ts = int(time.time())
        body_dict = {
            "event_id": "evt_stdin_1",
            "session_id": "sess_stdin_1",
            "status": "Approved",
            "timestamp": now_ts,
        }
        body_str = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        monkeypatch.setattr("sys.stdin", io.StringIO(body_str))

        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                sig,
                "--timestamp",
                str(now_ts),
                "--stdin",
                "--json",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["valid"] is True
        assert data["event_id"] == "evt_stdin_1"

    def test_cli_webhook_verify_skip_freshness_check(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        secret = "secret_ancient_key"
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", secret)

        # 5 years in the past
        ancient_ts = 1500000000
        body_dict = {
            "event_id": "evt_ancient",
            "session_id": "sess_ancient",
            "status": "Declined",
            "timestamp": ancient_ts,
        }
        body_str = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        monkeypatch.setattr("sys.stdin", io.StringIO(body_str))

        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                sig,
                "--timestamp",
                str(ancient_ts),
                "--stdin",
                "--skip-freshness-check",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "WARNING: Freshness validation disabled" in captured.err
        assert "[OK] Webhook signature verified successfully" in captured.out

    def test_cli_webhook_verify_signature_failure(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", "whsec_good")
        payload = '{"session_id":"s","status":"Approved","timestamp":1700000000}'
        monkeypatch.setattr("sys.stdin", io.StringIO(payload))

        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                "0" * 64,
                "--timestamp",
                "1700000000",
                "--stdin",
                "--skip-freshness-check",
                "--json",
            ]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "SIGNATURE_VERIFICATION_FAILED"

    # -------------------------------------------------------------------------
    # didit session get
    # -------------------------------------------------------------------------

    @respx.mock
    def test_cli_session_get_redacted_default(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_safe/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_safe",
                    "status": "In Progress",
                    "url": "https://verify.didit.me/sess_safe",
                    "session_token": "secret_token_123",
                    "vendor_data": "usr_safe",
                    "workflow_id": "wf_safe",
                },
            )
        )

        exit_code = main(["session", "get", "sess_safe", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["session_id"] == "sess_safe"
        assert data["session_token"] == "[REDACTED]"
        assert "url" not in data

    @respx.mock
    def test_cli_session_get_include_sensitive(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_sens/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_sens",
                    "status": "In Progress",
                    "url": "https://verify.didit.me/sess_sens",
                    "session_token": "secret_token_123",
                },
            )
        )

        exit_code = main(["session", "get", "sess_sens", "--json", "--include-sensitive"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["session_token"] == "secret_token_123"
        assert data["url"] == "https://verify.didit.me/sess_sens"

    @respx.mock
    def test_cli_session_get_with_decision_and_warnings(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_dec/").mock(
            return_value=Response(
                200,
                json={"session_id": "sess_dec", "status": "Declined"},
            )
        )
        respx.get("https://verification.didit.me/v3/session/sess_dec/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_dec",
                    "status": "Declined",
                    "warnings": [{"code": "EXPIRED_DOC", "message": "Document is expired"}],
                },
            )
        )

        exit_code = main(["session", "get", "sess_dec", "--decision"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:  sess_dec" in captured.out
        assert "Decision Outcome: Declined" in captured.out
        assert "EXPIRED_DOC" in captured.out

    @respx.mock
    def test_cli_session_get_not_found_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_404/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["session", "get", "sess_404", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "SESSION_NOT_FOUND"

    # -------------------------------------------------------------------------
    # didit session create
    # -------------------------------------------------------------------------

    @respx.mock
    def test_cli_session_create_success(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.post("https://verification.didit.me/v3/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_c1",
                    "status": "Not Started",
                    "url": "https://verify.didit.me/sess_c1",
                },
            )
        )

        exit_code = main(
            [
                "session",
                "create",
                "--workflow-id",
                "wf_123",
                "--vendor-data",
                "u_123",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID: sess_c1" in captured.out
        assert "Hosted URL: [REDACTED] (use --include-sensitive to view)" in captured.out
        assert "https://verify.didit.me/sess_c1" not in captured.out

        # With --include-sensitive
        exit_code_sens = main(
            [
                "session",
                "create",
                "--workflow-id",
                "wf_123",
                "--vendor-data",
                "u_123",
                "--include-sensitive",
            ]
        )
        assert exit_code_sens == 0
        captured_sens = capsys.readouterr()
        assert "Hosted URL: https://verify.didit.me/sess_c1" in captured_sens.out

    # -------------------------------------------------------------------------
    # didit session resubmit
    # -------------------------------------------------------------------------

    @respx.mock
    def test_cli_session_resubmit_success(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.patch("https://verification.didit.me/v3/session/sess_resub/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_resub",
                    "status": "Resubmitted",
                    "resubmit_info": {"nodes": ["document", "liveness"]},
                },
            )
        )

        exit_code = main(
            [
                "session",
                "resubmit",
                "sess_resub",
                "--nodes",
                "document",
                "liveness",
                "--json",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["requires_resubmission"] is True

    @respx.mock
    def test_cli_session_resubmit_not_found(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.patch("https://verification.didit.me/v3/session/sess_missing/update-status/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["session", "resubmit", "sess_missing", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "SESSION_NOT_FOUND"

    # -------------------------------------------------------------------------
    # didit session list (pagination & --all)
    # -------------------------------------------------------------------------

    @respx.mock
    def test_cli_session_list_pagination(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 10,
                    "next": "https://verification.didit.me/v3/sessions/?offset=2",
                    "results": [
                        {"session_id": "s1", "status": "Approved", "session_token": "tok1"},
                        {"session_id": "s2", "status": "Declined", "session_token": "tok2"},
                    ],
                },
            )
        )

        exit_code = main(["session", "list", "--limit", "2", "--offset", "0", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert len(data["results"]) == 2
        # Default is redacted
        assert data["results"][0]["session_token"] == "[REDACTED]"

    @respx.mock
    def test_cli_session_list_all_pages(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get(
            "https://verification.didit.me/v3/sessions/?limit=50&offset=0&session_kind=user"
        ).mock(
            return_value=Response(
                200,
                json={
                    "count": 3,
                    "next": "https://verification.didit.me/v3/sessions/?offset=2",
                    "results": [
                        {"session_id": "s1", "status": "Approved"},
                        {"session_id": "s2", "status": "Approved"},
                    ],
                },
            )
        )
        respx.get(
            "https://verification.didit.me/v3/sessions/?limit=50&offset=2&session_kind=user"
        ).mock(
            return_value=Response(
                200,
                json={
                    "count": 3,
                    "next": None,
                    "results": [{"session_id": "s3", "status": "Declined"}],
                },
            )
        )

        exit_code = main(["session", "list", "--all"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Total sessions: 3 (collected 3)" in captured.out
        assert "s1" in captured.out
        assert "s2" in captured.out
        assert "s3" in captured.out

    # -------------------------------------------------------------------------
    # didit session pdf (atomic write, 0600, --force)
    # -------------------------------------------------------------------------

    @respx.mock
    def test_cli_session_pdf_download_and_private_permissions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        pdf_content = b"%PDF-1.4 test secure pdf write"
        respx.get("https://verification.didit.me/v3/session/sess_pdf_sec/generate-pdf/").mock(
            return_value=Response(
                200, content=pdf_content, headers={"Content-Type": "application/pdf"}
            )
        )

        out_file = tmp_path / "report.pdf"
        exit_code = main(["session", "pdf", "sess_pdf_sec", "-o", str(out_file), "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        expected_perms = "0600" if sys.platform != "win32" else "private"
        assert data["permissions"] == expected_perms
        assert out_file.read_bytes() == pdf_content

        # Verify 0600 permissions on POSIX
        if sys.platform != "win32":
            mode = stat.S_IMODE(out_file.stat().st_mode)
            assert mode == 0o600

    @respx.mock
    def test_cli_session_pdf_prevent_overwrite_without_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        out_file = tmp_path / "existing.pdf"
        out_file.write_bytes(b"%PDF-1.4 old")

        respx.get("https://verification.didit.me/v3/session/sess_exist/generate-pdf/").mock(
            return_value=Response(
                200, content=b"%PDF-1.4 new", headers={"Content-Type": "application/pdf"}
            )
        )

        exit_code = main(["session", "pdf", "sess_exist", "-o", str(out_file), "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "FILE_EXISTS"

        # Overwrite with --force
        exit_code_force = main(
            ["session", "pdf", "sess_exist", "-o", str(out_file), "--force", "--json"]
        )
        assert exit_code_force == 0
        assert out_file.read_bytes() == b"%PDF-1.4 new"

    @respx.mock
    def test_cli_session_pdf_not_found(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_pdf_missing/generate-pdf/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["session", "pdf", "sess_pdf_missing", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "SESSION_NOT_FOUND"

    def test_secure_write_bytes_cleanup_on_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Test that temporary files are cleaned up if file replacement fails
        target = tmp_path / "final.pdf"

        def broken_replace(*args: Any, **kwargs: Any) -> None:
            raise OSError("Replace operation failed")

        monkeypatch.setattr(Path, "replace", broken_replace)
        with pytest.raises(OSError, match="Replace operation failed"):
            _secure_write_bytes(target, b"test")
        assert not target.exists()

    # -------------------------------------------------------------------------
    # didit sandbox scenarios
    # -------------------------------------------------------------------------

    def test_cli_sandbox_scenarios_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["sandbox", "scenarios"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Available Didit Sandbox Scenarios" in captured.out
        assert "approve" in captured.out

    def test_cli_sandbox_scenarios_filtered_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["sandbox", "scenarios", "--category", "decline", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["count"] > 0
        assert all(s["category"] == "decline" for s in data["scenarios"])

    # -------------------------------------------------------------------------
    # Root Error Handling & --debug
    # -------------------------------------------------------------------------

    def test_cli_unhandled_crash_without_debug(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def crash(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Internal crash error with confidential database tokens")

        monkeypatch.setattr("didit.cli._cmd_sandbox_scenarios", crash)

        exit_code = main(["sandbox", "scenarios"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err
        assert "An unexpected error occurred. Use --debug for details." in captured.err

    def test_cli_unhandled_crash_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def crash(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Secret exception detail")

        monkeypatch.setattr("didit.cli._cmd_sandbox_scenarios", crash)

        exit_code = main(["sandbox", "scenarios", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "INTERNAL_ERROR"
        assert "Secret exception detail" not in data["error"]["message"]

    def test_cli_unhandled_crash_with_debug(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def crash(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Debug stacktrace test")

        monkeypatch.setattr("didit.cli._cmd_sandbox_scenarios", crash)

        exit_code = main(["--debug", "sandbox", "scenarios"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Traceback (most recent call last):" in captured.err
        assert "Debug stacktrace test" in captured.err

    def test_emit_error_with_details(self, capsys: pytest.CaptureFixture[str]) -> None:
        from didit.cli import _emit_error

        code = _emit_error("ERR", "msg", is_json=True, details={"foo": "bar"})
        assert code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["error"]["details"] == {"foo": "bar"}

    def test_cli_webhook_verify_body_file_unreadable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", "whsec_test")
        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                "sig_123",
                "--timestamp",
                "1700000000",
                "--body-file",
                "/nonexistent/body.json",
            ]
        )
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Error reading body file" in captured.err

    def test_secure_write_bytes_cleanup_during_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from didit.cli import _secure_write_bytes

        target = tmp_path / "out.pdf"

        def broken_fdopen(*args: Any, **kwargs: Any) -> Any:
            raise OSError("Disk full")

        monkeypatch.setattr(os, "fdopen", broken_fdopen)
        with pytest.raises(OSError, match="Disk full"):
            _secure_write_bytes(target, b"%PDF-1.4 test")
        assert not target.exists()

    def test_cli_session_missing_api_key(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["session", "get", "s_123"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Missing Didit API key" in captured.err

    @respx.mock
    def test_cli_doctor_probe_connection_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            side_effect=ConnectError("Probe connection reset")
        )
        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Failed to connect to Didit API during authentication check" in captured.err

    @respx.mock
    def test_cli_doctor_probe_unexpected_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            side_effect=RuntimeError("probe unexpected crash")
        )
        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Authentication verification probe failed" in captured.err

        # With --debug
        exit_code = main(["--debug", "doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Traceback" in captured.err
        assert "probe unexpected crash" in captured.err

    def test_secure_write_bytes_chmod_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from didit.cli import _secure_write_bytes

        target = tmp_path / "chmod_fallback.pdf"

        def broken_chmod(*args: Any, **kwargs: Any) -> None:
            raise OSError("Operation not permitted")

        monkeypatch.setattr(os, "fchmod", broken_chmod, raising=False)
        monkeypatch.setattr(os, "chmod", broken_chmod, raising=False)
        _secure_write_bytes(target, b"%PDF-1.4 test")
        assert target.exists()

    def test_cli_webhook_verify_secret_file_unreadable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = main(
            [
                "webhook",
                "verify",
                "--signature",
                "sig_123",
                "--timestamp",
                "1700000000",
                "--secret-file",
                "/nonexistent/sec.key",
                "--stdin",
            ]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error reading webhook secret file" in captured.err

    @respx.mock
    def test_cli_session_get_decision_not_found(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_no_dec/").mock(
            return_value=Response(200, json={"session_id": "sess_no_dec", "status": "In Progress"})
        )
        respx.get("https://verification.didit.me/v3/session/sess_no_dec/decision/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )
        exit_code = main(["session", "get", "sess_no_dec", "--decision"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:  sess_no_dec" in captured.out
        assert "Decision Outcome" not in captured.out

    @respx.mock
    def test_cli_session_get_text_detailed_fields(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_full/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_full",
                    "status": "Resubmitted",
                    "url": "https://verify.didit.me/sess_full",
                    "workflow_id": "wf_full",
                    "vendor_data": "u_full",
                    "resubmit_info": {"nodes": ["document"]},
                },
            )
        )
        respx.get("https://verification.didit.me/v3/session/sess_full/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_full",
                    "status": "Resubmitted",
                    "warnings": [{"code": "STRING_WARN_CODE", "message": "Sample warn"}],
                },
            )
        )
        exit_code = main(["session", "get", "sess_full", "--decision", "--include-sensitive"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Hosted URL:  https://verify.didit.me/sess_full" in captured.out
        assert "Workflow ID: wf_full" in captured.out
        assert "Vendor Data: u_full" in captured.out
        assert "Resubmission Required: True" in captured.out
        assert "Decision Outcome: Resubmitted" in captured.out
        assert "Warnings:" in captured.out
        assert "- [STRING_WARN_CODE] Sample warn" in captured.out

    @respx.mock
    def test_cli_session_get_empty_warnings(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/s_nowarn/").mock(
            return_value=Response(200, json={"session_id": "s_nowarn", "status": "Approved"})
        )
        respx.get("https://verification.didit.me/v3/session/s_nowarn/decision/").mock(
            return_value=Response(
                200, json={"session_id": "s_nowarn", "status": "Approved", "warnings": []}
            )
        )
        exit_code = main(["session", "get", "s_nowarn", "--decision"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Decision Outcome: Approved" in captured.out
        assert "Warnings:" not in captured.out

    @respx.mock
    def test_cli_session_get_decision_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_dec_json/").mock(
            return_value=Response(200, json={"session_id": "sess_dec_json", "status": "Approved"})
        )
        respx.get("https://verification.didit.me/v3/session/sess_dec_json/decision/").mock(
            return_value=Response(200, json={"session_id": "sess_dec_json", "status": "Approved"})
        )
        exit_code = main(["session", "get", "sess_dec_json", "--decision", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert "decision" in data

    @respx.mock
    def test_cli_session_create_json_and_null_url(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.post("https://verification.didit.me/v3/session/").mock(
            return_value=Response(
                201,
                json={"session_id": "sess_c_null", "status": "Not Started", "url": None},
            )
        )
        # JSON mode
        exit_code = main(
            [
                "session",
                "create",
                "--vendor-data",
                "v1",
                "--workflow-id",
                "w1",
                "--json",
            ]
        )
        assert exit_code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["status"] == "ok"
        assert data["session_id"] == "sess_c_null"

        # Text mode without url
        exit_code = main(["session", "create", "--vendor-data", "v1", "--workflow-id", "w1"])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "Hosted URL" not in out

    @respx.mock
    def test_cli_session_resubmit_text_mode(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.patch("https://verification.didit.me/v3/session/sess_r_text/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_r_text",
                    "status": "Resubmitted",
                    "resubmit_info": {"nodes": ["document"], "available_attempts": 2},
                },
            )
        )
        exit_code = main(["session", "resubmit", "sess_r_text", "--nodes", "document"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:             sess_r_text" in captured.out
        assert "Status:                 Resubmitted" in captured.out
        assert "Requires Resubmission:  True" in captured.out
        assert "Resubmit Steps:         document" in captured.out
        assert "Remaining Attempts:     2" in captured.out

    @respx.mock
    def test_cli_session_resubmit_text_mode_no_info(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.patch("https://verification.didit.me/v3/session/sess_r_text2/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_r_text2",
                    "status": "Resubmitted",
                },
            )
        )
        exit_code = main(["session", "resubmit", "sess_r_text2"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:             sess_r_text2" in captured.out
        assert "Resubmit Details" not in captured.out

    @respx.mock
    def test_cli_session_list_text_mode(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 1,
                    "results": [
                        {"session_id": "s_text", "status": "Approved", "vendor_data": "u_text"}
                    ],
                },
            )
        )
        exit_code = main(["session", "list"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Total sessions: 1 (showing 1)" in captured.out
        assert "s_text [Approved] (u_text)" in captured.out

    @respx.mock
    def test_cli_session_list_all_max_sessions(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get(
            "https://verification.didit.me/v3/sessions/?limit=1&offset=0&session_kind=user"
        ).mock(
            return_value=Response(
                200,
                json={
                    "count": 5,
                    "next": "https://verification.didit.me/v3/sessions/?offset=1",
                    "results": [{"session_id": "s_cap", "status": "Approved"}],
                },
            )
        )
        exit_code = main(["session", "list", "--all", "--max-sessions", "1"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Total sessions: 5 (collected 1)" in captured.out

    @respx.mock
    def test_cli_session_list_all_json_and_empty_stop(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get(
            "https://verification.didit.me/v3/sessions/?limit=50&offset=0&session_kind=user"
        ).mock(
            return_value=Response(
                200,
                json={
                    "count": 1,
                    "next": "https://verification.didit.me/v3/sessions/?offset=1",
                    "results": [{"session_id": "s_all_1", "status": "Approved"}],
                },
            )
        )
        respx.get(
            "https://verification.didit.me/v3/sessions/?limit=50&offset=1&session_kind=user"
        ).mock(return_value=Response(200, json={"count": 1, "next": None, "results": []}))
        exit_code = main(["session", "list", "--all", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["collected"] == 1

    @respx.mock
    def test_cli_session_pdf_api_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_pdf_err/generate-pdf/").mock(
            return_value=Response(500, json={"detail": "PDF engine failure"})
        )
        exit_code = main(["session", "pdf", "sess_pdf_err", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "API_ERROR"

    @respx.mock
    def test_cli_session_pdf_write_io_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_pdf_io/generate-pdf/").mock(
            return_value=Response(
                200,
                content=b"%PDF-1.4 valid",
                headers={"Content-Type": "application/pdf"},
            )
        )

        def mock_secure_write(*args: Any, **kwargs: Any) -> None:
            raise PermissionError("Permission denied on target path")

        monkeypatch.setattr("didit.cli._secure_write_bytes", mock_secure_write)

        exit_code = main(["session", "pdf", "sess_pdf_io", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "IO_ERROR"

    @pytest.mark.parametrize(
        ("exc_cls", "expected_code"),
        [
            (DiditConfigurationError, "CONFIGURATION_ERROR"),
            (DiditAuthenticationError, "AUTHENTICATION_FAILED"),
            (DiditPermissionError, "PERMISSION_DENIED"),
            (DiditNotFoundError, "NOT_FOUND"),
            (DiditConnectionError, "CONNECTION_ERROR"),
            (DiditSignatureError, "SIGNATURE_VERIFICATION_FAILED"),
        ],
    )
    def test_cli_root_exception_handling(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        exc_cls: type[Exception],
        expected_code: str,
    ) -> None:
        def raise_exc(*args: Any, **kwargs: Any) -> None:
            raise exc_cls("Simulated error message")

        monkeypatch.setattr("didit.cli._cmd_sandbox_scenarios", raise_exc)
        exit_code = main(["sandbox", "scenarios", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == expected_code
        assert "Simulated error message" in data["error"]["message"]

    @respx.mock
    def test_cli_doctor_healthcheck_unexpected_exception(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/system/healthcheck/").mock(
            side_effect=RuntimeError("unexpected socket crash")
        )
        respx.get("https://verification.didit.me/v3/session/auth-probe-check/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )
        exit_code = main(["doctor"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[WARN] API Connection: Healthcheck unavailable" in captured.out
        assert "[OK] Authentication: API key verified" in captured.out

    @respx.mock
    def test_cli_session_resubmit_text_mode_no_available_attempts(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.patch("https://verification.didit.me/v3/session/sess_no_att/update-status/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_no_att",
                    "status": "Resubmitted",
                    "resubmit_info": {"nodes": ["document"]},
                },
            )
        )
        exit_code = main(["session", "resubmit", "sess_no_att", "--nodes", "document"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:             sess_no_att" in captured.out
        assert "Resubmit Steps:         document" in captured.out
        assert "Remaining Attempts:" not in captured.out

    @pytest.mark.parametrize(
        ("args_list", "expected_msg"),
        [
            (
                ["session", "list", "--max-sessions", "0", "--json"],
                "--max-sessions must be a positive integer greater than zero.",
            ),
            (
                ["session", "list", "--max-sessions", "-5", "--json"],
                "--max-sessions must be a positive integer greater than zero.",
            ),
            (
                ["session", "list", "--limit", "0", "--json"],
                "--limit must be a positive integer greater than zero.",
            ),
            (
                ["session", "list", "--limit", "-1", "--json"],
                "--limit must be a positive integer greater than zero.",
            ),
            (
                ["session", "list", "--offset", "-1", "--json"],
                "--offset must be greater than or equal to zero.",
            ),
        ],
    )
    def test_cli_session_list_invalid_pagination_bounds(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        args_list: list[str],
        expected_msg: str,
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        exit_code = main(args_list)
        assert exit_code == 2
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "INVALID_ARGUMENT"
        assert data["error"]["message"] == expected_msg

    @respx.mock
    def test_cli_sandbox_scenarios_live_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        respx.get("https://verification.didit.me/v1/sandbox/scenarios/").mock(
            return_value=Response(
                200,
                json=[
                    {
                        "slug": "custom_live_scenario",
                        "category": "document",
                        "description": "custom desc",
                    }
                ],
            )
        )
        exit_code = main(["sandbox", "scenarios", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["count"] == 1
        assert data["scenarios"][0]["slug"] == "custom_live_scenario"

    @respx.mock
    def test_cli_sandbox_scenarios_live_dict_wrapper(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        respx.get("https://verification.didit.me/v1/sandbox/scenarios/").mock(
            return_value=Response(
                200,
                json={
                    "scenarios": [
                        {
                            "slug": "dict_live_scenario",
                            "category": "fraud",
                            "description": "fraud desc",
                        }
                    ]
                },
            )
        )
        exit_code = main(["sandbox", "scenarios", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["count"] == 1
        assert data["scenarios"][0]["slug"] == "dict_live_scenario"

    @respx.mock
    def test_cli_sandbox_scenarios_live_unexpected_json_fallback(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        respx.get("https://verification.didit.me/v1/sandbox/scenarios/").mock(
            return_value=Response(
                200,
                json={"unexpected_key": "unexpected_value"},
            )
        )
        exit_code = main(["sandbox", "scenarios", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["count"] == 16

    @respx.mock
    def test_cli_sandbox_scenarios_live_error_fallback(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        respx.get("https://verification.didit.me/v1/sandbox/scenarios/").mock(
            side_effect=ConnectError("Could not reach sandbox service")
        )
        exit_code = main(["sandbox", "scenarios", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "ok"
        assert data["count"] == 16

    def test_cli_json_aware_argument_parser_with_json(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = main(["session", "list", "--limit", "not_a_number", "--json"])
        assert exit_code == 2
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "INVALID_ARGUMENT"
        assert "invalid int value" in data["error"]["message"]

    def test_cli_argument_parser_without_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["session", "list", "--limit", "not_a_number"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "invalid int value" in captured.err

    def test_cli_main_missing_command_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["--json"])
        assert exit_code == 2
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert data["error"]["code"] == "MISSING_COMMAND"
        assert "No subcommand provided" in data["error"]["message"]

    def test_cli_main_missing_command_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main([])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "usage:" in captured.out
