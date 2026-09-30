"""Unit tests for Didit developer CLI utilities."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
import respx
from httpx import ConnectError, Response

from didit._version import __version__
from didit.cli import main
from didit.webhooks import compute_signature


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

        # Calling with no arguments prints usage and returns 0
        assert main([]) == 0
        captured_empty = capsys.readouterr()
        assert "usage: didit" in captured_empty.out

    def test_cli_doctor_missing_api_key(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Missing Didit API key" in captured.err

    def test_cli_doctor_missing_api_key_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["doctor", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert "Missing Didit API key" in data["error"]

    @respx.mock
    def test_cli_doctor_success(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_api_key_123")
        monkeypatch.setenv("DIDIT_WEBHOOK_SECRET", "whsec_test_456")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200, json={"count": 0, "next": None, "previous": None, "results": []}
            )
        )

        exit_code = main(["doctor"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] API Connection" in captured.out
        assert "[OK] Authentication: API key verified" in captured.out
        assert "[OK] Webhook Secret: Configured" in captured.out

    @respx.mock
    def test_cli_doctor_success_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_api_key_123")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200, json={"count": 0, "next": None, "previous": None, "results": []}
            )
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
    def test_cli_doctor_success_without_secret(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_api_key_123")
        monkeypatch.delenv("DIDIT_WEBHOOK_SECRET", raising=False)
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200, json={"count": 0, "next": None, "previous": None, "results": []}
            )
        )

        exit_code = main(["doctor"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] API Connection" in captured.out
        assert "[INFO] Webhook Secret: Not configured (optional)" in captured.out

    @respx.mock
    def test_cli_doctor_auth_failure(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "invalid_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(401, json={"detail": "Unauthorized API key"})
        )

        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "[FAIL] Authentication: Invalid or unauthorized API key (HTTP 401)" in captured.err

    @respx.mock
    def test_cli_doctor_auth_failure_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "invalid_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(401, json={"detail": "Unauthorized API key"})
        )

        exit_code = main(["doctor", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert "Invalid or unauthorized API key" in data["error"]

    @respx.mock
    def test_cli_doctor_connection_failure(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "valid_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            side_effect=ConnectError("Connection refused")
        )

        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "[FAIL] API Connection: Network or connection error" in captured.err

    @respx.mock
    def test_cli_doctor_connection_failure_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "valid_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            side_effect=ConnectError("Connection refused")
        )

        exit_code = main(["doctor", "--json"])
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "error"
        assert "Network or connection error" in data["error"]

    def test_cli_webhook_verify_success(self, capsys: pytest.CaptureFixture[str]) -> None:
        from didit.webhooks import canonical_json

        secret = "super_secret_webhook_key_789"
        ts = 1700000000
        body_dict = {
            "event_id": "evt_cli_1",
            "session_id": "sess_cli_1",
            "status": "Approved",
            "timestamp": ts,
        }
        body = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                secret,
                "--signature",
                sig,
                "--timestamp",
                str(ts),
                "--body",
                body,
                "--tolerance",
                "0",  # Disable age check for testing
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] Webhook signature verified successfully" in captured.out
        assert "evt_cli_1" in captured.out

    def test_cli_webhook_verify_success_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        from didit.webhooks import canonical_json

        secret = "super_secret_webhook_key_789"
        ts = 1700000000
        body_dict = {
            "event_id": "evt_cli_1",
            "session_id": "sess_cli_1",
            "status": "Approved",
            "timestamp": ts,
        }
        body = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                secret,
                "--signature",
                sig,
                "--timestamp",
                str(ts),
                "--body",
                body,
                "--tolerance",
                "0",
                "--json",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is True
        assert data["event_id"] == "evt_cli_1"

    def test_cli_webhook_verify_from_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from didit.webhooks import canonical_json

        secret = "super_secret_webhook_key_789"
        ts = 1700000000
        body_dict = {
            "event_id": "evt_cli_file",
            "session_id": "sess_cli_file",
            "status": "Approved",
            "timestamp": ts,
        }
        body = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        file_path = tmp_path / "payload.json"
        file_path.write_text(body, encoding="utf-8")

        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                secret,
                "--signature",
                sig,
                "--timestamp",
                str(ts),
                "--body-file",
                str(file_path),
                "--tolerance",
                "0",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] Webhook signature verified successfully" in captured.out

    def test_cli_webhook_verify_failure(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                "wrong_secret",
                "--signature",
                "0" * 64,
                "--timestamp",
                "1700000000",
                "--body",
                '{"event_id": "evt_fail", "timestamp": 1700000000}',
                "--tolerance",
                "0",
            ]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "[FAIL] Webhook verification failed" in captured.err

    def test_cli_webhook_verify_failure_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                "wrong_secret",
                "--signature",
                "0" * 64,
                "--timestamp",
                "1700000000",
                "--body",
                '{"event_id": "evt_fail", "timestamp": 1700000000}',
                "--tolerance",
                "0",
                "--json",
            ]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is False
        assert "error" in data

    def test_cli_webhook_verify_missing_body_arg(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                "s",
                "--signature",
                "sig",
                "--timestamp",
                "123",
            ]
        )
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Must provide either --body or --body-file" in captured.err

    def test_cli_webhook_verify_body_file_not_found(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                "s",
                "--signature",
                "sig",
                "--timestamp",
                "123",
                "--body-file",
                "/nonexistent/directory/payload.json",
            ]
        )
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error reading body file '/nonexistent/directory/payload.json'" in captured.err

    def test_cli_webhook_verify_positive_tolerance(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from didit.webhooks import canonical_json

        secret = "secret_tolerance_key"
        now_ts = int(time.time())
        body_dict = {
            "event_id": "evt_tol",
            "session_id": "sess_tol",
            "status": "Approved",
            "timestamp": now_ts,
        }
        body = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                secret,
                "--signature",
                sig,
                "--timestamp",
                str(now_ts),
                "--body",
                body,
                "--tolerance",
                "60",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] Webhook signature verified successfully" in captured.out

    def test_cli_webhook_verify_no_event_id(self, capsys: pytest.CaptureFixture[str]) -> None:
        from didit.webhooks import canonical_json

        secret = "secret_minimal_key"
        ts = 1700000000
        body_dict = {
            "session_id": "sess_no_evt",
            "status": "Approved",
            "timestamp": ts,
        }
        body = canonical_json(body_dict)
        sig = compute_signature(secret, body_dict)

        exit_code = main(
            [
                "webhook",
                "verify",
                "--secret",
                secret,
                "--signature",
                sig,
                "--timestamp",
                str(ts),
                "--body",
                body,
                "--tolerance",
                "0",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[OK] Webhook signature verified successfully" in captured.out
        assert "Event ID:   unknown" in captured.out
        assert "Session ID: sess_no_evt" in captured.out
        assert "Status:     Approved" in captured.out

    @respx.mock
    def test_cli_session_get_success(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_cli_1/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_cli_1",
                    "status": "In Progress",
                    "url": "https://verify.didit.me/sess_cli_1",
                    "vendor_data": "user_123",
                    "workflow_id": "wf_test",
                },
            )
        )

        exit_code = main(["session", "get", "sess_cli_1"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "sess_cli_1" in captured.out
        assert "In Progress" in captured.out
        assert "https://verify.didit.me/sess_cli_1" in captured.out

    @respx.mock
    def test_cli_session_get_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_cli_1/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_cli_1",
                    "status": "Approved",
                    "url": "https://verify.didit.me/sess_cli_1",
                    "vendor_data": "user_123",
                    "workflow_id": "wf_test",
                },
            )
        )

        exit_code = main(["session", "get", "sess_cli_1", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["session_id"] == "sess_cli_1"
        assert data["status"] == "Approved"

    @respx.mock
    def test_cli_session_get_with_decision(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_cli_dec/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_cli_dec",
                    "status": "Approved",
                    "url": "https://verify.didit.me/sess_cli_dec",
                },
            )
        )
        respx.get("https://verification.didit.me/v3/session/sess_cli_dec/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_cli_dec",
                    "status": "Approved",
                    "warnings": [{"code": "WARN_LOW", "message": "Low light"}],
                },
            )
        )

        exit_code = main(["session", "get", "sess_cli_dec", "--decision"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Decision Outcome: Approved" in captured.out
        assert "WARN_LOW" in captured.out

    @respx.mock
    def test_cli_session_get_not_found(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_404/").mock(
            return_value=Response(404, json={"detail": "Session not found"})
        )

        exit_code = main(["session", "get", "sess_404"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Session 'sess_404' not found" in captured.err

    @respx.mock
    def test_cli_session_create_success(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.post("https://verification.didit.me/v3/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_created_1",
                    "status": "Not Started",
                    "url": "https://verify.didit.me/sess_created_1",
                    "workflow_id": "wf_new",
                    "vendor_data": "user_new",
                },
            )
        )

        exit_code = main(
            [
                "session",
                "create",
                "--workflow-id",
                "wf_new",
                "--vendor-data",
                "user_new",
                "--scenario",
                "approve",
                "--lang",
                "es",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID: sess_created_1" in captured.out
        assert "https://verify.didit.me/sess_created_1" in captured.out

    @respx.mock
    def test_cli_session_create_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.post("https://verification.didit.me/v3/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_created_1",
                    "status": "Not Started",
                    "url": "https://verify.didit.me/sess_created_1",
                },
            )
        )

        exit_code = main(
            [
                "session",
                "create",
                "--workflow-id",
                "wf_new",
                "--vendor-data",
                "user_new",
                "--json",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["session_id"] == "sess_created_1"

    @respx.mock
    def test_cli_session_list_success(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 2,
                    "next": None,
                    "previous": None,
                    "results": [
                        {"session_id": "s1", "status": "Approved", "vendor_data": "u1"},
                        {"session_id": "s2", "status": "Declined", "vendor_data": "u2"},
                    ],
                },
            )
        )

        exit_code = main(["session", "list", "--limit", "10", "--status", "Approved"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Total sessions: 2" in captured.out
        assert "s1" in captured.out
        assert "s2" in captured.out

    @respx.mock
    def test_cli_session_list_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/sessions/").mock(
            return_value=Response(
                200,
                json={
                    "count": 1,
                    "next": None,
                    "previous": None,
                    "results": [{"session_id": "s1", "status": "Approved"}],
                },
            )
        )

        exit_code = main(["session", "list", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["count"] == 1
        assert len(data["results"]) == 1

    @respx.mock
    def test_cli_session_pdf_download(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        pdf_content = b"%PDF-1.4 test cli pdf content"
        respx.get("https://verification.didit.me/v3/session/sess_pdf_cli/generate-pdf/").mock(
            return_value=Response(
                200, content=pdf_content, headers={"Content-Type": "application/pdf"}
            )
        )

        output_path = tmp_path / "compliance_report.pdf"
        exit_code = main(["session", "pdf", "sess_pdf_cli", "-o", str(output_path)])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert f"Report saved to {output_path}" in captured.out
        assert output_path.read_bytes() == pdf_content

    @respx.mock
    def test_cli_session_pdf_default_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        monkeypatch.chdir(tmp_path)
        pdf_content = b"%PDF-1.4 default output pdf content"
        respx.get("https://verification.didit.me/v3/session/sess_pdf_def/generate-pdf/").mock(
            return_value=Response(
                200, content=pdf_content, headers={"Content-Type": "application/pdf"}
            )
        )

        exit_code = main(["session", "pdf", "sess_pdf_def"])
        assert exit_code == 0
        captured = capsys.readouterr()
        expected_file = tmp_path / "sess_pdf_def.pdf"
        assert f"Report saved to {expected_file}" in captured.out
        assert expected_file.read_bytes() == pdf_content

    @respx.mock
    def test_cli_session_pdf_not_found(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_pdf_missing/generate-pdf/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["session", "pdf", "sess_pdf_missing"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Session 'sess_pdf_missing' not found" in captured.err

    @respx.mock
    def test_cli_session_pdf_write_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_pdf_err/generate-pdf/").mock(
            return_value=Response(
                200, content=b"%PDF-1.4 sample", headers={"Content-Type": "application/pdf"}
            )
        )

        exit_code = main(["session", "pdf", "sess_pdf_err", "-o", str(tmp_path)])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert f"Error saving PDF report to '{tmp_path}'" in captured.err

    def test_cli_client_missing_api_key_for_session_command(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("DIDIT_API_KEY", raising=False)
        exit_code = main(["session", "get", "sess_no_key"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error: Missing Didit API key" in captured.err

    @respx.mock
    def test_cli_session_get_decision_not_found(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_dec_404/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_dec_404",
                    "status": "Approved",
                },
            )
        )
        respx.get("https://verification.didit.me/v3/session/sess_dec_404/decision/").mock(
            return_value=Response(404, json={"detail": "Not found"})
        )

        exit_code = main(["session", "get", "sess_dec_404", "--decision"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:  sess_dec_404" in captured.out
        assert "Decision Outcome:" not in captured.out

    @respx.mock
    def test_cli_session_get_decision_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_dec_json/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_dec_json",
                    "status": "Approved",
                },
            )
        )
        respx.get("https://verification.didit.me/v3/session/sess_dec_json/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_dec_json",
                    "status": "Approved",
                    "warnings": [],
                },
            )
        )

        exit_code = main(["session", "get", "sess_dec_json", "--decision", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["session_id"] == "sess_dec_json"
        assert "decision" in data
        assert data["decision"]["status"] == "Approved"

    @respx.mock
    def test_cli_session_get_sparse_and_decision_no_warnings(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.get("https://verification.didit.me/v3/session/sess_sparse/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_sparse",
                    "status": "Declined",
                },
            )
        )
        respx.get("https://verification.didit.me/v3/session/sess_sparse/decision/").mock(
            return_value=Response(
                200,
                json={
                    "session_id": "sess_sparse",
                    "status": "Declined",
                    "warnings": [],
                },
            )
        )

        exit_code = main(["session", "get", "sess_sparse", "--decision"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID:  sess_sparse" in captured.out
        assert "Decision Outcome: Declined" in captured.out
        assert "Hosted URL:" not in captured.out
        assert "Workflow ID:" not in captured.out
        assert "Vendor Data:" not in captured.out
        assert "Warnings:" not in captured.out

    @respx.mock
    def test_cli_session_create_no_url(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")
        respx.post("https://verification.didit.me/v3/session/").mock(
            return_value=Response(
                201,
                json={
                    "session_id": "sess_nourl",
                    "status": "Not Started",
                },
            )
        )

        exit_code = main(
            [
                "session",
                "create",
                "--workflow-id",
                "wf_test",
                "--vendor-data",
                "vd_test",
            ]
        )
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Session ID: sess_nourl" in captured.out
        assert "Hosted URL:" not in captured.out

    def test_cli_unhandled_exception_no_debug(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def mock_error(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Generic crash without debug")

        monkeypatch.setattr("didit.cli._cmd_doctor", mock_error)
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")

        exit_code = main(["doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error: Generic crash without debug\n" in captured.err
        assert "Traceback" not in captured.err

    def test_cli_debug_unhandled_exception(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Pass a bogus command with --debug that causes an error
        def mock_error(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Unexpected internal crash")

        monkeypatch.setattr("didit.cli._cmd_doctor", mock_error)
        monkeypatch.setenv("DIDIT_API_KEY", "test_key")

        exit_code = main(["--debug", "doctor"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "RuntimeError: Unexpected internal crash" in captured.err
        assert "Traceback (most recent call last):" in captured.err
