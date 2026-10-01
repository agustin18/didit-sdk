"""Developer CLI utilities for Didit Identity Verification.

Provides operational tools for configuration inspection (doctor),
webhook signature debugging, session inspection, compliance report downloads,
and sandbox scenario exploration.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import traceback
import urllib.parse
from pathlib import Path
from typing import Any, NoReturn

import httpx

from didit._version import __version__
from didit.client import Didit
from didit.config import DEFAULT_BASE_URL, DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.errors import (
    DiditAPIError,
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditNotFoundError,
    DiditPermissionError,
    DiditSignatureError,
)
from didit.resources.sessions import _secure_write_bytes as _secure_write_bytes
from didit.webhooks import parse_webhook_payload

SANDBOX_SCENARIOS: list[dict[str, str]] = [
    {
        "slug": "approve",
        "category": "success",
        "description": "Happy path verification resulting in Approved status.",
    },
    {
        "slug": "decline_document_expired",
        "category": "decline",
        "description": "Identification document expiration date is in the past.",
    },
    {
        "slug": "decline_could_not_recognize_document",
        "category": "decline",
        "description": "Document format or features could not be identified.",
    },
    {
        "slug": "decline_mrz_validation",
        "category": "decline",
        "description": "Machine Readable Zone (MRZ) checksum validation failed.",
    },
    {
        "slug": "decline_minimum_age",
        "category": "decline",
        "description": "Calculated user age is below the workflow minimum threshold.",
    },
    {
        "slug": "decline_face_match_low_similarity",
        "category": "decline",
        "description": "Facial similarity between selfie and ID photo is below threshold.",
    },
    {
        "slug": "decline_liveness_attack",
        "category": "decline",
        "description": "Presentation or biometric spoofing attack detected.",
    },
    {
        "slug": "decline_aml_hit",
        "category": "decline",
        "description": "User matched against global sanction or AML watchlists.",
    },
    {
        "slug": "decline_ip_blocklist",
        "category": "decline",
        "description": "Client IP address flagged on security blocklist.",
    },
    {
        "slug": "decline_poa_address_mismatch",
        "category": "decline",
        "description": "Proof of address document does not match submitted address.",
    },
    {
        "slug": "decline_nfc_chip_not_verified",
        "category": "decline",
        "description": "NFC chip cryptographic authentication failed.",
    },
    {
        "slug": "decline_database_no_match",
        "category": "decline",
        "description": "No record found in authoritative identity database.",
    },
    {
        "slug": "decline_kyb_registry_mismatch",
        "category": "decline",
        "description": "Company registry data mismatch during business verification.",
    },
    {
        "slug": "review_aml_possible_match",
        "category": "review",
        "description": "Potential PEP or AML match requiring manual compliance review.",
    },
    {
        "slug": "review_face_match_borderline",
        "category": "review",
        "description": "Biometric similarity score is borderline, flagged for human inspection.",
    },
    {
        "slug": "review_poa_partial_match",
        "category": "review",
        "description": "Proof of address partially matches provided profile.",
    },
]


def _emit_success(
    payload: dict[str, Any],
    is_json: bool,
    text_lines: list[str] | None = None,
) -> int:
    """Emit successful command output conforming to formatting contract."""
    if is_json:
        result: dict[str, Any] = {"status": "ok"}
        for k, v in payload.items():
            if k == "status":
                result["session_status"] = v
            else:
                result[k] = v
        print(json.dumps(result, indent=2))
    else:
        for line in text_lines or []:
            print(line)
    return 0


def _emit_error(
    code: str,
    message: str,
    is_json: bool,
    exit_code: int = 1,
    details: dict[str, Any] | None = None,
) -> int:
    """Emit structured or human-readable error conforming to formatting contract."""
    if is_json:
        err_dict: dict[str, Any] = {"code": code, "message": message}
        if details:
            err_dict["details"] = details
        out = {"status": "error", "error": err_dict}
        print(json.dumps(out, indent=2))
    else:
        sys.stderr.write(f"Error: {message}\n")
    return exit_code


def _resolve_api_key(args: argparse.Namespace) -> str | None:
    """Resolve API key strictly from file or environment to prevent argv leakage."""
    api_key_file = getattr(args, "api_key_file", None)
    if api_key_file:
        try:
            return Path(api_key_file).read_text(encoding="utf-8").strip()
        except Exception as exc:
            raise DiditConfigurationError(
                f"Error reading API key file '{api_key_file}': {exc}"
            ) from exc
    return os.environ.get("DIDIT_API_KEY")


def _resolve_webhook_secret(args: argparse.Namespace) -> str | None:
    """Resolve webhook secret strictly from file or environment to prevent argv leakage."""
    secret_file = getattr(args, "secret_file", None)
    if secret_file:
        try:
            return Path(secret_file).read_text(encoding="utf-8").strip()
        except Exception as exc:
            raise DiditConfigurationError(
                f"Error reading webhook secret file '{secret_file}': {exc}"
            ) from exc
    return os.environ.get("DIDIT_WEBHOOK_SECRET")


def _resolve_body(args: argparse.Namespace) -> str:
    """Resolve webhook payload body strictly from file or stdin to prevent argv leakage."""
    body_file = getattr(args, "body_file", None)
    use_stdin = getattr(args, "stdin", False)
    if not body_file and not use_stdin:
        raise DiditConfigurationError("Must provide webhook body via --body-file or --stdin")
    if body_file:
        try:
            return Path(body_file).read_text(encoding="utf-8")
        except Exception as exc:
            raise DiditConfigurationError(f"Error reading body file '{body_file}': {exc}") from exc
    return sys.stdin.read()


def _get_client(args: argparse.Namespace) -> Didit:
    """Instantiate a synchronous Didit client resolving configuration safely."""
    api_key = _resolve_api_key(args)
    if not api_key:
        raise DiditConfigurationError(
            "Missing Didit API key. Set the DIDIT_API_KEY environment variable "
            "or provide --api-key-file."
        )

    base_url = (
        getattr(args, "base_url", None) or os.environ.get("DIDIT_BASE_URL") or DEFAULT_BASE_URL
    )
    return Didit(api_key=api_key, base_url=base_url)


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Diagnose API credentials, network connectivity, latency, and webhook secret."""
    is_json = getattr(args, "json", False)
    try:
        api_key = _resolve_api_key(args)
        webhook_secret = _resolve_webhook_secret(args)
    except DiditConfigurationError as exc:
        return _emit_error("CONFIGURATION_ERROR", str(exc), is_json=is_json)

    if not api_key:
        return _emit_error(
            "MISSING_API_KEY",
            "Missing Didit API key. Set DIDIT_API_KEY or provide --api-key-file.",
            is_json=is_json,
        )

    base_url = (
        getattr(args, "base_url", None) or os.environ.get("DIDIT_BASE_URL") or DEFAULT_BASE_URL
    )

    client = Didit(api_key=api_key, base_url=base_url)

    # 1. Connectivity & Latency Probe via dedicated root origin /system/healthcheck/
    parsed_base = urllib.parse.urlsplit(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    health_url = f"{origin}/system/healthcheck/"

    conn_ok = False
    conn_err_reason: str | None = None
    start_time = time.monotonic()
    try:
        with httpx.Client(timeout=10.0) as http_client:
            health_resp = http_client.get(health_url)
            latency_ms = (time.monotonic() - start_time) * 1000.0
            if health_resp.status_code == 200:
                conn_ok = True
            else:
                conn_ok = False
                conn_err_reason = f"HTTP {health_resp.status_code}"
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        latency_ms = (time.monotonic() - start_time) * 1000.0
        conn_ok = False
        conn_err_reason = str(exc) or "Network connection failed"
    except Exception as exc:
        latency_ms = (time.monotonic() - start_time) * 1000.0
        conn_ok = False
        conn_err_reason = str(exc) or "Unexpected healthcheck error"

    strict = getattr(args, "strict", False)
    if strict and not conn_ok:
        msg = f"Healthcheck probe unavailable at {health_url} ({conn_err_reason})"
        return _emit_error(
            "CONNECTIVITY_UNAVAILABLE",
            msg,
            is_json=is_json,
            exit_code=1,
        )

    # 2. Authentication Probe (verifying permissions without reading user KYC data)
    try:
        client.requestor.request("GET", "/session/auth-probe-check/")
    except DiditAuthenticationError:
        return _emit_error(
            "AUTHENTICATION_FAILED",
            "Invalid or unauthorized API key (HTTP 401).",
            is_json=is_json,
        )
    except DiditPermissionError:
        return _emit_error(
            "PERMISSION_DENIED",
            "API key lacks permissions to access sessions resource (HTTP 403).",
            is_json=is_json,
        )
    except DiditNotFoundError:
        # 404 on non-existent probe ID proves credentials and routing are valid
        pass
    except (DiditConnectionError, httpx.ConnectError):
        return _emit_error(
            "CONNECTION_ERROR",
            "Failed to connect to Didit API during authentication check.",
            is_json=is_json,
        )
    except Exception:
        if getattr(args, "debug", False):
            raise
        return _emit_error(
            "PROBE_FAILED",
            "Authentication verification probe failed.",
            is_json=is_json,
        )

    payload: dict[str, Any] = {
        "base_url": base_url,
        "latency_ms": round(latency_ms, 2),
        "connectivity": "ok" if conn_ok else "unavailable",
        "authenticated": True,
        "webhook_secret_configured": bool(webhook_secret),
    }
    conn_text = (
        f"[OK] API Connection: Connected to {origin} (latency: {latency_ms:.1f}ms)"
        if conn_ok
        else f"[WARN] API Connection: Healthcheck unavailable at {health_url}"
    )
    text_lines = [
        conn_text,
        "[OK] Authentication: API key verified",
    ]
    if webhook_secret:
        text_lines.append("[OK] Webhook Secret: Configured")
    else:
        text_lines.append("[INFO] Webhook Secret: Not configured (optional)")

    return _emit_success(payload, is_json=is_json, text_lines=text_lines)


def _cmd_webhook_verify(args: argparse.Namespace) -> int:
    """Verify an incoming webhook signature against secret, timestamp, and body."""
    is_json = getattr(args, "json", False)

    tolerance = getattr(args, "tolerance", DEFAULT_WEBHOOK_MAX_AGE_SECONDS)
    if tolerance < 1:
        return _emit_error(
            "INVALID_TOLERANCE",
            "--tolerance must be a positive integer greater than zero.",
            is_json=is_json,
            exit_code=2,
        )

    try:
        secret = _resolve_webhook_secret(args)
    except DiditConfigurationError as exc:
        return _emit_error("CONFIGURATION_ERROR", str(exc), is_json=is_json)

    if not secret:
        return _emit_error(
            "MISSING_WEBHOOK_SECRET",
            "Missing webhook secret. Set DIDIT_WEBHOOK_SECRET or provide --secret-file.",
            is_json=is_json,
        )

    try:
        body = _resolve_body(args)
    except DiditConfigurationError as exc:
        return _emit_error("INVALID_INPUT", str(exc), is_json=is_json, exit_code=2)

    skip_freshness = getattr(args, "skip_freshness_check", False)
    if skip_freshness:
        sys.stderr.write(
            "WARNING: Freshness validation disabled; verifying signature authenticity only.\n"
        )

    headers = {
        "X-Signature-V2": args.signature,
        "X-Timestamp": str(args.timestamp),
    }

    try:
        raw_bytes = body.encode("utf-8") if isinstance(body, str) else body
        payload = parse_webhook_payload(
            raw_bytes,
            headers,
            secret,
            max_age_seconds=tolerance,
            verify_freshness=not skip_freshness,
        )
        event_id = payload.event_id or "unknown"
        data = {
            "valid": True,
            "event_id": event_id,
            "session_id": payload.session_id,
            "session_status": payload.status.value,
        }
        text_lines = [
            "[OK] Webhook signature verified successfully",
            f"Event ID:   {event_id}",
            f"Session ID: {payload.session_id}",
            f"Status:     {payload.status.value}",
        ]
        return _emit_success(data, is_json=is_json, text_lines=text_lines)
    except DiditSignatureError as exc:
        return _emit_error(
            "SIGNATURE_VERIFICATION_FAILED",
            f"Webhook verification failed: {exc}",
            is_json=is_json,
        )


def _cmd_session_get(args: argparse.Namespace) -> int:
    """Fetch status and optional decision details for a session."""
    is_json = getattr(args, "json", False)
    include_sensitive = getattr(args, "include_sensitive", False)
    client = _get_client(args)
    try:
        session = client.sessions.get(args.session_id)
    except DiditNotFoundError:
        return _emit_error(
            "SESSION_NOT_FOUND",
            f"Session '{args.session_id}' not found",
            is_json=is_json,
        )

    decision_data: dict[str, Any] | None = None
    if getattr(args, "decision", False):
        try:
            decision = client.sessions.get_decision(args.session_id)
            decision_data = decision.model_dump() if include_sensitive else decision.redacted_dump()
        except DiditNotFoundError:
            decision_data = None

    if is_json:
        sess_dict = session.model_dump() if include_sensitive else session.redacted_dump()
        if decision_data is not None:
            sess_dict["decision"] = decision_data
        return _emit_success(sess_dict, is_json=True)

    text_lines = [
        f"Session ID:  {session.session_id}",
        f"Status:      {session.status.value}",
    ]
    if session.url and include_sensitive:
        text_lines.append(f"Hosted URL:  {session.url}")
    if session.workflow_id:
        text_lines.append(f"Workflow ID: {session.workflow_id}")
    if session.vendor_data:
        text_lines.append(f"Vendor Data: {session.vendor_data}")
    if session.requires_resubmission:
        text_lines.append("Resubmission Required: True")

    if decision_data:
        dec_status = decision_data.get("status")
        dec_status_val = (
            getattr(dec_status, "value", str(dec_status)) if dec_status is not None else "UNKNOWN"
        )
        text_lines.append(f"Decision Outcome: {dec_status_val}")
        warnings = decision_data.get("warnings") or []
        if warnings:
            text_lines.append("Warnings:")
            for w in warnings:
                code = w.get("code") or w.get("risk") or "UNKNOWN"
                msg = w.get("message") or ""
                text_lines.append(f"  - [{code}] {msg}".rstrip())

    return _emit_success({}, is_json=False, text_lines=text_lines)


def _cmd_session_create(args: argparse.Namespace) -> int:
    """Create a new verification session."""
    is_json = getattr(args, "json", False)
    include_sensitive = getattr(args, "include_sensitive", False)
    client = _get_client(args)
    session = client.sessions.create(
        workflow_id=args.workflow_id,
        vendor_data=args.vendor_data,
        callback=args.callback,
        language=args.lang,
        sandbox_scenario=args.scenario,
    )

    if is_json:
        sess_dict = session.model_dump() if include_sensitive else session.redacted_dump()
        return _emit_success(sess_dict, is_json=True)

    text_lines = [
        f"Session ID: {session.session_id}",
        f"Status:     {session.status.value}",
    ]
    if include_sensitive and session.url:
        text_lines.append(f"Hosted URL: {session.url}")
    elif session.url:
        text_lines.append("Hosted URL: [REDACTED] (use --include-sensitive to view)")

    return _emit_success({}, is_json=False, text_lines=text_lines)


def _cmd_session_resubmit(args: argparse.Namespace) -> int:
    """Request document or biometric resubmission for an existing session."""
    is_json = getattr(args, "json", False)
    include_sensitive = getattr(args, "include_sensitive", False)
    client = _get_client(args)
    try:
        session = client.sessions.resubmit(
            args.session_id,
            nodes_to_resubmit=args.nodes,
        )
    except DiditNotFoundError:
        return _emit_error(
            "SESSION_NOT_FOUND",
            f"Session '{args.session_id}' not found",
            is_json=is_json,
        )

    if is_json:
        sess_dict = session.model_dump() if include_sensitive else session.redacted_dump()
        return _emit_success(sess_dict, is_json=True)

    text_lines = [
        f"Session ID:             {session.session_id}",
        f"Status:                 {session.status.value}",
        f"Requires Resubmission:  {session.requires_resubmission}",
    ]
    if session.resubmit_info:
        nodes_str = ", ".join(session.resubmit_info.nodes) if session.resubmit_info.nodes else "all"
        text_lines.append(f"Resubmit Steps:         {nodes_str}")
        if session.resubmit_info.available_attempts is not None:
            text_lines.append(f"Remaining Attempts:     {session.resubmit_info.available_attempts}")

    return _emit_success({}, is_json=False, text_lines=text_lines)


def _cmd_session_list(args: argparse.Namespace) -> int:
    """List sessions with filtering and full CLI pagination."""
    is_json = getattr(args, "json", False)
    include_sensitive = getattr(args, "include_sensitive", False)
    client = _get_client(args)

    fetch_all = getattr(args, "all", False)
    max_sessions = getattr(args, "max_sessions", 500)
    current_offset = getattr(args, "offset", 0)
    page_limit = getattr(args, "limit", 10)

    if max_sessions is not None and max_sessions <= 0:
        return _emit_error(
            "INVALID_ARGUMENT",
            "--max-sessions must be a positive integer greater than zero.",
            is_json=is_json,
            exit_code=2,
        )

    if page_limit <= 0:
        return _emit_error(
            "INVALID_ARGUMENT",
            "--limit must be a positive integer greater than zero.",
            is_json=is_json,
            exit_code=2,
        )

    if current_offset < 0:
        return _emit_error(
            "INVALID_ARGUMENT",
            "--offset must be greater than or equal to zero.",
            is_json=is_json,
            exit_code=2,
        )

    if fetch_all:
        collected: list[Any] = []
        total_count = 0
        while len(collected) < max_sessions:
            page = client.sessions.list(
                limit=min(50, max_sessions - len(collected)),
                offset=current_offset,
                status=args.status,
                country=args.country,
                vendor_data=args.vendor_data,
                workflow_id=args.workflow_id,
            )
            total_count = page.count
            if not page.results:
                break
            collected.extend(page.results)
            current_offset += len(page.results)
            if page.next is None:
                break

        if is_json:
            results_dump = [
                (item.model_dump() if include_sensitive else item.redacted_dump())
                for item in collected
            ]
            return _emit_success(
                {"count": total_count, "results": results_dump, "collected": len(collected)},
                is_json=True,
            )

        text_lines = [f"Total sessions: {total_count} (collected {len(collected)})"]
        for item in collected:
            vendor_str = f" ({item.vendor_data})" if item.vendor_data else ""
            text_lines.append(f"  - {item.session_id} [{item.status.value}]{vendor_str}")
        return _emit_success({}, is_json=False, text_lines=text_lines)

    page = client.sessions.list(
        limit=page_limit,
        offset=current_offset,
        status=args.status,
        country=args.country,
        vendor_data=args.vendor_data,
        workflow_id=args.workflow_id,
    )

    if is_json:
        dump_data = page.model_dump() if include_sensitive else page.redacted_dump()
        return _emit_success(dump_data, is_json=True)

    text_lines = [f"Total sessions: {page.count} (showing {len(page.results)})"]
    for item in page.results:
        vendor_str = f" ({item.vendor_data})" if item.vendor_data else ""
        text_lines.append(f"  - {item.session_id} [{item.status.value}]{vendor_str}")

    return _emit_success({}, is_json=False, text_lines=text_lines)


def _cmd_session_pdf(args: argparse.Namespace) -> int:
    """Download compliance PDF report for a session using direct-to-disk streaming."""
    is_json = getattr(args, "json", False)
    force = getattr(args, "force", False)
    client = _get_client(args)

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", args.session_id) + ".pdf"
    out_path = Path(args.output).resolve() if args.output else Path(safe_name).resolve()

    try:
        saved_path = client.sessions.download_pdf_report(
            args.session_id,
            destination=out_path,
            force=force,
        )
        pdf_size = saved_path.stat().st_size
    except FileExistsError as exc:
        return _emit_error("FILE_EXISTS", str(exc), is_json=is_json)
    except DiditNotFoundError:
        return _emit_error(
            "SESSION_NOT_FOUND",
            f"Session '{args.session_id}' not found",
            is_json=is_json,
        )
    except DiditAPIError as exc:
        return _emit_error("API_ERROR", str(exc), is_json=is_json)
    except Exception as exc:
        return _emit_error(
            "IO_ERROR",
            f"Error saving PDF report to '{out_path}': {exc}",
            is_json=is_json,
        )

    perms = "0600" if sys.platform != "win32" else "private"
    data = {
        "saved_to": str(saved_path),
        "bytes": pdf_size,
        "session_id": args.session_id,
        "permissions": perms,
    }
    mode_text = "mode: 0600" if sys.platform != "win32" else "permissions: private"
    text_lines = [f"Report saved to {saved_path} ({pdf_size} bytes, {mode_text})"]
    return _emit_success(data, is_json=is_json, text_lines=text_lines)


def _cmd_sandbox_scenarios(args: argparse.Namespace) -> int:
    """List available Didit sandbox testing scenarios."""
    is_json = getattr(args, "json", False)
    category = getattr(args, "category", None)
    strict = getattr(args, "strict", False)

    base_url = (
        getattr(args, "base_url", None) or os.environ.get("DIDIT_BASE_URL") or DEFAULT_BASE_URL
    )
    parsed_base = urllib.parse.urlsplit(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    live_url = f"{origin}/v1/sandbox/scenarios/"

    api_key: str | None = None
    try:
        api_key = _resolve_api_key(args)
    except DiditConfigurationError:
        api_key = None

    headers: dict[str, str] = {}
    if api_key:
        headers["x-api-key"] = api_key

    scenarios = SANDBOX_SCENARIOS
    remote_error: str | None = None
    try:
        with httpx.Client(timeout=5.0) as http_client:
            resp = http_client.get(live_url, headers=headers)
            if resp.is_success:
                data = resp.json()
                if isinstance(data, list):
                    scenarios = data
                elif (
                    isinstance(data, dict)
                    and "scenarios" in data
                    and isinstance(data["scenarios"], list)
                ):
                    scenarios = data["scenarios"]
                else:
                    remote_error = "Invalid format returned by remote sandbox scenarios endpoint"
            else:
                remote_error = f"HTTP {resp.status_code} returned by remote endpoint"
    except Exception as exc:
        remote_error = str(exc) or "Network connection failed"

    if strict and remote_error:
        return _emit_error(
            "CONNECTIVITY_UNAVAILABLE",
            f"Remote sandbox scenarios catalog unavailable at {live_url}: {remote_error}",
            is_json=is_json,
            exit_code=1,
        )

    if category:
        scenarios = [s for s in scenarios if s.get("category") == category]

    if is_json:
        return _emit_success({"count": len(scenarios), "scenarios": scenarios}, is_json=True)

    text_lines = [f"Available Didit Sandbox Scenarios ({len(scenarios)}):"]
    for s in scenarios:
        cat = s.get("category", "scenario")
        cat_badge = f"[{cat.upper()}]"
        desc = s.get("description", "")
        text_lines.append(f"  • {s['slug']:<36} {cat_badge:<10} {desc}")

    return _emit_success({}, is_json=False, text_lines=text_lines)


class JSONAwareArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that emits structured JSON envelopes on error when --json is passed."""

    _active_argv: list[str] = []

    def error(self, message: str) -> NoReturn:
        if "--json" in getattr(JSONAwareArgumentParser, "_active_argv", []):
            _emit_error("INVALID_ARGUMENT", message, is_json=True, exit_code=2)
            sys.exit(2)
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser with inherited common options."""
    common_parser = JSONAwareArgumentParser(add_help=False)
    common_parser.add_argument(
        "--api-key-file",
        default=argparse.SUPPRESS,
        help=(
            "Path to file containing Didit API key (defaults to DIDIT_API_KEY environment variable)"
        ),
    )
    common_parser.add_argument(
        "--base-url",
        default=argparse.SUPPRESS,
        help=f"Didit API base URL (defaults to DIDIT_BASE_URL or {DEFAULT_BASE_URL})",
    )
    common_parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Format output as parseable JSON",
    )
    common_parser.add_argument(
        "--include-sensitive",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Include raw sensitive KYC data and tokens in JSON output (default: false)",
    )
    common_parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show full stack traces on unhandled errors",
    )

    parser = JSONAwareArgumentParser(
        prog="didit",
        description="Didit Identity Verification CLI Utilities",
        parents=[common_parser],
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"didit-sdk {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="subcommand", help="Available subcommands", parser_class=JSONAwareArgumentParser
    )

    # didit doctor
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Diagnose API credentials, network connectivity, latency, and webhook secret",
        parents=[common_parser],
    )
    doctor_parser.add_argument(
        "--secret-file",
        help="Path to file containing webhook secret to inspect (defaults to DIDIT_WEBHOOK_SECRET)",
    )
    doctor_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Fail with non-zero exit code if healthcheck or latency probe is unavailable",
    )
    doctor_parser.set_defaults(func=_cmd_doctor)

    # didit webhook
    webhook_parser = subparsers.add_parser(
        "webhook", help="Webhook inspection and verification", parents=[common_parser]
    )
    webhook_subparsers = webhook_parser.add_subparsers(
        dest="webhook_subcommand", parser_class=JSONAwareArgumentParser
    )

    webhook_verify = webhook_subparsers.add_parser(
        "verify", help="Verify raw webhook signature and timestamp", parents=[common_parser]
    )
    webhook_verify.add_argument(
        "--secret-file",
        help="Path to file containing Didit webhook secret (defaults to DIDIT_WEBHOOK_SECRET)",
    )
    webhook_verify.add_argument("--signature", required=True, help="Value of X-Signature-V2 header")
    webhook_verify.add_argument("--timestamp", required=True, help="Value of X-Timestamp header")

    body_group = webhook_verify.add_mutually_exclusive_group()
    body_group.add_argument("--body-file", help="Path to file containing raw JSON body")
    body_group.add_argument(
        "--stdin", action="store_true", help="Read raw JSON body from standard input"
    )

    webhook_verify.add_argument(
        "--tolerance",
        type=int,
        default=DEFAULT_WEBHOOK_MAX_AGE_SECONDS,
        help=(
            f"Maximum age in seconds (positive integer, default {DEFAULT_WEBHOOK_MAX_AGE_SECONDS})"
        ),
    )
    webhook_verify.add_argument(
        "--skip-freshness-check",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Disable timestamp freshness check and verify cryptographic signature authenticity only"
        ),
    )
    webhook_verify.set_defaults(func=_cmd_webhook_verify)

    # didit session
    session_parser = subparsers.add_parser(
        "session", help="Verification session operations", parents=[common_parser]
    )
    session_subparsers = session_parser.add_subparsers(
        dest="session_subcommand", parser_class=JSONAwareArgumentParser
    )

    # didit session get
    session_get = session_subparsers.add_parser(
        "get", help="Retrieve session details and status", parents=[common_parser]
    )
    session_get.add_argument("session_id", help="Didit session identifier")
    session_get.add_argument(
        "--decision",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Also fetch and display verification decision outcome and warnings",
    )
    session_get.set_defaults(func=_cmd_session_get)

    # didit session create
    session_create = session_subparsers.add_parser(
        "create", help="Create a new verification session", parents=[common_parser]
    )
    session_create.add_argument("--workflow-id", required=True, help="Didit workflow identifier")
    session_create.add_argument(
        "--vendor-data", required=True, help="Internal reference identifier for user"
    )
    session_create.add_argument("--callback", help="Optional redirect callback URL")
    session_create.add_argument("--scenario", help="Optional sandbox outcome scenario slug")
    session_create.add_argument("--lang", help="Optional UI language code (e.g. 'es', 'en')")
    session_create.set_defaults(func=_cmd_session_create)

    # didit session resubmit
    session_resubmit = session_subparsers.add_parser(
        "resubmit",
        help="Request document or biometric resubmission for an existing session",
        parents=[common_parser],
    )
    session_resubmit.add_argument("session_id", help="Didit session identifier")
    session_resubmit.add_argument(
        "--nodes",
        nargs="*",
        help=(
            "Optional exact upstream workflow node IDs to resubmit "
            "(e.g. 'document-verification-node', 'face-liveness-node')"
        ),
    )
    session_resubmit.set_defaults(func=_cmd_session_resubmit)

    # didit session list
    session_list = session_subparsers.add_parser(
        "list", help="List verification sessions", parents=[common_parser]
    )
    session_list.add_argument("--limit", type=int, default=10, help="Maximum sessions per page")
    session_list.add_argument("--offset", type=int, default=0, help="Pagination offset")
    session_list.add_argument(
        "--all",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Iterate over all pages up to --max-sessions limit",
    )
    session_list.add_argument(
        "--max-sessions",
        type=int,
        default=500,
        help="Maximum total sessions to collect when --all is set (default: 500)",
    )
    session_list.add_argument("--status", help="Filter by status")
    session_list.add_argument("--country", help="Filter by 3-letter country code")
    session_list.add_argument("--vendor-data", help="Filter by vendor reference")
    session_list.add_argument("--workflow-id", help="Filter by workflow ID")
    session_list.set_defaults(func=_cmd_session_list)

    # didit session pdf
    session_pdf = session_subparsers.add_parser(
        "pdf", help="Download compliance PDF report for a session", parents=[common_parser]
    )
    session_pdf.add_argument("session_id", help="Didit session identifier")
    session_pdf.add_argument(
        "-o", "--output", help="Output file path (defaults to <session_id>.pdf)"
    )
    session_pdf.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Overwrite destination file if it already exists",
    )
    session_pdf.set_defaults(func=_cmd_session_pdf)

    # didit sandbox
    sandbox_parser = subparsers.add_parser(
        "sandbox", help="Sandbox testing and scenario catalog", parents=[common_parser]
    )
    sandbox_subparsers = sandbox_parser.add_subparsers(
        dest="sandbox_subcommand", parser_class=JSONAwareArgumentParser
    )

    # didit sandbox scenarios
    sandbox_scenarios = sandbox_subparsers.add_parser(
        "scenarios",
        help="Explore available sandbox testing scenario slugs",
        parents=[common_parser],
    )
    sandbox_scenarios.add_argument(
        "--category",
        choices=["success", "decline", "review"],
        help="Filter scenarios by category outcome",
    )
    sandbox_scenarios.add_argument(
        "--strict",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Fail-closed if remote sandbox scenarios catalog is unreachable",
    )
    sandbox_scenarios.set_defaults(func=_cmd_sandbox_scenarios)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point with universal error and JSON handling."""
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    JSONAwareArgumentParser._active_argv = raw_argv
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 0

    if not hasattr(args, "func"):
        if "--json" in raw_argv:
            return _emit_error(
                "MISSING_COMMAND",
                "No subcommand provided. Use --help for usage details.",
                is_json=True,
                exit_code=2,
            )
        parser.print_help()
        return 0

    is_json = getattr(args, "json", False)
    debug = getattr(args, "debug", False)

    try:
        return int(args.func(args))
    except DiditConfigurationError as exc:
        return _emit_error("CONFIGURATION_ERROR", str(exc), is_json=is_json)
    except DiditAuthenticationError as exc:
        return _emit_error("AUTHENTICATION_FAILED", str(exc), is_json=is_json)
    except DiditPermissionError as exc:
        return _emit_error("PERMISSION_DENIED", str(exc), is_json=is_json)
    except DiditNotFoundError as exc:
        return _emit_error("NOT_FOUND", str(exc), is_json=is_json)
    except DiditConnectionError as exc:
        return _emit_error("CONNECTION_ERROR", str(exc), is_json=is_json)
    except DiditSignatureError as exc:
        return _emit_error("SIGNATURE_VERIFICATION_FAILED", str(exc), is_json=is_json)
    except Exception:
        if debug:
            traceback.print_exc(file=sys.stderr)
            return 1
        return _emit_error(
            "INTERNAL_ERROR",
            "An unexpected error occurred. Use --debug for details.",
            is_json=is_json,
        )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
