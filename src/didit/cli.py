"""Developer CLI utilities for Didit Identity Verification.

Provides operational tools for configuration inspection (doctor),
webhook signature debugging, session inspection, and compliance report downloads.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from didit._version import __version__
from didit.client import Didit
from didit.config import DEFAULT_BASE_URL, DEFAULT_WEBHOOK_MAX_AGE_SECONDS
from didit.errors import (
    DiditAuthenticationError,
    DiditConfigurationError,
    DiditConnectionError,
    DiditNotFoundError,
    DiditSignatureError,
)
from didit.webhooks import parse_webhook_payload


def _get_client(args: argparse.Namespace) -> Didit:
    """Instantiate a synchronous Didit client resolving arguments and environment."""
    api_key = getattr(args, "api_key", None) or os.environ.get("DIDIT_API_KEY")
    if not api_key:
        raise DiditConfigurationError(
            "Missing Didit API key. Provide --api-key or set the "
            "DIDIT_API_KEY environment variable."
        )

    base_url = (
        getattr(args, "base_url", None) or os.environ.get("DIDIT_BASE_URL") or DEFAULT_BASE_URL
    )
    return Didit(api_key=api_key, base_url=base_url)


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Diagnose API credentials, network connectivity, latency, and webhook secret."""
    is_json = getattr(args, "json", False)
    api_key = getattr(args, "api_key", None) or os.environ.get("DIDIT_API_KEY")
    if not api_key:
        error_msg = (
            "Missing Didit API key. Provide --api-key or set the "
            "DIDIT_API_KEY environment variable."
        )
        if is_json:
            print(json.dumps({"status": "error", "error": error_msg}))
        else:
            sys.stderr.write(f"Error: {error_msg}\n")
        return 1

    base_url = (
        getattr(args, "base_url", None) or os.environ.get("DIDIT_BASE_URL") or DEFAULT_BASE_URL
    )
    webhook_secret = getattr(args, "secret", None) or os.environ.get("DIDIT_WEBHOOK_SECRET")

    start_time = time.monotonic()
    try:
        client = Didit(api_key=api_key, base_url=base_url)
        # Probe remote API using minimal session list query
        client.sessions.list(limit=1)
        latency_ms = (time.monotonic() - start_time) * 1000.0
    except DiditAuthenticationError:
        if is_json:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": "Invalid or unauthorized API key (HTTP 401)",
                    }
                )
            )
        else:
            sys.stderr.write("[FAIL] Authentication: Invalid or unauthorized API key (HTTP 401)\n")
        return 1
    except (DiditConnectionError, Exception) as exc:
        if is_json:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": f"Network or connection error: {exc}",
                    }
                )
            )
        else:
            sys.stderr.write("[FAIL] API Connection: Network or connection error\n")
        return 1

    if is_json:
        payload: dict[str, Any] = {
            "status": "ok",
            "base_url": base_url,
            "latency_ms": round(latency_ms, 2),
            "authenticated": True,
            "webhook_secret_configured": bool(webhook_secret),
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"[OK] API Connection: Connected to {base_url} (latency: {latency_ms:.1f}ms)")
        print("[OK] Authentication: API key verified")
        if webhook_secret:
            print(f"[OK] Webhook Secret: Configured (length: {len(webhook_secret)} chars)")
        else:
            print("[INFO] Webhook Secret: Not configured (optional)")

    return 0


def _cmd_webhook_verify(args: argparse.Namespace) -> int:
    """Verify an incoming webhook signature against secret, timestamp, and body."""
    is_json = getattr(args, "json", False)
    if not args.body and not args.body_file:
        sys.stderr.write("Error: Must provide either --body or --body-file\n")
        return 2

    if args.body_file:
        try:
            body = Path(args.body_file).read_text(encoding="utf-8")
        except Exception as exc:
            sys.stderr.write(f"Error reading body file '{args.body_file}': {exc}\n")
            return 1
    else:
        body = args.body

    tolerance_val = getattr(args, "tolerance", None)
    tolerance = int(tolerance_val) if tolerance_val is not None else None
    if tolerance is not None and tolerance <= 0:
        max_age = 315360000  # 10 years
    else:
        max_age = tolerance or DEFAULT_WEBHOOK_MAX_AGE_SECONDS

    headers = {
        "X-Signature-V2": args.signature,
        "X-Timestamp": str(args.timestamp),
    }

    try:
        raw_bytes = body.encode("utf-8") if isinstance(body, str) else body
        payload = parse_webhook_payload(
            raw_bytes,
            headers,
            args.secret,
            max_age_seconds=max_age,
        )
        event_id = payload.event_id or "unknown"
        if is_json:
            print(
                json.dumps(
                    {
                        "valid": True,
                        "event_id": event_id,
                        "session_id": payload.session_id,
                        "status": payload.status.value,
                    }
                )
            )
        else:
            print("[OK] Webhook signature verified successfully")
            print(f"Event ID:   {event_id}")
            print(f"Session ID: {payload.session_id}")
            print(f"Status:     {payload.status.value}")
        return 0
    except DiditSignatureError as exc:
        if is_json:
            print(json.dumps({"valid": False, "error": str(exc)}))
        else:
            sys.stderr.write(f"[FAIL] Webhook verification failed: {exc}\n")
        return 1


def _cmd_session_get(args: argparse.Namespace) -> int:
    """Fetch status and optional decision details for a session."""
    is_json = getattr(args, "json", False)
    client = _get_client(args)
    try:
        session = client.sessions.get(args.session_id)
    except DiditNotFoundError:
        sys.stderr.write(f"Error: Session '{args.session_id}' not found\n")
        return 1

    decision_data: dict[str, Any] | None = None
    if getattr(args, "decision", False):
        try:
            decision = client.sessions.get_decision(args.session_id)
            decision_data = decision.model_dump()
        except DiditNotFoundError:
            decision_data = None

    if is_json:
        out = session.model_dump()
        if decision_data is not None:
            out["decision"] = decision_data
        print(json.dumps(out, indent=2))
    else:
        print(f"Session ID:  {session.session_id}")
        print(f"Status:      {session.status.value}")
        if session.url:
            print(f"Hosted URL:  {session.url}")
        if session.workflow_id:
            print(f"Workflow ID: {session.workflow_id}")
        if session.vendor_data:
            print(f"Vendor Data: {session.vendor_data}")
        if decision_data:
            dec_status = decision_data.get("status")
            dec_status_val = (
                getattr(dec_status, "value", str(dec_status))
                if dec_status is not None
                else "UNKNOWN"
            )
            print(f"Decision Outcome: {dec_status_val}")
            warnings = decision_data.get("warnings", [])
            if warnings:
                print("Warnings:")
                for w in warnings:
                    code = w.get("code") or w.get("risk") or "UNKNOWN"
                    msg = w.get("message") or ""
                    print(f"  - [{code}] {msg}")

    return 0


def _cmd_session_create(args: argparse.Namespace) -> int:
    """Create a new verification session."""
    is_json = getattr(args, "json", False)
    client = _get_client(args)
    session = client.sessions.create(
        workflow_id=args.workflow_id,
        vendor_data=args.vendor_data,
        callback=args.callback,
        language=args.lang,
        sandbox_scenario=args.scenario,
    )

    if is_json:
        print(json.dumps(session.model_dump(), indent=2))
    else:
        print(f"Session ID: {session.session_id}")
        print(f"Status:     {session.status.value}")
        if session.url:
            print(f"Hosted URL: {session.url}")

    return 0


def _cmd_session_list(args: argparse.Namespace) -> int:
    """List sessions with optional filtering."""
    is_json = getattr(args, "json", False)
    client = _get_client(args)
    page = client.sessions.list(
        limit=args.limit,
        status=args.status,
        country=args.country,
        vendor_data=args.vendor_data,
        workflow_id=args.workflow_id,
    )

    if is_json:
        print(json.dumps(page.model_dump(), indent=2))
    else:
        print(f"Total sessions: {page.count} (showing {len(page.results)})")
        for item in page.results:
            vendor_str = f" ({item.vendor_data})" if item.vendor_data else ""
            print(f"  - {item.session_id} [{item.status.value}]{vendor_str}")

    return 0


def _cmd_session_pdf(args: argparse.Namespace) -> int:
    """Download the compliance PDF report for a session."""
    client = _get_client(args)
    try:
        pdf_bytes = client.sessions.generate_pdf_report(args.session_id)
    except DiditNotFoundError:
        sys.stderr.write(f"Error: Session '{args.session_id}' not found\n")
        return 1

    default_name = f"{args.session_id}.pdf"
    out_path = Path(args.output).resolve() if args.output else Path(default_name).resolve()
    try:
        out_path.write_bytes(pdf_bytes)
        print(f"Report saved to {out_path} ({len(pdf_bytes)} bytes)")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Error saving PDF report to '{out_path}': {exc}\n")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser with inherited common options."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--api-key",
        default=argparse.SUPPRESS,
        help="Didit API key (defaults to DIDIT_API_KEY environment variable)",
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
        help="Format output as JSON",
    )
    common_parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show full stack traces on unhandled errors",
    )

    parser = argparse.ArgumentParser(
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

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # didit doctor
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Diagnose API credentials, network connectivity, latency, and webhook secret",
        parents=[common_parser],
    )
    doctor_parser.add_argument(
        "--secret",
        help="Optional webhook secret to inspect (defaults to DIDIT_WEBHOOK_SECRET)",
    )
    doctor_parser.set_defaults(func=_cmd_doctor)

    # didit webhook
    webhook_parser = subparsers.add_parser(
        "webhook", help="Webhook inspection and verification", parents=[common_parser]
    )
    webhook_subparsers = webhook_parser.add_subparsers(dest="webhook_subcommand")

    webhook_verify = webhook_subparsers.add_parser(
        "verify", help="Verify raw webhook signature and timestamp", parents=[common_parser]
    )
    webhook_verify.add_argument("--secret", required=True, help="Didit webhook secret key")
    webhook_verify.add_argument("--signature", required=True, help="Value of X-Signature-V2 header")
    webhook_verify.add_argument("--timestamp", required=True, help="Value of X-Timestamp header")
    webhook_verify.add_argument("--body", help="Raw JSON webhook payload string")
    webhook_verify.add_argument("--body-file", help="Path to file containing raw JSON body")
    webhook_verify.add_argument(
        "--tolerance",
        default=str(DEFAULT_WEBHOOK_MAX_AGE_SECONDS),
        help=(
            f"Maximum age in seconds (default {DEFAULT_WEBHOOK_MAX_AGE_SECONDS}, 0 disables check)"
        ),
    )
    webhook_verify.set_defaults(func=_cmd_webhook_verify)

    # didit session
    session_parser = subparsers.add_parser(
        "session", help="Verification session operations", parents=[common_parser]
    )
    session_subparsers = session_parser.add_subparsers(dest="session_subcommand")

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

    # didit session list
    session_list = session_subparsers.add_parser(
        "list", help="List verification sessions", parents=[common_parser]
    )
    session_list.add_argument("--limit", type=int, default=10, help="Maximum sessions to list")
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
    session_pdf.set_defaults(func=_cmd_session_pdf)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 0

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return int(args.func(args))
    except Exception as exc:
        if getattr(args, "debug", False):
            traceback.print_exc(file=sys.stderr)
        else:
            sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
