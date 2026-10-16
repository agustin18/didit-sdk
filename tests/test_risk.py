"""Tests for Didit Standalone Risk APIs (Email, Phone, IP).

Validates data models, PII-safe representations, synchronous and asynchronous
client resources, offline simulation parity, and CLI subcommands.
"""

from __future__ import annotations

import json

import pytest
import respx

from didit.cli import main
from didit.client import AsyncDidit, Didit
from didit.models.risk import (
    EmailRiskRequest,
    EmailRiskResponse,
    IPRiskRequest,
    IPRiskResponse,
    PhoneRiskRequest,
    PhoneRiskResponse,
    RiskSignals,
)
from didit.simulation import SimulatedAsyncDidit, SimulatedDidit
from didit.transport import RequestOptions


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


class TestRiskModels:
    def test_risk_signals_properties_and_redaction(self) -> None:
        signals = RiskSignals(
            ip="192.168.1.100",
            device_id="device-secret-uuid-1234",
            device_platform="ios",
            device_model="iPhone15,2",
            os_version="17.4",
            app_version="2.1.0",
            user_agent="Mozilla/5.0 TestAgent",
            extra_custom_param="allowed",
        )
        assert signals.ip == "192.168.1.100"
        assert signals.device_platform == "ios"
        # Representation masks IP and sensitive device ID
        repr_str = repr(signals)
        assert "192.168.1.100" not in repr_str
        assert "device-secret" not in repr_str

        # Redacted dump
        redacted = signals.redacted_dump()
        assert redacted["ip"] == "192.168.*.*"
        assert redacted["device_id"] == "dev***34"
        assert redacted["device_platform"] == "ios"
        assert str(signals) == repr_str

    def test_email_risk_models(self) -> None:
        req = EmailRiskRequest(
            email="alice@example.com",
            country_code="US",
            signals=RiskSignals(ip="1.1.1.1"),
            vendor_data="lead-999",
            metadata={"source": "onboarding"},
            enable_social=True,
        )
        assert req.email == "alice@example.com"
        assert req.enable_social is True
        assert "alice@example.com" not in repr(req)
        assert "a***e@example.com" in repr(req)

        redacted_req = req.redacted_dump()
        assert redacted_req["email"] == "a***e@example.com"
        assert redacted_req["vendor_data"] == "lead-999"
        assert redacted_req["enable_social"] is True

        # Response model
        resp = EmailRiskResponse(
            request_id="req-email-123",
            status="Approved",
            created_at="2026-10-16T12:00:00Z",
            vendor_data="lead-999",
            metadata="custom-str-metadata",
            email={
                "status": "Approved",
                "email": "alice@example.com",
                "is_breached": True,
                "breaches": [{"name": "breach_1"}],
                "is_disposable": False,
                "is_undeliverable": False,
                "matches": [
                    {"email": "alice@example.com", "vendor_data": "lead-old"},
                    {"email": None},
                ],
                "email_social": {"profiles_registered": 2, "details": "secret"},
                "enrichment": {"score": 42.5},
            },
            email_social={"top_level": "secret_social"},
        )
        assert resp.is_approved is True
        assert resp.is_breached is True
        assert resp.is_disposable is False
        assert resp.is_undeliverable is False
        assert resp.request_id == "req-email-123"
        assert resp.metadata == "custom-str-metadata"
        assert resp.score == 42.5
        assert resp.enrichment == {"score": 42.5}

        # Test fallback to email_intelligence when enrichment absent
        resp_fallback = EmailRiskResponse(
            request_id="req-fb",
            status="Approved",
            created_at="2026-10-16T12:00:00Z",
            email={"email_intelligence": {"score": 88}},
        )
        assert resp_fallback.score == 88.0
        assert resp_fallback.enrichment == {"score": 88}

        resp_no_enrich = EmailRiskResponse(
            request_id="req-none",
            status="Approved",
            created_at="2026-10-16T12:00:00Z",
            email={},
        )
        assert resp_no_enrich.score is None
        assert resp_no_enrich.enrichment is None

        repr_resp = repr(resp)
        assert "alice@example.com" not in repr_resp
        assert "req-email-123" in repr_resp

        redacted_resp = resp.redacted_dump()
        assert redacted_resp["status"] == "Approved"
        assert redacted_resp["email"]["email"] == "a***e@example.com"
        assert redacted_resp["email"]["matches"][0]["email"] == "a***e@example.com"
        assert redacted_resp["email"]["matches"][1]["email"] is None
        assert redacted_resp["email"]["email_social"] == "[REDACTED]"
        assert redacted_resp["email_social"] == "[REDACTED]"

        # Test raw dict signals in EmailRiskRequest
        # (e.g. via model_construct or untyped deserialization)
        req_dict_signals = EmailRiskRequest.model_construct(
            email="alice@example.com",
            signals={"ip": "1.2.3.4", "device_id": "device-12345678", "extra": "val"},
        )
        redacted_req_dict = req_dict_signals.redacted_dump()
        assert redacted_req_dict["signals"]["ip"] == "1.2.*.*"
        assert redacted_req_dict["signals"]["device_id"] == "dev***78"
        assert redacted_req_dict["signals"]["extra"] == "val"

        # Test non-numeric score returns None
        resp_bad_score = EmailRiskResponse(
            request_id="r-bad",
            status="Approved",
            created_at="now",
            email={"enrichment": {"score": "not_a_number"}},
        )
        assert resp_bad_score.score is None

        # Test dict signals without ip or device_id
        req_dict_empty = EmailRiskRequest.model_construct(
            email="alice@example.com", signals={"other": 123}
        )
        assert req_dict_empty.redacted_dump()["signals"] == {"other": 123}

    def test_phone_risk_models(self) -> None:
        req = PhoneRiskRequest(
            phone_number="+14155552671",
            country_code="US",
            vendor_data="lead-555",
            metadata=[1, 2, 3],
            enable_social=True,
        )
        assert req.phone_number == "+14155552671"
        assert "+14155552671" not in repr(req)
        assert "+14***71" in repr(req)
        assert req.metadata == [1, 2, 3]

        redacted_req = req.redacted_dump()
        assert redacted_req["phone_number"] == "+14***71"

        # Raw dict signals in PhoneRiskRequest
        phone_req_dict = PhoneRiskRequest.model_construct(
            phone_number="+14155552671",
            signals={"ip": "192.168.1.1", "device_id": "short"},
        )
        redacted_phone_dict = phone_req_dict.redacted_dump()
        assert redacted_phone_dict["signals"]["ip"] == "192.168.*.*"
        assert redacted_phone_dict["signals"]["device_id"] == "***"

        # Test non-numeric score returns None in phone
        phone_bad_score = PhoneRiskResponse(
            request_id="r-bad-p",
            status="Approved",
            created_at="now",
            phone={"enrichment": {"score": "invalid"}},
        )
        assert phone_bad_score.score is None

        # Response model
        resp = PhoneRiskResponse(
            request_id="req-phone-456",
            status="Approved",
            created_at="2026-10-16T12:00:00Z",
            phone={
                "status": "Approved",
                "phone_number": "4155552671",
                "full_number": "+14155552671",
                "is_disposable": False,
                "is_virtual": False,
                "carrier": {"name": "Verizon", "type": "mobile"},
                "matches": [
                    {"phone_number": "+14155552671"},
                    {"phone_number": None},
                ],
                "phone_social": {"profiles_registered": 1},
                "enrichment": {"score": 15.0},
            },
            phone_social={"raw": "details"},
        )
        assert resp.is_approved is True
        assert resp.is_disposable is False
        assert resp.is_virtual is False
        assert resp.carrier_name == "Verizon"
        assert resp.score == 15.0
        assert resp.enrichment == {"score": 15.0}

        resp_phone_fb = PhoneRiskResponse(
            request_id="r-phone-fb",
            status="Approved",
            created_at="2026-10-16T12:00:00Z",
            phone={"phone_intelligence": {"score": 33}},
        )
        assert resp_phone_fb.score == 33.0
        assert resp_phone_fb.enrichment == {"score": 33}

        resp_phone_empty = PhoneRiskResponse(
            request_id="r-phone-empty",
            status="Approved",
            created_at="2026-10-16T12:00:00Z",
            phone={},
        )
        assert resp_phone_empty.score is None
        assert resp_phone_empty.enrichment is None

        repr_resp = repr(resp)
        assert "+14155552671" not in repr_resp

        redacted_resp = resp.redacted_dump()
        assert redacted_resp["status"] == "Approved"
        assert redacted_resp["phone"]["full_number"] == "+14***71"
        assert redacted_resp["phone"]["phone_number"] == "415***71"
        assert redacted_resp["phone"]["matches"][0]["phone_number"] == "+14***71"
        assert redacted_resp["phone"]["matches"][1]["phone_number"] is None
        assert redacted_resp["phone"]["phone_social"] == "[REDACTED]"
        assert redacted_resp["phone_social"] == "[REDACTED]"

    def test_ip_risk_models(self) -> None:
        req = IPRiskRequest(
            ip_address="8.8.8.8",
            claimed_country="ESP",
            user_agent="Mozilla/5.0",
            metadata=12345,
        )
        assert req.ip_address == "8.8.8.8"
        assert req.metadata == 12345
        assert "8.8.8.8" not in repr(req)

        redacted_req = req.redacted_dump()
        assert redacted_req["ip_address"] == "8.8.*.*"
        assert redacted_req["claimed_country"] == "ESP"

        # Response model
        resp = IPRiskResponse(
            request_id="req-ip-789",
            status="In Review",
            created_at="2026-10-16T12:00:00Z",
            ip={
                "status": "In Review",
                "ip_address": "8.8.8.8",
                "ip_country_code": "USA",
                "latitude": 37.386,
                "longitude": -122.0838,
                "is_vpn_or_tor": True,
                "is_data_center": True,
                "country_mismatch": True,
                "threat": {"is_tor": False},
            },
        )
        assert resp.is_approved is False
        assert resp.is_vpn_or_tor is True
        assert resp.is_data_center is True
        assert resp.country_mismatch is True
        assert resp.ip_country_code == "USA"

        repr_resp = repr(resp)
        assert "8.8.8.8" not in repr_resp

        redacted_resp = resp.redacted_dump()
        assert redacted_resp["status"] == "In Review"
        assert redacted_resp["ip"]["ip_address"] == "8.8.*.*"
        assert "latitude" not in redacted_resp["ip"]
        assert "longitude" not in redacted_resp["ip"]

    def test_masking_edge_cases(self) -> None:
        from didit.models.risk import _mask_email, _mask_ip, _mask_phone

        assert _mask_email(None) is None
        assert _mask_email("") == "***"
        assert _mask_email("a@b.com") == "a***@b.com"
        assert _mask_email("invalid-email") == "***"

        assert _mask_phone(None) is None
        assert _mask_phone("") == "***"
        assert _mask_phone("123") == "***"

        assert _mask_ip(None) is None
        assert _mask_ip("") == "***"
        assert _mask_ip("2001:db8::1") == "2001:***:1"
        assert _mask_ip("invalid-ip") == "***"


# =========================================================================
# Synchronous Resource Tests
# =========================================================================


class TestSyncRiskResource:
    @respx.mock
    def test_risk_email_success(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={
                "request_id": "req-1",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "vendor_data": "usr-1",
                "email": {
                    "status": "Approved",
                    "email": "alice@example.com",
                    "is_breached": False,
                    "breaches": [],
                    "is_disposable": False,
                    "is_undeliverable": False,
                },
            },
        )

        resp = client.risk.email(
            "alice@example.com",
            country_code="US",
            signals=RiskSignals(ip="1.2.3.4"),
            vendor_data="usr-1",
            metadata={"source": "test"},
            enable_social=True,
        )

        assert route.called
        assert resp.request_id == "req-1"
        assert resp.status == "Approved"
        assert resp.is_approved is True
        sent_payload = json.loads(route.calls.last.request.content)
        assert sent_payload["email"] == "alice@example.com"
        assert sent_payload["country_code"] == "US"
        assert sent_payload["signals"]["ip"] == "1.2.3.4"
        assert sent_payload["enable_social"] is True

    def test_risk_email_validation_empty(self, client: Didit) -> None:
        with pytest.raises(ValueError, match="email must not be empty"):
            client.risk.email("   ")

    @respx.mock
    def test_risk_phone_success(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={
                "request_id": "req-2",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "phone": {
                    "status": "Approved",
                    "full_number": "+14155552671",
                    "carrier": {"name": "AT&T", "type": "mobile"},
                },
            },
        )

        resp = client.risk.phone("+14155552671", country_code="US")
        assert route.called
        assert resp.request_id == "req-2"
        assert resp.carrier_name == "AT&T"

    def test_risk_phone_validation_empty(self, client: Didit) -> None:
        with pytest.raises(ValueError, match="phone_number must not be empty"):
            client.risk.phone("")

    @respx.mock
    def test_risk_ip_success(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={
                "request_id": "req-3",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "ip": {
                    "status": "Approved",
                    "ip_address": "8.8.8.8",
                    "country_mismatch": False,
                    "threat": {},
                },
            },
        )

        resp = client.risk.ip("8.8.8.8", claimed_country="USA")
        assert route.called
        assert resp.request_id == "req-3"
        assert resp.country_mismatch is False

    def test_risk_ip_validation_empty(self, client: Didit) -> None:
        with pytest.raises(ValueError, match="ip_address must not be empty"):
            client.risk.ip("  ")

    @respx.mock
    def test_risk_options_forwarding(self, client: Didit, base_url: str) -> None:
        route = respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={
                "request_id": "req-custom",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "email": {"status": "Approved"},
            },
        )
        opts = RequestOptions(headers={"x-custom-trace": "trace-123"})
        client.risk.email("alice@example.com", options=opts)
        assert route.called
        assert route.calls.last.request.headers.get("x-custom-trace") == "trace-123"


# =========================================================================
# Asynchronous Resource Tests
# =========================================================================


class TestAsyncRiskResource:
    @pytest.mark.asyncio
    @respx.mock
    async def test_async_risk_email_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={
                "request_id": "req-async-1",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "email": {"status": "Approved", "is_breached": False},
            },
        )
        resp = await async_client.risk.email("async@example.com")
        assert route.called
        assert resp.request_id == "req-async-1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_risk_phone_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={
                "request_id": "req-async-2",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "phone": {"status": "Approved"},
            },
        )
        resp = await async_client.risk.phone("+14155552671")
        assert route.called
        assert resp.request_id == "req-async-2"

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_risk_ip_success(self, async_client: AsyncDidit, base_url: str) -> None:
        route = respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={
                "request_id": "req-async-3",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "ip": {"status": "Approved", "country_mismatch": False},
            },
        )
        resp = await async_client.risk.ip("1.1.1.1")
        assert route.called
        assert resp.request_id == "req-async-3"


# =========================================================================
# Simulation Tests
# =========================================================================


class TestSimulatedRisk:
    def test_simulated_risk_sync(self) -> None:
        sim = SimulatedDidit()
        # Email
        email_res = sim.risk.email("simulated@example.com", country_code="US")
        assert email_res.is_approved is True
        assert email_res.email["email"] == "simulated@example.com"
        assert email_res.is_breached is False

        # Phone
        phone_res = sim.risk.phone("+14155552671")
        assert phone_res.is_approved is True
        assert phone_res.carrier_name == "Simulated Wireless"

        # IP
        ip_res = sim.risk.ip("8.8.8.8", claimed_country="USA")
        assert ip_res.is_approved is True
        assert ip_res.country_mismatch is False

    @pytest.mark.asyncio
    async def test_simulated_risk_async(self) -> None:
        asim = SimulatedAsyncDidit()
        email_res = await asim.risk.email("async-sim@example.com")
        assert email_res.is_approved is True

        phone_res = await asim.risk.phone("+14155552671")
        assert phone_res.is_approved is True

        ip_res = await asim.risk.ip("8.8.8.8")
        assert ip_res.is_approved is True


# =========================================================================
# CLI Subcommand Tests
# =========================================================================


class TestRiskCLI:
    @respx.mock
    def test_cli_risk_email_text(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={
                "request_id": "req-cli-email",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "vendor_data": "vdata-1",
                "email": {
                    "status": "Approved",
                    "email": "alice@example.com",
                    "is_breached": False,
                    "is_disposable": False,
                    "is_undeliverable": False,
                },
            },
        )

        exit_code = main(["risk", "email", "alice@example.com", "--country-code", "US"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Request ID: req-cli-email" in out
        assert "Status:     Approved" in out
        assert "alice@example.com" not in out
        assert "a***e@example.com" in out

    @respx.mock
    def test_cli_risk_email_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={
                "request_id": "req-cli-email-json",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "email": {
                    "status": "Approved",
                    "email": "alice@example.com",
                    "is_breached": False,
                    "is_disposable": False,
                    "is_undeliverable": False,
                },
            },
        )

        exit_code = main(["--json", "risk", "email", "alice@example.com"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        data = json.loads(out)
        assert data["request_id"] == "req-cli-email-json"
        assert data["email"]["email"] == "a***e@example.com"

    @respx.mock
    def test_cli_risk_phone_include_sensitive(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={
                "request_id": "req-cli-phone",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "phone": {
                    "status": "Approved",
                    "full_number": "+14155552671",
                    "carrier": {"name": "Verizon", "type": "mobile"},
                },
            },
        )

        exit_code = main(["--include-sensitive", "risk", "phone", "+14155552671"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "+14155552671" in out

    @respx.mock
    def test_cli_risk_ip_text_and_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={
                "request_id": "req-cli-ip",
                "status": "In Review",
                "created_at": "2026-10-16T10:00:00Z",
                "ip": {
                    "status": "In Review",
                    "ip_address": "8.8.8.8",
                    "ip_country_code": "USA",
                    "country_mismatch": True,
                    "threat": {},
                },
            },
        )

        exit_code = main(["risk", "ip", "8.8.8.8", "--claimed-country", "ESP"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Status:     In Review" in out
        assert "8.8.8.8" not in out
        assert "8.8.*.*" in out

    @respx.mock
    def test_cli_risk_api_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/email/risk/").respond(
            400,
            json={"error": "invalid_email", "message": "Malformed email format"},
        )

        exit_code = main(["risk", "email", "invalid-email"])
        assert exit_code == 1
        out, err = capsys.readouterr()
        assert "Error:" in err

        exit_code_json = main(["--json", "risk", "email", "invalid-email"])
        assert exit_code_json == 1
        out_json, _ = capsys.readouterr()
        assert "API_ERROR" in out_json

    @respx.mock
    def test_cli_risk_domain_exceptions_bubble(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        # 403 maps to DiditPermissionError -> PERMISSION_DENIED
        respx.post(f"{base_url}/email/risk/").respond(
            403,
            json={"error": "permission_denied", "message": "Risk API feature disabled"},
        )
        exit_code = main(["--json", "risk", "email", "test@example.com"])
        assert exit_code == 1
        out, _ = capsys.readouterr()
        assert "PERMISSION_DENIED" in out

    @respx.mock
    def test_cli_risk_phone_api_error_and_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/phone/risk/").respond(
            400,
            json={"error": "invalid_phone", "message": "Malformed phone number"},
        )
        exit_code = main(["risk", "phone", "bad-phone"])
        assert exit_code == 1
        _, err = capsys.readouterr()
        assert "Error:" in err

        respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={
                "request_id": "req-phone-json",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "phone": {"full_number": "+14155552671"},
            },
        )
        exit_code_json = main(["--json", "risk", "phone", "+14155552671"])
        assert exit_code_json == 0
        out, _ = capsys.readouterr()
        assert "req-phone-json" in out

    @respx.mock
    def test_cli_risk_phone_text_branches(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={
                "request_id": "req-phone-full",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "vendor_data": "vdata-phone",
                "phone": {
                    "full_number": "+14155552671",
                    "carrier": {"name": "T-Mobile"},
                    "is_disposable": False,
                    "is_virtual": True,
                },
            },
        )
        exit_code = main(["risk", "phone", "+14155552671"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Carrier:    T-Mobile" in out
        assert "Disposable: False" in out
        assert "Virtual:    True" in out
        assert "Vendor Data: vdata-phone" in out

    @respx.mock
    def test_cli_risk_ip_api_error_and_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/ip/risk/").respond(
            400,
            json={"error": "invalid_ip", "message": "Malformed IP address"},
        )
        exit_code = main(["risk", "ip", "bad-ip"])
        assert exit_code == 1
        _, err = capsys.readouterr()
        assert "Error:" in err

        respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={
                "request_id": "req-ip-json",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "ip": {"ip_address": "8.8.8.8"},
            },
        )
        exit_code_json = main(["--json", "risk", "ip", "8.8.8.8"])
        assert exit_code_json == 0
        out, _ = capsys.readouterr()
        assert "req-ip-json" in out

    @respx.mock
    def test_cli_risk_ip_text_branches(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={
                "request_id": "req-ip-branches",
                "status": "In Review",
                "created_at": "2026-10-16T10:00:00Z",
                "vendor_data": "vdata-ip",
                "ip": {
                    "ip_address": "8.8.8.8",
                    "ip_country_code": "ESP",
                    "country_mismatch": True,
                    "is_vpn_or_tor": True,
                    "is_data_center": True,
                },
            },
        )
        exit_code = main(["--include-sensitive", "risk", "ip", "8.8.8.8"])
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Country:    ESP" in out
        assert "Mismatch:   True" in out
        assert "VPN/Tor:    True" in out
        assert "Vendor Data: vdata-ip" in out
        assert "8.8.8.8" in out

    @respx.mock
    def test_cli_risk_minimal_text_branches(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], base_url: str
    ) -> None:
        monkeypatch.setenv("DIDIT_API_KEY", "cli_test_key")
        # Minimal email
        respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={
                "request_id": "req-min-email",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "email": {},
            },
        )
        assert main(["risk", "email", "min@example.com"]) == 0
        out_email, _ = capsys.readouterr()
        assert "Breached:" not in out_email
        assert "Disposable:" not in out_email
        assert "Vendor Data:" not in out_email

        # Minimal phone
        respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={
                "request_id": "req-min-phone",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "phone": {},
            },
        )
        assert main(["risk", "phone", "+14155552671"]) == 0
        out_phone, _ = capsys.readouterr()
        assert "Carrier:" not in out_phone
        assert "Disposable:" not in out_phone
        assert "Virtual:" not in out_phone
        assert "Vendor Data:" not in out_phone

        # Minimal ip
        respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={
                "request_id": "req-min-ip",
                "status": "Approved",
                "created_at": "2026-10-16T10:00:00Z",
                "ip": {},
            },
        )
        assert main(["risk", "ip", "8.8.8.8"]) == 0
        out_ip, _ = capsys.readouterr()
        assert "Country:" not in out_ip
        assert "Mismatch:" not in out_ip
        assert "VPN/Tor:" not in out_ip
        assert "DataCenter:" not in out_ip
        assert "Vendor Data:" not in out_ip


class TestRiskEdgeCasesAndBranches:
    def test_mask_device_id_branches(self) -> None:
        from didit.models.risk import _mask_device_id

        assert _mask_device_id(None) is None
        assert _mask_device_id("short") == "***"
        assert _mask_device_id("dev-1234567") == "dev***67"

    def test_model_redacted_dump_with_none_fields(self) -> None:
        signals = RiskSignals()
        dump = signals.redacted_dump()
        assert dump["ip"] is None
        assert dump["device_id"] is None

        # EmailRiskRequest with None signals and RiskSignals
        req_none = EmailRiskRequest(email="a@b.com", signals=None)
        assert req_none.redacted_dump()["signals"] is None

        req_sig = EmailRiskRequest(email="a@b.com", signals=RiskSignals(ip="1.2.3.4"))
        assert req_sig.redacted_dump()["signals"]["ip"] == "1.2.*.*"

        # EmailRiskResponse with missing/empty email dict and non-dict email
        resp_no_email = EmailRiskResponse(
            request_id="r1", status="Approved", created_at="now", email={}
        )
        assert resp_no_email.is_breached is None
        assert resp_no_email.is_disposable is None
        assert resp_no_email.is_undeliverable is None
        assert resp_no_email.redacted_dump()["email"] == {}

        resp_none_email = EmailRiskResponse.model_construct(
            request_id="r1", status="Approved", created_at="now", email=None
        )
        assert resp_none_email.redacted_dump()["email"] is None

        # PhoneRiskRequest with RiskSignals
        phone_req_sig = PhoneRiskRequest(
            phone_number="+12345678", signals=RiskSignals(ip="1.2.3.4")
        )
        assert phone_req_sig.redacted_dump()["signals"]["ip"] == "1.2.*.*"

        # PhoneRiskResponse with empty phone or non-dict carrier
        # or only phone_number / only full_number
        phone_resp = PhoneRiskResponse(
            request_id="r2",
            status="Approved",
            created_at="now",
            phone={"carrier": "invalid_carrier"},
        )
        assert phone_resp.carrier_name is None
        assert phone_resp.is_disposable is None
        assert phone_resp.is_virtual is None
        assert phone_resp.redacted_dump()["phone"] == {"carrier": "invalid_carrier"}

        phone_resp_none = PhoneRiskResponse.model_construct(
            request_id="r2", status="Approved", created_at="now", phone=None
        )
        assert phone_resp_none.redacted_dump()["phone"] is None

        phone_resp_only_nat = PhoneRiskResponse(
            request_id="r2",
            status="Approved",
            created_at="now",
            phone={"phone_number": "4155552671"},
        )
        assert phone_resp_only_nat.redacted_dump()["phone"]["phone_number"] == "415***71"

        phone_resp_only_full = PhoneRiskResponse(
            request_id="r2",
            status="Approved",
            created_at="now",
            phone={"full_number": "+14155552671"},
        )
        assert phone_resp_only_full.redacted_dump()["phone"]["full_number"] == "+14***71"

        # IPRiskResponse with empty ip and non-dict ip
        ip_resp = IPRiskResponse(request_id="r3", status="Approved", created_at="now", ip={})
        assert ip_resp.is_vpn_or_tor is None
        assert ip_resp.is_data_center is None
        assert ip_resp.country_mismatch is None
        assert ip_resp.ip_country_code is None
        assert ip_resp.redacted_dump()["ip"] == {}

        ip_resp_none = IPRiskResponse.model_construct(
            request_id="r3", status="Approved", created_at="now", ip=None
        )
        assert ip_resp_none.redacted_dump()["ip"] is None

    def test_build_signals_payload_branches(self) -> None:
        from didit.resources.risk import _build_signals_payload

        assert _build_signals_payload(None) is None
        assert _build_signals_payload({"ip": "1.1.1.1"}) == {"ip": "1.1.1.1"}
        with pytest.raises(TypeError, match="signals must be a RiskSignals or dict"):
            _build_signals_payload("invalid_type")  # type: ignore[arg-type]

    def test_resources_init_with_raw_httpx(self, base_url: str) -> None:
        import httpx

        from didit.resources.risk import AsyncRiskResource, RiskResource

        with httpx.Client(base_url=base_url) as raw_client:
            res = RiskResource(raw_client)
            assert res._http is raw_client

        raw_async = httpx.AsyncClient(base_url=base_url)
        ares = AsyncRiskResource(raw_async)
        assert ares._http is raw_async

    @respx.mock
    def test_sync_risk_all_optional_params(self, client: Didit, base_url: str) -> None:
        respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={"request_id": "r-phone", "status": "Approved", "created_at": "now", "phone": {}},
        )
        respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={"request_id": "r-ip", "status": "Approved", "created_at": "now", "ip": {}},
        )

        p = client.risk.phone(
            "+1234567890",
            country_code="US",
            signals=RiskSignals(ip="1.1.1.1"),
            vendor_data="vd",
            metadata={"meta": 1},
            enable_social=True,
        )
        assert p.request_id == "r-phone"

        ip = client.risk.ip(
            "1.2.3.4",
            claimed_country="ESP",
            user_agent="agent",
            vendor_data="vd",
            metadata={"meta": 1},
        )
        assert ip.request_id == "r-ip"

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_risk_validations_and_optional_params(
        self, async_client: AsyncDidit, base_url: str
    ) -> None:
        with pytest.raises(ValueError, match="email must not be empty"):
            await async_client.risk.email("")

        with pytest.raises(ValueError, match="phone_number must not be empty"):
            await async_client.risk.phone("")

        with pytest.raises(ValueError, match="ip_address must not be empty"):
            await async_client.risk.ip("")

        respx.post(f"{base_url}/email/risk/").respond(
            200,
            json={"request_id": "ra-email", "status": "Approved", "created_at": "now", "email": {}},
        )
        respx.post(f"{base_url}/phone/risk/").respond(
            200,
            json={"request_id": "ra-phone", "status": "Approved", "created_at": "now", "phone": {}},
        )
        respx.post(f"{base_url}/ip/risk/").respond(
            200,
            json={"request_id": "ra-ip", "status": "Approved", "created_at": "now", "ip": {}},
        )

        em = await async_client.risk.email(
            "test@example.com",
            country_code="US",
            signals={"ip": "1.1.1.1"},
            vendor_data="vd",
            metadata={"m": 1},
            enable_social=True,
        )
        assert em.request_id == "ra-email"

        ph = await async_client.risk.phone(
            "+14155552671",
            country_code="US",
            signals=RiskSignals(ip="1.1.1.1"),
            vendor_data="vd",
            metadata={"m": 1},
            enable_social=True,
        )
        assert ph.request_id == "ra-phone"

        ip = await async_client.risk.ip(
            "1.2.3.4",
            claimed_country="ESP",
            user_agent="agent",
            vendor_data="vd",
            metadata={"m": 1},
        )
        assert ip.request_id == "ra-ip"

    def test_simulation_validations_and_formats(self) -> None:
        sim = SimulatedDidit()
        with pytest.raises(ValueError, match="email must not be empty"):
            sim.risk.email("   ")

        with pytest.raises(ValueError, match="phone_number must not be empty"):
            sim.risk.phone("")

        with pytest.raises(ValueError, match="ip_address must not be empty"):
            sim.risk.ip("")

        # phone number without leading +
        p = sim.risk.phone("14155552671")
        assert p.phone["full_number"] == "+14155552671"
        assert p.phone["phone_number"] == "14155552671"

        # ip with claimed_country None
        ip = sim.risk.ip("8.8.8.8", claimed_country=None)
        assert ip.ip["ip_country_code"] == "USA"
