"""Data models for Didit Standalone Risk APIs (Email, Phone, IP)."""

from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _mask_email(email: str | None) -> str | None:
    """Mask email address to preserve user privacy in logs and representations."""
    if email is None:
        return None
    cleaned = email.strip()
    if not cleaned or "@" not in cleaned:
        return "***"
    local, domain = cleaned.split("@", 1)
    if len(local) <= 2:
        masked_local = f"{local[0]}***" if local else "***"
    else:
        masked_local = f"{local[0]}***{local[-1]}"
    return f"{masked_local}@{domain}"


def _mask_phone(phone: str | None) -> str | None:
    """Mask phone number to preserve user privacy in logs and representations."""
    if phone is None:
        return None
    cleaned = phone.strip()
    if not cleaned or len(cleaned) <= 4:
        return "***"
    return f"{cleaned[:3]}***{cleaned[-2:]}"


def _mask_ip(ip: str | None) -> str | None:
    """Mask IPv4 or IPv6 address to preserve network privacy in logs and representations."""
    if ip is None:
        return None
    cleaned = ip.strip()
    if not cleaned:
        return "***"
    if ":" in cleaned:
        parts = cleaned.split(":")
        return f"{parts[0]}:***:{parts[-1]}"
    parts = cleaned.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "***"


def _mask_device_id(device_id: str | None) -> str | None:
    """Mask hardware or app device identifier."""
    if device_id is None:
        return None
    cleaned = device_id.strip()
    if len(cleaned) <= 6:
        return "***"
    return f"{cleaned[:3]}***{cleaned[-2:]}"


class RiskSignals(BaseModel):
    """Optional client device and network context observed by the calling application."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    ip: str | None = Field(
        default=None, description="IPv4 or IPv6 address observed for the end user"
    )
    device_id: str | None = Field(
        default=None, description="Stable device identifier (e.g. ANDROID_ID, identifierForVendor)"
    )
    device_platform: str | None = Field(
        default=None, description="Platform of end user device (android, ios, ipados, tvos, web)"
    )
    device_model: str | None = Field(default=None, description="Reported device model")
    os_version: str | None = Field(default=None, description="Operating system version")
    app_version: str | None = Field(default=None, description="Calling application version")
    user_agent: str | None = Field(default=None, description="Browser or app user agent")

    def __repr__(self) -> str:
        return (
            f"RiskSignals(device_platform={self.device_platform!r}, "
            f"device_model={self.device_model!r}, "
            f"os_version={self.os_version!r}, "
            f"app_version={self.app_version!r}, "
            f"ip={_mask_ip(self.ip)!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump with IP and device ID masked."""
        data = self.model_dump()
        if self.ip is not None:
            data["ip"] = _mask_ip(self.ip)
        if self.device_id is not None:
            data["device_id"] = _mask_device_id(self.device_id)
        return data


class EmailRiskRequest(BaseModel):
    """Payload to risk-score an email address without OTP verification."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    email: str = Field(..., description="Email address to score")
    country_code: str | None = Field(
        default=None, description="Optional ISO 3166-1 country hint for intelligence coverage"
    )
    signals: RiskSignals | dict[str, Any] | None = Field(
        default=None, description="Observed device and network signals"
    )
    vendor_data: str | None = Field(
        default=None, description="Stable external reference identifier"
    )
    metadata: dict[str, Any] | None = Field(
        default=None, description="Optional non-sensitive customer metadata"
    )
    enable_social: bool = Field(
        default=False, description="When true, query online platform footprint"
    )

    def __repr__(self) -> str:
        return (
            f"EmailRiskRequest(email={_mask_email(self.email)!r}, "
            f"country_code={self.country_code!r}, "
            f"enable_social={self.enable_social!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump with email address masked."""
        data = self.model_dump()
        data["email"] = _mask_email(self.email)
        if isinstance(self.signals, RiskSignals):
            data["signals"] = self.signals.redacted_dump()
        return data


class EmailRiskResponse(BaseModel):
    """Evaluation result for an email risk assessment lookup."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    request_id: str = Field(..., description="Unique API session ID created for this request")
    status: str = Field(..., description="Final decision outcome (Approved, In Review, Declined)")
    created_at: str = Field(..., description="ISO 8601 timestamp of evaluation")
    vendor_data: str | None = Field(default=None, description="Echo of provided vendor_data")
    metadata: dict[str, Any] | None = Field(default=None, description="Echo of provided metadata")
    email: dict[str, Any] = Field(
        default_factory=dict, description="Detailed email risk intelligence and deliverability"
    )

    @property
    def is_approved(self) -> bool:
        """Return True if decision status is Approved."""
        return self.status.lower() == "approved"

    @property
    def is_breached(self) -> bool | None:
        """Return True if email was identified in credential breaches."""
        return self.email.get("is_breached")

    @property
    def is_disposable(self) -> bool | None:
        """Return True if email domain belongs to a throwaway/disposable provider."""
        return self.email.get("is_disposable")

    @property
    def is_undeliverable(self) -> bool | None:
        """Return True if address was found undeliverable."""
        return self.email.get("is_undeliverable")

    def __repr__(self) -> str:
        return (
            f"EmailRiskResponse(request_id={self.request_id!r}, "
            f"status={self.status!r}, "
            f"created_at={self.created_at!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump redacting email PII."""
        data = copy.deepcopy(self.model_dump())
        if "email" in data and isinstance(data["email"], dict):
            raw_email = data["email"].get("email")
            if raw_email:
                data["email"]["email"] = _mask_email(raw_email)
        return data


class PhoneRiskRequest(BaseModel):
    """Payload to risk-score a phone number without OTP verification."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    phone_number: str = Field(..., description="Phone number to score in E.164 format")
    country_code: str | None = Field(
        default=None, description="Optional ISO 3166-1 country hint for intelligence coverage"
    )
    signals: RiskSignals | dict[str, Any] | None = Field(
        default=None, description="Observed device and network signals"
    )
    vendor_data: str | None = Field(
        default=None, description="Stable external reference identifier"
    )
    metadata: dict[str, Any] | None = Field(
        default=None, description="Optional non-sensitive customer metadata"
    )
    enable_social: bool = Field(
        default=False, description="When true, query online platform footprint"
    )

    def __repr__(self) -> str:
        return (
            f"PhoneRiskRequest(phone_number={_mask_phone(self.phone_number)!r}, "
            f"country_code={self.country_code!r}, "
            f"enable_social={self.enable_social!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump with phone number masked."""
        data = self.model_dump()
        data["phone_number"] = _mask_phone(self.phone_number)
        if isinstance(self.signals, RiskSignals):
            data["signals"] = self.signals.redacted_dump()
        return data


class PhoneRiskResponse(BaseModel):
    """Evaluation result for a phone risk assessment lookup."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    request_id: str = Field(..., description="Unique API session ID created for this request")
    status: str = Field(..., description="Final decision outcome (Approved, In Review, Declined)")
    created_at: str = Field(..., description="ISO 8601 timestamp of evaluation")
    vendor_data: str | None = Field(default=None, description="Echo of provided vendor_data")
    metadata: dict[str, Any] | None = Field(default=None, description="Echo of provided metadata")
    phone: dict[str, Any] = Field(
        default_factory=dict, description="Detailed phone risk intelligence, carrier, and line type"
    )

    @property
    def is_approved(self) -> bool:
        """Return True if decision status is Approved."""
        return self.status.lower() == "approved"

    @property
    def is_disposable(self) -> bool | None:
        """Return True if phone number is a burner or disposable number."""
        return self.phone.get("is_disposable")

    @property
    def is_virtual(self) -> bool | None:
        """Return True if line type is virtual (VOIP, ISP, or VPN)."""
        return self.phone.get("is_virtual")

    @property
    def carrier_name(self) -> str | None:
        """Return resolved carrier name if present."""
        carrier = self.phone.get("carrier")
        if isinstance(carrier, dict):
            return carrier.get("name")
        return None

    def __repr__(self) -> str:
        return (
            f"PhoneRiskResponse(request_id={self.request_id!r}, "
            f"status={self.status!r}, "
            f"created_at={self.created_at!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump redacting phone PII."""
        data = copy.deepcopy(self.model_dump())
        if "phone" in data and isinstance(data["phone"], dict):
            raw_phone = data["phone"].get("phone_number")
            if raw_phone:
                data["phone"]["phone_number"] = _mask_phone(raw_phone)
            full_phone = data["phone"].get("full_number")
            if full_phone:
                data["phone"]["full_number"] = _mask_phone(full_phone)
        return data


class IPRiskRequest(BaseModel):
    """Payload to risk-score an IP address."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    ip_address: str = Field(..., description="IPv4 or IPv6 address to score")
    claimed_country: str | None = Field(
        default=None, description="Optional ISO country claimed by user for mismatch check"
    )
    user_agent: str | None = Field(
        default=None, description="User agent string observed by backend"
    )
    vendor_data: str | None = Field(
        default=None, description="Stable external reference identifier"
    )
    metadata: dict[str, Any] | None = Field(
        default=None, description="Optional non-sensitive customer metadata"
    )

    def __repr__(self) -> str:
        return (
            f"IPRiskRequest(ip_address={_mask_ip(self.ip_address)!r}, "
            f"claimed_country={self.claimed_country!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump with IP address masked."""
        data = self.model_dump()
        data["ip_address"] = _mask_ip(self.ip_address)
        return data


class IPRiskResponse(BaseModel):
    """Evaluation result for an IP risk assessment lookup."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    request_id: str = Field(..., description="Unique API session ID created for this request")
    status: str = Field(..., description="Final decision outcome (Approved or In Review)")
    created_at: str = Field(..., description="ISO 8601 timestamp of evaluation")
    vendor_data: str | None = Field(default=None, description="Echo of provided vendor_data")
    metadata: dict[str, Any] | None = Field(default=None, description="Echo of provided metadata")
    ip: dict[str, Any] = Field(
        default_factory=dict, description="Detailed IP geolocation, ASN, and threat analysis"
    )

    @property
    def is_approved(self) -> bool:
        """Return True if decision status is Approved."""
        return self.status.lower() == "approved"

    @property
    def is_vpn_or_tor(self) -> bool | None:
        """Return True if IP is associated with VPN or Tor infrastructure."""
        return self.ip.get("is_vpn_or_tor")

    @property
    def is_data_center(self) -> bool | None:
        """Return True if IP belongs to data center or hosting provider."""
        return self.ip.get("is_data_center")

    @property
    def country_mismatch(self) -> bool | None:
        """Return True if resolved country conflicts with claimed country."""
        return self.ip.get("country_mismatch")

    @property
    def ip_country_code(self) -> str | None:
        """Return resolved country code for IP address."""
        return self.ip.get("ip_country_code")

    def __repr__(self) -> str:
        return (
            f"IPRiskResponse(request_id={self.request_id!r}, "
            f"status={self.status!r}, "
            f"created_at={self.created_at!r})"
        )

    __str__ = __repr__

    def redacted_dump(self) -> dict[str, Any]:
        """Privacy-safe dictionary dump redacting IP address."""
        data = copy.deepcopy(self.model_dump())
        if "ip" in data and isinstance(data["ip"], dict):
            raw_ip = data["ip"].get("ip_address")
            if raw_ip:
                data["ip"]["ip_address"] = _mask_ip(raw_ip)
        return data
