"""Automated OpenAPI contract drift tests against official Didit OpenAPI V3 specification.

Ensures that didit-sdk data models, HTTP endpoints, parameters, enums,
and payload schemas strictly match upstream Didit API specifications (docs.didit.me).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from didit.models.enums import (
    CURRENT_DIDIT_LANGUAGES,
    CallbackMethod,
    Language,
    SessionStatus,
)
from didit.models.session import (
    ContactDetails,
    CreateSessionRequest,
    ExpectedDetails,
    ResubmitFeature,
    ResubmitNode,
    UpdateSessionStatusRequest,
    UpdateSessionStatusResponse,
)


@pytest.fixture(scope="module")
def openapi_spec() -> dict[str, Any]:
    """Load frozen official Didit OpenAPI V3 specification snapshot."""
    spec_path = Path(__file__).parent / "contracts" / "openapi_v3.json"
    assert spec_path.exists(), f"OpenAPI contract specification not found at {spec_path}"
    with open(spec_path, encoding="utf-8") as f:
        return json.load(f)


def test_openapi_spec_metadata(openapi_spec: dict[str, Any]) -> None:
    """Verify OpenAPI version and service info match official specification."""
    assert openapi_spec.get("openapi") == "3.0.0"
    info = openapi_spec.get("info", {})
    assert "Didit" in info.get("title", "")
    assert "x-api-key" in info.get("description", "")


def test_openapi_supported_paths_exist(openapi_spec: dict[str, Any]) -> None:
    """Verify all perimeter endpoints supported by didit-sdk exist in OpenAPI spec."""
    paths = openapi_spec.get("paths", {})

    expected_endpoints = {
        "/v3/session/": "post",
        "/v3/sessions/": "get",
        "/v3/session/{sessionId}/decision/": "get",
        "/v3/session/{sessionId}/update-status/": "patch",
        "/v3/session/{sessionId}/generate-pdf/": "get",
        "/v3/session/{sessionId}/sandbox/arm/": "post",
        "/system/healthcheck": "get",
    }

    for path, method in expected_endpoints.items():
        assert path in paths, f"Supported endpoint path '{path}' missing from Didit OpenAPI spec"
        assert method in paths[path], (
            f"HTTP method '{method}' for '{path}' missing from Didit OpenAPI spec"
        )


def test_openapi_create_session_request_schema(openapi_spec: dict[str, Any]) -> None:
    """Verify CreateSessionRequest matches OpenAPI schema properties and required fields."""
    paths = openapi_spec.get("paths", {})
    create_schema = paths["/v3/session/"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]

    # Required fields upstream: exactly ['workflow_id']
    upstream_required = set(create_schema.get("required", []))
    assert upstream_required == {"workflow_id"}

    # SDK model required fields
    sdk_fields = CreateSessionRequest.model_fields
    assert sdk_fields["workflow_id"].is_required() is True
    assert sdk_fields["vendor_data"].is_required() is False

    # Check key upstream properties are supported on SDK model
    upstream_props = create_schema.get("properties", {})
    for prop in [
        "workflow_id",
        "vendor_data",
        "callback",
        "callback_method",
        "metadata",
        "language",
        "contact_details",
        "expected_details",
        "portrait_image",
        "sandbox_scenario",
    ]:
        assert prop in upstream_props, f"Expected property '{prop}' missing in OpenAPI"
        assert prop in sdk_fields, f"Property '{prop}' missing on CreateSessionRequest model"

    # Verify callback_method enum choices
    cb_schema = upstream_props["callback_method"]
    assert set(cb_schema["enum"]) == {m.value for m in CallbackMethod}
    assert cb_schema["default"] == "initiator"

    # Verify metadata supports arbitrary JSON values (dict, list, int, str)
    req_dict = CreateSessionRequest(workflow_id="wf_1", metadata={"key": "val"})
    assert req_dict.metadata == {"key": "val"}
    req_list = CreateSessionRequest(workflow_id="wf_1", metadata=["tag1", 42])
    assert req_list.metadata == ["tag1", 42]
    req_scalar = CreateSessionRequest(workflow_id="wf_1", metadata="simple_string")
    assert req_scalar.metadata == "simple_string"

    contact_props = upstream_props.get("contact_details", {}).get("properties", {})
    for f_name in ["email", "send_notification_emails", "email_lang"]:
        assert f_name in ContactDetails.model_fields
        assert f_name in contact_props

    expected_props = upstream_props.get("expected_details", {}).get("properties", {})
    for f_name in [
        "first_name",
        "last_name",
        "date_of_birth",
        "nationality",
        "identification_number",
    ]:
        assert f_name in ExpectedDetails.model_fields
        assert f_name in expected_props


def test_openapi_update_status_request_schema(openapi_spec: dict[str, Any]) -> None:
    """Verify UpdateSessionStatusRequest matches PATCH /v3/session/{id}/update-status/ schema."""
    paths = openapi_spec.get("paths", {})
    update_schema = paths["/v3/session/{sessionId}/update-status/"]["patch"]["requestBody"][
        "content"
    ]["application/json"]["schema"]

    upstream_required = set(update_schema.get("required", []))
    assert upstream_required == {"new_status"}

    sdk_fields = UpdateSessionStatusRequest.model_fields
    assert sdk_fields["new_status"].is_required() is True

    # Validate nodes_to_resubmit item schema
    nodes_prop = update_schema["properties"]["nodes_to_resubmit"]
    assert nodes_prop["type"] == "array"
    item_schema = nodes_prop["items"]
    assert set(item_schema.get("required", [])) == {"node_id", "feature"}
    assert "node_id" in ResubmitNode.model_fields
    assert "feature" in ResubmitNode.model_fields

    upstream_features = set(item_schema["properties"]["feature"]["enum"])
    sdk_features = {f.value for f in ResubmitFeature}

    # Verify every upstream feature choice is represented in ResubmitFeature
    for feat in upstream_features:
        assert feat in sdk_features, f"Upstream feature '{feat}' missing from ResubmitFeature"


def test_openapi_update_status_200_response_contract(openapi_spec: dict[str, Any]) -> None:
    """Verify 200 response of update-status returns only session_id."""
    paths = openapi_spec.get("paths", {})
    resp_200 = paths["/v3/session/{sessionId}/update-status/"]["patch"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]

    props = resp_200.get("properties", {})
    assert "session_id" in props
    # Upstream documentation specifically states response contains only session_id
    assert "status" not in props

    # SDK UpdateSessionStatusResponse model validation
    resp_obj = UpdateSessionStatusResponse.model_validate(
        {"session_id": "3472fb7c-8f7c-4d1a-9cf4-cf3d74ce1a60"}
    )
    assert resp_obj.session_id == "3472fb7c-8f7c-4d1a-9cf4-cf3d74ce1a60"
    assert resp_obj.status is None


def test_openapi_session_statuses_drift(openapi_spec: dict[str, Any]) -> None:
    """Verify SessionStatus enum values match the 10 official Didit session statuses."""
    paths = openapi_spec.get("paths", {})
    decision_schema = paths["/v3/session/{sessionId}/decision/"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]

    upstream_statuses = set(decision_schema["properties"]["status"]["enum"])
    sdk_statuses = {s.value for s in SessionStatus}

    assert sdk_statuses == upstream_statuses, (
        f"Session status enum mismatch. SDK: {sdk_statuses} vs Upstream: {upstream_statuses}"
    )


def test_openapi_languages_drift(openapi_spec: dict[str, Any]) -> None:
    """Verify Language enum values cover all official Didit OpenAPI supported language codes."""
    paths = openapi_spec.get("paths", {})
    create_schema = paths["/v3/session/"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]

    upstream_langs = set(create_schema["properties"]["language"]["enum"])
    # CURRENT_DIDIT_LANGUAGES has exact set equality with the 54 official OpenAPI languages
    assert upstream_langs == CURRENT_DIDIT_LANGUAGES
    assert len(CURRENT_DIDIT_LANGUAGES) == 54

    # Language enum also retains EU and GL as deprecated legacy compatibility aliases
    assert {"eu", "gl"}.issubset({lang.value for lang in Language})
    assert len(Language) == 56
