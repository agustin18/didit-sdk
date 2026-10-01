"""Live Upstream OpenAPI Contract Drift Detection.

Connects to Didit's official public OpenAPI specification at https://docs.didit.me/openapi-25.json
and performs semantic validation of the supported perimeter.

Execution:
- By default (in regular offline development and PR CI), this test suite skips to preserve
  deterministic, offline-capable test runs.
- Set environment variable `DIDIT_CHECK_UPSTREAM_DRIFT=1`
  (or run in scheduled / workflow_dispatch CI) to execute the live semantic drift audit
  against Didit's cloud documentation.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest

from didit.models.enums import (
    CURRENT_DIDIT_LANGUAGES,
    CallbackMethod,
    Language,
    SessionStatus,
)
from didit.models.session import ResubmitFeature

LIVE_OPENAPI_URL = "https://docs.didit.me/openapi-25.json"


@pytest.fixture(scope="module")
def live_openapi_spec() -> dict[str, Any]:
    """Fetch live Didit OpenAPI specification from official docs URL."""
    if os.environ.get("DIDIT_CHECK_UPSTREAM_DRIFT") != "1":
        pytest.skip(
            "Live upstream OpenAPI drift detection skipped. "
            "Set DIDIT_CHECK_UPSTREAM_DRIFT=1 to run against docs.didit.me"
        )

    try:
        resp = httpx.get(LIVE_OPENAPI_URL, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        pytest.fail(
            f"Failed to fetch live Didit OpenAPI specification from {LIVE_OPENAPI_URL}: {exc}"
        )


def test_live_upstream_spec_metadata(live_openapi_spec: dict[str, Any]) -> None:
    """Verify live OpenAPI specification metadata."""
    assert live_openapi_spec.get("openapi") == "3.0.0"
    info = live_openapi_spec.get("info", {})
    assert "Didit" in info.get("title", "")
    assert "x-api-key" in info.get("description", "")


def test_live_upstream_supported_paths_exist(live_openapi_spec: dict[str, Any]) -> None:
    """Verify all supported perimeter endpoints exist in live upstream OpenAPI spec."""
    paths = live_openapi_spec.get("paths", {})

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
        assert path in paths, f"Live upstream missing supported endpoint: {path}"
        assert method in paths[path], f"Live upstream missing HTTP method '{method}' for '{path}'"


def test_live_upstream_create_session_contract(live_openapi_spec: dict[str, Any]) -> None:
    """Verify live create session schema, required fields, and callback_method."""
    paths = live_openapi_spec.get("paths", {})
    create_schema = paths["/v3/session/"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]

    assert set(create_schema.get("required", [])) == {"workflow_id"}

    props = create_schema.get("properties", {})
    assert "workflow_id" in props
    assert "vendor_data" in props
    assert "callback" in props
    assert "callback_method" in props
    assert "metadata" in props
    assert "language" in props

    # callback_method enum choices
    cb_enum = set(props["callback_method"].get("enum", []))
    assert cb_enum == {m.value for m in CallbackMethod}


def test_live_upstream_update_status_contract(live_openapi_spec: dict[str, Any]) -> None:
    """Verify live update-status schema and 200 response shape."""
    paths = live_openapi_spec.get("paths", {})
    update_op = paths["/v3/session/{sessionId}/update-status/"]["patch"]

    # Request body
    body_schema = update_op["requestBody"]["content"]["application/json"]["schema"]
    assert set(body_schema.get("required", [])) == {"new_status"}

    # Resubmit nodes schema
    nodes_prop = body_schema["properties"]["nodes_to_resubmit"]
    assert nodes_prop["type"] == "array"
    assert set(nodes_prop["items"].get("required", [])) == {"node_id", "feature"}

    upstream_features = set(nodes_prop["items"]["properties"]["feature"]["enum"])
    sdk_features = {f.value for f in ResubmitFeature}
    for feat in upstream_features:
        assert feat in sdk_features, f"Live upstream added new feature choice: {feat}"

    # Response 200 schema contains only session_id
    resp_200 = update_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert "session_id" in resp_200.get("properties", {})
    assert "status" not in resp_200.get("properties", {})


def test_live_upstream_decision_status_enum(live_openapi_spec: dict[str, Any]) -> None:
    """Verify live decision statuses match SDK SessionStatus enum."""
    paths = live_openapi_spec.get("paths", {})
    decision_schema = paths["/v3/session/{sessionId}/decision/"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]

    upstream_statuses = set(decision_schema["properties"]["status"]["enum"])
    sdk_statuses = {s.value for s in SessionStatus}
    assert sdk_statuses == upstream_statuses, (
        f"Live upstream statuses diverged: {upstream_statuses} vs SDK: {sdk_statuses}"
    )


def test_live_upstream_languages_exact_match(live_openapi_spec: dict[str, Any]) -> None:
    """Verify live OpenAPI languages match CURRENT_DIDIT_LANGUAGES."""
    paths = live_openapi_spec.get("paths", {})
    create_schema = paths["/v3/session/"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]

    upstream_langs = set(create_schema["properties"]["language"]["enum"])
    assert upstream_langs == CURRENT_DIDIT_LANGUAGES
    assert {"eu", "gl"}.issubset({lang.value for lang in Language})
