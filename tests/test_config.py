"""Tests for DiditConfig and environment resolution."""

import os
from unittest.mock import patch

import pytest

from didit.config import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    DiditConfig,
)
from didit.errors import DiditConfigurationError


class TestDiditConfig:
    def test_direct_initialization(self) -> None:
        cfg = DiditConfig(
            api_key="test_key",
            base_url="https://custom.api.com/",
            timeout=15.0,
            max_retries=3,
            webhook_secret="whsec_123",
        )
        assert cfg.api_key == "test_key"
        assert cfg.base_url == "https://custom.api.com/"
        assert cfg.timeout == 15.0
        assert cfg.max_retries == 3
        assert cfg.webhook_secret == "whsec_123"

    def test_from_env_all_defaults(self) -> None:
        with patch.dict(os.environ, {"DIDIT_API_KEY": "env_key"}, clear=True):
            cfg = DiditConfig.from_env()
            assert cfg.api_key == "env_key"
            assert cfg.base_url == DEFAULT_BASE_URL
            assert cfg.timeout == DEFAULT_TIMEOUT
            assert cfg.max_retries == DEFAULT_MAX_RETRIES
            assert cfg.webhook_secret is None

    def test_from_env_missing_api_key_raises_error(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(DiditConfigurationError, match="Missing Didit API key"),
        ):
            DiditConfig.from_env()

    def test_from_env_custom_variables(self) -> None:
        env = {
            "DIDIT_API_KEY": "env_key",
            "DIDIT_BASE_URL": "https://staging.didit.me/v3/",
            "DIDIT_TIMEOUT": "45.5",
            "DIDIT_MAX_RETRIES": "5",
            "DIDIT_WEBHOOK_SECRET": "sec_env",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = DiditConfig.from_env()
            assert cfg.api_key == "env_key"
            assert cfg.base_url == "https://staging.didit.me/v3"  # stripped trailing slash
            assert cfg.timeout == 45.5
            assert cfg.max_retries == 5
            assert cfg.webhook_secret == "sec_env"

    def test_from_env_explicit_kwargs_override_env(self) -> None:
        env = {"DIDIT_API_KEY": "env_key", "DIDIT_TIMEOUT": "10"}
        with patch.dict(os.environ, env, clear=True):
            cfg = DiditConfig.from_env(api_key="override_key", timeout=25.0)
            assert cfg.api_key == "override_key"
            assert cfg.timeout == 25.0
