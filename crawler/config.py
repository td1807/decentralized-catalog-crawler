"""
Configuration loading.

Requirement #1 of the assignment is "no hardcoded URLs". Every provider the
crawler talks to, and every operational knob (timeouts, retry counts, download
size caps, database location), comes from a YAML file supplied at runtime.

Validation happens once, at startup, and raises ConfigError with a precise
message. It is much cheaper to reject a bad config immediately than to discover
the problem halfway through a crawl.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

import yaml

from .errors import ConfigError

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF_SECONDS = 0.5
DEFAULT_MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_DATABASE_PATH = "./data/catalog.db"


@dataclass(frozen=True)
class ProviderConfig:
    """One provider we are willing to crawl."""

    provider_id: str
    manifest_url: str
    enabled: bool = True


@dataclass(frozen=True)
class CrawlerSettings:
    """Global operational settings."""

    database_path: str = DEFAULT_DATABASE_PATH
    request_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES


@dataclass(frozen=True)
class Config:
    settings: CrawlerSettings
    providers: List[ProviderConfig]


def _as_positive_number(raw: Any, key: str, cast) -> Any:
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"crawler.{key} must be a number, got {raw!r}") from None
    if value <= 0:
        raise ConfigError(f"crawler.{key} must be greater than zero")
    return value


def load_config(path: str | os.PathLike[str]) -> Config:
    """Read, parse and validate the YAML configuration file at ``path``."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Configuration file is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Configuration file must contain a YAML mapping at the top level")

    settings = _parse_settings(raw.get("crawler") or {}, config_path)
    providers = _parse_providers(raw.get("providers"))
    return Config(settings=settings, providers=providers)


def _parse_settings(raw: Any, config_path: Path) -> CrawlerSettings:
    if not isinstance(raw, dict):
        raise ConfigError("'crawler' section must be a mapping")

    database_path = raw.get("database_path", DEFAULT_DATABASE_PATH)
    if not isinstance(database_path, str) or not database_path.strip():
        raise ConfigError("crawler.database_path must be a non-empty string")

    # Relative paths are resolved against the config file's own directory, so
    # the crawler behaves the same no matter which folder you launch it from.
    resolved_db = Path(database_path)
    if not resolved_db.is_absolute():
        resolved_db = (config_path.parent / resolved_db).resolve()

    return CrawlerSettings(
        database_path=str(resolved_db),
        request_timeout_seconds=_as_positive_number(
            raw.get("request_timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            "request_timeout_seconds",
            float,
        ),
        max_retries=int(
            _as_positive_number(raw.get("max_retries", DEFAULT_MAX_RETRIES), "max_retries", int)
        ),
        retry_backoff_seconds=_as_positive_number(
            raw.get("retry_backoff_seconds", DEFAULT_RETRY_BACKOFF_SECONDS),
            "retry_backoff_seconds",
            float,
        ),
        max_download_bytes=int(
            _as_positive_number(
                raw.get("max_download_bytes", DEFAULT_MAX_DOWNLOAD_BYTES),
                "max_download_bytes",
                int,
            )
        ),
    )


def _parse_providers(raw: Any) -> List[ProviderConfig]:
    if not isinstance(raw, list) or not raw:
        raise ConfigError("'providers' must be a non-empty list")

    providers: List[ProviderConfig] = []
    seen_ids: set[str] = set()

    for position, entry in enumerate(raw):
        ctx = f"providers[{position}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{ctx} must be a mapping")

        provider_id = entry.get("id")
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise ConfigError(f"{ctx}.id must be a non-empty string")
        if provider_id in seen_ids:
            raise ConfigError(f"{ctx}.id '{provider_id}' is duplicated")
        seen_ids.add(provider_id)

        manifest_url = entry.get("manifest_url")
        if not isinstance(manifest_url, str) or not manifest_url.strip():
            raise ConfigError(f"{ctx}.manifest_url must be a non-empty string")

        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{ctx}.enabled must be true or false")

        providers.append(
            ProviderConfig(
                provider_id=provider_id.strip(),
                manifest_url=manifest_url.strip(),
                enabled=enabled,
            )
        )

    return providers
