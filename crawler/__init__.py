"""Decentralized catalog crawler."""

from .config import Config, CrawlerSettings, ProviderConfig, load_config
from .crawler import Crawler, CrawlReport, ProviderResult
from .errors import (
    ConfigError,
    CrawlerError,
    FetchError,
    StorageError,
    VerificationError,
)
from .fetcher import Fetcher
from .storage import CatalogStore

__version__ = "1.0.0"

__all__ = [
    "Config",
    "CrawlerSettings",
    "ProviderConfig",
    "load_config",
    "Crawler",
    "CrawlReport",
    "ProviderResult",
    "CatalogStore",
    "Fetcher",
    "CrawlerError",
    "ConfigError",
    "FetchError",
    "VerificationError",
    "StorageError",
]
