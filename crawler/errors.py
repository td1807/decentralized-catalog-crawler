"""
Typed errors for the crawler.

Why a custom hierarchy instead of raising bare ValueError everywhere?
Because the orchestrator needs to make different decisions depending on *why*
something failed:

  - A FetchError is usually transient (provider's CDN hiccuped) -> retry later,
    keep the provider enabled.
  - A VerificationError is a trust failure -> stop processing this provider
    immediately and do NOT write anything to the database. This is the "fail
    closed" principle: when security checks fail, we refuse the data rather than
    accepting it with a warning.
  - A ConfigError is an operator mistake -> fail fast at startup.
"""


class CrawlerError(Exception):
    """Base class for every error this application raises deliberately."""


class ConfigError(CrawlerError):
    """The configuration file is missing, malformed, or logically invalid."""


class FetchError(CrawlerError):
    """A remote file could not be retrieved (network, HTTP status, size limit)."""


class VerificationError(CrawlerError):
    """
    A cryptographic or structural trust check failed.

    Raised for: bad signature, unknown key id, digest mismatch, provider
    identity mismatch, or a version that would roll the catalog backwards.
    """


class StorageError(CrawlerError):
    """The storage backend could not complete an operation."""
