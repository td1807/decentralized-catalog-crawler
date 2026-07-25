"""
Networking layer.

Deliberately narrow responsibility: given a URL, return raw bytes. It knows
nothing about manifests, signatures or databases. That separation is what lets
the tests run entirely offline - the test suite points the crawler at
``file://`` URLs and exercises the exact same code path as a real HTTPS crawl.

Three defensive behaviours are built in:

1. TIMEOUTS. A provider whose server accepts the connection and then goes
   silent must not hang the crawler forever.

2. BOUNDED RETRIES WITH BACKOFF. Transient failures (DNS blip, 503 from a CDN)
   are retried a few times with an increasing pause. Permanent failures such as
   HTTP 404 are *not* retried, because retrying cannot change the outcome.

3. A DOWNLOAD SIZE CAP. We stream the response and abort once it exceeds
   ``max_download_bytes``. Without this, a malicious or broken provider could
   exhaust our memory with an endless response - a denial-of-service risk that
   exists *before* any signature check can possibly help us, because we have to
   receive the bytes before we can verify them.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

import requests

from .config import CrawlerSettings
from .errors import FetchError

# HTTP statuses where a retry has a realistic chance of succeeding.
RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


class Fetcher:
    """Retrieves raw bytes from ``http(s)://``, ``file://`` or plain local paths."""

    def __init__(self, settings: CrawlerSettings, session: Optional[requests.Session] = None):
        self._settings = settings
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": "decentralized-catalog-crawler/1.0"})

    # ------------------------------------------------------------------ public

    def fetch(self, url: str) -> bytes:
        """Return the raw bytes at ``url``, or raise FetchError."""
        scheme = urlparse(url).scheme.lower()
        if scheme in ("http", "https"):
            return self._fetch_http(url)
        if scheme == "file":
            return self._fetch_file(url)
        if scheme == "":
            return self._read_path(Path(url))
        raise FetchError(f"Unsupported URL scheme '{scheme}' in {url}")

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "Fetcher":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ----------------------------------------------------------------- private

    def _fetch_http(self, url: str) -> bytes:
        last_error: Optional[str] = None

        for attempt in range(1, self._settings.max_retries + 1):
            try:
                with self._session.get(
                    url,
                    timeout=self._settings.request_timeout_seconds,
                    stream=True,
                ) as response:
                    if response.status_code in RETRYABLE_STATUS_CODES:
                        last_error = f"HTTP {response.status_code}"
                        self._sleep_before_retry(attempt)
                        continue
                    if response.status_code >= 400:
                        # Permanent: 404, 403, 401... retrying is pointless.
                        raise FetchError(f"HTTP {response.status_code} while fetching {url}")
                    return self._read_capped(response, url)

            except requests.Timeout:
                last_error = "request timed out"
                self._sleep_before_retry(attempt)
            except requests.ConnectionError as exc:
                last_error = f"connection error: {exc}"
                self._sleep_before_retry(attempt)
            except requests.RequestException as exc:
                raise FetchError(f"Request to {url} failed: {exc}") from exc

        raise FetchError(
            f"Giving up on {url} after {self._settings.max_retries} attempts "
            f"(last error: {last_error})"
        )

    def _read_capped(self, response: requests.Response, url: str) -> bytes:
        """Stream the body, aborting if it grows past the configured cap."""
        limit = self._settings.max_download_bytes

        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    raise FetchError(
                        f"{url} declares {declared} bytes, above the "
                        f"{limit} byte limit"
                    )
            except ValueError:
                pass  # Header was garbage; the streaming check below still protects us.

        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            chunks.extend(chunk)
            if len(chunks) > limit:
                raise FetchError(f"{url} exceeded the {limit} byte download limit")
        return bytes(chunks)

    def _fetch_file(self, url: str) -> bytes:
        parsed = urlparse(url)
        # url2pathname handles the platform differences, including Windows
        # drive letters in URLs such as file:///C:/data/manifest.json
        local = url2pathname(unquote(parsed.path))
        if parsed.netloc and parsed.netloc not in ("", "localhost"):
            local = f"//{parsed.netloc}{local}"
        return self._read_path(Path(local))

    def _read_path(self, path: Path) -> bytes:
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise FetchError(f"Could not read local file {path}: {exc}") from exc

        if size > self._settings.max_download_bytes:
            raise FetchError(
                f"{path} is {size} bytes, above the "
                f"{self._settings.max_download_bytes} byte limit"
            )
        try:
            return path.read_bytes()
        except OSError as exc:
            raise FetchError(f"Could not read local file {path}: {exc}") from exc

    def _sleep_before_retry(self, attempt: int) -> None:
        if attempt < self._settings.max_retries:
            # Exponential backoff: 0.5s, 1s, 2s, ... so we do not hammer a
            # provider that is already struggling.
            time.sleep(self._settings.retry_backoff_seconds * (2 ** (attempt - 1)))
