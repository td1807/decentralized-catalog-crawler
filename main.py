#!/usr/bin/env python3
"""
Command-line entrypoint.

    python main.py crawl --config config.yaml
    python main.py list  --config config.yaml
    python main.py status --config config.yaml

Exit codes are meaningful so the crawler can be scheduled from cron or a CI
job and monitored without parsing its output:
    0  every enabled provider succeeded
    1  at least one provider failed verification or fetching
    2  the configuration itself was invalid
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from crawler import CatalogStore, Crawler, Fetcher, load_config
from crawler.errors import ConfigError, StorageError

EXIT_OK = 0
EXIT_PARTIAL_FAILURE = 1
EXIT_CONFIG_ERROR = 2


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)-8s %(message)s",
        stream=sys.stdout,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="catalog-crawler",
        description="Fetch, verify and merge catalog data from decentralized providers.",
    )
    parser.add_argument(
        "command",
        choices=["crawl", "list", "status"],
        help="crawl: run the crawler. list: print stored items. status: print crawl state.",
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml", help="Path to the YAML configuration file."
    )
    parser.add_argument(
        "-p", "--provider", default=None, help="Restrict 'list' output to one provider id."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    return parser


def cmd_crawl(config, store) -> int:
    with Fetcher(config.settings) as fetcher:
        report = Crawler(config, store, fetcher).run()
    print(report.render())
    return EXIT_PARTIAL_FAILURE if report.failed else EXIT_OK


def cmd_list(store, provider_id) -> int:
    items = store.list_items(provider_id)
    print(json.dumps(items, indent=2, ensure_ascii=False))
    print(f"\n{len(items)} item(s) in the catalog.", file=sys.stderr)
    return EXIT_OK


def cmd_status(config, store) -> int:
    print(f"{'PROVIDER':<24} {'APPLIED':>8} {'INDEX':>6}  {'STATUS':<12} LAST CRAWLED")
    print("-" * 78)
    for provider in config.providers:
        state = store.get_provider_state(provider.provider_id)
        print(
            f"{provider.provider_id:<24} "
            f"{state.last_applied_version:>8} "
            f"{state.last_index_version if state.last_index_version is not None else '-':>6}  "
            f"{state.last_status or 'never':<12} "
            f"{state.last_crawled_at or '-'}"
        )
    print(f"\nTotal items stored: {store.count_items()}")
    return EXIT_OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        store = CatalogStore(config.settings.database_path)
    except StorageError as exc:
        print(f"Storage error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        if args.command == "crawl":
            return cmd_crawl(config, store)
        if args.command == "list":
            return cmd_list(store, args.provider)
        return cmd_status(config, store)
    except KeyboardInterrupt:
        print("\nInterrupted. Any in-flight transaction was rolled back.", file=sys.stderr)
        return EXIT_PARTIAL_FAILURE
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
