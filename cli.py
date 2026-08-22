"""Command-line entry point for idor-scout."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from idor_scout.scanner import Endpoint, ScanConfig, run_scan


def parse_id_arg(raw: str) -> list[str]:
    """Parse an --ids argument like '100-110' or '5,7,9' into a list of IDs."""
    if "-" in raw and "," not in raw:
        start, end = raw.split("-", maxsplit=1)
        return [str(i) for i in range(int(start), int(end) + 1)]
    return [item.strip() for item in raw.split(",") if item.strip()]


def load_endpoints(path: str) -> list[Endpoint]:
    """Load endpoint templates from a text file, one per line."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [Endpoint.from_line(line) for line in lines if line.strip()]


def load_ids_file(path: str) -> list[str]:
    """Load a plain list of IDs from a text file, one per line."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip()]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idor-scout",
        description=(
            "Test API endpoints for IDOR-style authorization issues. "
            "Use only on systems you own or have explicit permission to test."
        ),
    )
    parser.add_argument("--base-url", required=True, help="e.g. https://target.example.test")
    parser.add_argument("--endpoints", required=True, help="Path to endpoint template file")
    parser.add_argument("--token-a", required=True, help="Bearer token for the testing account")
    parser.add_argument(
        "--token-b-owned-ids",
        required=True,
        help="Path to a file listing object IDs owned by a second account",
    )
    parser.add_argument("--ids", help="Optional ID range/list override, e.g. 100-110")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests, seconds")
    parser.add_argument("--output", help="Optional file to save results to")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )

    endpoints = load_endpoints(args.endpoints)
    owned_ids = parse_id_arg(args.ids) if args.ids else load_ids_file(args.token_b_owned_ids)

    config = ScanConfig(base_url=args.base_url, token_a=args.token_a, delay_seconds=args.delay)
    findings = run_scan(endpoints, owned_ids, config)

    lines = [str(f) for f in findings] or ["No possible IDOR issues found."]
    output_text = "\n".join(lines)

    print(output_text)
    if args.output:
        Path(args.output).write_text(output_text + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
