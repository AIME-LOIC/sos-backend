#!/usr/bin/env python3
"""
Small operational utility for checking SOS backend readiness.

Usage:
  python tools/sos_health_check.py --base-url http://127.0.0.1:8000
  python tools/sos_health_check.py --base-url https://sos-backend-q0h6.onrender.com
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class CheckResult:
    name: str
    ok: bool
    status_code: int | None
    latency_ms: int | None
    detail: str


def run_check(session: requests.Session, base_url: str, path: str, timeout: int) -> CheckResult:
    url = f"{base_url.rstrip('/')}{path}"
    start = time.perf_counter()
    try:
        response = session.get(url, timeout=timeout)
        latency_ms = int((time.perf_counter() - start) * 1000)
        ok = 200 <= response.status_code < 300
        detail = response.text[:180].strip().replace("\n", " ")
        return CheckResult(path, ok, response.status_code, latency_ms, detail)
    except requests.RequestException as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult(path, False, None, latency_ms, str(exc))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run basic health checks against SOS backend")
    parser.add_argument("--base-url", required=True, help="Backend base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON (useful for CI scripts)",
    )
    return parser.parse_args()


def as_dict(result: CheckResult) -> dict[str, Any]:
    return {
        "name": result.name,
        "ok": result.ok,
        "status_code": result.status_code,
        "latency_ms": result.latency_ms,
        "detail": result.detail,
    }


def main() -> int:
    args = parse_args()
    session = requests.Session()
    checks = ["/", "/healthz", "/web/"]
    results = [run_check(session, args.base_url, path, args.timeout) for path in checks]
    all_ok = all(item.ok for item in results)

    if args.json:
        print(
            json.dumps(
                {
                    "base_url": args.base_url,
                    "all_ok": all_ok,
                    "results": [as_dict(item) for item in results],
                },
                indent=2,
            )
        )
    else:
        print(f"Backend: {args.base_url}")
        for item in results:
            status = "OK" if item.ok else "FAIL"
            code = item.status_code if item.status_code is not None else "-"
            latency = item.latency_ms if item.latency_ms is not None else "-"
            print(f"[{status}] {item.name:<8} code={code:<4} latency={latency}ms  {item.detail}")
        print(f"Result: {'PASS' if all_ok else 'FAIL'}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
