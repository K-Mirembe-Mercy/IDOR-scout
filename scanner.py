"""Core logic for testing endpoints for IDOR-style authorization issues.

The approach is simple: take a list of endpoint templates containing an
`{id}` placeholder, substitute IDs that belong to a *different* user, and
send the request using the *first* user's credentials. If the server
returns a successful response with content, that's a signal the endpoint
may not be checking whether the requester actually owns the object.

This module makes no assumptions about *why* an endpoint fails a check —
it only flags candidates for a human to investigate further.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests

logger = logging.getLogger(__name__)

# Status codes that suggest the request went through and returned data,
# rather than being rejected by auth/authorization logic.
SUCCESS_CODES = {200, 201, 202}


@dataclass
class Endpoint:
    """A single endpoint template to test.

    Example: Endpoint(method="GET", path="/api/user/{id}/statement")
    """

    method: str
    path: str

    @classmethod
    def from_line(cls, line: str) -> "Endpoint":
        """Parse a line like 'GET /api/user/{id}/statement' into an Endpoint."""
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(f"Could not parse endpoint line: {line!r}")
        method, path = parts
        return cls(method=method.upper(), path=path)


@dataclass
class Finding:
    """A single flagged result worth a human's attention."""

    endpoint: Endpoint
    object_id: str
    status_code: int
    content_length: int

    def __str__(self) -> str:
        return (
            f"[POSSIBLE IDOR] {self.endpoint.method} "
            f"{self.endpoint.path.format(id=self.object_id)} "
            f"-> {self.status_code} ({self.content_length} bytes)"
        )


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    base_url: str
    token_a: str
    delay_seconds: float = 0.0
    timeout_seconds: float = 10.0
    findings: list[Finding] = field(default_factory=list)


def build_headers(token: str) -> dict:
    """Build a standard Bearer-auth header set."""
    return {"Authorization": f"Bearer {token}"}


def test_endpoint(
    endpoint: Endpoint,
    object_id: str,
    config: ScanConfig,
    session: requests.Session,
) -> Finding | None:
    """Test a single endpoint/ID combination as User A.

    Returns a Finding if the response looks like a successful, non-empty
    response despite the object belonging to a different user; otherwise
    returns None.
    """
    url = config.base_url.rstrip("/") + endpoint.path.format(id=object_id)
    headers = build_headers(config.token_a)

    try:
        response = session.request(
            endpoint.method,
            url,
            headers=headers,
            timeout=config.timeout_seconds,
        )
    except requests.RequestException as exc:
        logger.warning("Request failed for %s: %s", url, exc)
        return None

    if response.status_code in SUCCESS_CODES and len(response.content) > 0:
        return Finding(
            endpoint=endpoint,
            object_id=object_id,
            status_code=response.status_code,
            content_length=len(response.content),
        )
    return None


def run_scan(
    endpoints: list[Endpoint],
    owned_ids_of_b: list[str],
    config: ScanConfig,
) -> list[Finding]:
    """Run the full scan across all endpoint/ID combinations.

    Iterates every endpoint against every ID that belongs to User B,
    requesting as User A. Collects and returns all findings.
    """
    session = requests.Session()
    findings: list[Finding] = []

    for endpoint in endpoints:
        for object_id in owned_ids_of_b:
            finding = test_endpoint(endpoint, object_id, config, session)
            if finding:
                findings.append(finding)
                logger.info(str(finding))
            if config.delay_seconds:
                time.sleep(config.delay_seconds)

    return findings
