"""Tests for idor_scout.scanner."""

from unittest.mock import MagicMock

from idor_scout.scanner import Endpoint, ScanConfig, run_scan, test_endpoint


def test_endpoint_from_line_parses_method_and_path():
    endpoint = Endpoint.from_line("GET /api/user/{id}/statement")
    assert endpoint.method == "GET"
    assert endpoint.path == "/api/user/{id}/statement"


def test_endpoint_from_line_uppercases_method():
    endpoint = Endpoint.from_line("post /api/orders/{id}/cancel")
    assert endpoint.method == "POST"


def test_test_endpoint_flags_successful_response_with_content():
    endpoint = Endpoint(method="GET", path="/api/user/{id}/statement")
    config = ScanConfig(base_url="https://example.test", token_a="fake-token")

    fake_session = MagicMock()
    fake_response = MagicMock(status_code=200, content=b"some data")
    fake_session.request.return_value = fake_response

    finding = test_endpoint(endpoint, "42", config, fake_session)

    assert finding is not None
    assert finding.object_id == "42"
    assert finding.status_code == 200


def test_test_endpoint_ignores_forbidden_response():
    endpoint = Endpoint(method="GET", path="/api/user/{id}/statement")
    config = ScanConfig(base_url="https://example.test", token_a="fake-token")

    fake_session = MagicMock()
    fake_response = MagicMock(status_code=403, content=b"")
    fake_session.request.return_value = fake_response

    finding = test_endpoint(endpoint, "42", config, fake_session)

    assert finding is None


def test_run_scan_collects_findings_across_endpoints_and_ids():
    endpoints = [Endpoint(method="GET", path="/api/user/{id}/statement")]
    ids = ["1", "2"]
    config = ScanConfig(base_url="https://example.test", token_a="fake-token")

    fake_session = MagicMock()
    fake_response = MagicMock(status_code=200, content=b"data")
    fake_session.request.return_value = fake_response

    import idor_scout.scanner as scanner_module

    original_session_cls = scanner_module.requests.Session
    scanner_module.requests.Session = MagicMock(return_value=fake_session)
    try:
        findings = run_scan(endpoints, ids, config)
    finally:
        scanner_module.requests.Session = original_session_cls

    assert len(findings) == 2
