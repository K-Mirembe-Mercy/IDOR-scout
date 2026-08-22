# idor-scout

A small, beginner-friendly CLI tool that helps you test for **Insecure Direct Object Reference (IDOR)** issues — the class of bug where an app lets you view or modify someone else's data just by changing an ID in a request.

Built with low-bandwidth environments in mind: minimal dependencies, small request footprint, and clear offline-friendly output.

> ⚠️ **Use only on applications you own or have explicit written permission to test.** Unauthorized testing against systems you don't control is illegal in most jurisdictions, Uganda included. This tool is for learning, CTFs, and authorized assessments only.

## Why this exists

Most IDOR-testing walkthroughs stop at "change the ID in Burp Repeater and see what happens." That's fine for one request, but tedious across a real endpoint list. `idor-scout` automates the repetitive part — swapping an object ID across two authenticated sessions and diffing the responses — so you can focus on interpreting results instead of clicking through requests one by one.

It's deliberately simple. No sprawling framework, no unnecessary dependencies — just a clean, testable Python CLI you can read top to bottom in one sitting.

## What it does

Given:
- A list of endpoint templates (e.g. `GET /api/user/{id}/statement`)
- A range or list of IDs to try
- Two session tokens — one for "User A" (the tester) and one for "User B" (a second test account)

`idor-scout` requests each endpoint as User A, substituting IDs that belong to User B, and flags any response that returns a `200 OK` with content — a signal that authorization may not be checked per-object.

## Installation

```bash
git clone https://github.com/<your-username>/idor-scout.git
cd idor-scout
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```bash
python -m idor_scout.cli \
  --base-url https://target.example.test \
  --endpoints examples/endpoints.txt \
  --ids 100-110 \
  --token-a "$TOKEN_A" \
  --token-b-owned-ids examples/owned_by_b.txt
```

Example endpoint file (`examples/endpoints.txt`):

```
GET /api/user/{id}/statement
GET /api/transactions/{id}
POST /api/orders/{id}/cancel
```

Output is a plain-text summary, printed to stdout and optionally saved to a file with `--output results.txt` — so it works fine over a slow or unstable connection.

## Running the tests

```bash
pip install -r requirements.txt
pytest
```

## Project structure

```
idor_scout/
  cli.py        # argument parsing and entry point
  scanner.py    # core request/diff logic
tests/
  test_scanner.py
examples/
  endpoints.txt
  owned_by_b.txt
```

## Roadmap

- [ ] JSON output for CI pipelines
- [ ] Rate limiting / delay flag for slow or metered connections
- [ ] Optional auth-header templates beyond Bearer tokens

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Mercy](https://github.com/) while working toward the HTB CPTS certification. Part of a series on practical, beginner-accessible offensive security.
