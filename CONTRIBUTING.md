# Contributing to Recon MCP

Use a separate [development checkout](docs/installation.md#development-installation) and synthetic local state. Read the relevant user guide and [Security design](docs/security-design.md) before changing a security-sensitive path.

## Repository map

| Path | Purpose |
| --- | --- |
| `server.py` | STDIO entry point, tool registrations, and wire-facing schemas |
| `recon/` | Authorization, transport, local analysis, and campaign storage |
| `tests/` | Application regressions and controlled loopback TLS |
| `scripts/stable_deployment.py` and `release/tests/` | Guarded stable launcher and deployment regressions |
| `release/` | Runtime and qualification dependency locks and wheel provenance |
| `config/*.example.json` | Public synthetic policy examples |
| `docs/` | User guides and historical release and engineering records |

## Run checks

From the checkout root, install `.[dev]` and the OpenSSL CLI as described in [Installation](docs/installation.md#development-installation). Run:

```bash
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q release/tests/test_stable_deployment.py
git diff --check
```

Use reserved domains, temporary policy and campaign roots, mocked I/O, or controlled loopback fixtures. The [offline qualification procedure](docs/v0.2.0-release-preparation.md#clean-offline-regression-environment) uses the verified wheelhouse and a loopback-only namespace. Do not add real target requests or private policy files to tests.

## Make a focused change

- Keep function and tool signatures explicit. Reuse established validation, bounded I/O, redaction, and storage helpers where appropriate.
- Verify documentation against registered schemas and actual behavior. Include prerequisites and expected results. Keep the [tool reference](docs/tool-reference.md) and README tool index in sync with STDIO discovery. Preserve historical qualification records.
- Changes to authorization, HTTP transport, sensitive-data handling, campaign locking and storage, or deployment integrity require targeted regression tests and appropriate review. Include fail-closed cases and identify how you verified the boundary.
- Review dependency changes against package constraints and platform requirements. For a qualified dependency refresh, update evaluated pins, hash locks, and wheel provenance together and rerun the isolated installation and qualification checks.
- Keep private scope policies, program exports, evidence, credentials, tokens, and client configuration out of Git. Review the actual diff for sensitive data before opening a pull request.

A pull request should explain the user-facing change, affected boundaries, tests run, and remaining compatibility gaps. Use [Security policy](SECURITY.md) for suspected vulnerabilities.
