# Changelog

## 0.2.0 (prepared for release)

- Enforce complete HTTP(S) URL authorization for manual rules, one selected HackerOne snapshot, and a documented subset of Burp Advanced Scope. Add offline validation, summaries, policy comparison, capability reporting, and single and batch URL decisions.
- Bind campaign work to the current policy and record sanitized decision provenance. Refresh the current policy before passive discovery publishes results.
- Pin the TCP connection to a validated numeric endpoint while preserving HTTP authority and TLS hostname verification. Recheck redirects and isolate requests from environment proxies.
- Deny sensitive or ambiguous URLs before network execution and redact supported credential representations from diagnostics, errors, audit records, and artifact metadata.
- Coordinate campaign readers and writers on supported Linux storage. Detect interrupted artifact writes and preserve a restrictive storage-permission boundary.
- Update the MCP inventory to 67 tools. The independent review supplied for release preparation reported all seven audit findings closed and 601 tests passing. See the [release preparation report](docs/v0.2.0-release-preparation.md) for the supported environment, installation, migration, rollback, and verification results.
