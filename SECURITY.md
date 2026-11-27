# Security policy

## Release coverage

v0.2.0 is the current published and qualified release. Use that version when checking a potential issue, and include the exact version or commit in any report. Earlier versions and other environment combinations have no documented security support commitment. See [compatibility evidence](docs/compatibility.md) for the qualified Fedora, interpreter, storage, and MCP client boundary.

## Report a security issue privately

Use GitHub private vulnerability reporting for suspected Recon MCP vulnerabilities. Sign in to GitHub, open the repository's **Security → Advisories** page, and select **Report a vulnerability**. Keep vulnerability details out of public issues, pull requests, and discussions. [Open a private report](https://github.com/tobiasGuta/recon-mcp/security/advisories/new) · [GitHub private reporting guidance](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)

Include enough detail for the maintainer to reproduce and assess the issue privately.

- The affected Recon MCP release or commit, OS and architecture, Python and MCP SDK versions, and the install or client type.
- The security boundary affected, expected versus observed behavior, and the impact.
- The smallest synthetic input and sequence necessary to demonstrate the behavior, with redacted diagnostics and a clear indication of what was observed.
- Any relevant policy mode, campaign state, or deployment configuration summarized with synthetic values.

Keep real credentials, tokens, private policies and exports, raw captures, personal paths, and third-party evidence out of reports. Coordinate disclosure with maintainers in the private advisory.

## Research boundaries

Run research only within written authorization. Recon MCP enforces local URL policy, applies read-only transport checks, and records evidence for human review. External tools and hosted MCP clients have independent trust boundaries. Raw upstream data can contain sensitive content even when diagnostics are redacted. See [Security design](docs/security-design.md) and [Scope authorization](docs/scope-authorization.md).
