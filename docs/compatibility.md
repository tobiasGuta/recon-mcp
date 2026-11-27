# Compatibility and qualification evidence

The published v0.2.0 source is tied to commit `d7accaf3ce3085acf689e88863ba3079aa24360d`. Release qualification recorded 601 application regressions, seven deployment tests, 38 focused checks, seven audit findings independently closed, and 43 reviewed dependency wheels. Those are historical qualification results. [Release preparation and final verification](v0.2.0-release-preparation.md#qualification-and-release-status) · [Published release](https://github.com/tobiasGuta/recon-mcp/releases/tag/v0.2.0)

| Environment or capability | Evidence level | Scope of evidence |
| --- | --- | --- |
| Fedora Linux 45 x86_64, GIL-enabled CPython 3.15.2 | Independently qualified | Exact Fedora release environment, runtime wheelhouse, guarded installation, app tests, and real loopback TLS |
| Local Btrfs and tmpfs | Qualified test environments | Btrfs checkout and tmpfs storage fixtures. Ownership, permissions, and same-mount restrictions apply. |
| Local ext2/3/4 and XFS | Runtime-supported, outside the recorded filesystem fixtures | Accepted Linux mount types. See [campaign storage requirements](scope-authorization.md#fedora-campaign-storage). |
| Direct MCP STDIO | Independently qualified | Initialization, 67 registrations, and offline scope tools |
| Codex CLI 0.171.0 | Independently qualified offline | Guarded launcher, app-server discovery, and offline tool calls without a model turn |
| Google Antigravity | Operator-tested | Stable connectivity, discovery of 67 tools, offline diagnostics, and operator-reported practical use. Formal release qualification and live-network client testing remain outside the evidence. |
| Standalone Gemini CLI | Documented and unverified | Proposed STDIO setup and optional tool filtering |
| Other STDIO clients | Documented and unverified | Generic launch contract. Settings and behavior vary by client. |
| Windows, macOS, ARM, alternate Python versions or SDK combinations | Outside the Fedora qualification | Python `>=3.11` and MCP SDK 1.x are package constraints. Campaign storage requires CPython with the GIL on supported Linux storage. Windows execution remains unverified. |
| Free-threaded Python, unsupported mounts, and non-Linux campaign storage | Unsupported for campaign locking | Campaign storage fails closed when prerequisites are unavailable. |
| Burp Advanced Scope | Supported subset, exercised by release tests | Native Burp runtime parity is outside qualification. |
| External tool integrations | Adapter tests or informational contracts | Local import handling is covered where implemented. Standalone external tool operation is unverified. |
| Model-driven live network operations | Outside qualification | The controlled TLS tests verified transport behavior. Codex's qualification used offline app-server calls. |

The qualified runtime used MCP 1.30.0, HTTPX 0.29.0, HTTPCore 1.0.9, and Certifi 2026.11.20. See [the evaluated runtime pins](../release/fedora45-cpython315-runtime.txt) and [wheel provenance](../release/fedora45-cpython315-wheel-provenance.json).
