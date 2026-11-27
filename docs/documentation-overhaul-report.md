# Documentation overhaul report

## Initial audit

The original README combined a landing page, editable install instructions, Windows-oriented client examples, operations guidance, and a tool inventory. The qualified stable install, offline Codex procedure, and rollback details lived in release preparation material. Antigravity had no setup guide. The scope guide and security design recorded implementation details, while campaign lifecycle, troubleshooting, evidence retention, and client qualification boundaries were spread across several files. Historical records reflected different points in the qualification process. The original inventory gave signatures and left mode-specific behavior and side effects to the source.

The audit found consequential distinctions to document. Artifact verification and evidence graph reads can append audit records. Listing campaigns can initialize directories. Campaign JavaScript extraction shares a project-root file reader. The Nuclei and external source mapper entries describe contracts, while HAR, Burp XML, and DirFuzz have implemented import paths. Discovery, offline tool calls, and model-driven network use have different evidence.

## Files and structure

| Change | Files |
| --- | --- |
| Updated | `README.md`, `docs/scope-authorization.md`, `docs/security-design.md` |
| Created | `CONTRIBUTING.md`, `SECURITY.md`, `docs/README.md`, `docs/getting-started.md`, `docs/installation.md`, `docs/client-setup.md`, `docs/compatibility.md`, `docs/tool-reference.md`, `docs/campaigns.md`, `docs/workflows.md`, `docs/evidence-management.md`, `docs/integrations.md`, `docs/troubleshooting.md`, `docs/deployment.md`, and this report |

The root README routes readers to task-based guides. Its collapsible signature index also preserves the existing STDIO regression's inventory contract. Scope rules and decisions stay in the scope guide, while operational procedures and evidence handling have their own pages. The historical reports and release notes remain engineering records. The compatibility matrix uses the final release evidence and identifies operator-reported client outcomes separately.

## Verification

- Reviewed tracked documentation, packaging and license declarations, synthetic policies, the server registrations, tool implementations and regressions, the guarded launcher, and the release dependency manifests and provenance.
- Acquired the three v0.2.0 release attachments. Matched the release manifest digest, both archives, all 46 wheelhouse payload checksums, and the mirrored lock and provenance files. Compared 71 tracked runtime, config, test, and release files with the attached source archive.
- Ran the documented stable build, hash-locked installation, sealing, activation, manifest verification, and EOF startup in a disposable Fedora 45 deployment.
- Initialized the guarded server via direct STDIO in a network namespace. Compared the real `list_tools()` inventory and wire argument schemas with the reference, including required fields, nullable types, and defaults for all 67 tools. Exercised health, empty-policy denial, capability discovery, and synthetic allow and deny decisions.
- Verified Codex CLI 0.171.0 registration, inspection, listing, and removal in a disposable config. Its offline app-server discovered 67 tools and returned the expected health and empty-policy denial. No model turn was used.
- Exercised the manual and Burp policy examples, campaign creation and archival, local JavaScript, source map and API contract analysis, HAR and Burp XML imports, and a finding report rejection before promotion. Artifact integrity verification passed for the resulting synthetic campaign.
- Ran the application and deployment regressions using a fresh, hash-locked qualification venv and a loopback-only network namespace. The application suite passed 601 tests and the deployment suite passed seven.
- Checked current client setup against [Codex MCP documentation](https://developers.openai.com/codex/mcp/), [Antigravity MCP documentation](https://antigravity.google/docs/mcp?tab=ide), and [Gemini CLI MCP documentation](https://geminicli.com/docs/tools/mcp-server/).
- Checked Markdown structure and local links and heading anchors across 24 Markdown files. Validated fenced and inline JSON, JSONL, TOML, and Bash syntax. Parsed the new architecture flowchart and checked it against the server and launcher. Reviewed newly authored text for private paths, credentials, and evidence. `git diff --check` passed.
- Checked the public links and both badge labels. Two preserved historical GitHub blob views returned HTTP 503 from this environment. Their tagged raw files were available and matched the verified release archive.

## Remaining limitations

Antigravity remains operator-tested. Standalone Gemini CLI, other client environments, native Burp runtime parity, and model-driven live network operation remain outside the release evidence. Validation used synthetic inputs and public release materials.

## Private vulnerability reporting

On November 27, 2026, GitHub's repository API returned `enabled: true` for private vulnerability reporting. The [security policy](../SECURITY.md) directs reporters to the private advisory form. [Public repository setting](https://api.github.com/repos/tobiasGuta/recon-mcp/private-vulnerability-reporting)

## Publication scope

The `docs/professional-documentation` branch is based on release commit `d7accaf3ce3085acf689e88863ba3079aa24360d`. The publication inventory contains three updated Markdown files and 15 new Markdown files. Historical qualification records are preserved. Runtime code, tests, the deployment launcher, dependency files, policy examples, the application version, and the release tag are unchanged.

```text
docs: overhaul user guides, MCP client setup, and tool reference
```
