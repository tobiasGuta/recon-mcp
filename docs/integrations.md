# External integrations

| Integration | Implemented contract | Qualification boundary |
| --- | --- | --- |
| H1-Scope-Watcher | `h1_snapshots` reads reviewed, local structured scope JSON | The watcher and its upstream API refresh run separately |
| Burp Advanced Scope | `burp_advanced` compiles an anchored subset of exported URL rules | Native Burp runtime parity is outside qualification |
| Burp traffic and HAR | Campaign-local parsers save structured observation summaries | Import only, with no request replay |
| Go DirFuzz MCP | Save supplied analysis and import campaign-local observations into the graph | External execution and end-to-end operation are outside qualification |
| BugMap | Rank caller-supplied parent labels and return association hints | External synchronization and BugMap runtime were outside qualification |
| External source mapper | `external_sourcemapper_info` describes a local-file-only contract | Informational. Recon MCP's own local extractor is implemented. |
| Nuclei | `nuclei_integration_info` describes a future separate executor's expected boundary | Informational. There is no Nuclei execution or Nuclei-specific import tool in v0.2.0. |

## Scope sources

Maintain HackerOne snapshots in a local directory and select the authorized program by filename stem. The watcher owns acquisition and credentials. Recon MCP reads the local copy, interprets the supported structured fields, and can enforce a local age limit. Review program rules separately. For Burp, use a reviewed Advanced Scope configuration export. See [Scope authorization](scope-authorization.md) for both input contracts.

## Traffic already captured

Put a reviewed HAR or Burp item XML file in the campaign's `imports/` directory. Call `import_har_for_campaign` or `import_burp_xml_for_campaign` with the campaign ID and relative or absolute campaign-local path. HAR uses `log.entries`. Burp uses XML `item` elements and supports request text marked as base64. Both write observations, provenance, and audit output. Use the separate [traffic evidence workflow](workflows.md#d-existing-traffic-evidence) to review the result and manage raw inputs.

## DirFuzz and BugMap

`save_dirfuzz_analysis_for_campaign` takes a structured object supplied by the caller and stores it under `recon/dirfuzz/`. Use approved, already-collected observations. `import_dirfuzz_evidence_for_campaign` reads one selected analysis file in that directory, or samples the directory when the path is omitted. It recognizes lists under `discoveries`, `results`, or `interesting`, optionally nested under `result`. It uses URLs or paths, plus status when present, to create graph observations. `dirfuzz_integration_info` describes the separate tool boundary.

`recommend_bugmap_parent` accepts a host or URL and a caller-provided list of records with `id` and `label`. It returns a suggested parent, ranked alternatives, and a scope decision for review. The [interoperability flags](scope-authorization.md#interoperability-flags) distinguish an evidence-association hint from URL authorization. Neither adapter grants permission to run an external tool.

## Informational tool contracts

The external source mapper contract describes analysis of an already approved local `.map` file and campaign-local extracted output. The server makes no subprocess call for it. Prefer the built-in local extractor when using Recon MCP evidence workflows.

The Nuclei information tool returns `executed: false` and describes requirements for a separate future integration. Tool output and scope decisions from this server do not authorize another program's execution. Each external tool needs its own authorization and execution boundaries. [Security design](security-design.md#xml-subprocess-and-external-interaction-policy)
