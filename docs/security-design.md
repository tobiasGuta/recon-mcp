# Security Design

## Purpose and trust boundaries

Recon MCP is an authorized, low-risk, human-led reconnaissance assistant. It organizes passive evidence and deterministic local analysis. It is not an autonomous vulnerability scanner and does not validate, exploit, replay, submit, or automatically promote findings.

Recon MCP hands tool results to the connected client over STDIO. Local analyzers run in the server process. Passive provider requests disclose the queried root domain when the active policy explicitly allows the provider URL. The client can have additional data-handling behavior of its own.

DirFuzz and any future Nuclei implementation remain separate MCP servers with separate trust boundaries. Recon MCP only imports their already-saved, structured, redacted output.

## Data flow

1. The shared engine parses the actual HTTP(S) URL and compiles the active local policy.
2. The engine checks exclusions, inclusions, transport-independent address restrictions, and the campaign binding when present.
3. Only authorized URLs reach DNS. The transport checks every returned IP, revalidates policy before dispatch, and connects to an approved numeric address. It preserves the target hostname for HTTP and verified TLS.
4. Redirects, retries, fallbacks, and derived URLs repeat these checks. Each request gets its own pool and connection. Response streams stop at the applicable byte limit.
5. Campaign tools attach redacted authorization provenance to audit events and artifacts.

## Scope enforcement

[Scope authorization](scope-authorization.md) specifies each source, the rule subset, decision reason codes, migration, and offline verification. Legacy host inventory remains available for evidence organization. Complete URL decisions drive network authorization.

## Local file boundary

Campaign tools accept only resolved paths under the campaign or a narrower documented campaign subdirectory. A private lock file beside the active and archived roots provides one transaction boundary for supported Linux campaign operations. Traversal and symlinks are rejected. Reads are bounded before parsing. Artifact writes use a same-directory temporary file and atomic replacement, and failed writes remove the temporary file. HAR and Burp files must already be in the campaign (the `imports` directory is recommended); imports never replay traffic.

## Secret handling

Candidate secrets are fingerprinted from the normalized original with SHA-256 and immediately represented by a minimal prefix/suffix redaction. Full values and surrounding source lines are not stored or returned. Private keys report only their type/header, location, and fingerprint. Public client identifiers are recorded as client-configuration signals instead of secret exposures. Obvious placeholders are downgraded. Audit metadata applies an additional sensitive-key and token-shaped redaction layer.

No tool tests whether a discovered credential is active.

## Bounded processing

Configuration controls HTML, JavaScript, source-map, robots, sitemap, saved-artifact, extracted-file, extracted-total, signal, and endpoint limits. Integer limits have minimum and maximum validation bounds. Source-map extraction applies both file-count and total-content checks before writing extracted sources. Graph queries, provider output, diffs, and imported observations are bounded independently.

## Evidence graph schema

The graph is stored at `recon/graph/evidence-graph.json` with schema name `recon-mcp-evidence-graph` and version `1.0`. Nodes and edges use UUIDs. Node identity is a UUIDv5 over campaign ID and a SHA-256 fingerprint of node type, normalized value, source artifact, and any explicit observation fingerprint. Repeated observations append history; superficially similar but evidentially distinct observations are not merged.

Node fields are `uuid`, `campaign_id`, `node_type`, `normalized_value`, `display_label`, `source_artifact_path`, `created_by_tool`, `timestamp`, `scope_decision`, `confidence`, `fingerprint_sha256`, `manual_validation_required`, redacted `metadata`, and `observations`. Edge fields are `uuid`, `source_node`, `destination_node`, `edge_type`, `discovery_tool`, `timestamp`, `evidence_path`, and `confidence`.

The enumerations in `recon/evidence_graph.py` are the compatibility contract for a future Go DirFuzz emitter. Unknown types are rejected rather than silently invented.

## Artifact integrity and provenance

New structured artifacts contain an artifact UUID, tool/project versions, creation time, scope-snapshot hash, parent/input IDs, truncation status, and applied limits. A sibling `.metadata.json` contains the SHA-256 calculated from the final artifact bytes. The writer synchronizes an update marker before replacing either file. The verifier shares the storage lock and reports a surviving marker as an interrupted pair. Audit and negative-result history use descriptor-relative append and recover a bounded unterminated tail. Verification is read-only and reports verified, missing, modified, malformed, and unsupported legacy artifacts without rewriting evidence.

## XML, subprocess, and external interaction policy

Burp XML and sitemap parsing use `defusedxml`; entity expansion, DTD-based attacks, and external entities fail closed. Recon MCP does not need subprocesses for these features and does not use `shell=True`. It does not execute Nuclei or external source-map tools.

Passive providers necessarily receive the queried authorized root domain. Optional DNS resolution is off by default and uses the same current-policy and public-address checks for eligible HTTPS roots.

## Human approval points

- Scope assets and wildcard authority are configured by a human.
- Passive DNS resolution requires explicit opt-in.
- Secret and contract candidates require manual validation.
- Finding promotion continues through the existing human-gated finding pipeline.
- Reports remain local drafts and are never submitted.
- A future Nuclei MCP must build an exact-template, one-target plan and require explicit approval before execution.

## Final qualification boundaries

The final regression suite detects userinfo in nested query URLs and checks that diagnostics, HTTP errors, audit records, and artifact metadata suppress the recognized credentials. The shared inspection is bounded, and raw source evidence retains its original bytes. Campaign directories are private, and the storage lock requires a supported local Linux filesystem and GIL-enabled CPython. The trusted, untrusted, and wrong-host TLS cases used real loopback connections and temporary test certificates. [Final qualification report](v0.2.0-final-qualification-report.md)

## Threat model and limitations

Controls address unauthorized requests, unsafe DNS answers, oversized streams and files, path traversal, XML entities, secret leakage, and evidence modification. The transport pins the TCP peer within the application socket boundary. Local routing, NAT, and infrastructure interceptors can still redirect traffic after that boundary. Campaign synchronization requires a supported local Linux mount and cooperating processes. See [Operational limits](scope-authorization.md#operational-limits). Deterministic regex extraction can miss obfuscated code and can produce false positives; uncertainty and confidence are therefore explicit. Passive providers may be unavailable, incomplete, rate-limited, or privacy-sensitive. Artifact hashes detect modification but do not provide signatures or an external timestamp authority. Existing legacy artifacts without sidecars remain readable but are reported as unsupported legacy evidence.
