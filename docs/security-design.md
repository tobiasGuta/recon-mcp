# Security Design

## Purpose and trust boundaries

Recon MCP is an authorized, low-risk, human-led reconnaissance assistant. It organizes passive evidence and deterministic local analysis. It is not an autonomous vulnerability scanner and does not validate, exploit, replay, submit, or automatically promote findings.

The MCP client is a decision-support boundary, not a secret-processing service. Sensitive scanner and imported-traffic processing stays local. No source, secret candidate, request body, response body, or campaign artifact is sent to an AI or other analysis API. Passive provider adapters are the only new external-service boundary: they query fixed public certificate-transparency or OTX endpoints and do not contact discovered target hosts.

DirFuzz and any future Nuclei implementation remain separate MCP servers with separate trust boundaries. Recon MCP only imports their already-saved, structured, redacted output.

## Data flow

1. A target is normalized and checked against the current scope configuration or snapshot.
2. Network operations resolve every target and redirect hop and reject private, local, reserved, or out-of-scope destinations.
3. Response streams stop as soon as the applicable byte limit is exceeded.
4. Campaign-aware tools store bounded structured artifacts beneath that campaign and append an audit event.
5. Deterministic analyzers emit recon leads with `manual_validation_required: true`.
6. Humans separately decide whether and how to validate a lead with authorized accounts and non-destructive methods.

## Scope enforcement

Manual exact assets authorize only that normalized host. Wildcard assets authorize children, including deeply nested children, but exclude the apex. Legacy `allowed_domains` values are migrated safely: plain values are exact, and only an explicit `*.` prefix creates a wildcard. IDNs normalize to ASCII. Malformed assets and private, local, reserved, multicast, link-local, or unspecified IP addresses fail closed.

Scope decisions use stable reason codes including `exact_scope_match`, `wildcard_scope_match`, `no_matching_asset`, `unsupported_asset`, `blocked_target`, and eligibility-specific codes for imported snapshot scope.

## Local file boundary

Campaign tools accept only resolved paths under the campaign or a narrower documented campaign subdirectory. Traversal and symlinks are rejected. Reads are bounded before parsing. Artifact writes use a same-directory temporary file and atomic replacement, and failed writes remove the temporary file. HAR and Burp files must already be in the campaign (the `imports` directory is recommended); imports never replay traffic.

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

New structured artifacts contain an artifact UUID, tool/project versions, creation time, scope-snapshot hash, parent/input IDs, truncation status, and applied limits. A sibling `.metadata.json` contains the SHA-256 calculated from the final artifact bytes. Verification is read-only and reports verified, missing, modified, malformed, and unsupported legacy artifacts without rewriting evidence.

## XML, subprocess, and external interaction policy

Burp XML and sitemap parsing use `defusedxml`; entity expansion, DTD-based attacks, and external entities fail closed. Recon MCP does not need subprocesses for these features and does not use `shell=True`. It does not execute Nuclei or external source-map tools.

Passive providers necessarily receive the queried authorized root domain. DNS resolution is off by default and, when explicitly enabled, performs only bounded DNS lookups, rejects unsafe results, and does not probe HTTP.

## Human approval points

- Scope assets and wildcard authority are configured by a human.
- Passive DNS resolution requires explicit opt-in.
- Secret and contract candidates require manual validation.
- Finding promotion continues through the existing human-gated finding pipeline.
- Reports remain local drafts and are never submitted.
- A future Nuclei MCP must build an exact-template, one-target plan and require explicit approval before execution.

## Threat model and limitations

Controls address SSRF, redirects, DNS rebinding, private-network access, oversized streams/files, traversal, symlinks, XML entities, secret leakage, unbounded result sets, evidence tampering, and accidental promotion of recon leads. Deterministic regex extraction can miss obfuscated code and can produce false positives; uncertainty and confidence are therefore explicit. Passive providers may be unavailable, incomplete, rate-limited, or privacy-sensitive. Artifact hashes detect modification but do not provide signatures or an external timestamp authority. Existing legacy artifacts without sidecars remain readable but are reported as unsupported legacy evidence.
