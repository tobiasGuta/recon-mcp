# Evidence management

Campaign evidence records what a tool observed, where it came from, and which review decisions the operator made. Keep original files and structured observations private. Share the smallest reviewed subset needed for the task.

## Artifact layout

```text
output/campaigns/<campaign_id>/
├── campaign.json
├── scope.json
├── audit.jsonl
├── imports/
├── recon/
│   ├── graph/evidence-graph.json
│   ├── sourcemaps/{maps,extracted,analysis}/
│   └── other tool-specific artifact directories
├── findings/{hallucinations,needs_manual_validation,validated,rejected,report_candidates}/
├── evidence/
├── memory/negative_results.jsonl
└── reports/
```

`campaign.json` identifies the campaign and current policy binding. The campaign's `scope.json` records scope at creation. Artifact provenance can include a UUID, tool and project versions, UTC timestamp, the historical scope snapshot SHA-256, current campaign grant or decision where applicable, input identifiers, and processing limits. Verify those references before relying on a summary or diff. Historical paths can still name the original workspace after migration.

## Integrity and interrupted writes

New structured artifacts and some generated Markdown or raw artifacts have sibling `.metadata.json` integrity files. The `artifact_sha256` field describes the final saved bytes. Verify a single file with `sha256sum -- /absolute/path/to/artifact.json` and compare the value with the sibling sidecar. Hashes detect byte changes relative to the reference metadata. Signatures and independent timestamping are outside the format.

`verify_campaign_artifacts` checks existing artifact pairs. Review `verified_artifacts`, `missing_artifacts`, `modified_artifacts`, `malformed_metadata`, `unsupported_legacy_artifacts`, `interrupted_artifacts`, and `verification_truncated`. It leaves evidence bytes intact and records the check in the audit log. Some historical files and standalone JSON lack sidecars. Treat those as unverified by this mechanism.

A surviving `.<artifact-name>.recon-pending` marker indicates an interrupted artifact/sidecar publication. Preserve the files and marker for review. Identify the failed operation and choose a verified backup or an explicitly reviewed regeneration. Deleting the marker or rewriting the sidecar would erase evidence of the interruption. See [storage recovery](troubleshooting.md#campaign-storage).

## Audit, graph, and negative results

Audit and negative-result records are JSON Lines. A bounded interrupted tail can be recovered on append. Preserve committed lines and use the campaign's recorded decision IDs and timestamps when tracing an operation. Some writes can succeed while returning an audit warning. Read both the main result and any warnings.

Graph nodes capture normalized observations, provenance, scope decisions, confidence, and history. Edges connect the observations with relationships such as a subdomain being a child of a root. A confidence level or relationship reflects the extractor's evidence. Validate the underlying observation before relying on it. See the [graph schema](security-design.md#evidence-graph-schema). Negative results document checks that produced no supported finding and can inform summaries and future review.

## Finding and report evidence

New finding candidates start in `findings/hallucinations/`, including those with high input confidence. Record the supporting artifact or reviewed note, the applicable scope decision and date, reproducibility, and demonstrated impact. A report candidate requires all six [promotion gates](workflows.md#e-finding-validation-and-reporting). Gate values are human attestations stored by the tool. A generated note can set `evidence_saved` for an existing candidate. The report Markdown is a local draft for human review.

## Sensitive data and retention

Raw HAR, Burp XML, downloaded maps, and extracted `sourcesContent` can retain secrets, personal data, or internal code. Imports summarize selected metadata and leave the original files intact. Credential detection and metadata redaction are bounded. Plaintext notes, file paths, identifiers, and values in unrecognized formats can still be sensitive. Review material before sharing it with a client, a model provider, or a report recipient.

Stop cooperating writers for a consistent backup. Preserve private policy sources, both campaign trees, provenance files, audit logs, and interrupted-write markers, with ownership and permissions recorded. Restrict backup access and encrypt it when required by the evidence handling agreement. Verify backup bytes and test restoration in separate private storage. Decide what to retain or delete under the program's terms and [deployment recovery procedure](deployment.md#backup-and-migration).
