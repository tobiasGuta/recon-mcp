# Human-led workflows

Use synthetic inputs for practice. For actual evidence, review permission, handling terms, and the client data boundary first. The [tool reference](tool-reference.md) lists side effects and arguments for each call.

## A. First offline diagnostic session

**Objective.** Verify the connection and see one allow and one deny decision.

**Prerequisites.** A fresh or disposable instance and a configured STDIO client.

1. Call `health` and `get_scope_capabilities` with empty arguments. Check version, tool discovery, and the three supported sources.
2. Call `validate_scope_policy` before installing the [tutorial policy](getting-started.md#review-a-synthetic-policy-offline). Expect a valid empty policy and `safe_to_activate: false`.
3. Install the synthetic policy in the disposable runtime and validate again. Call `check_url_scope` for `https://api.example.test/public/` and `https://api.example.test/private/`.

**Expected result and boundaries.** Expect `allowed` and `path_mismatch`. These steps perform no target DNS or HTTP. If results differ, check the installation path and which policy the client process loads. Check `authorized` as well as `ok`.

## B. Authorized campaign organization

**Objective.** Start a case record, save a note and a non-finding observation, and review a summary.

**Prerequisites.** A supported local mount and a query-free permitted anchor. The [synthetic tutorial policy](getting-started.md#review-a-synthetic-policy-offline) works offline.

1. Confirm the allowed anchor and call `create_campaign` for `https://api.example.test/public/` with the program name `Example training`. Copy the returned ID and inspect it with `get_campaign`.
2. Add a note with `create_campaign_evidence_note` using a short `title` and reviewed `notes`. Record the offline comparison using `record_negative_result` with `check_type` set to `policy_review` and a factual `result`.
3. Generate `reports/summary.md` using `generate_campaign_summary`. Review the artifact paths and use `verify_campaign_artifacts` to check available integrity sidecars.

**Expected result and boundaries.** The calls create local state and audit entries. A list operation alone is insufficient to tell whether your specific campaign has a current binding. Check the ID, anchor, and fingerprint before any separately approved network work.

## C. JavaScript, source maps, and API contracts

**Objective.** Identify routing and API contract observations in reviewed frontend material.

**Prerequisites.** Synthetic or explicitly authorized local files and an active campaign for analyses that save artifacts.

1. For a small synthetic example, call `extract_endpoints_from_js` in raw mode.

   ```json
   {"source_type":"raw","file_or_url":"const route = '/api/catalog';"}
   ```

   This returns ordinary endpoint candidates. File mode accepts approved files whose resolved paths stay within the server tree. Use `extract_endpoints_for_campaign` to save endpoint and scoring results. Its local modes do not contact a target.

2. To analyze an existing map, place a reviewed `.map` file in the campaign's `recon/sourcemaps/maps/` directory. Call `extract_sourcemap_sources_for_campaign` with that path, then `analyze_sourcemap_sources_for_campaign` on the resulting directory. Extraction writes embedded `sourcesContent` subject to file and total-byte limits. Sources listed without embedded content are recorded as missing content.
3. Use `extract_api_contracts_for_campaign` on the reviewed extracted directory. It detects common client-side request patterns such as Fetch, Axios, Angular, XHR, WebSocket, JSON bodies, and named GraphQL operations. Review each candidate's endpoint uncertainty and its source location. If needed, use `scan_sensitive_artifacts_for_campaign` on the same local material and handle redacted candidates privately.

**Expected result and boundaries.** API patterns, routes, and source map references are manual-review observations. A high-priority observation can still be wrong. Never include complete candidate credential values in notes. For remote artifacts, the network-facing reference detection and download tools separately check the actual script or map URL, each redirect, and the current campaign binding. Source reference detection fetches a script, even though it does not download the referenced map. Inline data maps require manual review. See [processing limits](tool-reference.md#processing-limits).

## D. Existing traffic evidence

**Objective.** Summarize an already captured synthetic or authorized trace without replaying it.

**Prerequisites.** An active campaign, an approved local HAR or Burp XML export, and permission to store the source capture. Use reviewed synthetic data for practice.

1. Put a file such as `example.har` or `example.xml` in the campaign's `imports/` directory.
2. Call `import_har_for_campaign` with the campaign ID and `har_path: "imports/example.har"`, or `import_burp_xml_for_campaign` with `xml_path: "imports/example.xml"`.
3. Check `replayed: false`, the observation count, scope classifications, and truncation warnings. Inspect normalized URLs, field or parameter names when available, and provenance before sharing a summary.

**Expected result and boundaries.** Imports write summaries, graph observations, and audit entries. Input files remain on disk. Imported HTTP methods describe prior evidence. For example, an observed POST is never sent by the importer. Out-of-scope material can be recorded as excluded evidence. Keep source captures and summaries private until reviewed. [Evidence and retention](evidence-management.md#sensitive-data-and-retention)

## E. Finding validation and reporting

**Objective.** Move a supported observation through human review and prepare a local draft.

**Prerequisites.** An active campaign, current permission for any validation, and approved evidence. A synthetic observation such as “client route string observed in a bundle” is enough to practice triage.

1. Use `create_finding_candidate` with a `finding` object containing a short `title`, a synthetic `target`, a `summary`, and appropriate evidence references. Expect `status: "hallucination"` and `manual_validation_required: true`.
2. Use `get_finding` to review the record. Promote to `needs_manual_validation` when a human agrees to investigate. Confirm scope, actual behavior, repeatability, and impact independently. Record reproducible, non-destructive observations and link the reviewed evidence note. Reject the candidate or record a negative result when evidence does not support it.
3. If human validation supports the finding, promote to `validated` with a reason. Promote to `report_candidate` only when `scope_confirmed`, `evidence_saved`, `reproduced_manually`, `impact_proven`, `safe_non_destructive`, and `report_ready` are all true. Send actual JSON booleans for `gate_updates`.
4. Call `generate_report_candidate_markdown` using the campaign and finding IDs. Review the local draft, evidence, claims, redactions, and program reporting terms before sharing.

**Expected result and boundaries.** Promotion requires the next status and a reason. Demotion can step backward and rejection can close an unsupported lead. Software checks status and gate values. The human determines whether the evidence actually supports them. Common mistakes include jumping from the hallucination bin to validated, treating confidence as impact, and submitting a raw artifact as part of a draft.

## F. Two-client evidence review

**Objective.** Have Codex and Antigravity independently assess the same approved observation and compare the reasoning.

**Prerequisites.** Two [configured clients](client-setup.md#multiple-clients) and an approved, synthetic or redacted evidence excerpt. Decide who controls shared campaign writes.

1. Give each client the same evidence excerpt and ask which claims are supported, which are ambiguous, and which artifacts would resolve uncertainty. Keep the task offline with respect to targets. Prefer a pre-reviewed copy when underlying evidence may be sensitive.
2. Compare each client's analysis to the original evidence. Capture disagreements as review notes, then have the operator decide the final disposition.
3. If both processes use one stable tree, perform campaign mutations from one client at a time. Some tools that summarize or verify evidence append audit records, so account for those calls when a strict read-only review is required.

**Expected result and boundaries.** The review produces independent assessments and one human-approved campaign update. Shared filesystem access and hosted AI data handling are separate concerns. Client filters restrict tool exposure. OS permissions and isolated state establish a stronger evidence boundary.
