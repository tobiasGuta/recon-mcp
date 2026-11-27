# MCP tool reference

Recon MCP v0.2.0 exposes 67 tools over local STDIO. The entries below use the registered wire names and argument types. Required arguments have no default. Optional nullable arguments default to JSON `null` unless a different default is shown. Send a JSON object, or `{}` for a tool with no arguments.

Tool responses are objects described by their main fields below. Depending on the MCP tool and client, read `structuredContent` or the JSON in a text content block. A generic MCP error can indicate schema validation or an execution exception. Application failures usually use `ok: false`, `error`, or a nested scope decision. Scope checks use `authorized` to distinguish allow and deny. Inspect warnings and truncation fields before relying on a result.

## Capability matrix

Each entry shows its effects below. All categories except HTTP and the URL modes of mixed-input tools operate without network activity.

| Effect | Local inputs and state | Authorization |
| --- | --- | --- |
| Pure | Caller arguments or constants. No local file or campaign I/O. | No active policy required. |
| Policy or config | Reads the active config, local scope sources, or staged candidate files when needed. No campaign actions from this effect alone. | Describes policy or performs an offline decision. |
| HTTP | Reads policy and can send DNS and read-only HTTP requests. | Complete URL policy, transport checks, and current binding for campaign network operations. |
| HTTP / local / raw | Network only in URL mode. File mode reads an approved local file. Raw mode reads the supplied string. | Full URL checks for URL mode. Local modes use the documented path and processing limits. |
| Campaign read | Reads active or archived metadata or evidence. A first operation may initialize the storage parent and lock. | Supported private Linux storage and a valid campaign or archive ID where required. |
| Campaign write | Can read campaign inputs and write evidence, metadata, reports, memory, graph, or audit. Lifecycle operations can move or delete data. | Storage checks apply. Creation also requires a policy-allowed query-free anchor. Offline evidence operations do not require a current network binding. |
| Audit write or setup write | Reads as described and appends an audit record or initializes a directory. | Same storage requirements as other campaign operations. |
| Local write | Writes outside the campaign tree under project-local output. | Local filesystem checks. |
| Integration | Returns informational contracts or caller-supplied label associations. | No external execution. Policy is consulted for scope association. |

Campaign operations can fail with unsafe paths, permissions, unsupported storage, or a busy lock. Check [storage troubleshooting](troubleshooting.md#campaign-storage) before retrying. HTTP tools can fail from policy denial, unsafe DNS, redirect limits, HTTP or TLS errors, or bounded reads. See [network troubleshooting](troubleshooting.md#dns-http-and-tls).

## Processing limits

| Setting or boundary | Default or cap |
| --- | --- |
| HTTP and URL | 5 redirects, up to 64 distinct DNS results, and up to 8 numeric connection attempts per connect deadline |
| Request hygiene | `user_agent` defaults to `ReconMCP/0.2`, `request_delay_ms` to 500, and `fetch_headers_method` to HEAD |
| `max_requests_per_tool_call` | 20 by default. Bounds JavaScript URL collection results and the combined source map workflow's download budget. |
| `max_html_bytes`, `max_javascript_bytes`, `max_sourcemap_bytes` | 2 MiB, 5 MiB, 5 MiB |
| `max_robots_bytes`, `max_sitemap_bytes` | 512 KiB, 1 MiB |
| `max_saved_artifact_bytes`, `max_total_extracted_source_bytes` | 10 MiB and 20 MiB |
| `max_extracted_source_files`, `max_analysis_signals`, `max_endpoint_candidates` | 500, 1,000, and 1,000 |
| HAR and Burp traffic import | 50 MiB per input, up to 5,000 entries, and up to 200 names per bounded parameter or field list |
| Graph file | 20 MiB |

Configuration validation bounds byte settings to 1 KiB–100 MiB, extraction and analysis count settings to 1–10,000, request delay to 0–60,000 ms, and request budget to 1–1,000. Some tools apply smaller fixed bounds. Read `processing_limits` from `health` for active configured defaults.

## JavaScript input modes

The standalone and campaign endpoint extractors share the following behavior.

| `source_type` | Input and limits |
| --- | --- |
| `url` | Complete authorized HTTP(S) URL. Suffix determines HTML or JavaScript read limits. Redirects are rechecked, and the campaign variant requires current binding. Discovered endpoint strings are observations. |
| `file` | An already reviewed local `.js`, `.mjs`, `.cjs`, or `.map` file whose resolved path lies inside the server project tree. Use a physical path. Reads at most the smaller of 2 MiB and the configured JavaScript byte limit. |
| `raw` | Literal source text passed as `file_or_url`, bounded by the configured JavaScript limit. Use synthetic snippets when sharing examples. |
| Omitted or `null` | Auto-detects raw text containing a newline, `function `, or `=>`. For other inputs, HTTP(S) indicates URL mode and the remaining inputs use file mode. |

Use explicit modes for ambiguous inputs. Endpoint extraction returns candidates up to the configured cap. The campaign entry also writes an artifact and audit events.

## Authorization and scope

### `health`

**Arguments.** None.

**Effects.** Config. Reports startup health, version, the server's `available_tools`, and configured `processing_limits`. Reads the base config. A malformed base config sets `ok: false` and `configuration_error`. Use policy validation to check referenced sources.

**Example.** Call with `{}`.

### `check_scope`

**Arguments.** `domain` (string, required)

**Effects.** Policy. Accepts a hostname or a complete URL in `domain`. Returns a resolver decision with host inventory or full URL fields. Compare `evaluation_kind`, `in_scope`, and `network_execution_permitted`. An unknown host has no inventory match.

### `resolve_scope_target`

**Arguments.** `host_or_url` (string, required), `format` (string or null, optional, default `null`)

**Effects.** Policy. Returns normalized target, match, policy metadata, and eligibility where known. Use `format: "mcp_interop"` to add interoperability flags. URL denials and invalid policies use structured reasons. Inventory matches carry no network permission.

**Example.** `{"host_or_url":"api.example.test","format":"mcp_interop"}`

### `check_scope_batch`

**Arguments.** `hosts_or_urls` (array of string, required), `format` (string or null, optional, default `null`)

**Effects.** Policy. Returns `count` and ordered resolver `results`. Accepts up to 200 entries, 4,096 characters per entry, and 256 KiB total UTF-8. Oversized batches fail before evaluation. `format: "mcp_interop"` adds flags to each decision.

### `get_scope_map`

**Arguments.** None.

**Effects.** Policy. Returns machine-readable manual or HackerOne inventory in `entries`, with `count` and `warnings`. Burp returns a policy summary with empty `entries`. Invalid policy returns structured failure with no entries.

### `recommend_bugmap_parent`

**Arguments.** `host_or_url` (string, required), `available_bugmap_targets` (array of object, required)

**Effects.** Policy, integration. Ranks caller-supplied target objects with `id` and `label`. Returns the recommended parent ID and label, ranked alternatives, and `scope_decision`. An unmatched label yields `ok: false` and a warning. It does not access BugMap.

### `explain_scope_decision`

**Arguments.** `host_or_url` (string, required)

**Effects.** Policy. Adds human-readable `explanation` to the offline host or URL decision. Rejected or unresolved input is described using the decision's reason. Use the structured URL flags for permission decisions.

### `list_loaded_scope`

**Arguments.** None.

**Effects.** Policy. Returns the source, configured host and snapshot inventory counts, and warnings. Burp returns a policy summary. Empty manual inventory reports `ok: false`. Invalid sources fail closed.

### `validate_scope_policy`

**Arguments.** None.

**Effects.** Policy. Compiles the active policy. Returns `valid`, `safe_to_activate`, fingerprint, counts, supported rule descriptors, warnings, and errors. Invalid or unsupported inputs have both Boolean fields false. Empty or exclusion-only scope can be valid with `safe_to_activate: false`.

### `check_url_scope`

**Arguments.** `url` (string, required)

**Effects.** Policy. Evaluates one full URL offline. Returns [decision fields and reason codes](scope-authorization.md#reading-a-url-decision). The URL is limited to 4,096 characters. Malformed and sensitive inputs fail before dispatch.

**Example.** `{"url":"https://api.example.test/public/"}`

### `check_url_scope_batch`

**Arguments.** `urls` (array of string, required)

**Effects.** Policy. Returns ordered `results`, `count`, and a single `policy_fingerprint`. Limits are 100 URLs, 4,096 characters per URL, and 128 KiB aggregate UTF-8. Batch errors and policy errors are separate from individual denials.

### `get_scope_policy_summary`

**Arguments.** None.

**Effects.** Policy. Returns source, schema, fingerprint, validity, readiness, rule counts, constraints, warnings, and limitations. On policy failure, inspect `policy_error`.

### `compare_scope_policies`

**Arguments.** `before` (string, required), `after` (string, required)

**Effects.** Policy. Reads two named copies under `config/policies/`. Use names up to 64 characters without extensions or path separators. Returns fingerprints, added and removed rules, probable edits, and possible expansion or reduction. A changed fingerprint yields `comparison: "indeterminate"`. Missing or invalid candidates return an error.

**Example.** `{"before":"before","after":"after"}`

### `get_scope_capabilities`

**Arguments.** None.

**Effects.** Pure. Returns source capabilities, policy schema version, URL and batch limits, and enforcement limitations. Uses server constants. No loaded policy is needed.

## Scoped HTTP and JavaScript

### `fetch_headers`

**Arguments.** `url` (string, required)

**Effects.** HTTP. Returns final URL, status, method, headers, selected security headers, notes, and the scope decision. Defaults to HEAD. A transport error or status 403 or 405 can trigger a scope-checked GET with a one-byte Range request and no body consumption. An HTTP failure or scope denial returns an error.

### `fetch_robots`

**Arguments.** `url` (string, required)

**Effects.** HTTP. Checks the supplied URL and requests the origin's `/robots.txt` under the same policy. Returns status, preview, `allow`, `disallow`, and truncation flags. The default body limit is 512 KiB. Check the derived path on a scope denial.

### `fetch_sitemap`

**Arguments.** `url` (string, required)

**Effects.** HTTP. Checks the supplied URL and requests the origin's `/sitemap.xml`. Returns status, bounded `discovered_urls`, preview, truncation flags, and `parse_error` for unusable XML. Uses hardened XML parsing and a 1 MiB default body limit. Listed URLs are observations and are not fetched.

### `collect_js_urls`

**Arguments.** `url` (string, required)

**Effects.** HTTP. Fetches the input once plus permitted redirects, resolves script references against the final response URL, and returns only currently allowed `js_urls` with count and truncation. It does not fetch those scripts. The result cap defaults to 20. A denial or bounded HTTP error is returned for failed reads.

### `extract_endpoints_from_js`

**Arguments.** `file_or_url` (string, required), `source_type` (string or null, optional, default `null`)

**Effects.** HTTP / local / raw. Returns `source_type`, candidates in `endpoints`, count, truncation, notes, and a scope decision in URL mode. See [JavaScript input modes](#javascript-input-modes) for separate file, raw, and network constraints. Invalid mode, denied URL, unreadable input, and oversized input return errors.

**Example.** `{"file_or_url":"const route = '/api/catalog';","source_type":"raw"}`

### `fetch_headers_for_campaign`

**Arguments.** `campaign_id` (string, required), `url` (string, required)

**Effects.** HTTP, campaign write. Runs the header fetch under a current campaign binding. Returns `result`, saved `path`, and warnings. Saves a header artifact and audit events. Check the network decision and artifact error separately.

### `fetch_robots_for_campaign`

**Arguments.** `campaign_id` (string, required), `url` (string, required)

**Effects.** HTTP, campaign write. Runs the robots fetch with both original and derived URL checks. Returns the robots `result`, artifact `path`, and warnings. An out-of-scope origin file can be denied even when the supplied URL is allowed.

### `fetch_sitemap_for_campaign`

**Arguments.** `campaign_id` (string, required), `url` (string, required)

**Effects.** HTTP, campaign write. Runs the bounded sitemap fetch with both original and derived URL checks. Returns `result`, artifact `path`, and warnings. Inspect the nested parse error and truncation independently from save errors.

### `collect_js_urls_for_campaign`

**Arguments.** `campaign_id` (string, required), `url` (string, required)

**Effects.** HTTP, campaign write. Saves bounded script URL observations without requesting the scripts. Returns `result`, artifact `path`, and warnings. Inherits input URL and candidate checks from `collect_js_urls` and requires a current binding.

### `extract_endpoints_for_campaign`

**Arguments.** `campaign_id` (string, required), `file_or_url` (string, required), `source_type` (string or null, optional, default `null`)

**Effects.** HTTP / local / raw, campaign write. Uses the shared [JavaScript modes](#javascript-input-modes). URL mode requires the current campaign binding. File mode can read within the project tree. Raw mode reads an argument. Returns `result`, `scored_endpoints`, artifact `path`, and warnings. Failed analysis can still be recorded. Check extraction and save status before retrying.

### `discover_subdomains_passive_for_campaign`

**Arguments.** `campaign_id` (string, required), `root_domain` (string, required), `providers` (array of string or null, optional, default `null`), `max_results` (integer, optional, default `500`), `resolve_dns` (boolean, optional, default `false`)

**Effects.** HTTP, campaign write. Can query the fixed `certificate_transparency` and `alienvault_otx` providers. Null or an empty list selects both. Requires an allowed HTTPS root URL, current binding, and authorization of each actual provider request. The domain is disclosed to contacted providers. `resolve_dns` enables DNS only for candidates whose HTTPS root URL is authorized. Discovered hosts receive no HTTP requests. Returns results, scope classifications, `partial_failures`, and saved metadata. Reads the one-hour cache and writes cache, artifact, graph, and audit records. Provider response limit is 5 MiB and `max_results` is clamped to 1–5,000.

## Offline utilities and external contracts

### `dedupe_urls`

**Arguments.** `urls` (array of string, required)

**Effects.** Pure. Normalizes and sorts URLs with `original_count`, `deduped_count`, and `urls`. This is string normalization, with query information retained where applicable. It performs no authorization or evidence scrubbing. Pass reviewed inputs.

**Example.** `{"urls":["https://api.example.test/public/","https://api.example.test/public/"]}`

### `score_endpoint`

**Arguments.** `endpoint` (object or string, required)

**Effects.** Pure. Scores a supplied string or object using `value`, `url`, or `path`. Returns `score`, `priority`, reasons, and notes for manual review. An empty or unrecognized value can receive a generic score.

### `score_endpoints`

**Arguments.** `endpoints` (array of object or string, required)

**Effects.** Pure. Scores a supplied list and returns sorted `endpoints` and `count`. The schema rejects a non-array. Scores are review priorities.

### `generate_manual_test_plan`

**Arguments.** `target_summary` (object, required)

**Effects.** Pure. Builds a checklist from caller-supplied summary fields such as `endpoints` and `js_urls`. Returns `checklist`, `priority_items`, `dirfuzz_handoff`, and warnings. It writes no plan file. A non-object input fails schema validation.

### `create_evidence_note`

**Arguments.** `finding` (object, required)

**Effects.** Local write. Writes a new Markdown file under project-local `output/evidence/`. Accepts an object with optional fields such as `title`, `target`, and `notes`. Returns `path` and `title`. Unsafe output paths and I/O failures return errors. Use reviewed text.

**Example.** `{"finding":{"title":"Offline policy review","notes":"Synthetic example only"}}`

### `dirfuzz_integration_info`

**Arguments.** None.

**Effects.** Integration. Returns usage context and the separate tool names and workflow description in `recommended_tools` and `recommended_workflow`. No input files or external process are required.

### `external_sourcemapper_info`

**Arguments.** None.

**Effects.** Integration. Returns `executed: false`, a local-only model, and example placement for already-approved maps and extracted source. It requires no paths as input and starts no external program.

### `nuclei_integration_info`

**Arguments.** None.

**Effects.** Integration. Returns `executed: false`, `required_controls`, and `safety_boundary` for a future separate tool. It cannot execute or import Nuclei results.

## Campaign lifecycle

### `create_campaign`

**Arguments.** `program` (string, required), `target` (string, required), `notes` (string or null, optional, default `null`)

**Effects.** Policy, campaign write. Evaluates a query-free anchor offline. A bare hostname means its HTTPS root. Creates the directory layout, campaign metadata, scope snapshot, binding, and audit record. Returns `campaign_id`, `path`, and `scope_decision`. Denied anchors and unsafe storage fail.

**Example.** See [Create and inspect](campaigns.md#create-and-inspect).

### `list_campaigns`

**Arguments.** `limit` (integer, optional, default `50`)

**Effects.** Campaign read, setup write. Returns active `campaigns` and `count`, latest first. Effective limit is 1–500, with zero using the default. May create the active root. Missing or unsafe entries are omitted.

### `get_campaign`

**Arguments.** `campaign_id` (string, required)

**Effects.** Campaign read. Returns active `campaign` metadata, including the saved binding if present, and its `path`. An invalid ID, missing record, or unsafe path returns an error.

### `archive_campaign`

**Arguments.** `campaign_id` (string, required), `reason` (string or null, optional, default `null`)

**Effects.** Campaign write. Moves an active campaign to the archived tree on the same storage root, updates metadata, and records an audit event. Returns `campaign_id`, `archived_path`, and `reason`. Refuses an already occupied archive destination. Verify the result before retrying after a filesystem error.

### `list_archived_campaigns`

**Arguments.** `limit` (integer, optional, default `50`)

**Effects.** Campaign read, setup write. Returns archived `campaigns` and `count` sorted by newest archive timestamp. Effective limit is 1–500, with zero using the default. May create the archive root. Unreadable or unsafe entries are omitted.

### `get_archived_campaign`

**Arguments.** `campaign_id` (string, required)

**Effects.** Campaign read. Returns archived `campaign` metadata and archived `path`. Missing records, bad IDs, and unsafe paths fail.

### `delete_archived_campaign`

**Arguments.** `campaign_id` (string, required), `confirm_campaign_id` (string, required)

**Effects.** Campaign write. Permanently deletes the archived directory when both ID arguments match exactly. Returns `deleted: true` with the ID and a warning. Missing archive entries and confirmation mismatches fail. Review [archive and delete](campaigns.md#archive-and-delete) before using it.

## Findings, notes, and reports

### `create_finding_candidate`

**Arguments.** `campaign_id` (string, required), `finding` (object, required)

**Effects.** Campaign write. Accepts a finding object with optional `title`, `target`, `summary`, `confidence`, and `evidence`. Saves a redacted finding in the hallucination bin. Returns `finding`, `path`, and warnings. Duplicate IDs and oversized writes fail.

### `get_finding`

**Arguments.** `campaign_id` (string, required), `finding_id` (string, required)

**Effects.** Campaign read. Returns `finding` and `path` from the active campaign. Invalid IDs and missing records return errors. Reads use the configured artifact limit.

### `list_findings`

**Arguments.** `campaign_id` (string, required), `status` (string or null, optional, default `null`)

**Effects.** Campaign read. Returns `findings` and `count`. Optional status uses the exact pipeline state values in [the findings workflow](workflows.md#e-finding-validation-and-reporting). Unknown status fails and unreadable records can be skipped.

### `promote_finding`

**Arguments.** `campaign_id` (string, required), `finding_id` (string, required), `target_status` (string, required), `reason` (string, required), `gate_updates` (object or null, optional, default `null`)

**Effects.** Campaign write. Moves the finding through the allowed sequence. `gate_updates` may carry reviewed Boolean attestations for the six report gates. Returns updated `finding`, `path`, and warnings. Invalid transitions, blank reason, and incomplete report gates fail.

### `demote_finding`

**Arguments.** `campaign_id` (string, required), `finding_id` (string, required), `target_status` (string, required), `reason` (string, required)

**Effects.** Campaign write. Moves a finding back one stage using the documented reverse sequence. Returns updated `finding`, `path`, and warnings. A missing reason or unsupported transition fails.

### `reject_finding`

**Arguments.** `campaign_id` (string, required), `finding_id` (string, required), `reason` (string, required)

**Effects.** Campaign write. Moves an existing finding to `rejected` with the supplied reason. Returns updated `finding`, `path`, and warnings. Missing findings and blank reasons fail.

### `create_campaign_evidence_note`

**Arguments.** `campaign_id` (string, required), `finding` (object, required)

**Effects.** Campaign write. Saves a note and sidecar under `evidence/`. With a supplied `finding_id`, attempts to set `evidence_saved`. Returns `path`, `artifact_uuid`, `metadata_path`, `gate_update`, and warnings. The note can succeed with a gate-update warning.

### `record_negative_result`

**Arguments.** `campaign_id` (string, required), `target` (string, required), `check_type` (string, required), `result` (string, required), `repeat_after` (string or null, optional, default `null`), `metadata` (object or null, optional, default `null`)

**Effects.** Campaign write. Appends a bounded non-finding record and audits the write. `repeat_after` is a human reminder string. Returns `record`, `path`, and warnings. The JSONL writer rejects oversized records (1 MiB limit) and unsafe storage.

### `list_negative_results`

**Arguments.** `campaign_id` (string, required), `check_type` (string or null, optional, default `null`)

**Effects.** Campaign read. Returns `results` and `count`, optionally filtered by exact `check_type`. A missing memory file produces an empty list. The read limit is 20 MiB and malformed data can return an error.

### `generate_manual_test_plan_for_campaign`

**Arguments.** `campaign_id` (string, required)

**Effects.** Campaign write. Reads stored observations and writes or replaces `reports/manual_test_plan.md`. Returns `plan`, file and sidecar paths, artifact UUID, and warnings. It summarizes bounded top observations and fails if writing exceeds the artifact limit.

### `generate_campaign_summary`

**Arguments.** `campaign_id` (string, required)

**Effects.** Campaign write. Reads existing artifacts, finding counts, and memory. Writes or replaces `reports/summary.md` with sidecar. Returns `summary`, paths, UUID, and warnings. Unavailable campaigns and artifact write failures return errors.

### `generate_report_candidate_markdown`

**Arguments.** `campaign_id` (string, required), `finding_id` (string, required)

**Effects.** Campaign write. Reads a stored finding and writes a local report draft. Requires its status to be `report_candidate`. Returns `markdown`, paths, UUID, and warnings. Wrong status, missing finding, and write failure return errors.

## Source maps and local artifact analysis

### `detect_sourcemap_references_for_campaign`

**Arguments.** `campaign_id` (string, required), `js_url` (string, required)

**Effects.** HTTP, campaign write. Fetches the JS URL with current binding, resolves references against its final URL, and evaluates map candidates offline. Returns `references`, `downloadable`, `skipped`, decision, and saved `path`. Detection does not fetch maps. Inline data references are skipped. Denied or oversized JS cannot be processed.

### `download_sourcemap_for_campaign`

**Arguments.** `campaign_id` (string, required), `sourcemap_url` (string, required)

**Effects.** HTTP, campaign write. Checks the full map URL and current binding. Saves bounded, structurally recognized JSON bytes and metadata. Returns `map_path`, byte and source counts, presence of embedded content, and integrity metadata. Non-map content, size failures, and scope denials fail.

### `extract_sourcemap_sources_for_campaign`

**Arguments.** `campaign_id` (string, required), `map_path` (string, required)

**Effects.** Campaign write. Reads a local map whose resolved path is under `recon/sourcemaps/maps/`. Use its physical absolute path. Extracts embedded sources and an index within the campaign. Returns `extracted_dir`, `files_written`, `sources_without_content`, `metadata_path`, and warnings. Missing, invalid, or oversized maps fail. File-count and total-content limits apply before extraction.

### `analyze_sourcemap_sources_for_campaign`

**Arguments.** `campaign_id` (string, required), `extracted_dir` (string or null, optional, default `null`)

**Effects.** Campaign write. Reads local extracted text and saves analysis. Omit `extracted_dir` for all extracted subdirectories or pass a physical directory under the campaign extraction tree. Returns `files_analyzed`, endpoint candidates, scores, signals, `path`, and warnings. The per-file cap is at most 2 MiB. Review skipped or truncated results.

### `sourcemap_workflow_for_campaign`

**Arguments.** `campaign_id` (string, required), `js_url` (string, required)

**Effects.** HTTP, campaign write. Combines JS reference detection and authorized bounded map handling for one campaign JS URL. Returns detection, download, extraction and analysis counts and paths, and warnings. The map budget is configured requests minus one, and individual steps can fail with warnings. When no reference is found it records a negative result and returns `detected_count: 0`.

### `scan_sensitive_artifacts_for_campaign`

**Arguments.** `campaign_id` (string, required), `extracted_dir` (string or null, optional, default `null`)

**Effects.** Campaign write. Reads local extracted text, defaulting to the campaign extraction root. Saves redacted `matches`, fingerprints, counts, and separate `client_configuration_signals`; writes graph and audit records. No matches also records negative memory. File, total-byte, and signal limits apply. Outside-boundary or unreadable inputs fail or are skipped. It does not test credentials.

### `extract_api_contracts_for_campaign`

**Arguments.** `campaign_id` (string, required), `extracted_dir` (string or null, optional, default `null`)

**Effects.** Campaign write. Reads approved local files under the campaign extraction root by default and saves `contracts`, count, truncation, warnings, graph, and artifact metadata. Each contract represents an inference with endpoint uncertainty and provenance. File count, bytes, and result caps apply. Unsafe directories and save failures return errors.

## Imports, graph, and artifact integrity

### `save_dirfuzz_analysis_for_campaign`

**Arguments.** `campaign_id` (string, required), `analysis` (object, required)

**Effects.** Campaign write. Saves a caller-supplied analysis object under `recon/dirfuzz/` after supported redaction. Returns `path` and `result`, with save errors for unsafe or oversized artifacts. This is a write, independent of the graph import.

### `import_dirfuzz_evidence_for_campaign`

**Arguments.** `campaign_id` (string, required), `analysis_path` (string or null, optional, default `null`)

**Effects.** Campaign write. Imports file or directory results under `recon/dirfuzz/` into graph, with audit output. Null means up to 100 sorted JSON files. Reads at most 5 MiB and 2,000 observations per file. Returns graph path, counts, and node IDs. Unsafe paths fail and unreadable or invalid JSON files may be skipped.

### `import_har_for_campaign`

**Arguments.** `campaign_id` (string, required), `har_path` (string, required)

**Effects.** Policy, campaign write. Reads a campaign-local HAR and saves `observations`, count, truncation, `replayed: false`, graph observations, audit and artifact metadata. Supports `log.entries`. Invalid JSON, wrong structure, and unsafe paths fail. See [traffic import limits](#processing-limits).

### `import_burp_xml_for_campaign`

**Arguments.** `campaign_id` (string, required), `xml_path` (string, required)

**Effects.** Policy, campaign write. Reads campaign-local Burp item XML and returns an observation summary with `replayed: false`, count, truncation, and saved metadata. Uses entity-safe parsing. It writes graph and audit records. Invalid XML, unsafe input, and oversize files fail. See [traffic import limits](#processing-limits).

### `get_evidence_graph_summary`

**Arguments.** `campaign_id` (string, required)

**Effects.** Campaign read, audit write. Returns graph version and node/edge counts by type. Missing graph data can yield empty counts. Invalid or oversized graph data can fail. This call appends a campaign audit entry.

### `query_evidence_graph`

**Arguments.** `campaign_id` (string, required), `node_uuid` (string, required), `depth` (integer, optional, default `1`), `limit` (integer, optional, default `100`)

**Effects.** Campaign read, audit write. Reads the neighborhood of a node UUID with `nodes`, `edges`, and `truncated`. Depth is clamped to 0–3 and limit to 1–500 nodes with at most twice that many edges. Invalid or missing UUIDs return errors. Reads and lookup failures can append audit entries.

### `compare_campaign_recon`

**Arguments.** `campaign_id` (string, required), `baseline_campaign_id` (string, required)

**Effects.** Campaign write. Reads normalized artifacts from both active campaigns. Writes JSON and Markdown diffs in the current campaign and appends audit. Returns `changes` split into added, removed, and changed observations plus `truncated` and output paths. Caps each change list at 5,000 per category. Missing campaigns or failed saves return errors.

### `verify_campaign_artifacts`

**Arguments.** `campaign_id` (string, required)

**Effects.** Campaign read, audit write. Checks existing pairs without rewriting artifact bytes. Returns integrity lists, counts, interrupted markers, and `verification_truncated`. Scans up to 10,000 sidecars and markers each, with a 100 MiB per-artifact read bound. Missing or modified artifacts, malformed metadata, and incomplete publication can set `ok: false`.
