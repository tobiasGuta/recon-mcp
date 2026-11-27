# Campaigns

A campaign gives a review effort its own scope snapshot, audit events, artifacts, notes, finding candidates, and reports. Use [supported local Linux storage](scope-authorization.md#fedora-campaign-storage). In a stable deployment, the base is `runtime/output/`. In development it is the checkout's `output/`.

## Create and inspect

1. Confirm authorization with the program or owner. Validate the local policy and check a complete anchor URL offline. Campaign creation evaluates policy without sending a request.
2. Use a query-free anchor. A bare hostname is interpreted as its HTTPS root. Use a full URL for path or port restrictions. A query-only rule cannot anchor a campaign.
3. Call `create_campaign` with campaign metadata. This synthetic example uses the [tutorial policy](getting-started.md#review-a-synthetic-policy-offline).

   ```json
   {
     "program": "Example training",
     "target": "https://api.example.test/public/",
     "notes": "Synthetic material for offline review"
   }
   ```

4. Save the returned `campaign_id`. Pass it as `campaign_id` to `get_campaign` to inspect metadata and the active binding. `list_campaigns` enumerates active campaigns. It can initialize missing storage directories.

The campaign stores an original scope snapshot in `scope.json`. The campaign's live binding is in `campaign.json` and includes the anchor and policy fingerprint. A campaign ID or stored snapshot does not grant permission to send a request. Each network request must still pass current policy.

## Work with campaign evidence

- `create_campaign_evidence_note` saves Markdown under `evidence/`. Supplying an existing `finding_id` also attempts to set its `evidence_saved` gate.
- `record_negative_result` appends a useful non-finding outcome to `memory/negative_results.jsonl`. The optional `repeat_after` is recorded as text for human planning. `list_negative_results` can filter by `check_type`.
- `get_evidence_graph_summary` and `query_evidence_graph` read graph observations and append audit entries. `verify_campaign_artifacts` checks artifact bytes and also appends an audit entry.
- `create_finding_candidate` writes to the hallucination bin. Use the [finding review workflow](workflows.md#e-finding-validation-and-reporting) for promotion and reporting.
- `generate_campaign_summary` writes or replaces `reports/summary.md`. `generate_manual_test_plan_for_campaign` writes or replaces `reports/manual_test_plan.md`. Review warnings and check the resulting paths.

Campaign calls use a storage-wide lock shared by active and archived operations. The lock can be busy when another client is active. Stop competing writes before making a reviewed change to the underlying files. [Evidence layout](evidence-management.md#artifact-layout) · [Tool effects](tool-reference.md#capability-matrix)

## Reauthorize after policy changes

Network campaign operations require a current binding. A missing binding, a changed fingerprint, or an anchor denied by current policy blocks network work. Historical reads can continue. Review the current rules and the anchor, then use the [local interactive reauthorization CLI](scope-authorization.md#campaign-reauthorization) with the full reviewed fingerprint. Reauthorization updates the binding and audit trail. The original snapshot and historical artifacts remain available. The STDIO tool inventory has no reauthorization call.

## Archive and delete

Call `archive_campaign` with the exact campaign ID and an optional reason after reviewing the summary and backups. It moves the campaign to `output/archived_campaigns/` and marks the metadata archived. Use `list_archived_campaigns` or `get_archived_campaign` to inspect archived metadata. Active campaign operations use the active tree.

Permanent removal is available through `delete_archived_campaign` only after archival. Review the archived path and retention requirements and preserve a private backup when required. Pass the same exact archived ID as both `campaign_id` and `confirm_campaign_id`. The tool has no undo. Review the result and archive listing after any error before retrying.
