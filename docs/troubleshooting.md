# Troubleshooting

Use a disposable installation and synthetic inputs when reproducing an issue. Start with the first failing layer. A connection failure, an invalid policy, and a transport failure have different remedies.

## Client startup

| Symptom | What to check |
| --- | --- |
| Server absent or disconnected | Confirm the registration name, local STDIO transport, absolute executable path, and separate arguments. In Codex, inspect `codex mcp get recon` and `codex mcp list`, then check connection or discovery in the session. |
| Wrong Python or missing dependencies | For development, run the exact registered interpreter with `-VV` and `-m pip check`. For stable, check the Fedora interpreter and bundled release venv against the [installation guide](installation.md#qualified-stable-fedora-installation). |
| MCP SDK import or startup error | Recon MCP declares MCP SDK `>=1.0.0,<2.0.0`. The qualified combination used MCP 1.30.0. Recreate a clean development venv or reinstall the audited stable bundle if its dependency inventory differs. |
| Server appears idle in a terminal | A valid manual launch waits for STDIO JSON-RPC. Use the client's discovery view or call `health`. Close the manual process before switching a stable version. |
| Stable launcher refuses the path | Confirm that the absolute argument is the physical deployment root containing the launcher, `releases/`, and `runtime/`. Use the launcher path and arguments from [Client setup](client-setup.md). |
| Tool rejected with a generic MCP error | The server may return `Tool input or execution failed. Check the tool schema and arguments.` Compare names, JSON types, required fields, and client-visible tools to the [reference](tool-reference.md). |

## Policy and URL decisions

| Result | What to check |
| --- | --- |
| Valid policy with `safe_to_activate: false` | Missing scope means an empty deny-all policy. Check that your reviewed policy is under the active source tree's `config/scope.json`. |
| `invalid_policy` or `unsupported_policy` | Run offline validation and read `errors`/ `unsupported_rules`. Check JSON syntax, source, bounded file sizes, paths, file type, and snapshot age. |
| Burp rule rejected | Use the reported include or exclude index and field to find the unsupported expression. Review an independent candidate and test the intended behavior offline. See [Burp Advanced Scope](scope-authorization.md#burp-advanced-scope-configuration). |
| `no_matching_inclusion` | Compare the exact host against active rules. Wildcards cover descendants and a separate rule is needed for the apex. |
| `protocol_mismatch` or `port_mismatch` | Check the scheme and effective port. HTTPS defaults to 443 and HTTP to 80. |
| `path_mismatch` or `query_mismatch` | Check exact versus directory-prefix rules, exact query form, and authorization of any derived origin file or redirect. |
| `explicit_exclusion` | The matching exclusion takes precedence. Review the current written boundary before choosing another authorized asset. |
| `sensitive_url` or `invalid_url` | Remove secret-bearing material from the proposed work item and use a clean canonical URL where valid. The original may contain userinfo, a recognizable secret, malformed encoding, or ambiguous syntax. Do not paste it into a support ticket. |
| `policy_changed`, `invalid_campaign_binding`, or `invalid_campaign_anchor` | Review current policy, the original campaign host, and the query-free anchor. Use [local campaign reauthorization](scope-authorization.md#campaign-reauthorization) when appropriate, then repeat the offline check. |

## DNS, HTTP, and TLS

`unsafe_target` can indicate an unsafe literal host or a DNS answer set containing a private or otherwise unsafe address. `dns_failed` indicates public address validation could not complete. Inspect the intended hostname and environment with the authorized owner. Redirect or fallback restrictions apply to the new request independently.

Transport failures may surface as `HTTP request failed.` or a bounded response error. TLS can fail because the destination certificate is invalid, the hostname differs, the trust chain is unrecognized, the clock is wrong, or a network intermediary changes the connection. Check those with the owner and keep TLS verification enabled. If a bounded read rejects a response, review the documented size and truncation fields and use approved smaller inputs where available.

## Campaign storage

| Symptom | What to check |
| --- | --- |
| Permission or ownership refusal | Verify the owner, path components, mount, and mode only on the affected paths. Use [Fedora campaign storage](scope-authorization.md#fedora-campaign-storage) for targeted changes with writers stopped. |
| Supported local Linux filesystem required | Inspect the mount behind the output root with `findmnt -T output`. Use GIL-enabled CPython and a supported local filesystem. Keep active and archived roots on the same mount. |
| `Campaign storage is busy. Retry after the current operation completes.` | Wait for the other cooperating client or thread to finish. Check that its operation has completed before retrying a mutation. Preserve the lock file. |
| Interrupted publication or modified artifact | Check `verify_campaign_artifacts` results and the audit trail. Keep unexpected bytes and markers for review. Restore a verified pair or regenerate from reviewed input when appropriate. |
| Archived ID rejected | Inspect the active and archived listings. Permanent deletion requires an existing archived campaign and an exact ID match in both arguments. |

## Deployment and dependencies

| Symptom | What to check |
| --- | --- |
| `Release manifest checksum mismatch.` | Compare the selected release and expected manifest digest to the separately recorded digest. Verify the release inventory. |
| `Release files do not match the sealed inventory.` or `Active source does not match the sealed release.` | Stop clients. Inspect the installed version and integrity failure. Use a trusted sealed release or a clean verified installation and [activation recovery](deployment.md#rollback-and-interrupted-activation). |
| Activation refuses while clients are running | Close all clients using the guarded root and stop any manual launcher serving it. Retry once the shared lock is released. |
| Missing wheel or bad hash | Check the expected asset name, archive digest, wheelhouse checksums, architecture, interpreter build, and the exact hash lock. Reacquire the released asset if verification fails. |
| Offline namespace refused | Use a Fedora system that permits the documented user and network namespace. The qualified installation uses the recorded network-isolated procedure. |
