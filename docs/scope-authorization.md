# Scope authorization

Recon MCP authorizes a complete HTTP or HTTPS request URL against one active local policy. Host inventory tools can identify program assets and suggest evidence labels. A hostname-only lookup always reports `network_execution_permitted: false`. The six scope diagnostics and the local validation CLI perform no DNS lookups or HTTP requests.

## Choose a source

| Source | Authorization | Source limitations |
| --- | --- | --- |
| `manual` | Exact hosts, explicit wildcards, and optional scheme, effective port, exact path, directory prefix, and exact raw query restrictions. Exclusions override inclusions. | A bare hostname rule covers both supported schemes, all valid ports, and any accepted path or query. `url_include` narrows the initial inclusion list. |
| `h1_snapshots` | Local structured scope entries. Bare names match exactly, explicit `*.` rules match descendants, and complete URLs preserve scheme, port, exact path, and any explicitly present query. Submission eligibility is required. Bounty eligibility can be required separately. | Free-text instructions exclude the affected entries until a human translates them into a supported policy. Clearly non-web assets for iOS, Android, source code, executables, and hardware are skipped. Unrecognized asset types or snapshot fields invalidate the policy. Optional maximum age uses the local file modification time. |
| `burp_advanced` | Enabled Advanced Scope rules match protocol, normalized host, effective port, and path. Exclusions override inclusions. | Only the documented regex subset is supported. Burp's File field ignores queries. A Burp export carries no bounty-eligibility information. [PortSwigger Advanced Scope documentation](https://portswigger.net/burp/documentation/desktop/tools/target/scope) |

The active configuration is `config/scope.json` relative to the source tree the server loads. A development install reads it from the checkout. The guarded stable deployment reads it from the physical `runtime/` tree. Run the examples against disposable state. A missing file gives an empty manual policy. Empty scope denies every request. Malformed input denies requests without falling back to an earlier policy. When replacing an active file, write a complete replacement beside it and rename it over the old file. Recon MCP reads the current policy on demand and checks for changes while reading source files. H1 snapshot directories are local inputs. The server never calls HackerOne to refresh them.

### Manual configuration

```json
{
  "scope_source": "manual",
  "allowed_assets": [
    {"value": "api.example.test", "scheme": "https", "port": 443, "path_prefix": "/public/"},
    {"value": "*.cdn.example.test", "match": "wildcard", "scheme": "https", "port": 443},
    {"value": "docs.example.test", "scheme": "https", "port": 8443, "path": "/index.json", "query": "lang=en"}
  ],
  "url_exclude": [
    {"value": "api.example.test", "path_prefix": "/public/private/"}
  ],
  "blocked_domains": ["internal.example.test"]
}
```

An inclusion may be a plain legacy `allowed_domains` entry, a complete URL in `allowed_domains` or in an asset's `value`, or an asset object with explicit fields. Use either `path` or `path_prefix`. Prefixes end in `/`. For example, `/public/` covers `/public/about` and leaves `/public` outside that prefix. Use `query` to require an exact raw query string without its leading question mark. Parameter order, escaping, and repetition are significant. A query-free complete URL rule imposes no query constraint. A complete URL with no path uses `/`.

If an existing hostname list should stay in place, supply a `url_include` array of asset objects. A request must match the list of initial inclusions and one member of `url_include`. An explicit empty `url_include` denies all requests. `url_exclude` accepts the same asset format. `blocked_domains` accepts bare names and blocks each name plus its descendants. An explicit wildcard in an asset covers multiple subdomain levels and leaves the apex outside scope.

In this example, the exact query rule covers `https://docs.example.test:8443/index.json?lang=en`. Omitting the port, changing the path, or adding another query parameter denies it. The `api.example.test` exclusion overrides the otherwise eligible `/public/` inclusion.

### HackerOne snapshots

```json
{
  "scope_source": "h1_snapshots",
  "h1_snapshot_dir": "/absolute/path/to/local/snapshots",
  "h1_snapshot_program": "example-program",
  "include_only_submission_eligible": true,
  "include_only_bounty_eligible": false,
  "h1_snapshot_max_age_seconds": 86400
}
```

Point `h1_snapshot_dir` to the local snapshot directory. If it contains multiple JSON files, use `h1_snapshot_program` to select one by filename without `.json`. Network authorization uses one program. An unselected multi-program directory remains available as legacy host inventory. This source always requires submission eligibility for URL authorization. The existing submission filter continues to control inventory visibility. Non-submission-eligible entries and entries filtered by the optional bounty requirement are exclusions, including when a wildcard also covers the target. Nonempty asset instructions are handled as exclusions. An exact parent entry can still help label a child in the legacy inventory. To authorize the child, the policy must include it through an exact or explicit wildcard rule. An omitted age limit leaves freshness verification to the operator. Review the upstream program scope independently of the snapshot timestamp. Give Recon MCP only the local structured snapshot path. Keep API credentials and watcher configuration in the external integration's own private environment. [HackerOne structured scope schema](https://api.hackerone.com/hacker-reference/#structured-scope)

### Burp Advanced Scope configuration

```json
{
  "scope_source": "burp_advanced",
  "burp_scope_file": "/absolute/path/to/runtime/config/policies/burp-scope-reviewed.json"
}
```

In Burp Suite, configure **Target scope** using advanced rules. In **Settings**, save the **Target** project settings to a private JSON file. Use the **Target** subset to avoid including unrelated project configuration. Preserve the original export and copy only the reviewed scope into a candidate as needed. [PortSwigger settings export](https://portswigger.net/burp/documentation/desktop/settings) · [PortSwigger target scope](https://portswigger.net/burp/documentation/desktop/tools/target/scope)

This complete export uses reserved synthetic names.

```json
{
  "target": {
    "scope": {
      "advanced_mode": true,
      "include": [
        {
          "enabled": true,
          "protocol": "https",
          "host": "^api\\.example\\.test$",
          "port": "^443$",
          "file": "^/public/.*$"
        }
      ],
      "exclude": [
        {
          "enabled": true,
          "protocol": "https",
          "host": "^api\\.example\\.test$",
          "port": "^443$",
          "file": "^/public/private/.*$"
        }
      ]
    }
  }
}
```

Use an absolute path to a local export with `target.scope.advanced_mode: true` and `include` and `exclude` arrays. See [the synthetic export](../config/burp-scope.example.json). Keep the original export and prepare a reviewed local copy if edits are needed. Recon MCP opens files read-only. It rejects symlinks, remote URLs, unexpected enabled rule fields, and non-regular files.

Every rule requires a Boolean `enabled`. Disabled rules have no effect. The `protocol` field accepts HTTP, HTTPS, any, or blank, regardless of case. A missing or blank host, port, or file field matches all values of that component. The literal expression `.*` also matches all values. Other expressions require explicit `^` and `$` anchors. The supported ASCII grammar consists of literal alphanumerics and punctuation, escaped regex punctuation, dot, positive character classes with ASCII letter or digit ranges, and at most one `.*` per expression. DNS host expressions use lowercase ASCII or IDNA A-labels. For example, `^api\.example\.test$` matches the exact host, `^.*\.example\.test$` matches its descendants, `^443$` matches HTTPS's implicit or explicit port 443, and `^/public/.*$` matches paths beneath `/public/`.

Groups, alternation, lookarounds, backreferences, flags, Unicode classes, other quantifiers, unanchored patterns, and Burp IP range syntax are rejected. A single variable-width token is evaluated by matching fixed-width prefix and suffix portions. The parser rejects unsupported expressions before applying any rule, including unsupported exclusions. For example, `^/.*` has no closing anchor and is rejected. `^/.*$` is accepted and matches paths beginning with `/`. Confirm the intended match and exclusion semantics manually before editing either side of an export. Review allow and deny cases offline, including excluded paths and explicit non-default ports. Native Burp runtime parity is outside qualification.

## Offline validation and migration

For stable deployments, ordinary private state can look like this:

```text
~/.local/share/recon-mcp/runtime/
├── config/
│   ├── scope.json
│   └── policies/
│       ├── burp-scope.json
│       ├── burp-scope-reviewed.json
│       └── candidate-reviewed.json
└── output/
```

Use the same version's venv for the offline CLI. From the development checkout, set `py="$PWD/.venv/bin/python"`. From the stable runtime, set it to the active release's interpreter as shown below. Keep the physical runtime's code unchanged and use the guarded launcher for serving MCP.

```bash
root="$HOME/.local/share/recon-mcp"
cd -- "$root/runtime"
py="$root/releases/0.2.0/.venv/bin/python"
```

1. Stage changes separately in a private directory. The CLI accepts a config path for `validate` and `check` without activating it. On stable and development installations, use the selected `py` from the corresponding source root.

   ```bash
   "$py" -E -s -B -m recon.scope_cli validate --config config/policies/candidate-reviewed.json
   "$py" -E -s -B -m recon.scope_cli check https://api.example.test/public/ --config config/policies/candidate-reviewed.json
   "$py" -E -s -B -m recon.scope_cli check https://api.example.test/public/private/ --config config/policies/candidate-reviewed.json
   ```

   For the example Burp policy, the final check exits 1 with `explicit_exclusion`. Test both positive and negative URLs, including ports, schemes, paths, and queries. Check the full policy fingerprint, source, rule counts, and warnings.

2. Optionally compare staged copies named `before.json` and `after.json` inside `config/policies/`. Use physical local source paths within the comparison directory for all referenced files and snapshot directories. Relative H1 paths resolve from the working directory and must still fall inside the comparison directory. Use absolute paths for predictable comparisons.

   ```bash
   "$py" -E -s -B -m recon.scope_cli compare before after
   ```

3. Back up the active config and every referenced export or snapshot in private storage. Review the candidate's referenced files again before activation. From the physical source root, publish a complete same-directory replacement with private permissions.

   ```bash
   pending_policy=$(mktemp config/.scope.XXXXXXXX)
   install -m 0600 -- config/policies/candidate-reviewed.json "$pending_policy" &&
     mv -T -- "$pending_policy" config/scope.json &&
     "$py" -E -s -B -m recon.scope_cli validate
   ```

   Compare the active fingerprint to the reviewed candidate. If activation or verification fails, inspect the error and remove any unused temporary file. A changed fingerprint pauses network work for existing campaigns. To restore a backup, repeat validation and atomic replacement using the backed-up policy and its reviewed sources.

The CLI exits with status 1 when validation finds a rejected or empty policy, a URL is denied, the comparison fails, or campaign reauthorization fails. The MCP validation result distinguishes syntactic validity from readiness. A valid empty policy has `valid: true` and `safe_to_activate: false`. An indeterminate comparison may still succeed as a structural diff.

### Reading a URL decision

See the [tool reference](tool-reference.md#authorization-and-scope) for the six diagnostic schemas. Each URL decision includes a unique `decision_id`, a UTC `timestamp`, redacted normalized components, a policy source and schema version, and matching rule descriptions where available. Rule descriptions omit query values.

| Field | Meaning |
| --- | --- |
| `authorized` | The full URL satisfied the current compiled policy and offline URL checks. |
| `in_scope` | Mirrors `authorized` in the full URL response. A legacy hostname result uses this field for inventory membership. |
| `network_execution_permitted` | Mirrors `authorized` in the full URL response. Dispatch still checks policy, addresses, and applicable campaign binding. Host inventory always returns false here. |
| `reason_code` | Machine-readable reason for the decision. A regular scope denial can carry `ok: true`, so read `authorized` for the decision. |
| `policy_fingerprint` | SHA-256 of the canonical policy. It may be null if the URL was rejected before policy loaded. Formatting, rule order, duplicates, and HTTP processing settings do not affect it. |

With the sample manual policy, `https://api.example.test/public/` returns `allowed` and true for all three URL flags. `https://api.example.test/public/private/` returns `explicit_exclusion` and false for those flags. These results demonstrate local rule matching. Confirm current written program or owner permission independently.

### Interoperability flags

Eligibility fields are supplied by inventory and interoperability responses where applicable. The direct `check_url_scope` result has the decision fields above. Manual and Burp policies provide URL authorization. Their submission and bounty eligibility values are JSON `null`. H1 host inventory retains explicit Boolean eligibility values. Missing values remain unknown. An authorized H1 URL establishes submission eligibility under the current policy. A rejected URL leaves the remote program's eligibility unknown.

| Flag | Meaning |
| --- | --- |
| `scope_ok` | The legacy evidence association signal requires a reported scope match and explicit submission eligibility. |
| `authorized_url` | The complete URL passed current offline authorization. Host inventory cannot set this flag. |
| `submission_eligible`, `bounty_eligible` | Source-reported eligibility or `null` when unknown. |
| `can_test`, `can_scan` | Reserved values are always false. Consumers need their own authorization for execution. |
| `can_store_evidence` | The legacy evidence label follows `scope_ok` and carries no network permission. |
| `normalized_host`, `recommended_bugmap_target_label` | Redacted association hints for local consumers. |
| `risk_warning` | Diagnostic text about unknown or denied eligibility or policy limits. |

Existing consumers that treated `can_test`, `can_scan`, or manual inventory eligibility as approval must migrate to a complete URL decision and their own execution controls. The in-repository BugMap label recommendation remains available.

### Decision reason codes

| Reason code | Meaning |
| --- | --- |
| `allowed` | An applicable inclusion and any required narrowing rule matched. |
| `explicit_exclusion` | A policy exclusion matched. |
| `no_matching_inclusion` | No applicable inclusion matched the host. |
| `protocol_mismatch`, `port_mismatch`, `path_mismatch`, `query_mismatch` | At least one rule matched the preceding URL components but failed on the named constraint. A denial reports the furthest matching component in scheme, port, path, query order. |
| `invalid_url`, `sensitive_url` | The URL is ambiguous, malformed, or contains credential-like data. |
| `invalid_policy`, `unsupported_policy` | The policy could not be compiled safely. |
| `policy_changed` | An operation's expected fingerprint or campaign binding changed. |
| `unsafe_target`, `dns_failed` | The address is unsafe, or the transport could not establish public DNS results. |

Campaign and transport guard errors also include `invalid_campaign_binding`, `invalid_campaign_anchor`, `audit_unavailable`, `redirect_limit`, and `invalid_method` as applicable. The legacy hostname tools retain inventory-oriented reason codes and evidence labels.

## Campaign reauthorization

Creation records the canonical original target and its authorization decision in `campaign.json` and `scope.json`. A bare hostname uses its HTTPS root URL. Campaign anchors must be query-free. Use an explicit authorized URL for assets with path or port restrictions. A policy that authorizes only query-bearing URLs cannot anchor a campaign until the operator establishes a permitted query-free URL. Network-facing campaign operations require the current policy to match the saved binding and still permit the campaign anchor. Each actual network request independently passes the same current policy. Campaign bindings cover the active policy, so each request still needs its own inclusion and exclusion evaluation.

If a campaign has no binding or the fingerprint changed, review the active policy and reauthorize from a local interactive terminal. Use the same current environment and `py` path as for offline validation.

```bash
"$py" -E -s -B -m recon.scope_cli validate
"$py" -E -s -B -m recon.scope_cli check https://api.example.test/public/
"$py" -E -s -B -m recon.scope_cli reauthorize-campaign CAMPAIGN_ID https://api.example.test/public/ --confirm-fingerprint FULL_POLICY_FINGERPRINT
```

Use an anchor on the campaign's original normalized hostname. This updates its active binding and appends an audit event. The original scope snapshot, existing artifacts, and evidence remain available. Reauthorization is exposed through the local CLI and requires the currently reviewed fingerprint. Historical campaign reads continue when the active policy changes or becomes invalid.

## Operational limits

- The DNS preflight rejects mixed public and unsafe answers, malformed answers, empty sets, and more than 64 distinct addresses. The transport attempts at most eight approved numeric endpoints within the connect deadline and checks the reported TCP peer. Redirects and fallback requests each use a fresh connection. The original host remains the HTTP authority and TLS identity. Proxies from the environment are ignored and Certifi chain verification stays enabled. Local routing, destination NAT, infrastructure proxies, and interception are outside the application socket boundary. Policy files can change after the last decision. An egress policy can enforce restrictions at additional layers.
- URL matching uses the canonical request target, lowercase IDNA host, and effective port. Query inspection checks ambiguous separators and credential assignments across at most four decoding steps and rejects malformed encoding. The server rejects credentials, fragments, ambiguous authority syntax, encoded paths, repeated slashes, dot segments, and path parameters. Program constraints that depend on server-side routing, opaque application state, or documentation require human review.
- All scope configuration and Burp files are bounded to 1 MiB. Burp accepts up to 256 rules per list and 256 characters per expression. Policies have a 1,024 combined-rule limit. H1 snapshot reads allow up to 64 JSON files and 20 MiB total, subject to per-file and per-directory entry limits.
- Passive provider requests require both an authorized HTTPS root and authorization for the provider's actual URL, including a configured query restriction where applicable. Queries disclose the root to that provider. Optional DNS lookups only consider discovered hosts whose HTTPS root URL is authorized. Other names remain offline leads. The passive result’s legacy `testable` field records HTTPS root URL authorization and still requires manual review.
- Campaign dispatch appends structured audit records. Network artifacts include the current policy fingerprint and campaign binding alongside the original scope snapshot hash. Raw artifacts such as downloaded source maps can contain sensitive upstream content and should be stored privately. Historical artifacts retain their original bytes.
- Supported Linux campaign storage uses one kernel lock per output directory, shared by active and archived campaigns. The owning thread can reenter it. Concurrent readers and writers wait up to two seconds. The lock covers network campaign workflows, so a long-running workflow can cause other calls to return a busy error. The mount must be local and supported. Concurrent external software must honor the same lock. Artifact pairs use durable markers for interruption detection. Audit and memory appends preserve committed lines and recover bounded interrupted tails. These controls do not create a general crash-atomic transaction across an entire campaign workflow.

### Credential inspection and redaction

Scope checks inspect query values even when the surrounding parameter name is nonsensitive. Shared inspection classifies each value as clean, sensitive, or ambiguous. It examines nested URL authorities across up to four percent or form-decoding steps, with Unicode normalization and limited structural escaping. A separate inspection-only view checks for userinfo split by whitespace or controls. Apparent split authorities, malformed encoding, and excessive decoding fail closed. Query inspection is limited to 4,096 characters. Recognized credentials produce `sensitive_url`, and ambiguity produces `invalid_url`. Both stop before DNS. Only the authorized canonical URL, with its original query bytes, reaches the transport.

Diagnostic, error, audit, and artifact metadata redaction removes recognizable URL credentials. Plain textual context can retain the destination hostname. Nested credential-bearing query values are suppressed, and ambiguous or oversized text can be replaced in full. Sanitization scans at most 64 Ki characters per text value and bounds structured traversal. These checks cover supported URL representations. Application-specific, encrypted, or otherwise opaque payloads still require separate handling. Raw upstream evidence, including downloaded source maps, can contain sensitive content.

### Fedora campaign storage

New `output`, active and archived roots, campaign directories, and generated subdirectories are created with private `0700` permissions under normal Fedora umasks, including `0002`. The lock file is private `0600`. The storage parent must be owned by the running user, have owner access, and permit no group or other writes. Existing active and archived roots and campaign directories must be owned by that user with mode `0700`. A group-writable Git-created `output` directory fails closed. Existing permissions are never changed automatically.

Stop campaign writers before reviewing ownership and permissions. Use `stat -c '%a %U %n' -- output output/campaigns output/archived_campaigns` on directories that exist. After verifying that the paths are trusted directories you own, remove group and other write access from `output` with `chmod go-w -- output`. Set the existing active and archived roots to `0700` with `chmod 700 -- output/campaigns output/archived_campaigns`. Review individual existing campaign directories and apply `chmod 700` only to those that need correction. Ask the storage owner or administrator to investigate unexpected ownership, links, or mounts.

Campaign locking requires GIL-enabled CPython on Linux and an allowlisted local filesystem. The mount allowlist contains Btrfs, ext2/3/4, tmpfs, and XFS. The owning thread can reenter the lock, and independently launched processes coordinate through the same file. The bookkeeping assumes server threads run in the original process. Do not fork an in-flight campaign operation from a multithreaded server and resume it in the child. The single-threaded fork fixture verifies inherited lock cleanup without releasing the parent lock. Internal path snapshots require the caller to hold the storage lock while using those paths.

### TLS qualification

The Fedora fixture generated a temporary CA and leaf certificate and listened only on an ephemeral IPv4 loopback port. It executed the pinned transport and real OpenSSL handshake. The trusted certificate succeeded, SNI and HTTP Host matched the authorized identity, and the server observed the connection close. The untrusted and wrong-host certificates failed verification before HTTP. Only the test admits its exact loopback endpoint and uses its test CA. Production local-address restrictions and certificate verification apply as before. The fixture does not qualify external routing, Windows execution, or native Burp runtime parity.

See [Troubleshooting](troubleshooting.md#policy-and-url-decisions) for scope diagnostics and recovery.
