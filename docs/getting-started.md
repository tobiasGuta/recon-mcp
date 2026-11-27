# Getting started

An MCP client launches Recon MCP as a subprocess and exchanges JSON-RPC messages with it over standard input and output, called STDIO. The client discovers tools, sends arguments, and receives results. Recon MCP listens on the subprocess streams. You do not need to open a network port.

## Install and connect

On qualified Fedora, use the [stable release](installation.md#qualified-stable-fedora-installation). For code or documentation development, use a [separate checkout](installation.md#development-installation). You need a local STDIO-compatible client and access to the chosen Python environment.

Register the server in your [client](client-setup.md). Use a fresh or disposable installation for this exercise so you can start with empty scope and avoid changing private state.

In the client, call `health` with `{}`. Expect `ok: true`, `version: "0.2.0"` for the stable release, and 67 entries in `available_tools`. That field is the server inventory. Use the client's tool discovery view to see which tools the client exposes.

Call `validate_scope_policy` with `{}`. A missing config loads a valid empty policy. Expect `valid: true`, `inclusion_count: 0`, and `safe_to_activate: false`. A `check_url_scope` call for `https://api.example.test/public/` should return `no_matching_inclusion`. Neither tool resolves the hostname or sends HTTP.

## Review a synthetic policy offline

Save this JSON as `config/scope.json` in the disposable server tree. For stable installs, that is under `runtime/`. For development it is under the checkout root. Use [candidate validation](scope-authorization.md#offline-validation-and-migration) when changing any existing policy.

```json
{
  "scope_source": "manual",
  "allowed_assets": [
    {"value": "api.example.test", "scheme": "https", "port": 443, "path_prefix": "/public/"}
  ]
}
```

From the same client, call these tools individually with the listed arguments.

| Tool | JSON arguments | Expected fields |
| --- | --- | --- |
| `get_scope_capabilities` | `{}` | `sources` includes `manual`, `h1_snapshots`, and `burp_advanced` |
| `validate_scope_policy` | `{}` | `valid: true`, `safe_to_activate: true`, one inclusion and a fingerprint |
| `check_url_scope` | `{"url":"https://api.example.test/public/"}` | `authorized: true`, `network_execution_permitted: true`, `reason_code: "allowed"` |
| `check_url_scope` | `{"url":"https://api.example.test/private/"}` | `authorized: false`, `network_execution_permitted: false`, `reason_code: "path_mismatch"` |

The server reads policy on demand, so a valid edit should take effect without restarting the client. A positive offline result means the URL matches the current local policy. It says nothing about live DNS, TLS, or the rules of a real program. Keep this reserved domain for offline tests and confirm written authorization before working with real assets.

Next, use [Campaigns](campaigns.md) to organize synthetic notes or [Troubleshooting](troubleshooting.md) if the expected fields differ.
