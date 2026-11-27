# MCP client setup

Complete [installation](installation.md) and use a disposable, empty-policy instance for first connection checks. Use absolute paths that refer to the same installation. These templates pass no platform credentials to the server.

## Codex CLI

On the qualified stable environment, set `root` to the physical stable root. Configure the guarded launcher using the CLI or the TOML below.

```bash
root="$HOME/.local/share/recon-mcp"
codex mcp add recon -- /usr/bin/python3.15 -I -S -B "$root/stable_deployment.py" serve "$root"
codex mcp get recon
codex mcp list
```

The launcher sets the stable runtime working directory itself. For explicit working-directory and startup settings, put this table in `~/.codex/config.toml` or a trusted project's `.codex/config.toml`. Replace the placeholder root. Edit an existing `recon` table in place if present.

```toml
[mcp_servers.recon]
command = "/usr/bin/python3.15"
args = ["-I", "-S", "-B", "/absolute/path/to/recon-mcp/stable_deployment.py", "serve", "/absolute/path/to/recon-mcp"]
cwd = "/absolute/path/to/recon-mcp/runtime"
startup_timeout_sec = 30
required = true
```

For development, run from the checkout root.

```bash
checkout=$(pwd -P)
codex mcp add recon-dev -- "$checkout/.venv/bin/python" -B "$checkout/server.py"
codex mcp get recon-dev
codex mcp list
```

Use this TOML table for the equivalent development registration.

```toml
[mcp_servers.recon-dev]
command = "/absolute/path/to/checkout/.venv/bin/python"
args = ["-B", "/absolute/path/to/checkout/server.py"]
cwd = "/absolute/path/to/checkout"
```

To replace a CLI registration, close sessions using it, run `codex mcp remove recon`, and re-add it with the desired command. Edit trusted project TOML directly when it owns the definition. Inspect the loaded configuration with `mcp get` and `mcp list`. The interactive `/mcp` view shows session tools. Ask for `health` with no arguments and no target requests.

The qualified Codex CLI 0.171.0 path used the stable TOML, offline `app-server --listen stdio://`, tool discovery, and direct offline tool calls. It included health, all six scope diagnostics, and four URL decisions. The `mcp` registration subcommands manage configuration. The interactive model prompt is an operator check. For a fully offline check that avoids any hosted model invocation, use the [qualified app-server procedure](v0.2.0-release-preparation.md#codex-cli). [Official Codex MCP guide](https://developers.openai.com/codex/mcp/) · [Codex CLI reference](https://learn.chatgpt.com/docs/cli/reference)

## Google Antigravity

In Antigravity IDE, open the agent side panel menu and choose **MCP Servers**, **Manage MCP Servers**, then **View raw config**. The current documentation lists `~/.gemini/config/mcp_config.json` globally and `.agents/mcp_config.json` in the workspace. Use the file opened by your installation. Merge the `recon` entry into `mcpServers`, preserving other entries. Replace the paths with your physical stable root and runtime. Save, then refresh MCP servers in the client or restart it. [Official Antigravity MCP guide](https://antigravity.google/docs/mcp?tab=ide)

```json
{
  "mcpServers": {
    "recon": {
      "command": "/usr/bin/python3.15",
      "args": [
        "-I", "-S", "-B",
        "/absolute/path/to/recon-mcp/stable_deployment.py",
        "serve", "/absolute/path/to/recon-mcp"
      ],
      "cwd": "/absolute/path/to/recon-mcp/runtime",
      "disabled": false
    }
  }
}
```

This full-access entry exposes all 67 server tools, subject to client and workspace settings. Those tools include authorized network requests and campaign writes, archiving, and permanent archived deletion. Review the requested action in the client before approval. Where supported, Antigravity's `enabledTools` can limit discovery to tools such as `health`, `validate_scope_policy`, `get_scope_capabilities`, and `check_url_scope`.

In a disposable instance, confirm the server is connected and the unfiltered discovery lists 67 tools. Call `health` and check `ok: true` and `version: "0.2.0"`. Call `check_url_scope` for `https://api.example.test/public/` with empty scope. Expect `authorized: false`, `network_execution_permitted: false`, and `reason_code: "no_matching_inclusion"`. The tool call performs no DNS or HTTP. A hosted client session can still use its own network service.

Antigravity connectivity, discovery of all 67 tools, and offline diagnostic execution are operator-reported. The independent release and formal live-network client qualification do not cover Antigravity.

## Standalone Gemini CLI

This STDIO configuration is documented and unverified for Recon MCP. Put the `recon` entry in the CLI's `mcpServers` map in `~/.gemini/settings.json` or trusted project settings. The optional `includeTools` below exposes just the offline diagnostics and health. `excludeTools` takes precedence when both are present. Leave `trust` false for normal confirmations. Check `gemini mcp list` and the interactive `/mcp` view as supported by your version. Verify a tool call independently from listing the registration. [Official Gemini CLI MCP guide](https://geminicli.com/docs/tools/mcp-server/)

```json
{
  "mcpServers": {
    "recon": {
      "command": "/usr/bin/python3.15",
      "args": ["-I", "-S", "-B", "/absolute/path/to/recon-mcp/stable_deployment.py", "serve", "/absolute/path/to/recon-mcp"],
      "cwd": "/absolute/path/to/recon-mcp/runtime",
      "timeout": 30000,
      "trust": false,
      "includeTools": [
        "health", "validate_scope_policy", "check_url_scope", "check_url_scope_batch",
        "get_scope_policy_summary", "compare_scope_policies", "get_scope_capabilities"
      ]
    }
  }
}
```

## Other STDIO clients

Choose local STDIO transport. Use the stable command tuple below, or provide the development interpreter and `server.py` as in the Codex development example. JSON config keys, support for `cwd`, and confirmation settings depend on the client.

```json
{
  "mcpServers": {
    "recon": {
      "command": "/usr/bin/python3.15",
      "args": ["-I", "-S", "-B", "/absolute/path/to/recon-mcp/stable_deployment.py", "serve", "/absolute/path/to/recon-mcp"],
      "cwd": "/absolute/path/to/recon-mcp/runtime"
    }
  }
}
```

`command` is the executable. Each `args` entry is a separate argument. Use a physical working directory if supported. The launcher sets it for stable starts. Recon MCP exposes no HTTP or SSE MCP endpoint.

## Multiple clients

Codex and Antigravity can each launch a separate server process against the same stable root. Those processes share private policy and campaign storage. Cooperating campaign operations share a bounded storage lock, including readers, and a long operation can return a busy error to another client. Serialized operations can still make conflicting changes in succession. Choose a single operator for campaign edits, promotions, and archives, and review the current state before approving them.

Tool filters change what the client exposes. Use separate OS identities and isolated state when you need a filesystem access boundary. A hosted client may send tool results, arguments, or conversation context to its provider. Share only approved, redacted evidence. See [the two-client review workflow](workflows.md#f-two-client-evidence-review).
