import asyncio
import json
import re
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import server

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTICS = {
    "validate_scope_policy",
    "check_url_scope",
    "check_url_scope_batch",
    "get_scope_policy_summary",
    "compare_scope_policies",
    "get_scope_capabilities",
}


def test_scope_mcp_handshake_discovery_and_offline_calls(tmp_path):
    config = tmp_path / "scope.json"
    config.write_text(
        json.dumps(
            {
                "allowed_assets": [
                    {
                        "value": "api.example.test",
                        "scheme": "https",
                        "port": 443,
                        "path_prefix": "/public/",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "before.json").write_text(
        config.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (policies / "after.json").write_text("{}", encoding="utf-8")
    script = """import sys
import socket
from pathlib import Path
import recon.authorization
import recon.scope
import server
def unexpected_network(*args, **kwargs):
    raise AssertionError('The STDIO scope smoke test is offline.')
socket.getaddrinfo = unexpected_network
socket.socket.connect = unexpected_network
recon.scope.DEFAULT_SCOPE_PATH = Path(sys.argv[1])
recon.authorization.COMPARISON_ROOT = Path(sys.argv[2])
server.main()
"""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", script, str(config), str(policies)],
        cwd=str(ROOT),
    )

    async def exercise():
        async with (
            stdio_client(params) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            initialized = await session.initialize()
            assert initialized.serverInfo.name == "recon-mcp"
            discovered = {
                tool.name: tool for tool in (await session.list_tools()).tools
            }
            assert set(discovered) == set(server.AVAILABLE_TOOLS)
            assert len(discovered) == 67
            readme = (ROOT / "README.md").read_text(encoding="utf-8")
            inventory = readme.split("## Available Python MCP Tools", 1)[1].split(
                "##", 1
            )[0]
            assert set(re.findall(r"^- `([a-z_]+)\(", inventory, re.MULTILINE)) == set(
                discovered
            )

            sensitive = "https://AUDIT-RPC-USER:password@api.example.test/?token=AUDIT-RPC-QUERY"
            rejected = await session.call_tool(
                "check_url_scope", {"url": {"invalid_type": sensitive}}
            )
            assert rejected.isError
            assert "AUDIT-RPC" not in rejected.model_dump_json()
            rejected = await session.call_tool(
                "explain_scope_decision", {"host_or_url": sensitive}
            )
            assert not rejected.isError
            assert "AUDIT-RPC" not in rejected.model_dump_json()
            for name in DIAGNOSTICS:
                annotations = discovered[name].annotations
                assert annotations.readOnlyHint and not annotations.openWorldHint
                assert discovered[name].outputSchema["type"] == "object"
            assert discovered["check_url_scope"].inputSchema["required"] == ["url"]
            assert discovered["compare_scope_policies"].inputSchema["required"] == [
                "before",
                "after",
            ]

            async def call(name, arguments=None):
                response = await session.call_tool(name, arguments)
                assert not response.isError, response.content
                return response.structuredContent

            validation = await call("validate_scope_policy")
            assert validation["valid"] and validation["inclusion_count"] == 1
            allowed = await call(
                "check_url_scope",
                {"url": "https://api.example.test/public/?theme=confidential"},
            )
            assert allowed["authorized"] and "confidential" not in json.dumps(allowed)
            nested_url = "https://api.example.test/public/?next=https%3A%2F%2FRC-STDIO-USER%3ARC-STDIO-SECRET%40nested.example.test%2F"
            denied = await call("check_url_scope", {"url": nested_url})
            assert denied["reason_code"] == "sensitive_url"
            assert "RC-STDIO" not in json.dumps(denied)
            spaced_url = nested_url.replace("%40", "%20%40")
            denied = await call("check_url_scope", {"url": spaced_url})
            assert denied["reason_code"] == "invalid_url"
            assert not denied["network_execution_permitted"]
            assert "RC-STDIO" not in json.dumps(denied)
            batch = await call(
                "check_url_scope_batch",
                {
                    "urls": [
                        "https://api.example.test/public/",
                        "https://api.example.test/private/",
                    ]
                },
            )
            assert [result["reason_code"] for result in batch["results"]] == [
                "allowed",
                "path_mismatch",
            ]
            summary = await call("get_scope_policy_summary")
            assert summary["policy_fingerprint"] == validation["policy_fingerprint"]
            capabilities = await call("get_scope_capabilities")
            assert set(capabilities["sources"]) == {
                "manual",
                "h1_snapshots",
                "burp_advanced",
            }
            comparison = await call(
                "compare_scope_policies", {"before": "before", "after": "after"}
            )
            assert comparison["potential_authorization_reduction"]
            assert comparison["removed_rules"]
            config.write_text("malformed", encoding="utf-8")
            assert not (await call("validate_scope_policy"))["valid"]
            assert not (
                await call(
                    "check_url_scope", {"url": "https://api.example.test/public/"}
                )
            )["authorized"]
            config.write_text("{}", encoding="utf-8")
            assert not (await call("get_scope_policy_summary"))["safe_to_activate"]
            assert not (
                await call(
                    "check_url_scope", {"url": "https://api.example.test/public/"}
                )
            )["authorized"]

    async def smoke():
        await asyncio.wait_for(exercise(), timeout=15)

    asyncio.run(smoke())
