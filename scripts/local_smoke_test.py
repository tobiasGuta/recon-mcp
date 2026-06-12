"""Optional local smoke test for real H1-Scope-Watcher snapshots.

This script is intentionally not part of the default pytest suite. It reads only
snapshot JSON files from a user-supplied directory and does not make HTTP
requests or read H1-Scope-Watcher .env/config.yaml files.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.h1_scope import extract_allowed_hosts_from_h1_entries, load_h1_snapshots
from recon.scope import check_scope, list_loaded_scope


DEFAULT_BLOCKED_TARGETS = ["example.com", "localhost", "127.0.0.1", "192.168.1.10"]


def _config(snapshot_dir: Path) -> dict:
    return {
        "scope_source": "h1_snapshots",
        "h1_snapshot_dir": str(snapshot_dir),
        "include_only_bounty_eligible": False,
        "include_only_submission_eligible": True,
        "allowed_domains": [],
        "blocked_domains": ["localhost", "127.0.0.1", "0.0.0.0", "::1"],
    }


def _pick_allowed_host(snapshot_dir: Path, snapshot_file: str | None) -> str:
    entries = load_h1_snapshots(str(snapshot_dir))
    if snapshot_file:
        entries = [entry for entry in entries if Path(str(entry.get("_source_file"))).name == snapshot_file]
    if not entries:
        raise RuntimeError("No matching snapshot entries were loaded.")

    extracted = extract_allowed_hosts_from_h1_entries(
        entries,
        include_only_bounty_eligible=False,
        include_only_submission_eligible=True,
        blocked_domains=_config(snapshot_dir)["blocked_domains"],
    )
    allowed_hosts = extracted["allowed_hosts"]
    if not allowed_hosts:
        raise RuntimeError("No allowed hosts were extracted from the selected snapshot data.")

    first = allowed_hosts[0]
    return f"codex-smoke.{first['host']}" if first.get("wildcard") else first["host"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an optional local H1 snapshot smoke test.")
    parser.add_argument("--snapshot-dir", required=True, help="Directory containing H1-Scope-Watcher snapshot JSON files.")
    parser.add_argument("--snapshot-file", help="Optional single snapshot JSON filename to verify.")
    parser.add_argument(
        "--blocked-target",
        action="append",
        default=[],
        help="Additional target that must be out of scope. May be supplied more than once.",
    )
    args = parser.parse_args()

    snapshot_dir = Path(args.snapshot_dir).expanduser().resolve()
    blocked_targets = DEFAULT_BLOCKED_TARGETS + args.blocked_target

    import recon.scope as scope_module

    scope_module.load_scope = lambda: _config(snapshot_dir)

    summary = list_loaded_scope()
    if not summary.get("ok") or summary.get("allowed_hosts_count", 0) < 1:
        raise RuntimeError(f"Scope summary failed closed: {summary.get('warnings') or summary}")

    allowed_host = _pick_allowed_host(snapshot_dir, args.snapshot_file)
    allowed_result = check_scope(allowed_host)
    if not allowed_result.get("in_scope"):
        raise RuntimeError(f"Expected selected allowed host to be in scope: {allowed_host}")

    failures = []
    for target in blocked_targets:
        if check_scope(target).get("in_scope"):
            failures.append(target)
    if failures:
        raise RuntimeError(f"Expected these targets to be out of scope: {', '.join(failures)}")

    print("Local smoke test passed.")
    print(f"Snapshot directory: {snapshot_dir}")
    if args.snapshot_file:
        print(f"Snapshot file: {args.snapshot_file}")
    print(f"Allowed hosts loaded: {summary['allowed_hosts_count']}")
    print(f"Selected allowed host checked: {allowed_host}")
    print(f"Blocked targets checked: {', '.join(blocked_targets)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Local smoke test failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
