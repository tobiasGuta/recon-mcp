"""Local operator review. Intentionally not registered as an MCP tool."""
from __future__ import annotations

import argparse
import sys

from recon.findings import (
    PROMOTIONS, REPORT_GATES, REPORT_CANDIDATE, VALIDATED,
    get_finding, promote_finding,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review a finding in a trusted human-operated terminal.")
    parser.add_argument("campaign_id")
    parser.add_argument("finding_id")
    args = parser.parse_args(argv)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Review requires an interactive local terminal.", file=sys.stderr)
        return 2
    result = get_finding(args.campaign_id, args.finding_id)
    if not result.get("ok"):
        print(ascii(result.get("error")), file=sys.stderr)
        return 1
    finding = result["finding"]
    status = finding.get("status")
    target = PROMOTIONS.get(status)
    if target is None:
        print("No upward transition is available.", file=sys.stderr)
        return 1
    print("Review the finding and its evidence independently before approving.")
    print("Finding:", ascii(finding.get("title")))
    print("Target:", ascii(finding.get("target")))
    print("Evidence file:", ascii(result["path"]))
    print("Transition:", status, "->", target)
    gates: dict[str, bool] = {}
    try:
        if target in {VALIDATED, REPORT_CANDIDATE}:
            for gate in REPORT_GATES:
                if gate == "report_ready" and target != REPORT_CANDIDATE:
                    continue
                if input(f"Personally verified {gate}? [type yes] ") != "yes":
                    print("Review cancelled; no changes made.")
                    return 1
                gates[gate] = True
        reason = input("Review reason: ").strip()
        if not reason or input("Type APPROVE to apply this transition: ") != "APPROVE":
            print("Review cancelled; no changes made.")
            return 1
    except (EOFError, KeyboardInterrupt):
        print("\nReview cancelled; no changes made.", file=sys.stderr)
        return 1
    # Detect changes while the operator was reviewing. This is not a lock.
    current = get_finding(args.campaign_id, args.finding_id)
    if not current.get("ok") or current["finding"] != finding:
        print("Finding changed during review; restart review.", file=sys.stderr)
        return 1
    updated = promote_finding(args.campaign_id, args.finding_id, target, reason, gate_updates=gates)
    if not updated.get("ok"):
        print(ascii(updated.get("error")), file=sys.stderr)
        return 1
    print("Review recorded:", target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
