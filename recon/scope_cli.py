"""Local policy validation, URL checks, and human-operated campaign reauthorization."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from recon.authorization import (
    check_url_scope,
    compare_scope_policies,
    validate_scope_policy,
)
from recon.campaigns import reauthorize_campaign


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate a configuration offline.")
    validate.add_argument("--config", type=Path)
    check = commands.add_parser("check", help="Evaluate one complete URL offline.")
    check.add_argument("url")
    check.add_argument("--config", type=Path)
    compare = commands.add_parser(
        "compare", help="Compare two names from config/policies."
    )
    compare.add_argument("before")
    compare.add_argument("after")
    reauthorize = commands.add_parser(
        "reauthorize-campaign",
        help="Bind a campaign to the current policy after human review.",
    )
    reauthorize.add_argument("campaign_id")
    reauthorize.add_argument("target")
    reauthorize.add_argument("--confirm-fingerprint", required=True)
    args = parser.parse_args(argv)

    if args.command == "validate":
        result = validate_scope_policy(args.config)
        success = result["safe_to_activate"]
    elif args.command == "check":
        result = check_url_scope(args.url, config_path=args.config)
        success = result["authorized"]
    elif args.command == "compare":
        result = compare_scope_policies(args.before, args.after)
        success = result["ok"]
    else:
        if not sys.stdin.isatty():
            result = {
                "ok": False,
                "error": "Run campaign reauthorization from a local interactive terminal.",
            }
        else:
            result = reauthorize_campaign(
                args.campaign_id, args.target, args.confirm_fingerprint
            )
        success = result["ok"]

    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
