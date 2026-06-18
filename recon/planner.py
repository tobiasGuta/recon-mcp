"""Manual validation checklist generation."""

from __future__ import annotations


def _as_list(value: object) -> list:
    """Coerce target summary fields to a list."""
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def generate_manual_test_plan(target_summary: dict) -> dict:
    """Generate a safe, human-led recon and validation checklist."""
    if not isinstance(target_summary, dict):
        return {"ok": False, "error": "target_summary must be a dictionary."}

    endpoints = _as_list(target_summary.get("endpoints"))
    js_urls = _as_list(target_summary.get("js_urls"))
    interesting_headers = target_summary.get("interesting_headers") or {}

    checklist = [
        "Confirm the target, subdomains, and URLs are explicitly allowed by the bug bounty scope.",
        "Review authentication boundaries manually using authorized test accounts only.",
        "Check authorization-sensitive flows for IDOR or access control issues without bypassing controls.",
        "Review interesting endpoints for expected methods, parameters, roles, and documentation.",
        "Review JavaScript routes and API references for hidden or deprecated functionality.",
        "Review headers and cookie flags as configuration signals that may need manual validation.",
        "Review robots.txt and sitemap.xml for paths that deserve manual inspection.",
        "Look for public API documentation, OpenAPI specs, GraphQL schemas, and client configuration files.",
        "Hand off scoped directory fuzzing to the separate Go DirFuzz MCP server when appropriate.",
        "Collect screenshots, request/response metadata, timestamps, and affected URLs for evidence notes.",
        "Do not attempt exploitation, credential attacks, account creation, bypasses, or high-volume scanning without explicit permission.",
    ]

    priority_items = []
    if endpoints:
        priority_items.append(f"Manually review {len(endpoints)} extracted endpoint candidate(s).")
    if js_urls:
        priority_items.append(f"Review {len(js_urls)} JavaScript file(s) for routes and client-side API usage.")
    if interesting_headers:
        priority_items.append("Review observed security headers and cookie flags in context.")
    if not priority_items:
        priority_items.append("Start with scope confirmation, headers, robots.txt, sitemap.xml, and JavaScript collection.")

    dirfuzz_handoff = [
        "Use the Go DirFuzz MCP server only after confirming the target is in scope.",
        "Recommended Go DirFuzz tools: dirfuzz_build_scan, dirfuzz_scan, dirfuzz_scan_status, dirfuzz_analyze, dirfuzz_cancel.",
        "Use Python Recon MCP afterward to organize findings into evidence notes and manual review plans.",
    ]

    warnings = [
        "This checklist is for authorized, human-led security testing only.",
        "Do not run destructive requests, login attacks, brute force, bypass attempts, or out-of-scope scans.",
        "Possible endpoints are not vulnerabilities by themselves; validate manually and ethically.",
    ]

    return {
        "ok": True,
        "checklist": checklist,
        "priority_items": priority_items,
        "dirfuzz_handoff": dirfuzz_handoff,
        "warnings": warnings,
    }
