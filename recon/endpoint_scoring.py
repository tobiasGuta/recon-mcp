"""Endpoint prioritization for manual review."""

from __future__ import annotations

from urllib.parse import urlsplit


STATIC_SUFFIXES = (".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf")
RULES = [
    ("/admin", 6, "admin route"),
    ("/internal", 6, "internal route"),
    ("/graphql", 5, "GraphQL route"),
    ("/openapi", 5, "OpenAPI documentation route"),
    ("/swagger", 5, "Swagger documentation route"),
    ("/api/", 4, "API route"),
    ("/auth", 4, "auth route"),
    ("/oauth", 4, "OAuth route"),
    ("/debug", 3, "debug route"),
    ("/metrics", 3, "metrics route"),
    ("/config", 3, "configuration route"),
    ("/reset", 3, "reset route"),
    ("/user", 2, "user/account route"),
    ("/account", 2, "user/account route"),
]


def _endpoint_value(endpoint: dict | str) -> str:
    if isinstance(endpoint, dict):
        return str(endpoint.get("value") or endpoint.get("url") or endpoint.get("path") or "")
    return str(endpoint or "")


def _priority(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def score_endpoint(endpoint: dict | str) -> dict:
    """Score an endpoint candidate for manual review; no vulnerability is implied."""
    value = _endpoint_value(endpoint)
    lowered = value.lower()
    score = 0
    reasons: list[str] = []

    for needle, points, reason in RULES:
        if needle in lowered:
            score += points
            if reason not in reasons:
                reasons.append(reason)

    parsed = urlsplit(value)
    query = parsed.query or ("?" in value and value.split("?", 1)[1])
    path = parsed.path or value.split("?", 1)[0]
    if query:
        score += 2
        reasons.append("query parameters present")

    if path.lower().endswith(STATIC_SUFFIXES):
        score -= 5
        reasons.append("static asset")
    if path.count("/") <= 1 and "." in path.rsplit("/", 1)[-1]:
        score -= 3
        reasons.append("low-signal static route")

    return {
        "ok": True,
        "value": value,
        "score": score,
        "priority": _priority(score),
        "reasons": reasons or ["general manual review candidate"],
        "manual_validation_notes": [
            "Review authorization boundaries manually.",
            "Do not perform destructive actions.",
        ],
    }


def score_endpoints(endpoints: list[dict | str]) -> dict:
    """Score endpoint candidates for safe manual review prioritization."""
    if not isinstance(endpoints, list):
        return {"ok": False, "error": "endpoints must be a list."}
    scored = [score_endpoint(endpoint) for endpoint in endpoints]
    scored.sort(key=lambda item: (-item["score"], item["value"]))
    return {"ok": True, "endpoints": scored, "count": len(scored)}
