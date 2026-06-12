"""URL normalization and deduplication helpers."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Normalize a URL for safe comparison and deduplication."""
    raw = (url or "").strip()
    if not raw:
        return ""

    parts = urlsplit(raw)
    scheme = (parts.scheme or "https").lower()
    hostname = (parts.hostname or "").lower()

    if not hostname:
        return raw

    port = parts.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = hostname
    elif port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), doseq=True)
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, query, ""))


def dedupe_urls(urls: list[str]) -> dict:
    """Normalize and deduplicate URLs while preserving sorted output."""
    normalized = {normalize_url(url) for url in urls if normalize_url(url)}
    deduped = sorted(normalized)
    return {
        "ok": True,
        "original_count": len(urls),
        "deduped_count": len(deduped),
        "urls": deduped,
    }
