"""Shared deterministic redaction for URLs and token-shaped text."""

from __future__ import annotations

import re
import unicodedata
from enum import Enum, auto
from itertools import islice
from urllib.parse import (
    parse_qsl,
    unquote_plus,
    urlencode,
    urlsplit,
    urlunsplit,
)

EMBEDDED_URL = re.compile(
    r'(?i)(?<![a-z0-9+./-])(?:[a-z][a-z0-9+.-]{0,31}:)?//[^\s<>"]+'
)
URL_START = re.compile(r"(?i)^(?:[a-z][a-z0-9+.-]*:)?//")
SENSITIVE_NAME = re.compile(
    r"(?i)(token|secret|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key|signature|credential|access[_-]?key)"
)
TOKEN_SHAPE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|AKIA[A-Z0-9]{16})\b"
)
BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
ASSIGNMENT = re.compile(
    r"(?i)((?:token|secret|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key)\s*[=:]\s*['\"]?)[^'\"&\s,;}]{4,}"
)


BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
ESCAPED_BYTE = re.compile(r"%[0-9A-Fa-f]{2}")
CREDENTIAL_ASSIGNMENT = re.compile(SENSITIVE_NAME.pattern + r"[ \t]*[=:]")
MASKED_ASSIGNMENT = re.compile(
    SENSITIVE_NAME.pattern + r"[ \t]*[=:][ \t]*['\"]?<redacted>"
)
QUERY_PARTS = re.compile(r"[&;?#\n\r]")
MAX_DECODE_LAYERS = 4
MAX_QUERY_SCAN_LENGTH = 4096
MAX_TEXT_SCAN_LENGTH = 64 * 1024
MAX_STRUCTURE_DEPTH = 32
MAX_STRUCTURE_ITEMS = 20_000

# A locator identifies a candidate. Separate authority and decoded-view
# checks decide whether its boundaries can be trusted.
LOCATOR = re.compile(r"(?i)(?<![a-z0-9+.-])https?:[/\\]*|[/\\]{2,}")
AUTHORITY_TOKEN = re.compile(r"[^/\\?#\s]*")
AUTHORITY_END = re.compile(r"""[&,;()'"<>]""")
NESTED_AUTHORITY_END = re.compile(r"""[/\\?#&,;()'"<>]""")
HOST_AND_PORT = re.compile(r"(?:\[[0-9A-Fa-f:.]+\]|[\w.-]+)(?::[0-9]{1,5})?")
STRUCTURAL_ESCAPE = re.compile(r"\\{1,4}(?:u([0-9a-f]{4})|([/tnrf]))", re.IGNORECASE)
ENCODED_AT = re.compile(r"%(?:25){0,4}40", re.IGNORECASE)
REDACTED_URL_TEXT = "<credential-bearing-or-ambiguous-text-redacted>"


class Inspection(Enum):
    CLEAN = auto()
    SENSITIVE = auto()
    AMBIGUOUS = auto()


def _is_control(character: str) -> bool:
    return unicodedata.category(character) in {"Cc", "Cf"}


def _decode_structure(match: re.Match) -> str:
    if match[1]:
        character = unicodedata.normalize("NFKC", chr(int(match[1], 16)))
    else:
        character = {"/": "/", "t": "\t", "n": "\n", "r": "\r", "f": "\f"}[
            match[2].lower()
        ]
    # This is a structural inspection pass, not a general string decoder.
    if len(character) == 1 and (
        character in ":/\\@?#" or character.isspace() or _is_control(character)
    ):
        return character
    return match[0]


def _decoded_views(value: str, maximum: int):
    """Inspect the original and at most four percent/form-decoded copies."""
    for layer in range(MAX_DECODE_LAYERS + 1):
        view = STRUCTURAL_ESCAPE.sub(
            _decode_structure, unicodedata.normalize("NFKC", value)
        )
        if len(view) > maximum:
            raise ValueError("Decoded input exceeds the inspection length.")
        yield view
        if not ESCAPED_BYTE.search(view) and "+" not in view:
            return
        if layer == MAX_DECODE_LAYERS:
            raise ValueError("Input exceeds the supported URL decoding depth.")
        value = unquote_plus(view, errors="strict")


def _authorities(view: str):
    for locator in LOCATOR.finditer(view):
        token = AUTHORITY_TOKEN.match(view, locator.end())
        yield locator, token


def _plausible_authority(token: str) -> bool:
    if not HOST_AND_PORT.fullmatch(token):
        return False
    try:
        parsed = urlsplit("//" + token)
        return parsed.hostname is not None and (parsed.port is None or parsed.port > 0)
    except ValueError:
        return False


def _split_nested_authority(view: str, locator: re.Match, token: re.Match) -> bool:
    """Recognize apparent continuation across whitespace in a query value."""
    end = token.end()
    if end == len(view) or not view[end].isspace():
        return False
    start = locator.start()
    while start and view[start - 1].isspace():
        start -= 1
    if not start or view[start - 1] != "=":
        return False
    boundary = NESTED_AUTHORITY_END.search(view, end)
    return bool(view[end : boundary.start() if boundary else len(view)].strip())


def _inspect_authorities(view: str) -> Inspection:
    malformed = False
    for locator, token in _authorities(view):
        value = token[0]
        if "@" in value or ENCODED_AT.search(value):
            return Inspection.SENSITIVE
        # Allow prose labels like "HTTP: OK" and a bare "//" comment.
        if not value and (":" not in locator[0] or locator[0].endswith(":")):
            continue
        # A fragment of an encoded authority can only be evaluated in a
        # subsequent view. Unescaped prose/parameter delimiters end the host.
        atom = AUTHORITY_END.split(value, maxsplit=1)[0]
        if (
            not locator[0].endswith("//")
            or locator[0].endswith("///")
            or (not ESCAPED_BYTE.search(atom) and not _plausible_authority(atom))
            or _split_nested_authority(view, locator, token)
        ):
            malformed = True
    return Inspection.AMBIGUOUS if malformed else Inspection.CLEAN


def inspect_sensitive_data(value: str, *, query: bool = False) -> Inspection:
    """Classify data for both request admission and output filtering.

    Whitespace terminates a literal authority. A second, compact inspection
    view detects potential userinfo obscured by whitespace or controls. Only
    clear literal userinfo can be selectively removed from displayed text.
    None of the inspection views can become a request URL.
    """
    maximum = MAX_QUERY_SCAN_LENGTH if query else MAX_TEXT_SCAN_LENGTH
    if len(value) > maximum:
        return Inspection.AMBIGUOUS
    uncertain = query and BAD_PERCENT.search(value) is not None
    try:
        for view in _decoded_views(value, maximum):
            authority = _inspect_authorities(view)
            if (
                authority is Inspection.SENSITIVE
                or TOKEN_SHAPE.search(view)
                or BEARER.search(view)
                or CREDENTIAL_ASSIGNMENT.search(view)
                or (
                    query
                    and any(
                        SENSITIVE_NAME.search(item.partition("=")[0])
                        for item in QUERY_PARTS.split(view)
                    )
                )
            ):
                return Inspection.SENSITIVE
            compact = "".join(
                character
                for character in view
                if not character.isspace() and not _is_control(character)
            )
            if (
                compact != view
                and _inspect_authorities(compact) is Inspection.SENSITIVE
            ):
                uncertain = True
            if authority is Inspection.AMBIGUOUS or (
                query and any(map(_is_control, view))
            ):
                uncertain = True
    except (UnicodeError, ValueError):
        return Inspection.AMBIGUOUS
    return Inspection.AMBIGUOUS if uncertain else Inspection.CLEAN


def _is_sensitive(inspection: Inspection) -> bool:
    if inspection is Inspection.AMBIGUOUS:
        raise ValueError(
            "Sensitive URL inspection could not establish unambiguous input."
        )
    return inspection is Inspection.SENSITIVE


def query_contains_sensitive_data(query: str) -> bool:
    return _is_sensitive(inspect_sensitive_data(query, query=True))


def redact_text(value: object) -> str:
    text = str(value)
    state = inspect_sensitive_data(text)
    if state is Inspection.AMBIGUOUS:
        return REDACTED_URL_TEXT
    if state is Inspection.CLEAN:
        return text

    # Only remove a literal authority span when its host boundary is clear.
    pieces = []
    cursor = 0
    for locator, token in _authorities(text):
        if "@" not in token[0] or not locator[0].endswith("//"):
            continue
        userinfo, _, authority = token[0].rpartition("@")
        if not _plausible_authority(AUTHORITY_END.split(authority, maxsplit=1)[0]):
            continue
        pieces.append(text[cursor : token.start()])
        cursor = token.start() + len(userinfo) + 1
    if pieces:
        text = "".join([*pieces, text[cursor:]])
    text = TOKEN_SHAPE.sub("<redacted-token>", text)
    text = BEARER.sub(r"\1<redacted>", text)
    text = ASSIGNMENT.sub(r"\1<redacted>", text)
    # Avoid repeatedly recognizing the placeholder as a credential assignment.
    remaining = MASKED_ASSIGNMENT.sub("", text)
    return (
        text
        if inspect_sensitive_data(remaining) is Inspection.CLEAN
        else REDACTED_URL_TEXT
    )


def redact_url(value: object, *, redact_all_query_values: bool = False) -> str:
    text = str(value)
    if len(text) > MAX_TEXT_SCAN_LENGTH:
        return REDACTED_URL_TEXT
    try:
        parts = urlsplit(text)
    except ValueError:
        return (
            "<malformed-url-redacted>" if URL_START.match(text) else redact_text(text)
        )
    if not parts.netloc:
        return (
            "<malformed-url-redacted>" if URL_START.match(text) else redact_text(text)
        )
    try:
        authority = inspect_sensitive_data("//" + parts.netloc)
        if authority is Inspection.AMBIGUOUS or (
            authority is Inspection.SENSITIVE and parts.username is None
        ):
            return REDACTED_URL_TEXT
        hostname = parts.hostname or ""
        netloc = hostname
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]"
        if parts.port:
            netloc += f":{parts.port}"
        try:
            sensitive = query_contains_sensitive_data(parts.query)
        except ValueError:
            sensitive = True
        if sensitive:
            query = "<redacted>"
        else:
            query = urlencode(
                [
                    (key, "<redacted>" if redact_all_query_values else val)
                    for key, val in parse_qsl(parts.query, keep_blank_values=True)
                ]
            )
        return urlunsplit(
            (parts.scheme, redact_text(netloc), redact_text(parts.path), query, "")
        )
    except ValueError:
        return "<malformed-url-redacted>"


def redact_embedded_urls(value: object) -> str:
    """Redact credentials, fragments and every query value in embedded URLs."""

    def clean(match: re.Match) -> str:
        unfragmented = match[0].split("#", 1)[0]
        base, separator, _ = unfragmented.partition("?")
        return redact_url(base) + ("?<redacted>" if separator else "")

    text = str(value)
    if len(text) > MAX_TEXT_SCAN_LENGTH:
        return REDACTED_URL_TEXT
    return redact_text(EMBEDDED_URL.sub(clean, redact_text(text)))


def url_contains_sensitive_data(value: object) -> bool:
    text = str(value)
    if len(text) > MAX_TEXT_SCAN_LENGTH:
        raise ValueError("URL exceeds the inspection length.")
    if TOKEN_SHAPE.search(text) or BEARER.search(text):
        return True
    parts = urlsplit(text)
    return (
        parts.username is not None
        or parts.password is not None
        or _is_sensitive(inspect_sensitive_data("//" + parts.netloc))
        or query_contains_sensitive_data(parts.query)
    )


def redact_endpoint(value: object) -> str:
    text = redact_text(value)
    if text.startswith("/"):
        redacted = redact_url(f"https://placeholder.invalid{text}")
        prefix = "https://placeholder.invalid"
        return (
            redacted[len(prefix) :]
            if redacted.startswith(prefix)
            else "<redacted-endpoint>"
        )
    return redact_url(text)


def redact_structure(value: object, key: str = "") -> object:
    """Remove sensitive data while preserving bounded JSON-like shapes."""
    remaining = iter(range(MAX_STRUCTURE_ITEMS))
    return _redact_value(value, key, 0, remaining)


def _redact_value(value, key, depth, remaining):
    if depth > MAX_STRUCTURE_DEPTH or next(remaining, None) is None:
        return "<structure-redacted>"
    lowered = key.lower()
    if (
        SENSITIVE_NAME.search(key)
        and not lowered.endswith(("_candidates", "_signals"))
        and "fingerprint" not in lowered
        and "redacted" not in lowered
        and not lowered.endswith("_present")
        and not lowered.endswith("_names")
    ):
        return "<redacted>"
    if any(
        term in lowered for term in ("request_body", "response_body", "postdata")
    ) and not lowered.endswith("_field_names"):
        return "<redacted>"
    if isinstance(value, dict):
        return {
            redact_text(item_key): _redact_value(
                item_value, str(item_key), depth + 1, remaining
            )
            for item_key, item_value in islice(value.items(), 1000)
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(item, "", depth + 1, remaining) for item in value[:5000]]
    if isinstance(value, str):
        return (
            redact_url(value) if URL_START.match(value) else redact_embedded_urls(value)
        )
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return redact_text(value)
