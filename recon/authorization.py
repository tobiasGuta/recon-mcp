"""Authoritative, offline policy compilation and URL evaluation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import idna

from recon import scope
from recon.h1_scope import H1ScopeError, load_h1_snapshots
from recon.policy_io import PolicyFileError, read_policy_json
from recon.redaction import redact_text, url_contains_sensitive_data

SCHEMA_VERSION = 1
MAX_URL_LENGTH = 4096
MAX_RULES = 1024
MAX_BURP_RULES = 256
MAX_PATTERN_LENGTH = 256
MAX_BATCH_BYTES = 128 * 1024
MAX_BATCH_URLS = 100
DEFAULT_PORTS = {"http": 80, "https": 443}
COMPARISON_ROOT = scope.PROJECT_ROOT / "config" / "policies"
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
PATH_CHARS = re.compile(r"/[A-Za-z0-9._~!$&'()*+,=:@/\-]*")
CAPABILITIES = {
    "manual": {
        "constraints": [
            "host",
            "scheme",
            "effective_port",
            "path",
            "path_prefix",
            "exact_raw_query",
            "exclusions",
        ],
        "limitations": [
            "Hostname-only rules allow both HTTP schemes, all ports, paths and queries. Optional URL restrictions intersect legacy entries."
        ],
    },
    "h1_snapshots": {
        "constraints": [
            "host",
            "scheme",
            "effective_port",
            "exact_path",
            "exact_raw_query",
            "eligibility_exclusions",
            "optional_snapshot_age",
            "single_program_selection",
        ],
        "limitations": [
            "Hostname-only assets do not constrain URLs. Free-text instructions cannot be enforced. Freshness is measured from local file modification time when configured."
        ],
    },
    "burp_advanced": {
        "constraints": [
            "host_regex",
            "scheme",
            "effective_port_regex",
            "path_regex",
            "exclusions",
        ],
        "limitations": [
            "Restricted anchored ASCII regex subset. Burp file expressions ignore queries. The export conveys no bounty eligibility."
        ],
    },
}
COMMON_LIMITATIONS = (
    "Offline decisions do not resolve DNS or verify reachability.",
    "Current policy and public-address checks are required at dispatch.",
)


class AuthorizationError(scope.ScopeError):
    """A rejected request or invalid policy, with a safe structured decision."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "invalid_policy",
        decision: dict | None = None,
        source: str | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.decision = decision
        self.source = source


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str
    query: str | None = field(repr=False)

    @property
    def origin(self) -> str:
        hostname = f"[{self.host}]" if ":" in self.host else self.host
        authority = (
            hostname
            if self.port == DEFAULT_PORTS[self.scheme]
            else f"{hostname}:{self.port}"
        )
        return f"{self.scheme}://{authority}"

    @property
    def url(self) -> str:
        return (
            self.origin
            + self.path
            + ("?" + self.query if self.query is not None else "")
        )

    @property
    def redacted(self) -> str:
        return redact_text(self.origin + self.path) + (
            "?<redacted>" if self.query is not None else ""
        )

    def components(self) -> dict:
        return {
            "scheme": self.scheme,
            "hostname": self.host,
            "effective_port": self.port,
            "path": redact_text(self.path),
            "query_present": self.query is not None,
        }


def normalize_host(host: str) -> str:
    """Normalize only a literal hostname, using the same IDNA form on the wire."""
    if not isinstance(host, str) or not host or len(host) > 253 or "%" in host:
        raise ValueError("Invalid hostname.")
    candidate = host.removesuffix(".")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if candidate == "localhost":
            return candidate
    else:
        if candidate != host:
            raise ValueError("IP addresses must not have a trailing dot.")
        return str(address)
    try:
        labels = candidate.split(".")
        if len(labels) < 2 or any(not label for label in labels):
            raise ValueError("Expected a fully qualified hostname.")
        normalized = (
            idna.encode(candidate, uts46=True, std3_rules=True).decode("ascii").lower()
        )
    except idna.IDNAError as exc:
        raise ValueError("Invalid internationalized hostname.") from exc
    labels = normalized.split(".")
    if len(labels) < 2 or not all(HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid DNS hostname.")
    if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", labels[-1]):
        raise ValueError("Ambiguous numeric hostname.")
    return normalized


def valid_path(path: str) -> bool:
    return bool(
        PATH_CHARS.fullmatch(path)
        and "//" not in path
        and not {".", ".."}.intersection(path.split("/"))
    )


def parse_target(url: str) -> Target:
    """Validate a complete URL and verify the HTTP client's request-target encoding."""
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH or not url:
        raise AuthorizationError(
            "Expected a bounded, absolute HTTP(S) URL.", code="invalid_url"
        )
    if (
        "\\" in url
        or "#" in url
        or any(
            character.isspace() or ord(character) < 33 or ord(character) == 127
            for character in url
        )
    ):
        raise AuthorizationError(
            "URL contains ambiguous characters or a fragment.", code="invalid_url"
        )
    try:
        parts = urlsplit(url)
        if parts.scheme not in DEFAULT_PORTS or not parts.netloc or not parts.hostname:
            raise ValueError("Expected HTTP or HTTPS and a hostname.")
        if "@" in parts.netloc or url_contains_sensitive_data(url):
            raise AuthorizationError(
                "URL contains credentials or a sensitive query or token.",
                code="sensitive_url",
            )
        host = normalize_host(parts.hostname)
        authority = re.fullmatch(
            r"(?:\[([0-9A-Fa-f:.]+)\]|([^:\[\]]+))(?::([1-9][0-9]{0,4}))?", parts.netloc
        )
        if authority is None or bool(authority[1]) != (":" in host):
            raise ValueError("Ambiguous URL authority.")
        port = parts.port if parts.port is not None else DEFAULT_PORTS[parts.scheme]
        path = parts.path or "/"
        query = parts.query if "?" in url else None
        if not valid_path(path) or not (1 <= port <= 65535):
            raise ValueError("Ambiguous request path or port.")
        if redact_text(path) != path:
            raise AuthorizationError(
                "URL path contains credential-like data.", code="sensitive_url"
            )
        if query is not None and not query.isascii():
            raise ValueError("Ambiguous query encoding.")
        target = Target(parts.scheme, host, port, path, query)
        expected = path + ("?" + query if query is not None else "")
        if httpx.URL(target.url).raw_path != expected.encode("ascii"):
            raise ValueError("HTTP client would reinterpret the request target.")
        return target
    except (ValueError, UnicodeError, httpx.InvalidURL) as exc:
        if isinstance(exc, AuthorizationError):
            raise
        raise AuthorizationError(
            "Invalid or ambiguous HTTP(S) URL.", code="invalid_url"
        ) from exc


def safe_target(url: str) -> str:
    """Redact queries, credentials and malformed URLs in persistent provenance."""
    try:
        return parse_target(url).redacted
    except AuthorizationError:
        return "<redacted-invalid-or-sensitive-url>"


def _digest(value: object) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Rule:
    effect: str
    host: str = ""
    host_kind: str = "exact"
    scheme: str = ""
    port: int | str = ""
    path: str = ""
    path_kind: str = "exact"
    query: str | None = field(default=None, repr=False)
    patterns: tuple[BurpPattern | None, ...] = field(
        default=(), repr=False, compare=False
    )

    def signature(self) -> tuple:
        return (
            self.effect,
            self.host,
            self.host_kind,
            self.scheme,
            self.port,
            self.path,
            self.path_kind,
            self.query,
        )

    @property
    def rule_id(self) -> str:
        return _digest(self.signature())[:24]

    def describe(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "effect": self.effect,
            "host": redact_text(self.host),
            "host_match": self.host_kind,
            "scheme": self.scheme,
            "effective_port": self.port,
            "path": redact_text(self.path),
            "path_match": self.path_kind,
            "query_constrained": self.query is not None,
        }

    def matches_host(self, host: str) -> bool:
        if self.host_kind == "regex":
            return self.patterns[0] is None or self.patterns[0].matches(host)
        if self.host_kind == "suffix":
            return host == self.host or host.endswith("." + self.host)
        if self.host_kind == "wildcard":
            return host.endswith("." + self.host)
        return host == self.host

    def mismatch(self, target: Target) -> str | None:
        if not self.matches_host(target.host):
            return "no_matching_inclusion"
        if self.scheme and self.scheme != target.scheme:
            return "protocol_mismatch"
        if self.patterns:
            port, path = self.patterns[1:]
            if port is not None and not port.matches(str(target.port)):
                return "port_mismatch"
            if path is not None and not path.matches(target.path):
                return "path_mismatch"
        else:
            if self.port and self.port != target.port:
                return "port_mismatch"
            if self.path and (
                not target.path.startswith(self.path)
                if self.path_kind == "prefix"
                else self.path != target.path
            ):
                return "path_mismatch"
        if self.query is not None and self.query != target.query:
            return "query_mismatch"
        return None


@dataclass(frozen=True)
class Policy:
    source: str
    include: tuple[Rule, ...]
    exclude: tuple[Rule, ...]
    narrow: tuple[Rule, ...]
    fingerprint: str
    warnings: tuple[str, ...]
    disabled: int = 0


def _items(data: dict, key: str, maximum: int = MAX_RULES) -> list:
    items = data.get(key, [])
    if not isinstance(items, list) or len(items) > maximum:
        raise AuthorizationError(
            f"{key} must be a list with at most {maximum} entries."
        )
    return items


def _host_rule(
    value: str, effect: str, *, wildcard: bool = False, suffix: bool = False
) -> Rule:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Expected an unambiguous host or complete URL.")
    if redact_text(value) != value:
        raise ValueError("Policy asset contains credential-like text.")
    if "://" in value:
        if wildcard or suffix:
            raise ValueError("Wildcard and suffix rules require a bare hostname.")
        if url_contains_sensitive_data(value):
            raise ValueError("Policy URL contains credential-like data.")
        target = parse_target(value)
        return Rule(
            effect,
            target.host,
            scheme=target.scheme,
            port=target.port,
            path=target.path,
            query=target.query,
        )
    if value.startswith("*."):
        if suffix:
            raise ValueError("Blocked hostname suffixes use a bare hostname.")
        value, wildcard = value[2:], True
    host = normalize_host(value)
    if wildcard and _is_ip(host):
        raise ValueError("Wildcard IP rules are unsupported.")
    return Rule(
        effect, host, "suffix" if suffix else "wildcard" if wildcard else "exact"
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _manual_rule(item: object, effect: str) -> Rule:
    if not isinstance(item, dict) or item.keys() - {
        "value",
        "match",
        "scheme",
        "port",
        "path",
        "path_prefix",
        "query",
    }:
        raise ValueError("Expected value, optional match, and supported URL fields.")
    match = item.get("match", "exact")
    if match not in ("exact", "wildcard"):
        raise ValueError("match must be exact or wildcard.")
    if (
        "match" in item
        and match == "exact"
        and isinstance(item.get("value"), str)
        and item["value"].startswith("*.")
    ):
        raise ValueError("Explicit exact matching contradicts the wildcard value.")
    base = _host_rule(item.get("value"), effect, wildcard=match == "wildcard")
    restrictions = item.keys() - {"value", "match"}
    if not restrictions:
        return base
    if base.scheme or ("path" in item and "path_prefix" in item):
        raise ValueError(
            "Use a bare host with explicit URL fields and choose one path constraint."
        )
    scheme = item.get("scheme", "")
    port = item.get("port", "")
    path = item.get("path", item.get("path_prefix", ""))
    query = item.get("query")
    if "scheme" in item and (
        not isinstance(scheme, str) or scheme not in DEFAULT_PORTS
    ):
        raise ValueError("scheme must be http or https.")
    if "port" in item and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("port must be an integer from 1 to 65535.")
    if ("path" in item or "path_prefix" in item) and (
        not isinstance(path, str)
        or len(path) > MAX_URL_LENGTH
        or not valid_path(path)
        or ("path_prefix" in item and not path.endswith("/"))
    ):
        raise ValueError(
            "Expected a canonical path or a directory prefix ending in '/'."
        )
    if "query" in item and (
        not isinstance(query, str)
        or len(query) > MAX_URL_LENGTH
        or parse_target("https://policy.invalid/?" + query).query != query
    ):
        raise ValueError("query must be an exact, valid raw query string.")
    return Rule(
        effect,
        base.host,
        base.host_kind,
        scheme,
        port,
        path,
        "prefix" if "path_prefix" in item else "exact",
        query,
    )


def _parse_rules(items: list, field_name: str, parse) -> list[Rule]:
    rules = []
    for index, item in enumerate(items):
        try:
            rules.append(parse(item))
        except ValueError as exc:
            raise AuthorizationError(
                f"{field_name}[{index}]: {exc}",
                code=getattr(exc, "code", "invalid_policy"),
            ) from exc
    return rules


# At most one variable-width token. Remaining tokens consume one ASCII character.
REGEX_TOKEN = re.compile(
    r"\.\*|\\[.\-+?(){}\[\]$^|\\*]|\[(?:[A-Za-z0-9._/:]|[a-z]-[a-z]|[A-Z]-[A-Z]|[0-9]-[0-9])+\]|[A-Za-z0-9_/:.~,=\-]"
)


@dataclass(frozen=True)
class BurpPattern:
    prefix: re.Pattern
    suffix: re.Pattern | None = None
    prefix_length: int = 0
    suffix_length: int = 0

    def matches(self, value: str) -> bool:
        if self.suffix is None:
            return self.prefix.fullmatch(value) is not None
        if len(value) < self.prefix_length + self.suffix_length:
            return False
        # Split the fixed-width pieces instead of asking the regex engine to
        # search every possible split of the variable-width middle.
        return (
            self.prefix.fullmatch(value[: self.prefix_length]) is not None
            and self.suffix.fullmatch(value[len(value) - self.suffix_length :])
            is not None
        )


def _burp_regex(value: str, field_name: str) -> BurpPattern | None:
    if not value or value == ".*":
        return None
    if (
        len(value) > MAX_PATTERN_LENGTH
        or not value.startswith("^")
        or not value.endswith("$")
    ):
        raise ValueError(
            f"{field_name} must be blank or explicitly anchored with ^ and $."
        )
    body = value[1:-1]
    position = 0
    prefix = []
    suffix = None
    while position < len(body):
        match = REGEX_TOKEN.match(body, position)
        if match is None:
            raise ValueError(f"{field_name} uses an unsupported regex construct.")
        if match[0] == ".*":
            if suffix is not None:
                raise ValueError(f"{field_name} must contain at most one .* token.")
            suffix = []
        else:
            (prefix if suffix is None else suffix).append(match[0])
        position = match.end()
    if field_name == "host" and (
        value != value.lower() or any(character in value for character in "/:")
    ):
        raise ValueError(
            "host must use lowercase DNS/A-label syntax without IP range notation."
        )
    try:
        before = re.compile("".join(prefix), re.ASCII)
        if suffix is None:
            return BurpPattern(before)
        return BurpPattern(
            before, re.compile("".join(suffix), re.ASCII), len(prefix), len(suffix)
        )
    except re.error as exc:
        raise ValueError(f"{field_name} contains an invalid regex.") from exc


def _burp_rules(
    config: dict, boundary: Path | None
) -> tuple[list[Rule], list[Rule], int]:
    path = _source_path(config.get("burp_scope_file"), boundary, absolute=True)
    data, _ = read_policy_json(path)
    block = data.get("target") if isinstance(data, dict) else None
    block = block.get("scope") if isinstance(block, dict) else None
    if (
        not isinstance(block, dict)
        or block.get("advanced_mode") is not True
        or block.keys() != {"advanced_mode", "include", "exclude"}
    ):
        raise AuthorizationError(
            "Expected target.scope with advanced_mode=true and include/exclude lists.",
            code="unsupported_policy",
        )
    disabled = 0
    rule_lists = []
    for effect in ("include", "exclude"):
        rules = []
        for index, item in enumerate(_items(block, effect, MAX_BURP_RULES)):
            try:
                if not isinstance(item, dict) or type(item.get("enabled")) is not bool:
                    raise ValueError("Each rule needs a boolean enabled field.")
                if not item["enabled"]:
                    disabled += 1
                    continue
                if item.keys() - {"enabled", "protocol", "host", "port", "file"}:
                    raise ValueError("Enabled rule uses unsupported fields.")
                protocol, host, port, path_pattern = (
                    item.get(key, "") for key in ("protocol", "host", "port", "file")
                )
                if not all(
                    isinstance(value, str)
                    for value in (protocol, host, port, path_pattern)
                ):
                    raise ValueError("Protocol, host, port and file must be strings.")
                if protocol.lower() not in ("", "any", "http", "https"):
                    raise ValueError("Protocol must be HTTP, HTTPS, any, or blank.")
                patterns = tuple(
                    _burp_regex(value, name)
                    for value, name in (
                        (host, "host"),
                        (port, "port"),
                        (path_pattern, "file"),
                    )
                )
                scheme = protocol.lower() if protocol.lower() in DEFAULT_PORTS else ""
                rules.append(
                    Rule(
                        effect,
                        host,
                        "regex",
                        scheme,
                        port,
                        path_pattern,
                        "regex",
                        patterns=patterns,
                    )
                )
            except ValueError as exc:
                raise AuthorizationError(
                    f"Burp {effect}[{index}]: {exc}", code="unsupported_policy"
                ) from exc
        rule_lists.append(rules)
    return rule_lists[0], rule_lists[1], disabled


def _source_path(
    value: object, boundary: Path | None, *, absolute: bool = False
) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_URL_LENGTH
        or "://" in value
        or "\x00" in value
    ):
        raise AuthorizationError("Expected a local policy path.")
    path = Path(value).expanduser()
    if (
        (".." in path.parts)
        or (os.name == "nt" and path.anchor.startswith("\\\\"))
        or (absolute and not Path(value).is_absolute())
        or (boundary is not None and not path.absolute().is_relative_to(boundary))
    ):
        raise AuthorizationError(
            "Policy path must be absolute or within the selected local boundary as required."
        )
    return path


def _h1_rules(
    config: dict, boundary: Path | None
) -> tuple[list[Rule], list[Rule], list[str], str]:
    max_age = config.get("h1_snapshot_max_age_seconds")
    if "h1_snapshot_max_age_seconds" in config and (
        type(max_age) is not int or not 1 <= max_age <= 31_536_000
    ):
        raise AuthorizationError(
            "h1_snapshot_max_age_seconds must be an integer from 1 to 31536000."
        )
    source_path = _source_path(config.get("h1_snapshot_dir"), boundary)
    include = []
    exclude = []
    skipped_types = 0
    instruction_count = 0
    entry_fields = {
        "id",
        "type",
        "asset_type",
        "asset_identifier",
        "eligible_for_bounty",
        "eligible_for_submission",
        "instruction",
        "max_severity",
        "created_at",
        "updated_at",
        "reference",
        "confidentiality_requirement",
        "integrity_requirement",
        "availability_requirement",
        "_source_file",
        "_program_handle",
    }
    entries = load_h1_snapshots(
        str(source_path),
        max_age=max_age,
        program=config.get("h1_snapshot_program"),
        require_single_program=True,
    )
    for index, entry in enumerate(entries):
        if entry.keys() - entry_fields:
            raise AuthorizationError(
                f"H1 entry [{index}]: unrecognized scope field.",
                code="unsupported_policy",
            )
        asset_type = entry.get("asset_type", "")
        if not isinstance(asset_type, str):
            raise AuthorizationError(
                f"H1 entry [{index}]: asset_type must be a string."
            )
        asset_type = asset_type.strip().lower()
        if not scope._asset_type_supported(asset_type):
            if asset_type in {
                "ios",
                "android",
                "source_code",
                "executable",
                "hardware",
            }:
                skipped_types += 1
                continue
            raise AuthorizationError(
                f"H1 entry [{index}]: unsupported asset type could affect web scope.",
                code="unsupported_policy",
            )
        submission = entry.get("eligible_for_submission")
        bounty = entry.get("eligible_for_bounty")
        if any(
            value is not None and type(value) is not bool
            for value in (submission, bounty)
        ):
            raise AuthorizationError(
                f"H1 entry [{index}]: eligibility fields must be booleans."
            )
        instruction = entry.get("instruction")
        if instruction is not None and not isinstance(instruction, str):
            raise AuthorizationError(
                f"H1 entry [{index}]: instruction must be a string or null."
            )
        has_instruction = bool(instruction)
        instruction_count += has_instruction
        eligible = (
            submission is True
            and not has_instruction
            and (not config.get("include_only_bounty_eligible") or bounty is True)
        )
        effect = "include" if eligible else "exclude"
        try:
            identifier = entry.get("asset_identifier")
            if asset_type == "wildcard" and (
                not isinstance(identifier, str) or not identifier.startswith("*.")
            ):
                raise ValueError(
                    "Wildcard entries must use *. followed by a DNS suffix."
                )
            rule = _host_rule(identifier, effect)
        except ValueError as exc:
            raise AuthorizationError(f"H1 entry [{index}]: {exc}") from exc
        (include if eligible else exclude).append(rule)
    warnings = []
    if max_age is None:
        warnings.append(
            "Local snapshot age is unbounded. Confirm freshness with the snapshot operator."
        )
    if skipped_types:
        warnings.append(f"{skipped_types} non-web H1 asset entries were skipped.")
    if instruction_count:
        warnings.append(
            f"{instruction_count} H1 entries with instructions were excluded pending human review."
        )
    return include, exclude, warnings, entries[0]["_program_handle"]


def _ordered(rules: list[Rule]) -> tuple[Rule, ...]:
    return tuple(
        sorted(set(rules), key=lambda rule: (rule.host_kind != "exact", rule.rule_id))
    )


def compile_policy(config: dict, *, boundary: Path | None = None) -> Policy:
    """Compile the whole policy before making any authorization decision."""
    source = config.get("scope_source", "manual")
    if not isinstance(source, str) or source not in CAPABILITIES:
        raise AuthorizationError(
            "Unsupported scope_source. Use manual, h1_snapshots, or burp_advanced.",
            code="unsupported_policy",
        )
    if source != "manual" and (
        config.get("allowed_domains")
        or config.get("allowed_assets")
        or "url_include" in config
        or "url_exclude" in config
    ):
        raise AuthorizationError(
            "Manual rules cannot be combined with the selected scope source."
        )
    if source != "burp_advanced" and config.get("burp_scope_file"):
        raise AuthorizationError(
            "burp_scope_file requires the burp_advanced scope source."
        )
    if source != "h1_snapshots" and (
        config.get("h1_snapshot_dir")
        or "h1_snapshot_max_age_seconds" in config
        or "h1_snapshot_program" in config
    ):
        raise AuthorizationError(
            "Snapshot settings require the h1_snapshots scope source."
        )

    blocked = _parse_rules(
        _items(config, "blocked_domains"),
        "blocked_domains",
        lambda item: _host_rule(item, "exclude", suffix=True),
    )
    narrow = []
    disabled = 0
    snapshot_program = None
    warnings = []
    if source == "manual":
        include = _parse_rules(
            _items(config, "allowed_domains"),
            "allowed_domains",
            lambda item: _host_rule(item, "include"),
        )
        include += _parse_rules(
            _items(config, "allowed_assets"),
            "allowed_assets",
            lambda item: _manual_rule(item, "include"),
        )
        exclude = _parse_rules(
            _items(config, "url_exclude"),
            "url_exclude",
            lambda item: _manual_rule(item, "exclude"),
        )
        narrow = _parse_rules(
            _items(config, "url_include"),
            "url_include",
            lambda item: _manual_rule(item, "restrict"),
        )
        if "url_include" in config and not narrow:
            include = []
    elif source == "burp_advanced":
        include, exclude, disabled = _burp_rules(config, boundary)
    else:
        include, exclude, warnings, snapshot_program = _h1_rules(config, boundary)
    exclude += blocked
    if len(include) + len(exclude) + len(narrow) + disabled > MAX_RULES:
        raise AuthorizationError(f"Combined policy exceeds {MAX_RULES} rules.")
    if not include:
        warnings.append("No inclusion rules. All requests are denied.")
    include, exclude, narrow = _ordered(include), _ordered(exclude), _ordered(narrow)
    fingerprint = _digest(
        [
            SCHEMA_VERSION,
            source,
            config.get("h1_snapshot_max_age_seconds"),
            snapshot_program,
            [
                [rule.signature() for rule in group]
                for group in (include, exclude, narrow)
            ],
        ]
    )
    return Policy(
        source, include, exclude, narrow, fingerprint, tuple(warnings), disabled
    )


def load_policy(
    config_path: Path | None = None, *, boundary: Path | None = None
) -> Policy:
    """Load a complete, validated view of a local policy and its source."""

    def read_config() -> dict:
        return (
            scope.load_scope() if config_path is None else scope.load_scope(config_path)
        )

    config = {}
    try:
        config = read_config()
        policy = compile_policy(config, boundary=boundary)
        if policy.source != "manual" and read_config() != config:
            raise AuthorizationError(
                "Scope configuration changed while reading its source.",
                code="policy_changed",
            )
    except (
        scope.ScopeError,
        H1ScopeError,
        PolicyFileError,
        OSError,
        RuntimeError,
    ) as exc:
        message = (
            str(exc)
            if isinstance(exc, (scope.ScopeError, H1ScopeError, PolicyFileError))
            else "Could not safely read a local policy source."
        )
        raise AuthorizationError(
            message,
            code=getattr(exc, "code", "invalid_policy"),
            source=config.get("scope_source"),
        ) from exc
    return policy


REASONS = {
    "allowed": "A matching inclusion permits this URL under the current policy.",
    "no_matching_inclusion": "Target is out of scope because no applicable inclusion matched.",
    "explicit_exclusion": "An exclusion matched the target.",
    "protocol_mismatch": "The protocol is outside the matching host rule.",
    "port_mismatch": "The effective port is outside the matching rule.",
    "path_mismatch": "The path is outside the matching rule.",
    "query_mismatch": "The query is outside the matching rule.",
    "invalid_url": "Invalid or ambiguous HTTP(S) URL.",
    "sensitive_url": "URL contains credentials or a sensitive query or token.",
    "unsafe_target": "Target is an unsafe address or resolved to an unsafe address.",
    "dns_failed": "Public address verification failed.",
    "policy_changed": "The active authorization policy changed. Review it before retrying.",
}


def decision(
    policy: Policy | None,
    target: Target | None,
    code: str,
    *,
    include: Rule | None = None,
    exclude: Rule | None = None,
    restriction: Rule | None = None,
    detail: str | None = None,
    source: str | None = None,
) -> dict:
    allowed = code == "allowed"
    source = (
        policy.source
        if policy
        else source
        if isinstance(source, str) and source in CAPABILITIES
        else None
    )
    return {
        "ok": code
        not in {"invalid_policy", "unsupported_policy", "invalid_url", "sensitive_url"},
        "decision_id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "policy_source": source,
        "policy_fingerprint": policy.fingerprint if policy else None,
        "policy_schema_version": SCHEMA_VERSION,
        "authorized": allowed,
        "in_scope": allowed,
        "network_execution_permitted": allowed,
        "reason_code": code,
        "reason": detail
        or REASONS.get(code, "Authorization could not be established."),
        "normalized_url": target.components() if target else None,
        "target": target.redacted if target else None,
        "matched_inclusion_rule": include.describe() if include else None,
        "matched_exclusion_rule": exclude.describe() if exclude else None,
        "matched_restriction_rule": restriction.describe() if restriction else None,
        "enforcement_limitations": [
            *COMMON_LIMITATIONS,
            *CAPABILITIES.get(source, {}).get("limitations", []),
        ],
    }


def _match_group(rules: tuple[Rule, ...], target: Target) -> tuple[Rule | None, str]:
    ranking = (
        "no_matching_inclusion",
        "protocol_mismatch",
        "port_mismatch",
        "path_mismatch",
        "query_mismatch",
    )
    reason = ranking[0]
    for rule in rules:
        mismatch = rule.mismatch(target)
        if mismatch is None:
            return rule, "allowed"
        if ranking.index(mismatch) > ranking.index(reason):
            reason = mismatch
    return None, reason


def evaluate(
    policy: Policy, target: Target, *, expected_fingerprint: str | None = None
) -> dict:
    if expected_fingerprint is not None and policy.fingerprint != expected_fingerprint:
        return decision(policy, target, "policy_changed")
    if scope.is_private_or_loopback_host(target.host):
        return decision(policy, target, "unsafe_target")
    excluded, _ = _match_group(policy.exclude, target)
    included, reason = _match_group(policy.include, target)
    if excluded:
        return decision(
            policy, target, "explicit_exclusion", include=included, exclude=excluded
        )
    if included is None:
        return decision(policy, target, reason)
    restriction, reason = _match_group(policy.narrow, target)
    if policy.narrow and restriction is None:
        return decision(policy, target, reason, include=included)
    return decision(
        policy, target, "allowed", include=included, restriction=restriction
    )


def policy_failure(exc: Exception, target: Target | None = None) -> dict:
    detail = (
        str(exc)
        if isinstance(exc, scope.ScopeError)
        else "Could not safely read or use the current local policy."
    )
    return decision(
        None,
        target,
        getattr(exc, "code", "invalid_policy"),
        detail=detail,
        source=getattr(exc, "source", None),
    )


def require_url(
    url: str,
    *,
    expected_fingerprint: str | None = None,
    config_path: Path | None = None,
) -> tuple[Target, dict]:
    """Return the canonical target and decision or raise a structured denial."""
    target = None
    try:
        target = parse_target(url)
        policy = load_policy(config_path)
    except AuthorizationError as exc:
        result = policy_failure(exc, target)
    else:
        result = evaluate(policy, target, expected_fingerprint=expected_fingerprint)
        if result["authorized"]:
            return target, result
    raise AuthorizationError(
        result["reason"], code=result["reason_code"], decision=result
    )


def check_url_scope(url: str, *, config_path: Path | None = None) -> dict:
    """Evaluate a complete URL without sending DNS or HTTP traffic."""
    try:
        return require_url(url, config_path=config_path)[1]
    except AuthorizationError as exc:
        return exc.decision


def check_url_scope_batch(urls: list[str]) -> dict:
    """Evaluate a bounded batch against a single immutable policy."""
    if (
        len(urls) > MAX_BATCH_URLS
        or any(len(url) > MAX_URL_LENGTH for url in urls)
        or sum(len(url.encode("utf-8", errors="replace")) for url in urls)
        > MAX_BATCH_BYTES
    ):
        return {
            "ok": False,
            "error": "Batch exceeds the URL count, per-URL length, or aggregate byte limit.",
            "max_urls": MAX_BATCH_URLS,
            "max_url_length": MAX_URL_LENGTH,
            "max_batch_bytes": MAX_BATCH_BYTES,
        }
    try:
        policy = load_policy()
    except AuthorizationError as exc:
        return {
            "ok": False,
            "count": 0,
            "policy_error": policy_failure(exc),
            "results": [],
        }
    results = []
    for url in urls:
        try:
            target = parse_target(url)
        except AuthorizationError as exc:
            results.append(decision(policy, None, exc.code, detail=str(exc)))
        else:
            results.append(evaluate(policy, target))
    return {
        "ok": True,
        "count": len(results),
        "policy_fingerprint": policy.fingerprint,
        "results": results,
    }


def _summary(policy: Policy) -> dict:
    capabilities = CAPABILITIES[policy.source]
    return {
        "ok": True,
        "valid": True,
        "safe_to_activate": bool(policy.include),
        "policy_source": policy.source,
        "policy_schema_version": SCHEMA_VERSION,
        "policy_fingerprint": policy.fingerprint,
        "inclusion_count": len(policy.include),
        "exclusion_count": len(policy.exclude),
        "restriction_count": len(policy.narrow),
        "disabled_rule_count": policy.disabled,
        "supported_constraints": capabilities["constraints"],
        "unsupported_rules": [],
        "errors": [],
        "warnings": list(policy.warnings),
        "limitations": [*COMMON_LIMITATIONS, *capabilities["limitations"]],
    }


def validate_scope_policy(config_path: Path | None = None) -> dict:
    """Validate an active or explicitly chosen local configuration without activation."""
    try:
        policy = load_policy(config_path)
    except AuthorizationError as exc:
        failure = policy_failure(exc)
        return {
            "ok": False,
            "valid": False,
            "safe_to_activate": False,
            "policy_source": failure["policy_source"],
            "policy_schema_version": SCHEMA_VERSION,
            "policy_fingerprint": None,
            "inclusion_count": None,
            "exclusion_count": None,
            "restriction_count": None,
            "disabled_rule_count": None,
            "supported_constraints": [],
            "supported_rules": [],
            "unsupported_rules": [failure["reason"]]
            if failure["reason_code"] == "unsupported_policy"
            else [],
            "errors": [failure["reason"]],
            "warnings": [],
            "reason_code": failure["reason_code"],
        }
    return {
        **_summary(policy),
        "supported_rules": [
            rule.describe()
            for rule in (*policy.include, *policy.exclude, *policy.narrow)
        ],
    }


def get_scope_policy_summary() -> dict:
    try:
        return _summary(load_policy())
    except AuthorizationError as exc:
        return {
            "ok": False,
            "valid": False,
            "safe_to_activate": False,
            "policy_error": policy_failure(exc),
        }


def get_scope_capabilities() -> dict:
    return {
        "ok": True,
        "policy_schema_version": SCHEMA_VERSION,
        "sources": CAPABILITIES,
        "url_max_length": MAX_URL_LENGTH,
        "batch_max_urls": MAX_BATCH_URLS,
        "batch_max_bytes": MAX_BATCH_BYTES,
        "limitations": list(COMMON_LIMITATIONS),
    }


def _named_policy(name: str) -> Policy:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name):
        raise AuthorizationError(
            "Use a local policy name without an extension or path separators."
        )
    return load_policy(
        COMPARISON_ROOT / (name + ".json"), boundary=COMPARISON_ROOT.absolute()
    )


def compare_scope_policies(before: str, after: str) -> dict:
    """Compare two operator-staged policy names without changing active scope."""
    try:
        old = _named_policy(before)
        new = _named_policy(after)
    except AuthorizationError as exc:
        return {
            "ok": False,
            "comparison": "indeterminate",
            "error": policy_failure(exc)["reason"],
        }
    old_rules = set(old.include + old.exclude + old.narrow)
    new_rules = set(new.include + new.exclude + new.narrow)
    removed = _ordered(list(old_rules - new_rules))
    added = _ordered(list(new_rules - old_rules))
    modified = []
    for effect in ("include", "exclude", "restrict"):
        previous = [rule for rule in removed if rule.effect == effect]
        updated = [rule for rule in added if rule.effect == effect]
        for prior in previous:
            replacements = [
                rule
                for rule in updated
                if (prior.host, prior.host_kind) == (rule.host, rule.host_kind)
            ]
            if len(previous) == len(updated) == 1:
                replacements = updated
            elif (
                sum(
                    (rule.host, rule.host_kind) == (prior.host, prior.host_kind)
                    for rule in previous
                )
                != 1
            ):
                continue
            if len(replacements) != 1:
                continue
            current = replacements[0]
            fields = [
                "host",
                "host_kind",
                "scheme",
                "port",
                "path",
                "path_kind",
                "query",
            ]
            modified.append(
                {
                    "before": prior.describe(),
                    "after": current.describe(),
                    "changed_fields": [
                        field
                        for field in fields
                        if getattr(prior, field) != getattr(current, field)
                    ],
                }
            )
    identical = old.fingerprint == new.fingerprint
    indirect_change = (
        old.source != new.source
        or (not identical and not (added or removed))
        or old.narrow != new.narrow
    )
    return {
        "ok": True,
        "comparison": "identical" if identical else "indeterminate",
        "before_fingerprint": old.fingerprint,
        "after_fingerprint": new.fingerprint,
        "before_source": old.source,
        "after_source": new.source,
        "added_rules": [rule.describe() for rule in added],
        "removed_rules": [rule.describe() for rule in removed],
        "possible_modified_rules": modified,
        "exclusions_changed": old.exclude != new.exclude,
        "potential_authorization_expansion": indirect_change
        or any(rule.effect == "include" for rule in added)
        or any(rule.effect == "exclude" for rule in removed),
        "potential_authorization_reduction": indirect_change
        or any(rule.effect == "include" for rule in removed)
        or any(rule.effect == "exclude" for rule in added),
    }
