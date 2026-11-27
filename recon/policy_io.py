"""Bounded local reads for authorization inputs."""

from __future__ import annotations

import json
import os
import stat
from contextlib import ExitStack
from pathlib import Path

MAX_CONFIG_BYTES = 1024 * 1024


class PolicyFileError(ValueError):
    """A policy file could not be read or decoded safely."""


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def reject_path_links(path: Path) -> None:
    """Check native path components from the root, including Windows junctions."""
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PolicyFileError(
                "Policy paths must not traverse symbolic links or reparse points."
            )


def _open_at(path: Path, flags: int, stack: ExitStack) -> tuple[int, os.stat_result]:
    """Use descriptor-relative lookups where supported to avoid symlink races."""
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = os.open(path.anchor, directory_flags)
        stack.callback(os.close, parent)
        for part in path.parts[1:-1]:
            parent = os.open(part, directory_flags, dir_fd=parent)
            stack.callback(os.close, parent)
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise PolicyFileError("Expected a regular, non-symlink policy file.")
        return os.open(path.name, flags | os.O_NOFOLLOW, dir_fd=parent), before

    reject_path_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise PolicyFileError("Expected a regular, non-symlink policy file.")
    return os.open(path, flags), before


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyFileError("Duplicate JSON object key.")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise PolicyFileError("Non-finite JSON values are unsupported.")


def read_policy_json(
    path: Path, maximum: int = MAX_CONFIG_BYTES
) -> tuple[object, os.stat_result]:
    """Read a stable, bounded UTF-8 JSON file without following symlinks."""
    path = path.absolute()
    if ".." in path.parts or len(path.parts) > 64 or path == path.parent:
        raise PolicyFileError("Invalid policy file path.")
    if os.name == "nt" and path.anchor.startswith("\\\\"):
        raise PolicyFileError("Policy files must be on local drives.")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with ExitStack() as stack:
        fd, before = _open_at(path, flags, stack)
        handle = stack.enter_context(os.fdopen(fd, "rb"))
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or _signature(info) != _signature(before):
            raise PolicyFileError("Policy file changed while opening.")
        if info.st_size > maximum:
            raise PolicyFileError(f"Policy file exceeds {maximum} bytes.")
        raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise PolicyFileError(f"Policy file exceeds {maximum} bytes.")
        if _signature(info) != _signature(os.fstat(handle.fileno())) or _signature(
            info
        ) != _signature(path.lstat()):
            raise PolicyFileError("Policy file changed while reading.")
    try:
        return json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        ), info
    except json.JSONDecodeError as exc:
        raise PolicyFileError(
            f"Invalid JSON at line {exc.lineno}, column {exc.colno}."
        ) from exc
    except (UnicodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, PolicyFileError):
            raise
        raise PolicyFileError("Invalid or excessively complex UTF-8 JSON.") from exc
