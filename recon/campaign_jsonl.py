"""Coordinated and bounded append operations for campaign history."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from recon.campaign_lock import campaign_storage_lock, open_directory

MAX_RECORD = 1024 * 1024


def _complete_tail(fd: int, end: int) -> int:
    if end == 0 or os.pread(fd, 1, end - 1) == b"\n":
        return end
    start = max(0, end - MAX_RECORD - 1)
    tail = os.pread(fd, end - start, start)
    boundary = tail.rfind(b"\n")
    if start and boundary < 0:
        raise OSError(
            "Unterminated campaign history record exceeds the recovery bound."
        )
    record = tail[boundary + 1 :]
    if len(record) >= MAX_RECORD:
        raise OSError(
            "Unterminated campaign history record exceeds the recovery bound."
        )
    try:
        complete = isinstance(json.loads(record), dict)
    except (ValueError, RecursionError):
        complete = False
    if complete:
        if os.write(fd, b"\n") != 1:
            raise OSError("Could not complete the history delimiter.")
        return end + 1
    committed = start + boundary + 1
    os.ftruncate(fd, committed)
    return committed


def append_campaign_record(path: Path, record: dict) -> None:
    """Preserve complete records, removing only an incomplete final record."""
    data = (json.dumps(record, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(data) > MAX_RECORD:
        raise OSError("Campaign history record exceeds its size limit.")
    with campaign_storage_lock(), open_directory(path.parent) as dirfd:
        fd = os.open(
            path.name,
            os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=dirfd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("Campaign history must be a regular file with one link.")
            end = _complete_tail(fd, info.st_size)
            pending = memoryview(data)
            try:
                while pending:
                    size = os.write(fd, pending)
                    if size <= 0:
                        raise OSError("Could not append the campaign history record.")
                    pending = pending[size:]
                os.fsync(fd)
                os.fsync(dirfd)
            except OSError:
                os.ftruncate(fd, end)
                os.fsync(fd)
                raise
        finally:
            os.close(fd)
