"""One enforced transaction lock for coordinated campaign storage operations."""

from __future__ import annotations

import errno
import os
import stat
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from functools import wraps
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

LOCK_NAME = ".recon-campaigns.lock"
LOCK_TIMEOUT = 2.0
LOCAL_FILESYSTEMS = frozenset({"btrfs", "ext2", "ext3", "ext4", "tmpfs", "xfs"})
_held = threading.local()
_open_locks: set[int] = set()


class CampaignLockError(OSError):
    """Campaign storage cannot be synchronized safely."""


@contextmanager
def open_directory(path: Path, *, create: bool = False):
    """Open a directory without following links, creating missing parts privately if requested."""
    path = path.absolute()
    if ".." in path.parts or len(path.parts) > 64:
        raise OSError("Unsafe campaign directory.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _validate_directory(fd: int, label: str, *, private: bool) -> None:
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    allowed = (
        mode == 0o700 if private else ((mode & 0o700) == 0o700 and not (mode & 0o7022))
    )
    if info.st_uid != os.geteuid() or not allowed:
        required = (
            "mode 0700"
            if private
            else "owner access and no group or other write access"
        )
        raise CampaignLockError(
            f"{label} must be owned by the current user and have {required}. Review and correct the existing directory manually."
        )


def check_campaign_directory(path: Path) -> None:
    """Check an existing private campaign directory using a no-follow descriptor."""
    with open_directory(path) as fd:
        _validate_directory(fd, path.name, private=True)


def _ensure_storage_parent(path: Path) -> None:
    try:
        with open_directory(path):
            return
    except FileNotFoundError:
        with open_directory(path.parent) as parent:
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass


def _mount_id(fd: int) -> bytes:
    with open(f"/proc/self/fdinfo/{fd}", "rb") as info:
        for line in info:
            if line.startswith(b"mnt_id:"):
                return line.split()[1]
    raise CampaignLockError("Campaign storage mount could not be identified.")


def _check_mount(directory: int) -> bytes:
    mount = _mount_id(directory)
    with open("/proc/self/mountinfo", "rb") as mounts:
        for line in mounts:
            if line.split(b" ", 1)[0] == mount:
                filesystem = line.split(b" - ", 1)[1].split(b" ", 1)[0].decode("ascii")
                if filesystem in LOCAL_FILESYSTEMS:
                    return mount
                break
    raise CampaignLockError(
        "Campaign storage requires a supported local Linux filesystem."
    )


def _discard_inherited_locks():
    # flock locks follow inherited file descriptions, so a forked child must
    # close its copies before it can acquire its own transaction lock.
    inherited = tuple(_open_locks)
    _open_locks.clear()
    _held.path = None
    for fd in inherited:
        try:
            os.close(fd)
        except OSError:
            pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_discard_inherited_locks)


@contextmanager
def campaign_storage_lock():
    """Acquire the storage lock, reentering only on the owning thread."""
    if sys.platform != "linux" or fcntl is None:
        raise CampaignLockError(
            "Campaign storage locking requires Linux. Offline scope diagnostics remain available."
        )
    if (
        sys.implementation.name != "cpython"
        or not getattr(sys, "_is_gil_enabled", lambda: True)()
    ):
        raise CampaignLockError(
            "Campaign storage locking requires GIL-enabled CPython."
        )
    from recon import campaigns

    directory = campaigns.CAMPAIGNS_DIR.parent.absolute()
    held = getattr(_held, "path", None)
    if held is not None:
        if held != directory:
            raise CampaignLockError(
                "Cannot nest campaign operations across storage roots."
            )
        yield
        return

    _ensure_storage_parent(directory)
    with open_directory(directory) as dirfd:
        info = os.fstat(dirfd)
        _validate_directory(dirfd, "Campaign storage parent", private=False)
        mount = _check_mount(dirfd)
        fd = os.open(
            LOCK_NAME,
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=dirfd,
        )
        # Only the parent process may unlock or close these inherited contexts.
        owner_pid = os.getpid()
        acquired = False
        _open_locks.add(fd)
        try:
            locked_file = os.fstat(fd)
            if (
                not stat.S_ISREG(locked_file.st_mode)
                or locked_file.st_nlink != 1
                or locked_file.st_uid != os.geteuid()
                or locked_file.st_mode & 0o077
                or _mount_id(fd) != mount
            ):
                raise CampaignLockError(
                    "Campaign lock must be a private regular file on the storage mount."
                )
            deadline = time.monotonic() + LOCK_TIMEOUT
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EAGAIN, errno.EACCES):
                        raise CampaignLockError(
                            "Campaign storage locking is unavailable."
                        ) from exc
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CampaignLockError(
                            "Campaign storage is busy. Retry after the current operation completes."
                        ) from exc
                    time.sleep(min(0.025, remaining))
            current = os.stat(LOCK_NAME, dir_fd=dirfd, follow_symlinks=False)
            opened_dir = os.stat(directory, follow_symlinks=False)
            if not os.path.samestat(current, locked_file) or not os.path.samestat(
                opened_dir, info
            ):
                raise CampaignLockError(
                    "Campaign lock or storage directory changed during acquisition."
                )
            for root in (campaigns.CAMPAIGNS_DIR, campaigns.ARCHIVED_CAMPAIGNS_DIR):
                # An archive path away from this storage root cannot be used by
                # archive operations. Active-only clients can still read/write.
                if root.parent.absolute() != directory:
                    continue
                try:
                    with open_directory(root) as root_fd:
                        _validate_directory(root_fd, root.name, private=True)
                        if _mount_id(root_fd) != mount:
                            raise CampaignLockError(
                                "Campaign directories must share the storage mount."
                            )
                except FileNotFoundError:
                    pass
            _held.path = directory
            try:
                yield
            finally:
                if os.getpid() == owner_pid:
                    _held.path = None
        finally:
            if os.getpid() == owner_pid:
                try:
                    if acquired:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    _open_locks.discard(fd)
                    os.close(fd)


def campaign_operation(function):
    """Wrap a complete campaign operation and return structured lock failures."""

    @wraps(function)
    def coordinated(*args, **kwargs):
        with ExitStack() as stack:
            try:
                stack.enter_context(campaign_storage_lock())
            except OSError as exc:
                detail = (
                    str(exc)
                    if isinstance(exc, CampaignLockError)
                    else "Campaign lock could not be opened safely. Check the local storage path and permissions."
                )
                return {
                    "ok": False,
                    "error_code": "campaign_storage_unavailable",
                    "error": detail,
                    "warnings": [detail],
                }
            return function(*args, **kwargs)

    return coordinated
