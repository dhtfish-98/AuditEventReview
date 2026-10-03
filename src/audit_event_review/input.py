# SPDX-License-Identifier: GPL-3.0-only
"""Read one bounded POSIX regular file through directory descriptors."""

import os
import stat


def read_regular_file(path, maximum):
    dir_fd_support = getattr(os, "supports_dir_fd", None)
    if (
        os.name != "posix"
        or type(dir_fd_support) not in (set, frozenset)
        or os.open not in dir_fd_support
        or any(type(getattr(os, n, None)) is not int or getattr(os, n, None) <= 0 for n in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
    ):
        raise ValueError("safe_read_unavailable")
    path = os.fspath(path)
    if (
        type(path) is not str
        or not path
        or len(path) > 4096
        or "\0" in path
        or ".." in path.split("/")
    ):
        raise ValueError("local_path_contract")
    parts = [p for p in os.path.abspath(path).split("/") if p]
    if not parts:
        raise ValueError("regular_file_required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        fd = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("regular_file_budget")
        chunks, size = [], 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(fd)

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        if (
            size > maximum
            or size != after.st_size
            or identity(before) != identity(after)
        ):
            raise ValueError("input_changed_or_budget")
        return b"".join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
