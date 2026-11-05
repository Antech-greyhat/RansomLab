"""Guarded flat-file access for application-generated lab storage.

This is an internal adapter, not a public directory-encryption API. The service
layer must establish generated provenance, limits, durable intents and a lease.
See docs/implementation/filesystem-boundary.md for the platform contract.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from .core.errors import SafetyError, StateError, ValidationError


MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 10_000
_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\.(?:bin|json|key|flag|txt|db(?:-journal|-wal|-shm)?)\Z", re.ASCII)
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\Z", re.IGNORECASE)


def _check_name(name: str) -> None:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValidationError("A generated flat filename is required.")
    if _RESERVED.fullmatch(name.split(".", 1)[0]):
        raise ValidationError("Reserved filenames are not permitted.")


def _check_payload(data: bytes) -> None:
    if not isinstance(data, bytes) or len(data) > MAX_OBJECT_BYTES:
        raise ValidationError("Storage content must be bounded immutable bytes.")


def _check_expected(expected: dict[str, int] | None) -> None:
    if expected is None:
        return
    if not isinstance(expected, dict) or set(expected) != {"device", "inode"}:
        raise ValidationError("An object identity must contain device and inode.")
    if any(type(value) is not int or value < 0 for value in expected.values()):
        raise ValidationError("Object identity values must be nonnegative integers.")


class _Windows:
    """Small, typed Win32 surface. Constructed only on Windows."""

    READ = 0x80000000
    WRITE = 0x40000000
    READ_ATTRIBUTES = 0x80
    SHARE_READ = 1
    SHARE_WRITE = 2
    OPEN_EXISTING = 3
    CREATE_NEW = 1
    OPEN_ALWAYS = 4
    REPARSE = 0x400
    DIRECTORY = 0x10
    OPEN_REPARSE = 0x00200000
    BACKUP_SEMANTICS = 0x02000000

    def __init__(self) -> None:
        from ctypes import wintypes

        class FileInformation(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD),
                ("created", wintypes.FILETIME),
                ("accessed", wintypes.FILETIME),
                ("modified", wintypes.FILETIME),
                ("volume", wintypes.DWORD),
                ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD),
                ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD),
                ("index_low", wintypes.DWORD),
            ]

        self.Information = FileInformation
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
        self.kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel.GetFileType.argtypes = [wintypes.HANDLE]
        self.kernel.GetFileType.restype = wintypes.DWORD
        self.kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        self.kernel.GetDriveTypeW.restype = wintypes.UINT
        self.kernel.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR,
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.LPWSTR, wintypes.DWORD]
        self.kernel.GetVolumeInformationW.restype = wintypes.BOOL
        self.invalid_handle = ctypes.c_void_p(-1).value

    def local_ntfs(self, anchor: str) -> None:
        if self.kernel.GetDriveTypeW(anchor) != 3:
            raise SafetyError("Only a local fixed drive is supported on Windows.")
        filesystem = ctypes.create_unicode_buffer(64)
        if not self.kernel.GetVolumeInformationW(anchor, None, 0, None, None,
                                                 None, filesystem, len(filesystem)):
            raise SafetyError("The storage filesystem could not be verified.")
        if filesystem.value.upper() != "NTFS":
            raise SafetyError("The initial Windows storage adapter requires NTFS.")

    def open(self, path: Path, access: int, sharing: int, disposition: int,
             flags: int) -> int:
        handle = self.kernel.CreateFileW(str(path), access, sharing, None, disposition, flags, None)
        if handle == self.invalid_handle or handle is None:
            error = ctypes.get_last_error()
            if error in (2, 3):
                raise FileNotFoundError("The generated storage object does not exist.")
            raise SafetyError(f"Storage could not be opened safely (Windows error {error}).")
        return handle

    def information(self, handle: int) -> dict[str, int]:
        result = self.Information()
        if (self.kernel.GetFileType(handle) != 1
                or not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(result))):
            raise SafetyError("The storage object is not a verifiable disk object.")
        return {
            "attributes": result.attributes,
            "device": result.volume,
            "inode": (result.index_high << 32) | result.index_low,
            "size": (result.size_high << 32) | result.size_low,
            "links": result.links,
            "modified": (result.modified.dwHighDateTime << 32) | result.modified.dwLowDateTime,
        }


class SafeDirectory:
    """Hold ancestor protections while operating on a generated flat directory.

    ``path`` is supplied only by application services, never scenario input.
    Construction opens the directory; ``create=True`` requires a new final
    directory and existing parents. Closing releases all held descriptors.
    """

    def __init__(self, path: Path, create: bool = False):
        if type(create) is not bool:
            raise ValidationError("Directory creation policy must be boolean.")
        self.path = Path(path)
        self._handles: list[int] = []
        self._parts: list[str] = []
        self._closed = False
        self._win: _Windows | None = None
        self._identity: dict[str, int] = {}
        if not self.path.is_absolute() or ".." in self.path.parts:
            raise SafetyError("Storage requires an absolute, non-traversing local path.")
        try:
            if os.name == "nt":
                self._initialize_windows(create)
            elif sys.platform.startswith("linux"):
                self._initialize_linux(create)
            else:
                raise SafetyError("This operating system has no approved storage adapter.")
        except (OSError, ValueError) as error:
            self.close()
            raise SafetyError("The storage directory could not be opened safely.") from error
        except BaseException:
            self.close()
            raise

    def _initialize_windows(self, create: bool) -> None:
        raw = str(self.path)
        if raw.startswith("\\\\") or not re.fullmatch(r"[A-Za-z]:\\", self.path.anchor):
            raise SafetyError("UNC, device, extended and drive-relative paths are forbidden.")
        for component in self.path.parts[1:]:
            stem = component.split(".", 1)[0]
            if (":" in component or component.endswith((".", " "))
                    or _RESERVED.fullmatch(stem) or any(ord(c) < 32 for c in component)):
                raise SafetyError("A storage ancestor has an unsafe Windows name.")
        self._win = _Windows()
        self._win.local_ntfs(self.path.anchor)
        current = Path(self.path.anchor)
        ancestors = [current]
        for part in self.path.parts[1:]:
            current = current / part
            ancestors.append(current)
        if create and len(ancestors) == 1:
            raise SafetyError("A drive root cannot be a generated directory.")
        for index, ancestor in enumerate(ancestors):
            if create and index == len(ancestors) - 1:
                try:
                    os.mkdir(ancestor, 0o700)
                except FileExistsError as error:
                    raise SafetyError("A generated directory must be newly created.") from error
            handle = self._win.open(ancestor, self._win.READ_ATTRIBUTES,
                self._win.SHARE_READ, self._win.OPEN_EXISTING,
                self._win.BACKUP_SEMANTICS | self._win.OPEN_REPARSE)
            self._handles.append(handle)
            info = self._win.information(handle)
            if not info["attributes"] & self._win.DIRECTORY or info["attributes"] & self._win.REPARSE:
                raise SafetyError("Storage ancestors cannot be links or reparse points.")
        self._identity = self._object_identity(info)

    def _initialize_linux(self, create: bool) -> None:
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise SafetyError("No-follow directory handles are required.")
        self._verify_linux_mount()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        self._handles.append(os.open("/", flags))
        self._parts = list(self.path.parts[1:])
        if create and not self._parts:
            raise SafetyError("The filesystem root cannot be a generated directory.")
        for index, part in enumerate(self._parts):
            if create and index == len(self._parts) - 1:
                try:
                    os.mkdir(part, 0o700, dir_fd=self._handles[-1])
                except FileExistsError as error:
                    raise SafetyError("A generated directory must be newly created.") from error
            self._handles.append(os.open(part, flags, dir_fd=self._handles[-1]))
        info = os.fstat(self._handles[-1])
        if not stat.S_ISDIR(info.st_mode):
            raise SafetyError("A storage directory is required.")
        self._identity = {"device": info.st_dev, "inode": info.st_ino}

    def _verify_linux_mount(self) -> None:
        """Reject network/unknown filesystems using the kernel mount inventory."""
        try:
            inventory = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
            candidates = []
            for line in inventory.splitlines():
                head, tail = line.split(" - ", 1)
                mount = head.split()[4]
                mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), mount)
                if os.path.commonpath((str(self.path), mount)) == mount:
                    candidates.append((len(mount), tail.split()[0]))
            filesystem = max(candidates)[1]
        except (OSError, ValueError, IndexError) as error:
            raise SafetyError("The local Linux filesystem could not be verified.") from error
        if filesystem not in {"ext4", "xfs", "btrfs", "tmpfs", "overlay"}:
            raise SafetyError("Network or unsupported Linux storage is forbidden.")

    def _ensure_open(self) -> None:
        if self._closed:
            raise StateError("The storage directory is closed.")
        if self._win:
            for handle in self._handles:
                info = self._win.information(handle)
                if info["attributes"] & self._win.REPARSE or not info["attributes"] & self._win.DIRECTORY:
                    raise SafetyError("A held storage ancestor changed type.")
        else:
            for index, part in enumerate(self._parts):
                actual = os.stat(part, dir_fd=self._handles[index], follow_symlinks=False)
                held = os.fstat(self._handles[index + 1])
                if (not stat.S_ISDIR(actual.st_mode)
                        or (actual.st_dev, actual.st_ino) != (held.st_dev, held.st_ino)):
                    raise SafetyError("A held storage ancestor was replaced.")

    @staticmethod
    def _object_identity(info: dict[str, int]) -> dict[str, int]:
        return {"device": info["device"], "inode": info["inode"]}

    def _snapshot(self, descriptor: int) -> dict[str, int]:
        if self._win:
            import msvcrt
            info = self._win.information(msvcrt.get_osfhandle(descriptor))
            if info["attributes"] & (self._win.DIRECTORY | self._win.REPARSE):
                raise SafetyError("Only regular, non-reparse storage files are allowed.")
        else:
            value = os.fstat(descriptor)
            if not stat.S_ISREG(value.st_mode):
                raise SafetyError("Only regular storage files are allowed.")
            info = {"device": value.st_dev, "inode": value.st_ino, "size": value.st_size,
                    "links": value.st_nlink, "modified": value.st_mtime_ns}
        if info["links"] != 1 or info["device"] != self._identity["device"]:
            raise SafetyError("Linked objects or nested filesystem boundaries are forbidden.")
        if info["size"] > MAX_OBJECT_BYTES:
            raise SafetyError("The generated storage object exceeds the hard size bound.")
        return info

    def _open_file(self, name: str, *, write: bool = False, new: bool = False,
                   lease: bool = False, pin: bool = False) -> int:
        _check_name(name)
        self._ensure_open()
        descriptor = None
        try:
            if self._win:
                import msvcrt
                access = self._win.READ_ATTRIBUTES if pin else (
                    self._win.READ | (self._win.WRITE if write else 0))
                disposition = self._win.CREATE_NEW if new else (
                    self._win.OPEN_ALWAYS if lease else self._win.OPEN_EXISTING)
                sharing = self._win.SHARE_READ | (self._win.SHARE_WRITE if lease or pin else 0)
                handle = self._win.open(self.path / name, access, sharing, disposition, self._win.OPEN_REPARSE)
                try:
                    descriptor = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if write else os.O_RDONLY))
                except BaseException:
                    self._win.kernel.CloseHandle(handle)
                    raise
            else:
                flags = (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
                if new:
                    flags |= os.O_CREAT | os.O_EXCL
                elif lease:
                    flags |= os.O_CREAT
                descriptor = os.open(name, flags, 0o600, dir_fd=self._handles[-1])
            self._snapshot(descriptor)
            self._ensure_open()
            return descriptor
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        position = 0
        while position < len(data):
            written = os.write(descriptor, data[position:position + 65536])
            if written <= 0:
                raise StateError("A generated storage write made no progress.")
            position += written
        os.ftruncate(descriptor, len(data))
        os.fsync(descriptor)

    def create(self, name: str, data: bytes) -> dict[str, int]:
        _check_payload(data)
        try:
            descriptor = self._open_file(name, write=True, new=True)
        except FileExistsError as error:
            raise SafetyError("An existing object cannot be overwritten during generation.") from error
        try:
            self._write_all(descriptor, data)
            self._ensure_open()
            return self._object_identity(self._snapshot(descriptor))
        finally:
            os.close(descriptor)

    def read(self, name: str, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_OBJECT_BYTES:
            raise ValidationError("A positive bounded read size is required.")
        descriptor = self._open_file(name)
        try:
            before = self._snapshot(descriptor)
            if before["size"] > max_bytes:
                raise SafetyError("The generated object exceeds the requested read limit.")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise SafetyError("A storage read exceeded its byte limit.")
                chunks.append(chunk)
            after = self._snapshot(descriptor)
            self._ensure_open()
            if before != after or total != before["size"]:
                raise SafetyError("The generated object changed while being read.")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def replace(self, name: str, data: bytes, expected: dict[str, int] | None = None) -> dict[str, int]:
        """Write through one checked handle; callers must journal intent first.

        This deliberately avoids a second pathname lookup for a rename. A crash
        may leave a partial working copy, requiring clean-copy recovery.
        """
        _check_payload(data)
        _check_expected(expected)
        descriptor = self._open_file(name, write=True)
        try:
            actual = self._object_identity(self._snapshot(descriptor))
            if expected is not None and actual != expected:
                raise SafetyError("The generated object identity no longer matches its registry.")
            self._ensure_open()
            os.lseek(descriptor, 0, os.SEEK_SET)
            self._write_all(descriptor, data)
            self._ensure_open()
            return self._object_identity(self._snapshot(descriptor))
        finally:
            os.close(descriptor)

    def identity(self, name: str) -> dict[str, int]:
        descriptor = self._open_file(name)
        try:
            return self._object_identity(self._snapshot(descriptor))
        finally:
            os.close(descriptor)

    @contextmanager
    def pin(self, name: str):
        """Hold an existing regular file's identity without reading its bytes.

        Windows permits SQLite to write the file while denying its deletion or
        replacement. Pin existing SQLite sidecars as well as the main database.
        This does not authenticate database contents or prevent same-user edits.
        """
        descriptor = self._open_file(name, pin=True)
        try:
            yield self._object_identity(self._snapshot(descriptor))
            self._ensure_open()
            self._snapshot(descriptor)
        finally:
            os.close(descriptor)

    def exists(self, name: str) -> bool:
        try:
            self.identity(name)
            return True
        except FileNotFoundError:
            return False

    def names(self) -> list[str]:
        self._ensure_open()
        names = []
        with os.scandir(self.path if self._win else self._handles[-1]) as entries:
            for entry in entries:
                if len(names) >= MAX_DIRECTORY_ENTRIES:
                    raise SafetyError("The generated directory exceeds its entry bound.")
                names.append(entry.name)
        for name in names:
            try:
                _check_name(name)
            except ValidationError as error:
                raise SafetyError("The generated directory contains an unexpected entry.") from error
            self.identity(name)
        self._ensure_open()
        return sorted(names)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in reversed(self._handles):
            if self._win:
                self._win.kernel.CloseHandle(handle)
            else:
                os.close(handle)
        self._handles.clear()

    def __enter__(self) -> SafeDirectory:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class LabLease:
    """Nonblocking, cross-process mutation lease at a fixed generated filename."""

    def __init__(self, path: Path):
        self.path = Path(path)
        if self.path.name != "lease.flag":
            raise ValidationError("The mutation lease must use its fixed lease.flag name.")
        self._directory: SafeDirectory | None = None
        self._descriptor: int | None = None
        self._locked = False

    def __enter__(self) -> LabLease:
        if self._directory is not None:
            raise StateError("This mutation lease is already entered.")
        self._directory = SafeDirectory(self.path.parent)
        try:
            self._descriptor = self._directory._open_file("lease.flag", write=True, lease=True)
            if self._directory._snapshot(self._descriptor)["size"] > 1:
                raise SafetyError("The mutation lease file has unexpected content.")
            os.lseek(self._descriptor, 0, os.SEEK_SET)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self._descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise StateError("Another application operation owns this lab's mutation lease.") from error
            self._locked = True
            if os.fstat(self._descriptor).st_size == 0:
                os.write(self._descriptor, b"\0")
                os.fsync(self._descriptor)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_: Any) -> None:
        try:
            if self._descriptor is not None:
                try:
                    if self._locked:
                        os.lseek(self._descriptor, 0, os.SEEK_SET)
                        if os.name == "nt":
                            import msvcrt
                            msvcrt.locking(self._descriptor, msvcrt.LK_UNLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(self._descriptor)
        finally:
            self._descriptor = None
            self._locked = False
            if self._directory is not None:
                self._directory.close()
                self._directory = None
