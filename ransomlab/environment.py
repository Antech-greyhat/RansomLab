"""Minimal environment gate. Guest detection does not prove network isolation."""
from __future__ import annotations

import os
from pathlib import Path

from .core.errors import SafetyError, ValidationError


def _windows_unprivileged() -> bool:
    """Check the effective Windows token with separate API success checks.

    IsUserAnAdmin alone cannot establish that all underlying queries succeeded.
    An explicit TokenElevation query therefore also has to succeed. Prefer the
    thread token when impersonating, otherwise inspect the process token.
    """
    import ctypes

    pointer, u32, boolean = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
    token = pointer()
    kernel = None
    result = False
    try:
        kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x00000800)
        security = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=0x00000800)
        shell = ctypes.WinDLL("shell32.dll", use_last_error=True, winmode=0x00000800)
        signatures = (
            (kernel.GetCurrentThread, [], pointer),
            (kernel.GetCurrentProcess, [], pointer),
            (kernel.CloseHandle, [pointer], boolean),
            (security.OpenThreadToken, [pointer, u32, boolean, ctypes.POINTER(pointer)], boolean),
            (security.OpenProcessToken, [pointer, u32, ctypes.POINTER(pointer)], boolean),
            (security.GetTokenInformation, [pointer, u32, pointer, u32, ctypes.POINTER(u32)], boolean),
            (shell.IsUserAnAdmin, [], boolean),
        )
        for function, arguments, return_type in signatures:
            function.argtypes, function.restype = arguments, return_type
        if shell.IsUserAnAdmin() != 0:
            return False
        # TOKEN_QUERY; OpenAsSelf changes only the access check, not which
        # effective thread token is opened.
        ctypes.set_last_error(0)
        if not security.OpenThreadToken(kernel.GetCurrentThread(), 0x0008, True, ctypes.byref(token)):
            if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN
                return False
            if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
                return False
        if not token.value:
            return False
        elevated, returned = u32(), u32()
        # TOKEN_INFORMATION_CLASS.TokenElevation = 20; TOKEN_ELEVATION is DWORD.
        if not security.GetTokenInformation(token, 20, ctypes.byref(elevated),
                                            ctypes.sizeof(elevated), ctypes.byref(returned)):
            return False
        result = returned.value == ctypes.sizeof(elevated) and elevated.value == 0
    except (OSError, AttributeError, ValueError, TypeError, ctypes.ArgumentError):
        result = False
    finally:
        if token.value and kernel is not None:
            try:
                if not kernel.CloseHandle(token):
                    result = False
            except (OSError, AttributeError, ValueError, TypeError, ctypes.ArgumentError):
                result = False
    return result


def unprivileged_process() -> bool:
    """Reject elevation and unknown identity-query results; not an OS sandbox."""
    try:
        if os.name == "nt":
            return _windows_unprivileged()
        if os.name == "posix":
            identity = os.geteuid()
            return type(identity) is int and identity > 0
    except (OSError, AttributeError, ValueError, TypeError):
        return False
    return False


def vmware_guest() -> bool:
    """Read only the hypervisor manufacturer needed by the execution gate."""
    try:
        if os.name == "nt":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                manufacturer = winreg.QueryValueEx(key, "SystemManufacturer")[0]
                model = winreg.QueryValueEx(key, "SystemProductName")[0]
            return "vmware" in (str(manufacturer) + " " + str(model)).lower()
        vendor = Path("/sys/class/dmi/id/sys_vendor").read_text(encoding="utf-8")[:256]
        return "vmware" in vendor.lower()
    except (OSError, ValueError, TypeError):
        return False


def validate_attestation(snapshot: str, isolated: bool, disposable: bool) -> dict:
    if type(snapshot) is not str or not 1 <= len(snapshot) <= 64:
        raise ValidationError("A bounded snapshot label is required")
    if any(not (ch.isalnum() or ch in " _-.") for ch in snapshot):
        raise ValidationError("Snapshot labels may contain letters, digits, spaces, dots, hyphens and underscores")
    if isolated is not True or disposable is not True:
        raise SafetyError("A disposable guest, isolated network and clean snapshot must be confirmed")
    if not vmware_guest():
        raise SafetyError("File-impact actions require a verified VMware guest; detection failed")
    if not unprivileged_process():
        raise SafetyError("File-impact actions require a verified non-elevated process identity")
    return {"snapshot": snapshot, "isolated": True, "disposable": True, "vendor": "VMware"}


def require_guest(attestation: dict | None) -> None:
    if not isinstance(attestation, dict):
        raise SafetyError("The lab has not been armed with an isolation and snapshot attestation")
    validate_attestation(attestation.get("snapshot"), attestation.get("isolated"), attestation.get("disposable"))
