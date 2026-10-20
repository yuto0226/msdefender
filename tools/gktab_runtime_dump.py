"""Read selected gktab slots from an already initialized isolated process.

This script never loads mpengine.dll, starts a process, or writes to the target.
It requires an explicit PID and two acknowledgements before opening that process
with read-only rights.
"""

import argparse
import ctypes
import hashlib
import json
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Any

EXPECTED_VERSION = "1.443.903.0"
EXPECTED_SHA256 = "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3"
DEFAULT_DLL = Path("bin/1.443.903.0/mpengine.dll")
PREFERRED_IMAGE_BASE = 0x180000000
GTAB_GLOBAL_VA = 0x181289C80
GTAB_GLOBAL_RVA = GTAB_GLOBAL_VA - PREFERRED_IMAGE_BASE
GTAB_SIZE = 0x15C58
TARGET_TYPES = (0x20, 0x21, 0x30, 0x74, 0xC1)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
LIST_MODULES_ALL = 0x03
MAX_MODULES = 4096


class PoCError(RuntimeError):
    """Expected fail-closed validation error."""


def verify_binary(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise PoCError(f"mpengine SHA-256 mismatch: {digest}")
    return {
        "version": EXPECTED_VERSION,
        "path": str(resolved),
        "sha256": digest,
        "version_validation": "exact SHA-256 pin for documented binary",
    }


def win32_api() -> tuple[Any, Any, Any]:
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise PoCError("live memory reads are supported only on Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    from ctypes import wintypes

    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    )
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.IsWow64Process.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    )
    kernel32.IsWow64Process.restype = wintypes.BOOL
    psapi.EnumProcessModulesEx.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HMODULE),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    )
    psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    psapi.GetModuleFileNameExW.argtypes = (
        wintypes.HANDLE,
        wintypes.HMODULE,
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    return kernel32, psapi, ctypes


def win_error(message: str) -> PoCError:
    return PoCError(f"{message}: {ctypes.FormatError(ctypes.get_last_error()).strip()}")


def read_process(pid: int, expected_binary: Path) -> dict[str, Any]:
    kernel32, psapi, c = win32_api()
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if not handle:
        raise win_error("OpenProcess(read-only) failed")

    try:
        process_path = c.create_unicode_buffer(32768)
        path_length = c.c_ulong(len(process_path))
        if not kernel32.QueryFullProcessImageNameW(
            handle, 0, process_path, c.byref(path_length)
        ):
            raise win_error("QueryFullProcessImageNameW failed")
        is_wow64 = c.c_int()
        if not kernel32.IsWow64Process(handle, c.byref(is_wow64)):
            raise win_error("IsWow64Process failed")
        if is_wow64.value:
            raise PoCError("refusing a 32-bit target process")
        process_name = Path(process_path.value).name.casefold()
        if process_name in {"msmpeng.exe", "mpdefendercoreservice.exe"}:
            raise PoCError("refusing to read a Defender service process")

        module_array = (c.c_void_p * MAX_MODULES)()
        needed = c.c_ulong()
        if not psapi.EnumProcessModulesEx(
            handle,
            module_array,
            c.sizeof(module_array),
            c.byref(needed),
            LIST_MODULES_ALL,
        ):
            raise win_error("EnumProcessModulesEx failed")
        if needed.value % c.sizeof(c.c_void_p) or needed.value > c.sizeof(module_array):
            raise PoCError("module list exceeds bounded enumeration buffer")

        expected_path = str(expected_binary.resolve()).casefold()
        found: tuple[int, str] | None = None
        for module in module_array[: needed.value // c.sizeof(c.c_void_p)]:
            module_path = c.create_unicode_buffer(32768)
            length = psapi.GetModuleFileNameExW(
                handle, module, module_path, len(module_path)
            )
            if not length:
                raise win_error("GetModuleFileNameExW failed")
            if module_path.value.casefold() == expected_path:
                if found is not None:
                    raise PoCError(
                        "target process contains duplicate pinned module paths"
                    )
                found = (int(module), module_path.value)
        if found is None:
            raise PoCError("pinned mpengine.dll is not loaded in the specified process")
        module_base, module_path = found

        def read_exact(address: int, size: int) -> bytes:
            if size <= 0 or address <= 0 or address + size > 0x0000800000000000:
                raise PoCError("invalid or non-canonical target read range")
            buffer = (c.c_ubyte * size)()
            transferred = c.c_size_t()
            if not kernel32.ReadProcessMemory(
                handle, c.c_void_p(address), buffer, size, c.byref(transferred)
            ):
                raise win_error(f"ReadProcessMemory failed at 0x{address:x}")
            if transferred.value != size:
                raise PoCError(
                    f"short read at 0x{address:x}: {transferred.value}/{size}"
                )
            return bytes(buffer)

        gktab_pointer_address = module_base + GTAB_GLOBAL_RVA
        gktab_raw = read_exact(gktab_pointer_address, 8)
        gktab = struct.unpack("<Q", gktab_raw)[0]
        if not gktab or gktab % 8 or gktab + GTAB_SIZE > 0x0000800000000000:
            raise PoCError(f"invalid gktab pointer: 0x{gktab:x}")

        rows = []
        for record_type in TARGET_TYPES:
            handler_qword_index = 638 + 6 * record_type
            context_qword_index = 643 + 6 * record_type
            handler_offset = handler_qword_index * 8
            context_offset = context_qword_index * 8
            template_offset = 41968 + 88 * record_type
            if (
                handler_offset + 8 > GTAB_SIZE
                or context_offset + 8 > GTAB_SIZE
                or template_offset + 88 > GTAB_SIZE
            ):
                raise PoCError(f"type 0x{record_type:02x} slot exceeds gktab bounds")
            handler_address = gktab + handler_offset
            context_address = gktab + context_offset
            template_address = gktab + template_offset
            handler = read_exact(handler_address, 8)
            context = read_exact(context_address, 8)
            template = read_exact(template_address, 88)
            rows.append(
                {
                    "type": f"0x{record_type:02x}",
                    "handler": {
                        "qword_index": handler_qword_index,
                        "byte_offset": f"0x{handler_offset:x}",
                        "address": f"0x{handler_address:x}",
                        "raw_hex": handler.hex(),
                        "raw_qword_le": f"0x{struct.unpack('<Q', handler)[0]:016x}",
                    },
                    "context": {
                        "qword_index": context_qword_index,
                        "byte_offset": f"0x{context_offset:x}",
                        "address": f"0x{context_address:x}",
                        "raw_hex": context.hex(),
                        "raw_qword_le": f"0x{struct.unpack('<Q', context)[0]:016x}",
                    },
                    "template": {
                        "byte_offset": f"0x{template_offset:x}",
                        "address": f"0x{template_address:x}",
                        "size": 88,
                        "raw_hex": template.hex(),
                    },
                }
            )

        return {
            "format": "gktab-runtime-raw-v1",
            "binary": verify_binary(expected_binary),
            "target": {
                "pid": pid,
                "process_path": process_path.value,
                "module_path": module_path,
                "module_base": f"0x{module_base:x}",
                "gktab_global_rva": f"0x{GTAB_GLOBAL_RVA:x}",
                "gktab_pointer_address": f"0x{gktab_pointer_address:x}",
                "gktab_pointer_raw_hex": gktab_raw.hex(),
                "gktab_address": f"0x{gktab:x}",
            },
            "slots": rows,
        }
    finally:
        kernel32.CloseHandle(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pid",
        type=int,
        required=True,
        help="PID of an already initialized isolated harness",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_DLL,
        help="pinned 1.443.903.0 mpengine.dll",
    )
    parser.add_argument(
        "--confirm-isolated-harness",
        action="store_true",
        help="confirm PID is a disposable, isolated harness you started yourself",
    )
    parser.add_argument(
        "--confirm-initialized",
        action="store_true",
        help="confirm gktab initialization and registration are complete",
    )
    args = parser.parse_args()
    try:
        if platform.machine().casefold() not in {"amd64", "x86_64"}:
            raise PoCError("requires an x64 Windows host")
        if args.pid <= 0:
            raise PoCError("PID must be a positive explicit process ID")
        verify_binary(args.binary)
        if not args.confirm_isolated_harness or not args.confirm_initialized:
            raise PoCError(
                "guard: supply both --confirm-isolated-harness and "
                "--confirm-initialized after verifying the external VM/harness state"
            )
        result = read_process(args.pid, args.binary)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (OSError, PoCError) as error:
        print(f"gktab runtime dump refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
