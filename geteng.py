#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests>=2.32.5,<3",
#     "rich>=14.3.1,<15",
#     "tqdm>=4.67.1,<5",
# ]
# ///
"""List Defender package/engine versions and download definition packages.

    uv run geteng.py list
    uv run geteng.py download 1.443.6.0
    uv run geteng.py download 1.447.224.0 1.447.226.0
    uv run geteng.py update

Catalog: defender_version.json. Extraction requires 7-Zip or cabextract.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import html
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Never

import requests
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from tqdm import tqdm

CONSOLE = Console(highlight=False)
STATUS = Console(stderr=True, highlight=False)

SCRIPT_PATH = Path(__file__).resolve()
ROOT = SCRIPT_PATH.parent
CATALOG_PATH = ROOT / "defender_version.json"
ENDPOINT = "https://definitionupdates.microsoft.com/packages/content/mpam-fe.exe"
ARCHES = {"x64": "amd64", "x86": "x86", "arm64": "arm64"}
MACHINES = {"amd64": 0x8664, "x86": 0x014C, "arm64": 0xAA64}
WDSI_URL = "https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes"
CATALOG_MAX_AGE = timedelta(days=1)
LOG_LEVELS = {
    "ok": ("+", "green"),
    "error": ("-", "red"),
    "info": ("*", "cyan"),
    "warning": ("!", "yellow"),
    "download": (">", "cyan"),
    "fetch": ("<", "cyan"),
    "cancel": ("x", "yellow"),
    "work": ("~", "cyan"),
}


def report(level: str, label: str, message: str) -> None:
    symbol, style = LOG_LEVELS[level]
    line = Text(f"[{symbol}] {label}: ", style=f"bold {style}")
    line.append(message, style="default")
    STATUS.print(line)


class CliParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        report("error", "Error", message)
        raise SystemExit(2)


def version(value: str) -> str:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", value):
        raise argparse.ArgumentTypeError("expected a four-part version, e.g. 1.443.6.0")
    return value


def timeout_seconds(value: str) -> float:
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and greater than zero")
    return seconds


def load_catalog(*, required: bool = True) -> dict[str, Any]:
    if not CATALOG_PATH.is_file():
        if not required:
            return {"schema_version": 2, "versions": []}
        raise ValueError(f"Catalog not found: {CATALOG_PATH}. Run 'geteng.py update'.")
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid catalog JSON: {exc}") from exc
    if not isinstance(data.get("versions"), list):
        raise TypeError("Invalid catalog: versions must be a list")
    return data


def request_url(url: str, params: dict[str, str]) -> str:
    prepared = requests.Request("GET", url, params=params).prepare().url
    if prepared is None:
        raise ValueError(f"Cannot prepare URL: {url}")
    return prepared


def download_url(package: str, engine: str, arch: str) -> str:
    return request_url(
        ENDPOINT,
        {
            "packageType": "Signatures",
            "packageVersion": version(package),
            "arch": ARCHES[arch],
            "engineVersion": version(engine),
        },
    )


def select_engine(rows: list[dict], package: str, override: str | None) -> str:
    if override:
        return override
    matches = [row for row in rows if row["package_version"] == package]
    if not matches:
        raise ValueError(
            f"Package {package} is not in the catalog; specify --engine VERSION."
        )
    engines = sorted({row["engine_version"] for row in matches})
    if len(engines) != 1 or any(row["needs_review"] for row in matches):
        raise ValueError(
            f"Package {package} has ambiguous/source-anomalous metadata "
            f"({', '.join(engines)}); review 'list --package {package} --json' "
            "and specify --engine VERSION."
        )
    return version(engines[0])


def list_versions(args: argparse.Namespace, catalog: dict) -> int:
    rows = [
        row
        for row in catalog["versions"]
        if (not args.package or row["package_version"] == args.package)
        and (not args.engine or row["engine_version"] == args.engine)
    ]
    rows.sort(
        key=lambda row: (
            tuple(map(int, row["package_version"].split("."))),
            tuple(map(int, row["engine_version"].split("."))),
        ),
        reverse=True,
    )

    if args.json:
        print(json.dumps({**catalog, "versions": rows}, ensure_ascii=False, indent=2))
        return 0

    CONSOLE.print(Text(f"Defender packages | {len(rows)} records", style="bold cyan"))
    CONSOLE.print(Text(f"Catalog: {catalog['collected_at']}", style="dim"))

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("DATE", no_wrap=True)
    table.add_column("PACKAGE", no_wrap=True, style="cyan")
    compact = CONSOLE.width < 115
    if compact:
        table.add_column("DETAILS (platform / engine)")
    else:
        table.add_column("PLATFORM", no_wrap=True, style="dim")
        table.add_column("ENGINE", no_wrap=True)

    for row in rows:
        released = display_release(row)
        cells = [Text(released or "-"), Text(row["package_version"])]
        if compact:
            detail = Text("platform ", style="dim")
            detail.append((row["platform_version"] or "-") + "\n")
            detail.append("engine   ", style="dim")
            detail.append(row["engine_version"])
            cells.append(detail)
        else:
            cells.extend(
                [Text(row["platform_version"] or "-"), Text(row["engine_version"])]
            )
        table.add_row(*cells)

    CONSOLE.print(table)
    return 0


def display_release(row: dict) -> str:
    if row.get("package_release_at"):
        return row["package_release_at"].replace("T", " ")
    if row.get("engine_release_date"):
        return row["engine_release_date"] + " (engine)"
    if row.get("release_month"):
        return row["release_month"] + " (engine month)"
    return "-"


def find_extractor() -> tuple[str, str]:
    for name in ("7z", "7zz", "7za", "cabextract"):
        executable = shutil.which(name)
        if executable:
            return ("cabextract" if name == "cabextract" else "7z", executable)
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(variable):
            executable = Path(os.environ[variable]) / "7-Zip" / "7z.exe"
            if executable.is_file():
                return "7z", str(executable)
    raise ValueError("7-Zip/cabextract not found. Install one, or use --no-extract.")


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rmdx_metadata(path: Path) -> dict:
    file_size = path.stat().st_size
    overlap = b""
    scanned = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            block = overlap + chunk
            search_from = 0
            while (index := block.find(b"RMDX", search_from)) >= 0:
                offset = scanned - len(overlap) + index
                position = stream.tell()
                stream.seek(offset)
                header = stream.read(64)
                stream.seek(position)
                if len(header) == 64:
                    words = struct.unpack("<16I", header)
                    flags = words[3]
                    descriptor = offset + words[6]
                    if (
                        words[0] == 0x58444D52
                        and flags & 0x00200000
                        and descriptor + 8 <= file_size
                    ):
                        raw_value = words[1]
                        timestamp = None
                        if 946684800 <= raw_value < 4102444800:
                            timestamp = (
                                datetime.fromtimestamp(raw_value, timezone.utc)
                                .isoformat()
                                .replace("+00:00", "Z")
                            )
                        return {
                            "offset": offset,
                            "raw_value": raw_value,
                            "timestamp_utc": timestamp,
                            "flags": f"0x{flags:08X}",
                            "uncompressed_bytes": words[7],
                        }
                search_from = index + 4
            overlap = block[-3:]
            scanned += len(chunk)
    raise ValueError("RMDX header not found")


def pe_machine(path: Path) -> int:
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise ValueError(f"Not a PE file: {path.name}")
        stream.seek(struct.unpack_from("<I", header, 0x3C)[0])
        signature = stream.read(6)
    if len(signature) != 6 or signature[:4] != b"PE\0\0":
        raise ValueError(f"Invalid PE header: {path.name}")
    return struct.unpack_from("<H", signature, 4)[0]


def file_versions(path: Path) -> dict | None:
    """Read version resources through version.dll; do not load the sample DLL."""
    if os.name != "nt":
        return None
    from ctypes import wintypes

    api = ctypes.WinDLL("version", use_last_error=True)
    api.GetFileVersionInfoSizeW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    api.GetFileVersionInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    api.GetFileVersionInfoW.restype = wintypes.BOOL
    api.VerQueryValueW.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.UINT),
    ]
    api.VerQueryValueW.restype = wintypes.BOOL
    filename = str(path.resolve())
    ignored = wintypes.DWORD()
    size = api.GetFileVersionInfoSizeW(filename, ctypes.byref(ignored))
    if not size:
        raise ValueError(f"No version resource in {path.name}")
    buffer = ctypes.create_string_buffer(size)
    if not api.GetFileVersionInfoW(filename, 0, size, buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    pointer = ctypes.c_void_p()
    length = wintypes.UINT()
    if (
        not api.VerQueryValueW(
            buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)
        )
        or length.value < 52
    ):
        raise ValueError(f"No VS_FIXEDFILEINFO in {path.name}")
    words = struct.unpack("<13I", ctypes.string_at(pointer, 52))
    if words[0] != 0xFEEF04BD:
        raise ValueError(f"Invalid VS_FIXEDFILEINFO in {path.name}")

    def dotted(high: int, low: int) -> str:
        return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"

    return {
        "file_version": dotted(words[2], words[3]),
        "product_version": dotted(words[4], words[5]),
    }


def fetch_package(url: str, path: Path, timeout: float) -> dict:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    count = 0

    with requests.get(
        url,
        headers={"User-Agent": "geteng/1.0", "Accept-Encoding": "identity"},
        timeout=timeout,
        stream=True,
    ) as response:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError(f"Expected HTTP 200, got {response.status_code}")
        headers = {key.lower(): value for key, value in response.headers.items()}
        total = int(headers["content-length"]) if "content-length" in headers else None
        with (
            path.open("xb") as stream,
            tqdm(
                total=total,
                desc=path.name,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                dynamic_ncols=True,
                miniters=1,
                file=sys.stderr,
                disable=not sys.stderr.isatty(),
                colour=None if "NO_COLOR" in os.environ else "cyan",
            ) as progress,
        ):
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                stream.write(chunk)
                sha256.update(chunk)
                md5.update(chunk)
                count += len(chunk)
                progress.update(len(chunk))
        final_url = response.url

    if total is not None and count != total:
        raise ValueError(
            f"Incomplete download: expected {total} bytes, received {count}"
        )

    actual_md5 = base64.b64encode(md5.digest()).decode("ascii")
    if headers.get("content-md5") and headers["content-md5"] != actual_md5:
        raise ValueError("Content-MD5 mismatch; downloaded package rejected")

    pe_machine(path)
    return {
        "requested_url": url,
        "final_url": final_url,
        "http_status": 200,
        "headers": headers,
        "bytes": count,
        "sha256": sha256.hexdigest(),
        "content_md5_verified": "content-md5" in headers,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
    }


def extracted_file_manifest(folder: Path) -> list[dict]:
    files = []
    for path in sorted(folder.rglob("*"), key=lambda item: item.as_posix().lower()):
        if path.is_symlink():
            raise ValueError(
                f"Extracted symbolic link rejected: {path.relative_to(folder)}"
            )
        if path.is_file():
            resolved = path.resolve()
            if not resolved.is_relative_to(folder.resolve()):
                raise ValueError(f"Extracted path escapes output directory: {path}")
            item = {
                "path": path.relative_to(folder).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            if path.suffix.lower() == ".vdm":
                errors = []
                try:
                    item["file_versions"] = file_versions(path)
                except (OSError, ValueError) as exc:
                    item["file_versions"] = None
                    errors.append(f"version resource: {exc}")
                try:
                    item["rmdx"] = rmdx_metadata(path)
                except (OSError, ValueError, struct.error, OverflowError) as exc:
                    item["rmdx"] = None
                    errors.append(f"RMDX: {exc}")
                if errors:
                    item["metadata_error"] = "; ".join(errors)
            files.append(item)
    return files


def extract_package(
    package: Path, folder: Path, extractor: tuple[str, str]
) -> tuple[Path, list[dict]]:
    kind, executable = extractor
    if kind == "7z":
        command = [executable, "x", "-y", f"-o{folder}", str(package)]
    else:
        command = [executable, "-q", "-d", str(folder), str(package)]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=180,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise ValueError(f"Cannot extract package: {detail}")
    manifest = extracted_file_manifest(folder)
    engines = [
        folder / item["path"]
        for item in manifest
        if Path(item["path"]).name.lower() == "mpengine.dll"
    ]
    if len(engines) != 1:
        raise ValueError(f"Expected one mpengine.dll, found {len(engines)}")
    return engines[0], manifest


def download_one(
    package: str,
    engine: str,
    args: argparse.Namespace,
    extractor: tuple[str, str] | None,
) -> Path:
    arch = ARCHES[args.arch]
    output_root = args.output.resolve()
    destination = (output_root / package / arch).resolve()

    if not destination.is_relative_to(output_root):
        raise ValueError("Output path resolves outside the selected output root")
    if destination.exists():
        raise ValueError(
            f"Output already exists: {destination}. Use -o for another directory."
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    url = download_url(package, engine, args.arch)
    report("download", "Download", f"package {package} / engine {engine} / {arch}")

    # Rename staging after validation; remove temporary files on failure.
    with tempfile.TemporaryDirectory(
        prefix=".geteng-", dir=destination.parent
    ) as temporary:
        if Path(temporary).resolve().parent != destination.parent:
            raise ValueError(
                "Temporary directory resolves outside the output directory"
            )
        staging = Path(temporary) / "sample"
        staging.mkdir()
        archive = staging / "mpam-fe.exe"

        metadata = fetch_package(url, archive, args.timeout)
        report(
            "work",
            "Verify",
            f"{metadata['bytes'] / 1048576:.2f} MiB received; checking package version",
        )

        package_versions = file_versions(archive)
        if package_versions and package_versions["file_version"] != package:
            raise ValueError(
                f"Package version mismatch: requested {package}, received {package_versions['file_version']}"
            )

        metadata.update(
            {
                "package_version": package,
                "engine_version": engine,
                "arch": arch,
                "package_file_versions": package_versions,
                "engine": None,
                "extracted_files": [],
            }
        )

        if extractor:
            extracted = staging / "extracted"
            extracted.mkdir()
            report("info", "Extract", f"all package files using {extractor[0]}")
            dll, manifest = extract_package(archive, extracted, extractor)
            machine = pe_machine(dll)
            if machine != MACHINES[arch]:
                raise ValueError(
                    f"Engine architecture mismatch: requested {arch}, received PE Machine 0x{machine:04X}"
                )
            actual = file_versions(dll)
            if actual and actual["file_version"] != engine:
                raise ValueError(
                    f"Engine version mismatch: requested {engine}, received {actual['file_version']}"
                )
            metadata["engine"] = {
                "sha256": sha256_file(dll),
                "bytes": dll.stat().st_size,
                "path": dll.relative_to(staging).as_posix(),
                "machine": f"0x{machine:04X}",
                "versions": actual,
                "version_verified": actual is not None,
            }
            metadata["extracted_files"] = manifest

            report(
                "ok",
                "Verified",
                f"engine {actual['file_version'] if actual else 'version unavailable'} / {arch}",
            )

        (staging / "download.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        staging.rename(destination)

    files = (
        "mpam-fe.exe, extracted/, download.json"
        if extractor
        else "mpam-fe.exe, download.json"
    )
    report("ok", "Saved", files)
    print(destination)
    return destination


NAMES = (
    "msda-updates-previous-versions-technical-upgrade-support",
    "microsoft-defender-endpoint-releases",
    "microsoft-defender-antivirus-updates",
)
VERSION = r"\d+(?:\.\d+){2,3}"
MONTHS = {
    name: index
    for index, name in enumerate(
        (
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ),
        1,
    )
}


def release_dates(heading: str, raw_date: str | None) -> dict:
    """Separate an exact engine release date from the release-label month."""
    month = re.search(r"(" + "|".join(MONTHS) + r")[ -]+(\d{4})", heading)
    release_month = f"{month[2]}-{MONTHS[month[1]]:02d}" if month else None
    exact = None
    if raw_date:
        pattern = r"([A-Za-z]+ \d{1,2}, \d{4})"
        match = re.search(pattern + r"\s*\([^)]*\bEngine\b[^)]*\)", raw_date)
        if not match:
            match = re.fullmatch(pattern, raw_date)
        if match:
            # Parse English months independently of the machine's locale.
            name, day, year = match[1].replace(",", "").split()
            exact = date(int(year), MONTHS[name], int(day)).isoformat()
    return {"engine_release_date": exact, "release_month": release_month}


def source_field(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def parse_source(name: str, text: str) -> list[dict]:
    records = []
    section = ""
    for block in re.split(r"(?=^#{2,3} )", text, flags=re.MULTILINE):
        if block.startswith("## "):
            section = block.splitlines()[0][3:]
            continue
        if not block.startswith("### "):
            continue
        heading = block.splitlines()[0][4:].strip()
        clean = (
            block.replace("**", "")
            .replace("`", "")
            .replace("\ufffd", " ")
            .replace("\xa0", " ")
        )

        if name == "microsoft-defender-endpoint-releases":
            if section != "Microsoft Defender Antivirus releases":
                continue
            package = source_field(
                clean, r"^\| Security intelligence[^|]*\|\s*(" + VERSION + r")"
            )
            engine = source_field(clean, r"^\| Engine\s*\|\s*(" + VERSION + r")")
            platform = source_field(clean, r"^\| Platform\s*\|\s*(" + VERSION + r")")
            released = source_field(clean, r"^\| Engine\s*\|[^|]*\|\s*([^|]+)")
            kind = "release"
        else:
            package = source_field(
                clean,
                r"^- Security intelligence(?: update)? version:\s*(" + VERSION + r")",
            )
            engine = source_field(
                clean, r"^- Engine(?: version)?:\s*(" + VERSION + r")"
            )
            platform = source_field(
                clean, r"^- Platform(?:/Client| version)?:\s*(" + VERSION + r")"
            )
            released = source_field(clean, r"^- Release date:\s*(.+)")
            kind = "dism" if "DISM" in section else "release"
        if not package and not engine:
            continue
        if not package or not engine:
            raise ValueError(f"Incomplete version record in {name}: {heading}")
        notes = []
        needs_review = False
        header_engine = re.search(r"Engine:?\s*(" + VERSION + r")", heading)
        if header_engine and header_engine.group(1) != engine:
            notes.append(
                f"Heading engine: {header_engine.group(1)}; body engine: {engine}. Body value retained."
            )
            needs_review = True
        if len(engine.split(".")) != 4:
            notes.append(
                "Source engine has three version components; no correction applied."
            )
            needs_review = True
        if package == "1.159.11.0" and engine == "1.1.26080.3":
            notes.append(
                "August 2026 table lists 1.159.11.0; observed packages use 1.459. Source value retained."
            )
            needs_review = True
        records.append(
            {
                "package_version": package,
                "engine_version": engine,
                "platform_version": platform,
                "release": heading,
                "release_date": released,
                "kind": kind,
                "needs_review": needs_review,
                "source": name,
                "notes": notes,
                **release_dates(heading, released),
            }
        )
    if not records:
        raise ValueError(f"No records found in {name}; source format may have changed")
    return records


def observed_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = [
        {
            "package_version": "1.459.153.0",
            "engine_version": "1.1.26080.3",
            "platform_version": None,
            "release": "2026-09-11 HTTP capture",
            "release_date": None,
            "observed_at": "2026-09-11T04:22:44Z",
            "engine_release_date": None,
            "release_month": None,
            "kind": "capture",
            "needs_review": False,
            "source": "capture-2026-09-11",
            "notes": ["HTTP 200 captured; DLL version not checked in this capture."],
        }
    ]
    local_rows: dict[str, dict[str, Any]] = {}
    sample_root = ROOT / "bin"
    if sample_root.is_dir():
        for folder in sample_root.iterdir():
            file = folder / "mpengine.dll"
            if (
                folder.is_dir()
                and re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", folder.name)
                and file.is_file()
            ):
                relative = file.relative_to(ROOT).as_posix()
                local_rows.setdefault(
                    relative,
                    {
                        "package_version": folder.name,
                        "platform_version": None,
                        "release_date": None,
                        "observed_at": datetime.fromtimestamp(
                            file.stat().st_mtime, timezone.utc
                        ).isoformat(),
                        "kind": "local",
                        "needs_review": False,
                        "source": "local-files",
                        "local_path": relative,
                    },
                )
    for row in local_rows.values():
        local_path = row["local_path"]
        if not isinstance(local_path, str):
            raise TypeError("Local sample path must be a string")
        file = ROOT / local_path
        row.update(
            {
                "release": "Local sample",
                "engine_release_date": None,
                "release_month": None,
                "notes": ["Package from directory name; engine from DLL FileVersion."],
            }
        )
        if os.name == "nt" and file.is_file():
            versions = file_versions(file)
            if versions is None:
                raise ValueError(f"Cannot read version resource from {file}")
            row["engine_version"] = versions["file_version"]
            row["engine_sha256"] = sha256_file(file)
        records.append(row)
    return records


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    created = False
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(text)
        if path.exists():
            temporary.chmod(path.stat().st_mode & 0o777)
        temporary.replace(path)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def parse_package_release(text: str, package: str) -> dict:
    title = re.search(r'id=["\']titleVersion["\'][^>]*>\s*([^<]+)', text)
    release_date_node = re.search(r'id=["\']releaseDate_0["\'][^>]*>\s*([^<]+)', text)
    if not title or html.unescape(title[1]).strip() != package or not release_date_node:
        raise ValueError("WDSI returned no release date for the requested package")
    raw = html.unescape(release_date_node[1]).strip()
    match = re.fullmatch(
        r"(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(AM|PM)", raw
    )
    if not match:
        raise ValueError(f"Unrecognized WDSI date: {raw}")
    month, day, year, hour, minute, second = map(int, match.groups()[:6])
    if year < 2000 or not 1 <= hour <= 12:
        raise ValueError(f"Invalid WDSI date: {raw}")
    hour = hour % 12 + (12 if match[7] == "PM" else 0)
    released = (
        f"{date(year, month, day).isoformat()}T{time(hour, minute, second).isoformat()}"
    )
    return {"package_release_at": released, "package_release_raw": raw}


def fetch_release_date(
    package: str, folder: Path, offline: bool, timeout: float
) -> dict:
    path = folder / f"wdsi-{package}.html"
    url = request_url(WDSI_URL, {"requestVersion": package})
    try:
        if path.exists():
            raw = path.read_bytes()
            try:
                parsed = parse_package_release(raw.decode("utf-8"), package)
                return {
                    **parsed,
                    "package_release_url": url,
                    "package_release_sha256": hashlib.sha256(raw).hexdigest(),
                }
            except ValueError:
                if offline:
                    raise
        if offline:
            return {"package_release_lookup": "not-cached"}
        with requests.get(url, timeout=timeout) as response:
            response.raise_for_status()
            raw = response.content
        text = raw.decode("utf-8")
        atomic_write(path, text)
        parsed = parse_package_release(text, package)
        return {
            **parsed,
            "package_release_url": url,
            "package_release_sha256": hashlib.sha256(raw).hexdigest(),
        }
    except (OSError, ValueError, requests.RequestException) as exc:
        return {"package_release_lookup": str(exc)}


def update_catalog(
    args: argparse.Namespace, existing: dict, *, print_paths: bool = True
) -> int:
    folder = ROOT / "bin" / "geteng-sources"
    sources = {}
    records = []

    for name in NAMES:
        raw_url = f"https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/defender-endpoint/{name}.md"
        path = folder / (name + ".md")
        if not args.offline:
            report("fetch", "Fetch", name)
            with requests.get(raw_url, timeout=args.timeout) as response:
                response.raise_for_status()
                raw = response.content
            text = raw.decode("utf-8")
            parsed = parse_source(name, text)
            atomic_write(path, text)
        else:
            raw = path.read_bytes()
            parsed = parse_source(name, raw.decode("utf-8"))
        sources[name] = {
            "url": "https://learn.microsoft.com/en-us/defender-endpoint/" + name,
            "raw_url": raw_url,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        records.extend(parsed)

    sources["capture-2026-09-11"] = {
        "url": "docs/defender_download.md",
        "description": "HTTP 302 / 302 / 200 capture.",
    }
    sources["local-files"] = {
        "url": "bin/",
        "description": "Sample directory names and DLL FileVersion.",
    }
    sources["wdsi-release-notes"] = {
        "url": WDSI_URL,
        "description": "Package release timestamps; timezone not stated.",
    }
    records.extend(observed_records())

    previous = {
        (row["package_version"], row["engine_version"]): row
        for row in existing["versions"]
    }
    for row in records:
        old = previous.get((row["package_version"], row["engine_version"]), {})
        row.update(
            {
                key: old[key]
                for key in (
                    "package_release_at",
                    "package_release_raw",
                    "package_release_url",
                    "package_release_sha256",
                )
                if key in old
            }
        )
        peers = {
            other["engine_version"]
            for other in records
            if other["package_version"] == row["package_version"]
        }
        if len(peers) > 1:
            row["needs_review"] = True
            row["notes"].append(
                "Multiple engines: " + ", ".join(sorted(peers)) + "; specify --engine."
            )

    packages = sorted({row["package_version"] for row in records})
    dates = {}
    report("work", "Dates", f"WDSI release times for {len(packages)} packages")
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(
                fetch_release_date, package, folder, args.offline, args.timeout
            ): package
            for package in packages
        }
        with tqdm(
            total=len(futures),
            desc="Release dates",
            unit="pkg",
            file=sys.stderr,
            disable=not sys.stderr.isatty(),
            dynamic_ncols=True,
        ) as progress:
            for future in as_completed(futures):
                dates[futures[future]] = future.result()
                progress.update(1)

    for row in records:
        fresh = dates[row["package_version"]]
        if fresh.get("package_release_at"):
            row.pop("package_release_lookup", None)
        row.update(fresh)

    resolved = sum(bool(value.get("package_release_at")) for value in dates.values())
    report(
        "info",
        "Dates",
        f"{resolved} timestamps; {len(packages) - resolved} unavailable or uncached",
    )

    records.sort(
        key=lambda row: (
            tuple(map(int, row["package_version"].split("."))),
            tuple(map(int, row["engine_version"].split("."))),
        ),
        reverse=True,
    )

    data = {
        "schema_version": 2,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Defender release and DISM notes, WDSI package timestamps, HTTP capture, and local samples. Daily signature coverage and download availability are incomplete.",
        "sources": sources,
        "versions": records,
    }
    encoded = json.dumps(data, ensure_ascii=False)
    if ("?" * 3) in encoded or "\ufffd" in encoded:
        raise ValueError("Encoding error; catalog not updated")

    atomic_write(CATALOG_PATH, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    report("ok", "Updated", f"{len(records)} records / {len(packages)} packages")
    if print_paths:
        print(CATALOG_PATH)
    return 0


def load_or_update_catalog(args: argparse.Namespace) -> dict:
    existing = load_catalog(required=False)
    collected_at = existing.get("collected_at")
    stale = not CATALOG_PATH.is_file()
    if not stale:
        if not isinstance(collected_at, str):
            stale = True
        else:
            try:
                collected = datetime.fromisoformat(collected_at)
                if collected.tzinfo is None:
                    collected = collected.replace(tzinfo=timezone.utc)
                stale = (
                    datetime.now(timezone.utc) - collected.astimezone(timezone.utc)
                    >= CATALOG_MAX_AGE
                )
            except ValueError:
                stale = True
    if not stale:
        return existing

    reason = "missing" if not CATALOG_PATH.is_file() else "older than 24 hours"
    report("info", "Update", f"{CATALOG_PATH.name} is {reason}")
    refresh_args = argparse.Namespace(
        offline=False, timeout=getattr(args, "timeout", 30.0)
    )
    try:
        update_catalog(refresh_args, existing, print_paths=False)
    except (OSError, TypeError, ValueError, requests.RequestException) as exc:
        if existing.get("versions"):
            report("warning", "Update", f"{exc}; using the existing catalog")
            return existing
        raise ValueError(f"Automatic catalog update failed: {exc}") from exc
    return load_catalog()


def parser() -> argparse.ArgumentParser:
    result = CliParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = result.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list the version catalog")
    listing.add_argument("--package", help="filter by exact package version")
    listing.add_argument(
        "--engine", help="filter by exact engine version, including source spellings"
    )
    listing.add_argument(
        "--json", action="store_true", help="include sources, dates, and anomaly notes"
    )
    update = commands.add_parser("update", help="refresh the version catalog")
    update.add_argument(
        "--offline", action="store_true", help="reuse cached source pages"
    )
    update.add_argument(
        "--timeout",
        type=timeout_seconds,
        default=30.0,
        help="network I/O timeout in seconds (default: 30)",
    )
    download = commands.add_parser(
        "download", help="download packages and extract all package files"
    )
    download.add_argument(
        "packages",
        metavar="PACKAGE",
        type=version,
        nargs="+",
        help="one or more package versions",
    )
    download.add_argument(
        "--engine", type=version, help="explicit engine version (one package only)"
    )
    download.add_argument("--arch", choices=ARCHES, default="x64", help="default: x64")
    download.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("bin"),
        help="output root (default: bin)",
    )
    download.add_argument(
        "--no-extract", action="store_true", help="save mpam-fe.exe without extracting"
    )
    download.add_argument(
        "--timeout",
        type=timeout_seconds,
        default=60.0,
        help="network I/O timeout in seconds (default: 60)",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)

    try:
        if args.command == "update":
            return update_catalog(args, load_catalog(required=False))

        catalog = load_or_update_catalog(args)
        if args.command == "list":
            return list_versions(args, catalog)

        if args.engine and len(args.packages) != 1:
            cli.error("--engine requires exactly one PACKAGE")

        selections = [
            (package, select_engine(catalog["versions"], package, args.engine))
            for package in dict.fromkeys(args.packages)
        ]
        extractor = None if args.no_extract else find_extractor()
        failed = False

        for package, engine in selections:
            try:
                download_one(package, engine, args, extractor)
            except requests.HTTPError as exc:
                status = (
                    exc.response.status_code if exc.response is not None else "error"
                )
                report(
                    "error",
                    "Error",
                    f"{package}: HTTP {status}; this package/engine/architecture combination may no longer be available.",
                )
                failed = True
            except (
                OSError,
                ValueError,
                requests.RequestException,
                subprocess.SubprocessError,
            ) as exc:
                report("error", "Error", f"{package}: {exc}")
                failed = True

        return 1 if failed else 0
    except (OSError, TypeError, ValueError) as exc:
        report("error", "Error", str(exc))
        return 1
    except KeyboardInterrupt:
        report("cancel", "Cancelled", "Incomplete download removed.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
