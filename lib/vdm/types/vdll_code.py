"""Bounded raw PE view for VDLL code records."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

VDLL_CODE_TYPES: Final = (0x79, 0x7C, 0x91, 0x9C, 0xC4)
MIN_FILE_SIZE: Final = 0x400
MAX_DATA_DIRECTORIES: Final = 16
SECTION_HEADER_SIZE: Final = 40


@dataclass(frozen=True, slots=True)
class PeSection:
    name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int


@dataclass(frozen=True, slots=True)
class DataDirectory:
    rva: int
    size: int


@dataclass(frozen=True, slots=True)
class VdllCodePayload:
    type: int
    host: str
    raw: bytes
    machine: int
    magic: int
    size_image: int
    size_headers: int
    sections: tuple[PeSection, ...]
    numdirs: int
    cli_directory: DataDirectory
    cli_offset: int | None
    metadata_directory: DataDirectory
    metadata_offset: int | None
    export_directory: DataDirectory
    export_offset: int | None
    overlay: bytes


_HOST_ASSOCIATION: Final = {
    0x79: "x86 / PE32 (mpas corpus)",
    0x7C: "x64 / PE32+ (mpas corpus)",
    0x9C: "ARM / PE32 (mpas corpus)",
    0xC4: "x86 / PE32 (mpas corpus); managed marker derived from CLI",
    0x91: "ARM64 (receiver-confirmed; no observed records)",
}


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _rva_to_file_offset(
    rva: int,
    size: int,
    *,
    sections: tuple[PeSection, ...],
    size_headers: int,
    payload_size: int,
) -> int:
    """Map an entirely file-backed RVA range to its raw file offset."""
    if rva < size_headers:
        if rva + size > size_headers:
            raise ValueError("RVA range crosses PE header boundary")
        if rva + size > payload_size:
            raise ValueError("RVA range in PE headers extends beyond file bounds")
        return rva
    for index, section in enumerate(sections):
        copy_size = min(section.virtual_size, section.raw_size)
        delta = rva - section.virtual_address
        if delta >= 0 and delta + size <= copy_size:
            offset = section.raw_pointer + delta
            if offset + size > payload_size:
                raise ValueError(
                    f"section {index} RVA range extends beyond file bounds"
                )
            return offset
    raise ValueError("RVA range is not fully backed by PE headers or a section")


def parse_vdll_code(payload: bytes, type_byte: int = 0x79) -> VdllCodePayload:
    """Validate PE bounds and retain the entire input as raw PE file bytes."""
    if type_byte not in VDLL_CODE_TYPES:
        raise ValueError(f"unsupported VDLL code type 0x{type_byte:02X}")
    if len(payload) < MIN_FILE_SIZE:
        raise ValueError(
            f"PE file too small: need at least 0x400 bytes, have {len(payload):#x}"
        )
    if payload[:2] != b"MZ":
        raise ValueError("missing MZ signature")

    pe_offset = _u32(payload, 0x3C)
    if pe_offset == 0:
        raise ValueError("e_lfanew must be non-zero")
    if pe_offset + 24 > len(payload):
        raise ValueError("PE and COFF headers extend beyond file bounds")
    if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff = pe_offset + 4
    machine = _u16(payload, coff)
    section_count = _u16(payload, coff + 2)
    optional_size = _u16(payload, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_size
    if optional_size < 2:
        raise ValueError("optional header is shorter than the magic field")
    magic = _u16(payload, optional)
    if magic == 0x10B:
        count_offset, dirs_offset = 92, 96
        expected_optional_size = 224
    elif magic == 0x20B:
        count_offset, dirs_offset = 108, 112
        expected_optional_size = 240
    else:
        raise ValueError(
            f"unsupported optional-header magic 0x{magic:04X}; "
            "policy accepts PE32/PE32+"
        )
    if pe_offset + 24 + expected_optional_size >= len(payload):
        raise ValueError("PE optional header exceeds strict engine file bound")
    if optional_end > len(payload):
        raise ValueError("optional header extends beyond file bounds")
    if optional_size < expected_optional_size:
        raise ValueError(
            f"optional header too short for PE{32 if magic == 0x10B else 64}: "
            f"need {expected_optional_size} bytes, have {optional_size}"
        )

    declared_dirs = _u32(payload, optional + count_offset)
    if declared_dirs > MAX_DATA_DIRECTORIES:
        raise ValueError(f"too many data directories: {declared_dirs} (maximum 16)")
    if dirs_offset + declared_dirs * 8 > optional_size:
        raise ValueError("data directories extend beyond optional header")
    directories = [
        DataDirectory(
            _u32(payload, optional + dirs_offset + i * 8),
            _u32(payload, optional + dirs_offset + i * 8 + 4),
        )
        for i in range(declared_dirs)
    ]
    export = directories[0] if directories else DataDirectory(0, 0)
    cli = directories[14] if len(directories) > 14 else DataDirectory(0, 0)

    section_table = optional_end
    section_end = section_table + section_count * SECTION_HEADER_SIZE
    if section_end > len(payload):
        raise ValueError("section table extends beyond file bounds")
    sections: list[PeSection] = []
    size_image = _u32(payload, optional + 56)
    size_headers = _u32(payload, optional + 60) if optional_size >= 64 else 0
    max_raw_end = max(section_end, size_headers)
    for index in range(section_count):
        offset = section_table + index * SECTION_HEADER_SIZE
        raw_size = _u32(payload, offset + 16)
        raw_pointer = _u32(payload, offset + 20)
        raw_end = raw_pointer + raw_size
        if raw_pointer >= len(payload) or raw_end > len(payload):
            raise ValueError(f"section {index} raw range extends beyond file bounds")
        virtual_size = _u32(payload, offset + 8)
        virtual_address = _u32(payload, offset + 12)
        copy_size = min(virtual_size, raw_size)
        if copy_size:
            mapped_start = virtual_address & ~0xFFF
            mapped_end = _align_up(virtual_address + copy_size, 0x1000)
            if mapped_start >= size_image or mapped_end > size_image:
                raise ValueError(f"section {index} mapped range exceeds SizeOfImage")
        max_raw_end = max(max_raw_end, raw_end)
        sections.append(
            PeSection(
                payload[offset : offset + 8].rstrip(b"\0"),
                virtual_size,
                virtual_address,
                raw_size,
                raw_pointer,
            )
        )
    if max_raw_end > len(payload):
        raise ValueError("PE headers extend beyond file bounds")
    section_tuple = tuple(sections)
    export_offset = None
    if bool(export.rva) != bool(export.size):
        raise ValueError("export directory RVA and size must both be zero or non-zero")
    if export.rva and export.size:
        if export.size <= 0x28:
            raise ValueError("export directory size must exceed 0x28 bytes")
        if export.rva < size_headers:
            raise ValueError("export directory RVA must not lie in PE headers")
        export_offset = _rva_to_file_offset(
            export.rva,
            export.size,
            sections=section_tuple,
            size_headers=size_headers,
            payload_size=len(payload),
        )

    cli_offset = None
    metadata = DataDirectory(0, 0)
    metadata_offset = None
    if bool(cli.rva) != bool(cli.size):
        raise ValueError("CLI directory RVA and size must both be zero or non-zero")
    has_cli = bool(cli.rva and cli.size)
    if has_cli:
        if cli.size < 16:
            raise ValueError("CLI directory is too short for metadata fields")
        cli_offset = _rva_to_file_offset(
            cli.rva,
            16,
            sections=section_tuple,
            size_headers=size_headers,
            payload_size=len(payload),
        )
        metadata = DataDirectory(
            _u32(payload, cli_offset + 8), _u32(payload, cli_offset + 12)
        )
        if bool(metadata.rva) != bool(metadata.size):
            raise ValueError(
                "CLI metadata RVA and size must both be non-zero on managed path"
            )
        if not metadata.rva:
            raise ValueError(
                "CLI metadata RVA and size must be non-zero on managed path"
            )
        metadata_offset = _rva_to_file_offset(
            metadata.rva,
            metadata.size,
            sections=section_tuple,
            size_headers=size_headers,
            payload_size=len(payload),
        )
    if not export.rva and not has_cli:
        raise ValueError("managed path without export requires a valid CLI directory")

    return VdllCodePayload(
        type=type_byte,
        host=_HOST_ASSOCIATION[type_byte],
        raw=payload,
        machine=machine,
        magic=magic,
        size_image=size_image,
        size_headers=size_headers,
        sections=section_tuple,
        numdirs=declared_dirs,
        cli_directory=cli,
        cli_offset=cli_offset,
        metadata_directory=metadata,
        metadata_offset=metadata_offset,
        export_directory=export,
        export_offset=export_offset,
        overlay=payload[max_raw_end:],
    )


def _parser_for(type_byte: int):
    return lambda payload: parse_vdll_code(payload, type_byte)


def render_vdll_code(parsed: VdllCodePayload) -> FormatResult:
    rows = (
        ("type", f"0x{parsed.type:02X}"),
        ("host_association", parsed.host),
        ("file_size", f"{len(parsed.raw)} B"),
        ("machine", f"0x{parsed.machine:04X}"),
        ("optional_magic", f"0x{parsed.magic:04X}"),
        ("size_image", f"0x{parsed.size_image:X}"),
        ("size_headers", f"0x{parsed.size_headers:X}"),
        ("sections", str(len(parsed.sections))),
        ("numdirs", str(parsed.numdirs)),
        (
            "export_directory",
            f"RVA=0x{parsed.export_directory.rva:X}, size=0x{parsed.export_directory.size:X}",
        ),
        (
            "cli_directory",
            f"RVA=0x{parsed.cli_directory.rva:X}, size=0x{parsed.cli_directory.size:X}",
        ),
        (
            "cli_file_offset",
            "none" if parsed.cli_offset is None else f"0x{parsed.cli_offset:X}",
        ),
        (
            "metadata_directory",
            f"RVA=0x{parsed.metadata_directory.rva:X}, size=0x{parsed.metadata_directory.size:X}",
        ),
        (
            "metadata_file_offset",
            "none"
            if parsed.metadata_offset is None
            else f"0x{parsed.metadata_offset:X}",
        ),
        (
            "export_file_offset",
            "none" if parsed.export_offset is None else f"0x{parsed.export_offset:X}",
        ),
        (
            "managed_marker",
            "yes" if parsed.cli_directory.rva or parsed.cli_directory.size else "no",
        ),
        ("overlay_size", f"{len(parsed.overlay)} B"),
    )
    return FormatResult(sections=(DisplaySection("VDLL Code PE", rows=rows),))


FAMILY_SPECS: Final = tuple(
    FamilySpec(
        type_byte,
        f"VDLL_CODE_{type_byte:02X}",
        _parser_for(type_byte),
        render_vdll_code,
    )
    for type_byte in VDLL_CODE_TYPES
)
VDLL_CODE_SPECS: Final = FAMILY_SPECS
