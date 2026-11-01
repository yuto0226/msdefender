"""RSDS PDB-path source recipe over explicitly resolved mapped snapshots.

No PE mapper, process-path lookup, regex engine, Unicode normalizer or reporting
policy runs here. Missing context is distinct from a known mapping failure.
"""

from dataclasses import dataclass
from typing import Literal


class UnsupportedPdbPathSource(ValueError):
    """Required mapped context is absent, inconsistent or insufficiently readable."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"expected uint{bits}")


@dataclass(frozen=True, slots=True)
class PdbMappedBytes:
    """Resolved storage at an engine mapped address, not a disk file offset.

    data=None explicitly records failure of the original mapping helper for
    this stage. Omission of the entire snapshot means unknown context instead.
    Path bytes resolve the successful mmap_string_ex storage; mapping-window,
    cache and remap failure histories are not reconstructed from file bytes.
    """

    address: int
    data: bytes | None

    def __post_init__(self) -> None:
        _uint(self.address, 64)
        if self.data is not None and not isinstance(self.data, bytes):
            raise TypeError("resolved storage must be bytes or actual mapping failure")


@dataclass(frozen=True, slots=True)
class PdbDebugSnapshot:
    """Partial scan_debugdir pecontext with lazy, resolved mapping stages.

    directory_rva/size are u32 at pe+0x20F4/+0x20F8; mapped_base is u64 at
    pe+0x83798. directory resolves __mmap_ex(...,28); codeview resolves the
    24-byte header; path resolves mmap_string_ex at CodeView+24. First entry
    only: extra directory entries and NB10 are outside this caller recipe.
    """

    directory_rva: int
    directory_size: int
    mapped_base: int
    directory: PdbMappedBytes | None = None
    codeview: PdbMappedBytes | None = None
    path: PdbMappedBytes | None = None

    def __post_init__(self) -> None:
        _uint(self.directory_rva, 32)
        _uint(self.directory_size, 32)
        _uint(self.mapped_base, 64)
        if any(
            item is not None and not isinstance(item, PdbMappedBytes)
            for item in (self.directory, self.codeview, self.path)
        ):
            raise TypeError("expected typed mapping stages or missing context")


@dataclass(frozen=True, slots=True)
class PdbPathSource:
    """Recipe-local source result, not scan_filepath execution or eligibility."""

    status: Literal["selected", "gated", "mapping_failed"]
    reason: str
    subject: bytes | None = None
    cstring: bytes | None = None
    path_address: int | None = None
    max_length: int | None = None
    guid_raw: bytes | None = None
    age: int | None = None

    @property
    def subject_available(self) -> bool:
        return self.subject is not None


def _resolved(
    stage: PdbMappedBytes | None, address: int, size: int, name: str
) -> bytes | None:
    if stage is None:
        raise UnsupportedPdbPathSource(f"missing resolved {name} mapping context")
    if stage.address != address:
        raise UnsupportedPdbPathSource(
            f"{name} mapped address does not match original arithmetic"
        )
    if stage.data is not None and len(stage.data) < size:
        raise UnsupportedPdbPathSource(
            f"{name} storage lacks the required readable span"
        )
    return stage.data


def project_pdb_path_source(snapshot: PdbDebugSnapshot | None) -> PdbPathSource:
    """Select the original RSDS path CString from resolved runtime mappings.

    u32 directory values are zero-extended into modulo-u64 mapped-address
    additions. Path max length is SizeOfData-23, exactly as the original caller;
    it is not silently changed to -24. Search no farther than that bound and
    never append NUL. Empty paths gate out. Resource/mapping execution and
    attribute/NID/SNID/basename/regex/reporting policies remain external.
    """
    if not isinstance(snapshot, PdbDebugSnapshot):
        raise UnsupportedPdbPathSource("missing typed resolved pecontext snapshot")
    if snapshot.directory_rva == 0:
        return PdbPathSource("gated", "zero_debug_directory_rva")
    if snapshot.directory_size < 28:
        return PdbPathSource("gated", "debug_directory_size_below_28")
    mask = 0xFFFFFFFFFFFFFFFF
    directory_address = (snapshot.mapped_base + snapshot.directory_rva) & mask
    directory = _resolved(snapshot.directory, directory_address, 28, "directory")
    if directory is None:
        return PdbPathSource("mapping_failed", "directory_mapping_failed")
    if int.from_bytes(directory[12:16], "little") != 2:
        return PdbPathSource("gated", "first_debug_entry_is_not_type2")
    codeview_rva = int.from_bytes(directory[20:24], "little")
    if codeview_rva == 0:
        return PdbPathSource("gated", "zero_address_of_raw_data")
    size_of_data = int.from_bytes(directory[16:20], "little")
    if size_of_data < 25:
        return PdbPathSource("gated", "codeview_size_below_25")
    codeview_address = (snapshot.mapped_base + codeview_rva) & mask
    header = _resolved(snapshot.codeview, codeview_address, 24, "codeview")
    if header is None:
        return PdbPathSource("mapping_failed", "codeview_mapping_failed")
    if header[:4] != b"RSDS":
        return PdbPathSource("gated", "codeview_signature_is_not_rsds")
    address = (codeview_address + 24) & mask
    maximum = size_of_data - 23
    data = _resolved(snapshot.path, address, 0, "path")
    if data is None:
        return PdbPathSource(
            "mapping_failed",
            "path_mapping_failed",
            path_address=address,
            max_length=maximum,
        )
    end = data.find(b"\0", 0, maximum)
    if end < 0:
        if len(data) < maximum:
            raise UnsupportedPdbPathSource(
                "missing continuation/termination context for mapped CString"
            )
        return PdbPathSource(
            "gated",
            "no_nul_within_original_max_length",
            path_address=address,
            max_length=maximum,
        )
    if end == 0:
        return PdbPathSource(
            "gated", "empty_pdb_path", path_address=address, max_length=maximum
        )
    return PdbPathSource(
        "selected",
        "original_rsds_path_cstring",
        data[:end],
        data[: end + 1],
        address,
        maximum,
        header[4:20],
        int.from_bytes(header[20:24], "little"),
    )
