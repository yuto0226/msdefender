"""A0 record-local friendly SHA256 candidate for explicit full-UFS caller uses.

The profile selects a statically observed caller purpose, not a claim that the
entire native IsSignedFile/troj_scan flow executed. Complete immutable bytes are
the current UFS scan object, which may be a container member or transformed view.
This is a cold byte projection or a source-consistent-cache value projection;
GetHashes success alone does not establish cache/source consistency. Store/NID/
namespace/TTL/attribute/allow/bypass/verdict policy is not evaluated here.
"""

import hashlib
from dataclasses import dataclass
from typing import Final, Literal

from .types.friendlyfile import FriendlyFileSha256, parse_friendlyfile_sha256

FriendlyFileCallerProfile = Literal[
    "IsSignedFile.full_current_ufs_object", "troj_scan.full_current_ufs_object"
]
FRIENDLY_FILE_CALLER_PROFILES: Final = (
    "IsSignedFile.full_current_ufs_object",
    "troj_scan.full_current_ufs_object",
)


@dataclass(frozen=True, slots=True)
class FriendlyFileSha256Candidate:
    computed_sha256: bytes
    record_local_friendly_candidate: bool
    caller_profile: FriendlyFileCallerProfile


def evaluate_friendlyfile_sha256(
    record: FriendlyFileSha256,
    scan_object_bytes: bytes,
    *,
    caller_profile: FriendlyFileCallerProfile,
) -> FriendlyFileSha256Candidate:
    """Compare one raw A0 digest with the complete current UFS object's SHA256.

    A true result means only a friendly lookup-key candidate. It does not confirm
    that the record loaded or that native Lookup/status133/attributes accepted it.
    Optional tail bytes are not digest inputs and do not acquire a new meaning.
    Missing object bytes or an unknown caller profile are errors, not mismatches.
    """
    if not isinstance(record, FriendlyFileSha256):
        raise TypeError("record must be a parsed FriendlyFileSha256")
    if not isinstance(scan_object_bytes, bytes):
        raise TypeError("scan_object_bytes must be complete immutable UFS object bytes")
    if caller_profile not in FRIENDLY_FILE_CALLER_PROFILES:
        raise ValueError("an explicit verified full-UFS caller profile is required")
    parsed = parse_friendlyfile_sha256(record.raw)
    digest = hashlib.sha256(scan_object_bytes).digest()
    return FriendlyFileSha256Candidate(digest, digest == parsed.sha256, caller_profile)
