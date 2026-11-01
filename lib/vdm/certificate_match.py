"""6C record-local key/time/signed predicate, without X509 or trust policy."""

from dataclasses import dataclass

from .types._certificate_key import normalize_certificate_key
from .types.revoked_certificate import RevokedCertificate, parse_revoked_certificate


@dataclass(frozen=True, slots=True)
class RevokedCertificateMatch:
    normalized_record_key: bytes
    record_local_match: bool | None
    signed_file_required: bool


def evaluate_revoked_certificate(
    record: RevokedCertificate,
    query_key: bytes,
    *,
    certificate_time: int,
    policy: int,
    signed_file: bool | None,
) -> RevokedCertificateMatch:
    """CompareValues/ShouldReport with explicit raw uint64 time/uint8 policy.

    signed_file is the external IsSignedFile boolean. None is unknown only when
    this record actually reaches that gate. No lookup membership, namespace,
    certificate field selection, or final revocation/trust verdict is inferred.
    """
    if not isinstance(record, RevokedCertificate):
        raise TypeError("record must be RevokedCertificate")
    if not isinstance(query_key, bytes) or len(query_key) != 20:
        raise ValueError("query_key must be 20 immutable bytes")
    if type(certificate_time) is not int or not 0 <= certificate_time < 1 << 64:
        raise ValueError("certificate_time must be uint64 FILETIME")
    if type(policy) is not int or not 0 <= policy <= 255:
        raise ValueError("policy must be uint8")
    if signed_file is not None and type(signed_file) is not bool:
        raise TypeError("signed_file must be bool or None")
    parsed = parse_revoked_certificate(record.raw)
    key = normalize_certificate_key(parsed.key_data).normalized_key
    if query_key != key or certificate_time < parsed.filetime:
        return RevokedCertificateMatch(key, False, False)
    required = policy != 0 and not parsed.revoke_flags & 1
    return RevokedCertificateMatch(key, signed_file if required else True, required)
