"""Source-only RevokedCertProviderFunc callback recipes, without trust policy.

Runtime normalized keys and original record metadata are explicit facts. No
callback, ReportCertificate, NID, FILETIME policy or signed-file service runs.
The supplied payload binds provenance; its hash is never an engine identity.
Epoch identifies this callback invocation, not an entire scan: a post-report
snapshot must come from this exact call, even when another call has equal args.
"""

from dataclasses import dataclass
from typing import Literal

from .types.revoked_certificate import RevokedCertificate, parse_revoked_certificate


class RevokedRootSnapshotError(ValueError):
    """Malformed, mismatched or outside-profile source facts."""


class _Missing(Exception):
    pass


@dataclass(frozen=True, slots=True)
class RevokedRootMetadata:
    epoch: str
    payload_raw: bytes
    normalized_record_key: bytes | None
    threat_id: int | None
    sigseq: int | None
    identity: bytes | None


@dataclass(frozen=True, slots=True)
class RevokedRootPostReportSnapshot:
    epoch: str
    payload_raw: bytes
    callable_profile: Literal["CResmgrCertStore.ScanImpl.root_Do_call"] | None
    input_threat_id: int | None
    input_sigseq: int | None
    input_identity: bytes | None
    scanresult: int | None
    error: int | None


@dataclass(frozen=True, slots=True)
class RevokedRootQuerySnapshot:
    epoch: str
    normalized_query_key: bytes | None
    value_index: int | None
    callback_present: bool | None
    callback_return_u8: int | None
    post_report: RevokedRootPostReportSnapshot | None


@dataclass(frozen=True, slots=True)
class RevokedRootArguments:
    threat_id: int
    zero: int
    sigseq: int
    identity: bytes


@dataclass(frozen=True, slots=True)
class RevokedRootPostReportProjection:
    status: Literal["projected", "unknown"]
    reason: str
    callback_return_u8: int | None
    scanresult: int | None
    error: int | None
    callable_bound: bool


@dataclass(frozen=True, slots=True)
class RevokedRootCallbackProjection:
    epoch: str
    status: Literal["projected", "unknown", "exception"]
    reason: str
    key_equal: bool | None
    requests_callback: bool | None
    arguments: RevokedRootArguments | None
    callback_return_u8: int | None
    callback_result_source: str | None
    local_compare_result: bool | None
    post_report: RevokedRootPostReportProjection | None
    exception_type: Literal["std::bad_function_call"] | None
    callback_execution: None = None
    final_trust_or_scan_verdict: None = None


def _uint(value: int | None, bits: int, name: str) -> None:
    if value is not None and (type(value) is not int or not 0 <= value < 1 << bits):
        raise RevokedRootSnapshotError(f"{name} must be uint{bits} or None")


def _bytes(value: bytes | None, size: int | None, name: str, required=False) -> None:
    if value is None:
        if required:
            raise RevokedRootSnapshotError(f"{name} must be immutable bytes")
        return
    if type(value) is not bytes or size is not None and len(value) != size:
        raise RevokedRootSnapshotError(f"{name} must be {size or 'immutable'} bytes")


def _epoch(value: str) -> None:
    if type(value) is not str or not value:
        raise RevokedRootSnapshotError("epoch must be a nonempty opaque string")


def _need(value, reason):
    if value is None:
        raise _Missing(reason)
    return value


def _metadata(value: RevokedRootMetadata) -> None:
    if not isinstance(value, RevokedRootMetadata):
        raise RevokedRootSnapshotError("expected RevokedRootMetadata")
    _epoch(value.epoch)
    _bytes(value.payload_raw, None, "payload_raw", True)
    _bytes(value.normalized_record_key, 20, "normalized_record_key")
    _uint(value.threat_id, 32, "threat_id")
    _uint(value.sigseq, 64, "sigseq")
    _bytes(value.identity, 20, "identity")


def _post_snapshot(value: RevokedRootPostReportSnapshot) -> None:
    if not isinstance(value, RevokedRootPostReportSnapshot):
        raise RevokedRootSnapshotError("expected RevokedRootPostReportSnapshot")
    _epoch(value.epoch)
    _bytes(value.payload_raw, None, "post_report.payload_raw", True)
    if value.callable_profile not in (None, "CResmgrCertStore.ScanImpl.root_Do_call"):
        raise RevokedRootSnapshotError("unsupported post-report callable profile")
    _uint(value.input_threat_id, 32, "input_threat_id")
    _uint(value.input_sigseq, 64, "input_sigseq")
    _bytes(value.input_identity, 20, "input_identity")
    _uint(value.scanresult, 32, "scanresult")
    _uint(value.error, 32, "error")


def project_revoked_root_post_report(
    metadata: RevokedRootMetadata, snapshot: RevokedRootPostReportSnapshot
) -> RevokedRootPostReportProjection:
    """Project only the known ScanImpl-captured Do_call from bound post-state.

    An arbitrary std::function is not assigned this polarity. Error is an
    independent uint32 result, never a substitute for missing post-scanresult.
    The input metadata refers to the original callback arguments, before any
    ReportCertificate substitutions; no report-internal behavior is simulated.
    """
    _metadata(metadata)
    _post_snapshot(snapshot)
    if snapshot.epoch != metadata.epoch or snapshot.payload_raw != metadata.payload_raw:
        raise RevokedRootSnapshotError("post-report epoch/payload binding mismatch")
    for left, right in (
        (snapshot.input_threat_id, metadata.threat_id),
        (snapshot.input_sigseq, metadata.sigseq),
        (snapshot.input_identity, metadata.identity),
    ):
        if left is not None and right is not None and left != right:
            raise RevokedRootSnapshotError(
                "post-report original input metadata mismatch"
            )
    bound = False
    try:
        _need(snapshot.callable_profile, "post_report_callable_unknown")
        for value, name in (
            (metadata.threat_id, "threat_id"),
            (metadata.sigseq, "sigseq"),
            (metadata.identity, "identity"),
            (snapshot.input_threat_id, "input_threat_id"),
            (snapshot.input_sigseq, "input_sigseq"),
            (snapshot.input_identity, "input_identity"),
        ):
            _need(value, f"post_report_{name}_unknown")
        bound = True
        state = _need(snapshot.scanresult, "post_report_scanresult_unknown")
        return RevokedRootPostReportProjection(
            "projected",
            "known_root_Do_call",
            int(state != 1),
            state,
            snapshot.error,
            True,
        )
    except _Missing as exc:
        return RevokedRootPostReportProjection(
            "unknown",
            str(exc),
            None,
            snapshot.scanresult if bound else None,
            snapshot.error if bound else None,
            bound,
        )


def project_revoked_root_callback(
    record: RevokedCertificate,
    metadata: RevokedRootMetadata,
    snapshot: RevokedRootQuerySnapshot,
) -> RevokedRootCallbackProjection:
    """Project value_index0 key equality, callback ABI and AL==0 comparison.

    Runtime normalized_record_key is authoritative for this callback profile;
    this function never replaces it with wire normalization or a key/identity
    guess. Use the existing certificate-key normalizer separately only when its
    successful source profile is explicitly appropriate. No FILETIME/flags gate
    from evaluate_revoked_certificate is applied here.
    """
    if not isinstance(record, RevokedCertificate) or type(record.raw) is not bytes:
        raise RevokedRootSnapshotError("expected immutable parsed RevokedCertificate")
    parse_revoked_certificate(record.raw)
    _metadata(metadata)
    if metadata.payload_raw != record.raw:
        raise RevokedRootSnapshotError("metadata payload binding mismatch")
    if not isinstance(snapshot, RevokedRootQuerySnapshot):
        raise RevokedRootSnapshotError("expected RevokedRootQuerySnapshot")
    _epoch(snapshot.epoch)
    if snapshot.epoch != metadata.epoch:
        raise RevokedRootSnapshotError("query/metadata epoch mismatch")
    _bytes(snapshot.normalized_query_key, 20, "normalized_query_key")
    _uint(snapshot.value_index, 64, "value_index")
    _uint(snapshot.callback_return_u8, 8, "callback_return_u8")
    if (
        snapshot.callback_present is not None
        and type(snapshot.callback_present) is not bool
    ):
        raise RevokedRootSnapshotError("callback_present must be bool or None")
    if snapshot.post_report is not None:
        _post_snapshot(snapshot.post_report)
        if (
            snapshot.post_report.epoch != metadata.epoch
            or snapshot.post_report.payload_raw != metadata.payload_raw
        ):
            raise RevokedRootSnapshotError("post-report epoch/payload binding mismatch")
    status, reason, equal, requests, args, raw, source, comparison, post, exception = (
        "projected",
        "key_mismatch",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    try:
        index = _need(snapshot.value_index, "value_index_unknown")
        if index != 0:
            raise RevokedRootSnapshotError("nonzero value_index assertion domain")
        query = _need(snapshot.normalized_query_key, "normalized_query_key_unknown")
        key = _need(metadata.normalized_record_key, "normalized_record_key_unknown")
        equal = query == key
        if not equal:
            requests, comparison = False, False
        elif not _need(snapshot.callback_present, "callback_presence_unknown"):
            status, reason, requests, exception = (
                "exception",
                "empty_function_object",
                False,
                "std::bad_function_call",
            )
        else:
            requests = True
            args = RevokedRootArguments(
                _need(metadata.threat_id, "threat_id_unknown"),
                0,
                _need(metadata.sigseq, "sigseq_unknown"),
                _need(metadata.identity, "identity_unknown"),
            )
            raw = snapshot.callback_return_u8
            if raw is not None:
                source = "explicit_callback_AL"
            if snapshot.post_report is not None:
                post = project_revoked_root_post_report(metadata, snapshot.post_report)
                if post.callable_bound and raw is not None and raw > 1:
                    raise RevokedRootSnapshotError(
                        "known Do_call returns canonical AL0/1 even with unknown scanresult"
                    )
                if post.callback_return_u8 is not None:
                    if raw is not None and raw != post.callback_return_u8:
                        raise RevokedRootSnapshotError(
                            "callback AL conflicts with known Do_call post-state"
                        )
                    if raw is None:
                        raw, source = (
                            post.callback_return_u8,
                            "known_root_Do_call_post_state",
                        )
            raw = _need(raw, "callback_result_unknown")
            comparison, reason = raw == 0, "callback_result_projected"
    except _Missing as exc:
        status, reason = "unknown", str(exc)
    return RevokedRootCallbackProjection(
        snapshot.epoch,
        status,
        reason,
        equal,
        requests,
        args,
        raw,
        source,
        comparison,
        post,
        exception,
    )
