"""Conditional original path algorithms with explicit dynamic runtime bindings.

The profile assumes valid owned output (cleanup marker zero, no allocation
aliasing), CRT locale-changed flag zero, and successful allocation/string
operations. It models candidate text, statuses and logical ownership effects;
actual memory, reference counts and opaque handles belong to the backends.
"""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

ORIGINAL_PATH_VIRTUALIZATION_PROFILE: Final = MappingProxyType(
    {
        "name": "mpengine.original_path_virtualization.raw_c_locale_u16.v1",
        "input": "UTF-16LE code units with surrogatepass; first NUL terminates",
        "locale_precondition": "__acrt_locale_changed_data == 0",
        "output_precondition": "well-formed owned output; marker zero; no allocation aliasing",
        "resource_precondition": "allocation, copy, append and printf succeed",
        "runtime_queries": "get_context, OS query and profile resolution repeated in original order",
        "resolver_success": "return_u32 low byte nonzero; release every nonnull view even on failure",
        "worker_order": "flags&2, eligibility, flags&1, flags&4",
        "outside_profile": (
            "actual_heap_and_reference_count_effects",
            "opaque_handle_sources_and_WOW_candidate_generation",
            "nonzero_CRT_locale_state",
            "allocation_and_string_resource_failures",
            "invalid_context_or_owned_output_invariants",
        ),
    }
)


class MissingPathRuntimeBackend(RuntimeError):
    """An actually reached runtime provider has not been supplied."""


@dataclass(frozen=True, slots=True)
class PathContext:
    """One GetGlobalCtx snapshot; counts are QWORD UTF-16 code-unit counts."""

    global_dword: int
    profile_manager: object
    prefix_28: str
    count_40: int
    count_48: int
    prefix_30: str
    count_50: int
    prefix_38: str
    count_58: int


@dataclass(frozen=True, slots=True)
class ProfileView:
    """One resolved CPMProfile snapshot, without naming unknown pointer roles."""

    required_58_nonnull: bool
    required_60_nonnull: bool
    flags_b8: int
    base_b0: str | None
    reference_token: object = None


@dataclass(frozen=True, slots=True)
class Resolution:
    """Raw BOOL return and independently nullable resolved reference."""

    return_u32: int
    profile: ProfileView | None


@dataclass(frozen=True, slots=True)
class ProviderPaths:
    """A provider's DWORD return and net owned candidate list."""

    return_u32: int
    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PathEffect:
    """A logical action, not a claim that physical free/refcount was executed."""

    kind: str
    path: str | None = None
    count: int | None = None


@dataclass(frozen=True, slots=True)
class PathResult:
    status: int
    paths: tuple[str, ...]
    effects: tuple[PathEffect, ...]


@dataclass(frozen=True, slots=True)
class RuntimeBindings:
    """Callbacks are invoked when reached, never cached by the algorithms.

    Enumeration may be a dynamic iterator. ``redirection`` is an optional net
    provider override; absent it, the verified allocation-success text algorithm
    runs. WOW generation has no default and is required when its gate is one.
    Only ``None`` represents a NULL handle; integer tokens are opaque Python
    values. Callback exceptions are model errors, not native return statuses.
    A context view's fields remain stable while its original helper uses it;
    repeated get_context calls may return different views. Redirection overrides
    own their net output/status, without detailed ownership effects here.
    """

    get_context: Callable[[], PathContext]
    offline_scan: Callable[[], int]
    get_os_info: Callable[[int, int], int]
    resolve_profile: Callable[[object, object], Resolution] | None = None
    release_profile: Callable[[ProfileView], None] | None = None
    enumerate_profiles: Callable[[object], Iterable[object | None]] | None = None
    close_profile_cursor: Callable[[object, object], None] | None = None
    wow_candidates: Callable[[str], ProviderPaths] | None = None
    redirection: Callable[[PathContext, str, tuple[str, ...]], ProviderPaths] | None = (
        None
    )


def _units(text: str) -> tuple[int, ...]:
    raw = text.encode("utf-16le", errors="surrogatepass")
    units = tuple(raw[i] | raw[i + 1] << 8 for i in range(0, len(raw), 2))
    return units[: units.index(0)] if 0 in units else units


def _text(units: Sequence[int]) -> str:
    return b"".join(unit.to_bytes(2, "little") for unit in units).decode(
        "utf-16le", errors="surrogatepass"
    )


def _fold(unit: int) -> int:
    return unit + 32 if 0x41 <= unit <= 0x5A else unit


def _same(a: Sequence[int], b: Sequence[int]) -> bool:
    return len(a) == len(b) and all(_fold(x) == _fold(y) for x, y in zip(a, b))


def _find(haystack: tuple[int, ...], needle: tuple[int, ...]) -> int | None:
    return next(
        (
            i
            for i in range(len(haystack) - len(needle) + 1)
            if _same(haystack[i : i + len(needle)], needle)
        ),
        None,
    )


def path_prefix_suffix_offset(
    path: str | None, prefix: str | None, count_u16: int
) -> int | None:
    """Return an offset into the original UTF-16 path; zero is a valid match."""
    if path is None or prefix is None:
        return None
    source, key = _units(path), _units(prefix)
    extended = (0x5C, 0x5C, 0x3F, 0x5C)
    skip = 4 if source[:4] == extended else 0
    key = key[4:] if key[:4] == extended else key
    count = min(count_u16 & 0xFFFFFFFFFFFFFFFF, len(key))
    return skip + count if _same(source[skip : skip + count], key[:count]) else None


def profile_path_from_first_colon(path: str, base_b0: str | None) -> str | None:
    """Copy base + suffix after the first colon, with no separator insertion."""
    source = _units(path)
    if base_b0 is None or 0x3A not in source:
        return None
    return _text(_units(base_b0) + source[source.index(0x3A) + 1 :])


class _Output:
    def __init__(self, paths: Sequence[str]):
        self.paths = [_text(_units(path)) for path in paths]
        self.effects: list[PathEffect] = []

    def add(self, path: str) -> None:
        path = _text(_units(path))
        if any(_same(_units(path), _units(old)) for old in self.paths):
            self.effects.append(PathEffect("discard_duplicate_candidate", path))
        else:
            self.paths.append(path)
            self.effects.append(PathEffect("append_candidate", path))

    def clear(self) -> None:
        self.effects.append(PathEffect("clear_output", count=len(self.paths)))
        self.paths.clear()

    def result(self, status: int) -> PathResult:
        return PathResult(status & 0xFFFFFFFF, tuple(self.paths), tuple(self.effects))


def _eligible(path: str, runtime: RuntimeBindings) -> bool:
    offline = runtime.offline_scan() & 0xFFFFFFFF
    version = runtime.get_os_info(int(offline == 0), 1) & 0xFFFFFFFF
    ctx = runtime.get_context()
    return version >= 6 and any(
        path_prefix_suffix_offset(path, prefix, count) is not None
        for prefix, count in (
            (ctx.prefix_28, ctx.count_40),
            (ctx.prefix_30, ctx.count_50),
            (ctx.prefix_38, ctx.count_58),
        )
    )


def _resolve(runtime: RuntimeBindings, manager: object, handle: object) -> Resolution:
    if runtime.resolve_profile is None:
        raise MissingPathRuntimeBackend("resolve_profile is required")
    return runtime.resolve_profile(manager, handle)


def _release(runtime: RuntimeBindings, profile: ProfileView | None) -> None:
    if profile is not None:
        if runtime.release_profile is None:
            raise MissingPathRuntimeBackend("release_profile notification is required")
        runtime.release_profile(profile)


def _successful_view(resolution: Resolution) -> ProfileView | None:
    if resolution.return_u32 & 0xFF:
        if resolution.profile is None:
            raise ValueError("successful resolution requires a nonnull profile view")
        return resolution.profile
    return None


def _valid(runtime: RuntimeBindings, manager: object, handle: object | None) -> bool:
    if handle is None:
        return False
    resolution = _resolve(runtime, manager, handle)
    try:
        view = _successful_view(resolution)
        return (
            view is not None and view.required_58_nonnull and view.required_60_nonnull
        )
    finally:
        _release(runtime, resolution.profile)


def _profile_virtualizable(
    runtime: RuntimeBindings, manager: object, handle: object
) -> bool:
    resolution = _resolve(runtime, manager, handle)
    try:
        view = _successful_view(resolution)
        return view is not None and bool(view.flags_b8 & 1)
    finally:
        _release(runtime, resolution.profile)


def _profile_path(path: str, handle: object, runtime: RuntimeBindings) -> str | None:
    ctx = runtime.get_context()
    if not _eligible(path, runtime):
        return None
    resolution = _resolve(runtime, ctx.profile_manager, handle)
    try:
        view = _successful_view(resolution)
        if view is None or not view.flags_b8 & 1:
            return None
        return profile_path_from_first_colon(path, view.base_b0)
    finally:
        _release(runtime, resolution.profile)


def _worker(
    path: str,
    handle: object | None,
    flags: int,
    out: _Output,
    consume: bool,
    runtime: RuntimeBindings,
) -> int:
    ctx = runtime.get_context()
    if flags & 2:
        out.add(path)
    status = 0
    if _eligible(path, runtime):
        if flags & 1:
            if not _valid(runtime, ctx.profile_manager, handle):
                status = 4
            elif _profile_virtualizable(runtime, ctx.profile_manager, handle):
                candidate = _profile_path(path, handle, runtime)
                if candidate is None:
                    status = 5
                else:
                    out.add(candidate)
        if status == 0 and flags & 4:
            if runtime.enumerate_profiles is None:
                raise MissingPathRuntimeBackend("enumerate_profiles is required")
            for current in runtime.enumerate_profiles(ctx.profile_manager):
                if current is None:
                    break
                if _profile_virtualizable(runtime, ctx.profile_manager, current):
                    candidate = _profile_path(path, current, runtime)
                    if candidate is None:
                        if runtime.close_profile_cursor is None:
                            raise MissingPathRuntimeBackend(
                                "close_profile_cursor is required"
                            )
                        runtime.close_profile_cursor(ctx.profile_manager, current)
                        out.effects.append(PathEffect("close_enum_cursor"))
                        status = 5
                        break
                    out.add(candidate)
    if status:
        out.clear()
    if consume:
        out.effects.append(PathEffect("consume_input", path))
    return status


def virtualize_path_worker(
    path: str,
    profile_handle: object | None,
    flags: int,
    initial_paths: Sequence[str],
    *,
    consume_input: bool,
    runtime: RuntimeBindings,
) -> PathResult:
    """Run the original worker content/status algorithm on an owned output list."""
    path = _text(_units(path))
    out = _Output(initial_paths)
    return out.result(_worker(path, profile_handle, flags, out, consume_input, runtime))


def _wow_gate(path: str, runtime: RuntimeBindings) -> int:
    ctx = runtime.get_context()
    if path_prefix_suffix_offset(path, ctx.prefix_28, ctx.count_48) is not None:
        return 1
    offset = path_prefix_suffix_offset(path, ctx.prefix_30, ctx.count_50)
    if offset is None:
        return 0
    suffix = _units(path)[offset : offset + 6]
    return int(
        not any(_same(suffix, _units(excluded)) for excluded in (" (x86)", " (arm)"))
    )


def _redirection(ctx: PathContext, path: str, out: _Output) -> int:
    base, source = _units(ctx.prefix_28), _units(path)
    count = ctx.count_40 & 0xFFFFFFFFFFFFFFFF
    if len(base) <= count:
        raise ValueError("redirection requires prefix_28 length greater than count_40")
    needle = base[:count] + _units("\\sysnative\\")
    offset = _find(source, needle)
    if offset is not None:
        out.add(
            _text(
                source[: offset + count]
                + _units("\\system32\\")
                + source[offset + count + 11 :]
            )
        )
    return 0


def virtualize_simple_path(
    path: str,
    profile_handle: object | None,
    flags: int,
    initial_paths: Sequence[str],
    *,
    consume_input: bool,
    runtime: RuntimeBindings,
) -> PathResult:
    """Run wrapper + worker; WOW text generation remains an explicit provider."""
    path = _text(_units(path))
    out = _Output(initial_paths)
    ctx = runtime.get_context()
    if _wow_gate(path, runtime) == 1:
        if runtime.wow_candidates is None:
            raise MissingPathRuntimeBackend("wow_candidates is required")
        temporary = runtime.wow_candidates(path)
        status = temporary.return_u32 & 0xFFFFFFFF
        if status == 0:
            for candidate in temporary.paths:
                status = _worker(
                    _text(_units(candidate)), profile_handle, flags, out, False, runtime
                )
                if status:
                    break
        out.effects.append(PathEffect("clear_temporary", count=len(temporary.paths)))
        if status:
            out.clear()
            if consume_input:
                out.effects.append(PathEffect("consume_input", path))
            return out.result(status)
    if (ctx.global_dword & 0xFFFFFFFF) >= 6 and _find(
        _units(path), _units("\\sysnative\\")
    ) is not None:
        if runtime.redirection is None:
            status = _redirection(ctx, path, out)
        else:
            redirected = runtime.redirection(ctx, path, tuple(out.paths))
            out.paths = [_text(_units(item)) for item in redirected.paths]
            status = redirected.return_u32 & 0xFFFFFFFF
        if status == 8:
            out.effects.append(PathEffect("clear_temporary", count=0))
            out.clear()
            if consume_input:
                out.effects.append(PathEffect("consume_input", path))
            return out.result(5)
    return out.result(_worker(path, profile_handle, flags, out, consume_input, runtime))
