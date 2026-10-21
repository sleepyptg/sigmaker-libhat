"""libhat-backed implementation of the sigmaker speedups contract.

The original ida-sigmaker talks to an optional Cython module through a small,
duck-typed protocol. This module implements the same callables with libhat's
SIMD scanner (and native helper kernels), which lets the whole plugin run on
libhat without changing its generation algorithm.
"""

from __future__ import annotations

import array
import contextlib
import contextvars
import enum
import threading
from dataclasses import dataclass, replace

from . import libhat_native

__all__ = [
    "ScanAlignment",
    "ScanHint",
    "ScanOptions",
    "Signature",
    "scan_bytes",
    "find_all",
    "count",
    "build_byte_index",
    "seed_offsets",
    "refine_offsets",
    "filter_offsets_by_search_ranges",
    "LibhatScanTruncated",
    "available",
    "engine_info",
    "current_options",
    "use_options",
    "push_options",
    "pop_options",
]


class LibhatScanTruncated(RuntimeError):
    """Raised when a native scan hit its result cap.

    Returning a partial offset list without telling the caller would make
    uniqueness checks trust an incomplete candidate set.
    """


class ScanAlignment(enum.IntEnum):
    """libhat scan alignment (stride between candidate starts)."""

    X1 = 1
    X4 = 4
    X16 = 16

    @classmethod
    def from_name(cls, name: str) -> "ScanAlignment":
        normalized = name.strip().lower().replace(" ", "")
        return {
            "x1": cls.X1,
            "1": cls.X1,
            "x4": cls.X4,
            "4": cls.X4,
            "x16": cls.X16,
            "16": cls.X16,
        }.get(normalized, cls.X1)


class ScanHint(enum.IntFlag):
    """libhat scan hints. Values match ``libhat_hint`` in the C API."""

    NONE = 0
    X86_64 = 1 << 0
    PAIR0 = 1 << 1
    AARCH64 = 1 << 2


class ScanHintMode(enum.Enum):
    """User-facing hint selection, including automatic processor detection."""

    AUTO = "auto"
    NONE = "none"
    X86_64 = "x86_64"
    AARCH64 = "aarch64"

    @classmethod
    def from_name(cls, name: str) -> "ScanHintMode":
        normalized = name.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.AUTO


@dataclass(frozen=True, slots=True)
class ScanOptions:
    alignment: ScanAlignment = ScanAlignment.X1
    hints: ScanHint = ScanHint.NONE
    pair0: bool = False

    def with_pairs(self, enabled: bool) -> "ScanOptions":
        hints = self.hints
        if enabled:
            hints |= ScanHint.PAIR0
        else:
            hints &= ~ScanHint.PAIR0
        return replace(self, hints=hints)


_DEFAULT_OPTIONS = ScanOptions()
_SCAN_OPTIONS: contextvars.ContextVar[ScanOptions] = contextvars.ContextVar(
    "libhat_scan_options", default=_DEFAULT_OPTIONS
)


def current_options() -> ScanOptions:
    return _SCAN_OPTIONS.get()


@contextlib.contextmanager
def use_options(options: ScanOptions):
    token = _SCAN_OPTIONS.set(options)
    try:
        yield options
    finally:
        _SCAN_OPTIONS.reset(token)


def push_options(options: ScanOptions):
    """Install scan options and return a token for :func:`pop_options`."""
    return _SCAN_OPTIONS.set(options)


def pop_options(token) -> None:
    """Restore the scan options that preceded a :func:`push_options` call."""
    _SCAN_OPTIONS.reset(token)


def _engine_or_raise() -> libhat_native.LibhatEngine:
    return libhat_native.get_engine()


def available() -> bool:
    try:
        _engine_or_raise()
        return True
    except Exception:
        return False


def engine_info() -> tuple[str | None, str | None, str | None]:
    """Return ``(version, path, error)`` for the status line."""
    engine, error = libhat_native.engine_status()
    if engine is None:
        return None, None, error
    return engine.version, str(engine.path), None


def Signature(ida_signature: str) -> libhat_native.NativeSignature:
    """Parse an IDA/canonical signature into a native libhat signature."""
    return _engine_or_raise().create_signature(ida_signature)


def scan_bytes(data_mv, sig: libhat_native.NativeSignature) -> int:
    """Return the first match offset in ``data_mv``, or ``-1``."""
    if getattr(sig, "size_bytes", 0) == 0:
        return 0
    options = current_options()
    offset = _engine_or_raise().find_first(
        sig,
        data_mv,
        alignment=int(options.alignment),
        hints=int(options.hints),
    )
    return -1 if offset is None else offset


def find_all(
    data_mv,
    sig: libhat_native.NativeSignature,
    limit: int = 0,
    *,
    max_matches: int = 0,
) -> array.array:
    """Return every match offset in ``data_mv`` as an ``array('Q')``.

    ``limit`` caps both the number of matches returned and the scan work. It is
    used by uniqueness checks, which only need to know whether the answer is
    0, 1, or 2+.

    ``max_matches`` is forwarded to the native result buffer. The plugin's
    search loop bounds each call to one 8 MiB chunk, so the default of 0
    (unlimited) is safe there; a partial result is never returned silently.
    """
    if getattr(sig, "size_bytes", 0) == 0:
        return array.array("Q", [0])
    options = current_options()
    offsets, truncated = _engine_or_raise().find_all(
        sig,
        data_mv,
        alignment=int(options.alignment),
        hints=int(options.hints),
        limit=limit,
        max_matches=max_matches,
    )
    if truncated:
        raise LibhatScanTruncated(
            "the native scan exceeded its result limit; "
            "narrow the pattern or search scope"
        )
    return offsets


def count(data_mv, sig: libhat_native.NativeSignature, limit: int = 0) -> int:
    """Return how many positions match, stopping early at ``limit`` hits."""
    if getattr(sig, "size_bytes", 0) == 0:
        return 0
    options = current_options()
    return _engine_or_raise().count(
        sig,
        data_mv,
        alignment=int(options.alignment),
        hints=int(options.hints),
        limit=limit,
    )


def build_byte_index(data_mv) -> tuple[array.array, array.array]:
    return _engine_or_raise().build_byte_index(data_mv)


def seed_offsets(
    raw: array.array,
    seed_offset: int,
    pattern_size: int,
    buffer_size: int,
) -> tuple[array.array, int]:
    return _engine_or_raise().seed_offsets(
        raw, seed_offset, pattern_size, buffer_size
    )


def refine_offsets(
    data_mv,
    candidates: array.array,
    count: int,
    index: int,
    value: int,
    mask: int,
) -> int:
    return _engine_or_raise().refine_offsets(
        data_mv, candidates, count, index, value, mask
    )


def _verify_offsets_impl(
    data_mv,
    candidates: array.array,
    count: int,
    values: bytes,
    masks: bytes,
    start_index: int = 0,
) -> int:
    return _engine_or_raise().verify_offsets(
        data_mv, candidates, count, values, masks, start_index
    )


def __getattr__(name: str):
    """Expose ``verify_offsets`` only when the native library implements it.

    The plugin feature-detects optional kernels with
    ``getattr(module, "verify_offsets", None)``. Publishing the symbol from a
    stale ``libhat_scan`` would turn that probe into a runtime error, so it has
    to be absent when the DLL predates the fused kernel. Resolving it caches
    the function in the module globals, keeping hot-loop lookups cheap.
    """
    if name == "verify_offsets":
        engine = libhat_native.engine()
        if engine is not None and engine.supports_verify_offsets:
            globals()["verify_offsets"] = _verify_offsets_impl
            return _verify_offsets_impl
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def filter_offsets_by_search_ranges(
    candidates: array.array,
    count: int,
    pattern_size: int,
    range_starts,
    range_ends,
) -> int:
    return _engine_or_raise().filter_offsets(
        candidates,
        count,
        pattern_size,
        range_starts,
        range_ends,
    )


# The original _Speedups validator checks for an API range when one is
# declared. Matching its contract keeps the adapter drop-in compatible.
SPEEDUPS_API_MIN = 1
SPEEDUPS_API_MAX = 1


def _warm_engine() -> None:
    try:
        _engine_or_raise()
    except Exception:
        # A missing native library is not fatal: the plugin falls back to its
        # pure-Python scanner and says so in the UI.
        pass


_WARM_LOCK = threading.Lock()
_WARMED = False


def warm_engine() -> None:
    global _WARMED
    with _WARM_LOCK:
        if _WARMED:
            return
        _WARMED = True
        _warm_engine()


warm_engine()
