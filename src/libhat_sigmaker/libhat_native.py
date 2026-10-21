"""ctypes bindings and pattern parsing for the libhat scan bridge.

This module is deliberately free of any ``idaapi``/``ida_*`` imports so it can
be unit tested outside IDA. The plugin core and the native backend both use it.
"""

from __future__ import annotations

import array
import ctypes
import os
import pathlib
import re
import string
import sys
import threading
from dataclasses import dataclass

__all__ = [
    "LibhatNativeError",
    "ParsedPattern",
    "NativeSignature",
    "LibhatEngine",
    "engine",
    "get_engine",
    "parse_pattern",
    "to_native_pattern",
]

_HEX_DIGITS = frozenset(string.hexdigits)
_BINARY_DIGITS = frozenset("01?")
_SEPARATOR_TRANS = str.maketrans(
    {
        ",": " ",
        ";": " ",
        ":": " ",
        "|": " ",
        "_": " ",
        "-": " ",
        ".": "?",
        "\t": " ",
        "\n": " ",
        "\r": " ",
    }
)
_ESCAPED_RUN_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
_ESCAPED_BYTE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
_PREFIXED_RUN_RE = re.compile(r"(?:0x[0-9A-Fa-f]{2})+")
_PREFIXED_BYTE_RE = re.compile(r"0x([0-9A-Fa-f]{2})")
_MASK_STRING_RE = re.compile(r"(?:^|(?<=\s))(x(?:\?|x)+)\s*$")
_BINARY_MASK_RE = re.compile(r"(?:^|(?<=\s))(0b[01]+)\s*$")
_QUOTED_RE = re.compile(r'"([^"\n]*)"|\'([^\'\n]*)\'')
_COMPILE_SIGNATURE_RE = re.compile(
    r"hat::compile_signature\s*<\s*(.*?)\s*>\s*\(\s*\)", re.DOTALL
)
_PARSE_SIGNATURE_RE = re.compile(
    r"hat::parse_signature\s*\(\s*(.*?)\s*\)", re.DOTALL
)
_SIG_SUFFIX_RE = re.compile(r"^(.*?)\s*(?:_sig|_sigv)\s*;?\s*$", re.DOTALL)


class LibhatNativeError(RuntimeError):
    """Raised when the native libhat scan bridge cannot be used."""


@dataclass(frozen=True, slots=True)
class ParsedPattern:
    """A signature normalized to libhat-compatible tokens plus byte masks."""

    canonical: str
    values: bytes
    masks: bytes

    def __len__(self) -> int:
        return len(self.values)

    @property
    def has_exact_byte(self) -> bool:
        return any(mask == 0xFF for mask in self.masks)

    @property
    def exact_runs(self) -> list[tuple[int, int]]:
        """Return ``(start, length)`` for every run of fully exact bytes."""
        runs: list[tuple[int, int]] = []
        start: int | None = None
        for index, mask in enumerate(self.masks):
            if mask == 0xFF:
                if start is None:
                    start = index
            elif start is not None:
                runs.append((start, index - start))
                start = None
        if start is not None:
            runs.append((start, len(self.masks) - start))
        return runs


def _strip_wrapper(text: str) -> str:
    s = text.strip()
    if not s:
        return ""

    match = _COMPILE_SIGNATURE_RE.search(s)
    if match:
        return _strip_quotes(match.group(1).strip())

    match = _PARSE_SIGNATURE_RE.search(s)
    if match:
        return _strip_quotes(match.group(1).strip())

    match = _SIG_SUFFIX_RE.match(s)
    if match and ("_sig" in s):
        inner = _strip_quotes(match.group(1).strip())
        if inner:
            if '"' in inner or "'" in inner:
                quoted = _QUOTED_RE.search(inner)
                if quoted:
                    inner = (
                        quoted.group(1)
                        if quoted.group(1) is not None
                        else quoted.group(2) or ""
                    ).strip()
            if inner:
                return inner

    # A full C++ declaration such as:
    #   inline constexpr auto sig = "48 8B ? ?"_sig;
    # or a plain quoted signature.
    if s.count('"') >= 2 or s.count("'") >= 2:
        match = _QUOTED_RE.search(s)
        if match:
            inner = (match.group(1) if match.group(1) is not None else match.group(2) or "").strip()
            if inner:
                return inner

    return _strip_quotes(s)


def _strip_quotes(text: str) -> str:
    s = text.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'`":
        s = s[1:-1].strip()
    return s


def _token_is_binary(token: str) -> bool:
    return len(token) == 8 and all(ch in _BINARY_DIGITS for ch in token)


def _binary_token(token: str) -> tuple[str, int, int]:
    value = 0
    mask = 0
    for index, ch in enumerate(token):
        bit = 1 << (7 - index)
        if ch == "?":
            continue
        mask |= bit
        if ch == "1":
            value |= bit

    if mask == 0:
        canonical = "??"
    elif mask == 0xFF:
        canonical = f"{value:02X}"
    elif mask == 0xF0:
        canonical = f"{value >> 4:X}?"
    elif mask == 0x0F:
        canonical = f"?{value & 0x0F:X}"
    else:
        canonical = "".join(
            "?" if not (mask & (1 << (7 - i))) else ("1" if value & (1 << (7 - i)) else "0")
            for i in range(8)
        )
    return canonical, value & mask, mask


def _nibble_token(token: str) -> tuple[str, int, int]:
    hi, lo = token[0], token[1]
    mask = (0xF0 if hi != "?" else 0) | (0x0F if lo != "?" else 0)
    value = ((int(hi, 16) if hi != "?" else 0) << 4) | (
        int(lo, 16) if lo != "?" else 0
    )
    if mask == 0:
        return "??", 0, 0
    return f"{hi.upper()}{lo.upper()}", value & mask, mask


def _split_pair_token(token: str) -> list[str]:
    """Split a run such as ``488B??4?`` into canonical pair tokens."""
    result: list[str] = []
    index = 0
    while index < len(token):
        chunk = token[index : index + 2]
        if len(chunk) == 1:
            chunk = ("?" if chunk == "?" else chunk) + "?"
        result.append(chunk)
        index += 2
    return result


def _normalize_token(raw: str) -> list[str]:
    token = raw.strip()
    if not token:
        return []

    if token.lower().startswith("0x"):
        token = token[2:]
    elif token.lower().startswith("0b") and len(token) > 2:
        token = token[2:]
        if _token_is_binary(token):
            return [token]

    if _ESCAPED_RUN_RE.fullmatch(token):
        return [value.upper() for value in _ESCAPED_BYTE_RE.findall(token)]
    if _PREFIXED_RUN_RE.fullmatch(token):
        return [value.upper() for value in _PREFIXED_BYTE_RE.findall(token)]

    if token == "?":
        return ["??"]
    if len(token) == 2 and all(ch in _HEX_DIGITS or ch == "?" for ch in token):
        return [token.upper()]
    if len(token) == 1 and token in _HEX_DIGITS:
        return [token.upper() + "?"]
    if _token_is_binary(token):
        return [token]

    if len(token) > 2 and all(ch in _HEX_DIGITS or ch == "?" for ch in token):
        return [part.upper() for part in _split_pair_token(token)]

    raise ValueError(f"invalid signature token: {raw!r}")


def _tokens(text: str) -> list[str]:
    translated = text.translate(_SEPARATOR_TRANS)
    tokens: list[str] = []
    for raw in translated.split():
        tokens.extend(_normalize_token(raw))
    return tokens


def _bytes_from_token(token: str) -> tuple[str, int, int]:
    if token == "?":
        token = "??"
    if len(token) == 8 and _token_is_binary(token):
        return _binary_token(token)
    if len(token) == 2 and all(ch in _HEX_DIGITS or ch == "?" for ch in token):
        return _nibble_token(token)
    raise ValueError(f"invalid signature token: {token!r}")


def _parsed_from_tokens(tokens: list[str]) -> ParsedPattern:
    if not tokens:
        raise ValueError("empty signature")
    canonical: list[str] = []
    values = bytearray()
    masks = bytearray()
    for token in tokens:
        canon, value, mask = _bytes_from_token(token)
        canonical.append(canon)
        values.append(value)
        masks.append(mask)
    return ParsedPattern(" ".join(canonical), bytes(values), bytes(masks))


def _parse_mask_form(text: str) -> ParsedPattern | None:
    match = _MASK_STRING_RE.search(text)
    binary = False
    if match is None:
        match = _BINARY_MASK_RE.search(text)
        binary = match is not None
    if match is None:
        return None

    byte_text = text[: match.start()].strip()
    mask_text = match.group(1).strip()
    if not byte_text:
        return None

    tokens = _tokens(byte_text)
    if not tokens:
        return None
    parsed = _parsed_from_tokens(tokens)
    if len(parsed.values) != len(mask_text if not binary else mask_text[2:]):
        return None

    if binary:
        bits = mask_text[2:][::-1]
        masks = bytes(0xFF if bit == "1" else 0x00 for bit in bits)
    else:
        masks = bytes(0xFF if ch == "x" else 0x00 for ch in mask_text)

    values = bytearray()
    canonical: list[str] = []
    for value, mask in zip(parsed.values, masks):
        value &= mask
        values.append(value)
        if mask == 0:
            canonical.append("??")
        elif mask == 0xFF:
            canonical.append(f"{value:02X}")
        else:
            canonical.append(
                "".join(
                    "?" if not (mask & (1 << (7 - i))) else ("1" if value & (1 << (7 - i)) else "0")
                    for i in range(8)
                )
            )
    return ParsedPattern(" ".join(canonical), bytes(values), masks)


def parse_pattern(text: str) -> ParsedPattern:
    """Parse IDA, x64dbg, C array, and libhat signature syntax.

    Raises:
        ValueError: if the input cannot be parsed as a signature.
    """
    if not isinstance(text, str):
        raise ValueError("signature must be a string")
    s = _strip_wrapper(text)
    if not s:
        raise ValueError("empty signature")

    masked = _parse_mask_form(s)
    if masked is not None:
        return masked

    return _parsed_from_tokens(_tokens(s))


def to_native_pattern(text: str) -> str:
    """Return the canonical libhat token string for ``text``."""
    return parse_pattern(text).canonical


def _library_names() -> tuple[str, ...]:
    if sys.platform.startswith("win"):
        return ("libhat_scan.dll",)
    if sys.platform.startswith("darwin"):
        return ("libhat_scan.dylib",)
    return ("libhat_scan.so",)


def _candidate_directories() -> list[pathlib.Path]:
    package_dir = pathlib.Path(__file__).resolve().parent
    env_path = os.environ.get("LIBHAT_SIGMAKER_DLL")
    candidates: list[pathlib.Path] = []
    if env_path:
        env = pathlib.Path(env_path)
        candidates.append(env if env.is_dir() else env.parent)
    candidates.extend(
        [
            package_dir,
            package_dir / "native",
            package_dir.parent / "native",
            package_dir.parent.parent / "build" / "native" / "bin" / "Release",
            package_dir.parent.parent / "build" / "native" / "bin" / "Debug",
            package_dir.parent.parent / "build" / "bin" / "Release",
            pathlib.Path.cwd(),
        ]
    )
    for entry in sys.path:
        if entry:
            candidates.append(pathlib.Path(entry))
    return candidates


def _find_library() -> pathlib.Path:
    env_path = os.environ.get("LIBHAT_SIGMAKER_DLL")
    if env_path:
        env = pathlib.Path(env_path)
        if env.is_file():
            return env
        if env.is_dir():
            for name in _library_names():
                candidate = env / name
                if candidate.is_file():
                    return candidate

    seen: set[pathlib.Path] = set()
    for directory in _candidate_directories():
        try:
            resolved = directory.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        for name in _library_names():
            candidate = resolved / name
            if candidate.is_file():
                return candidate
    raise LibhatNativeError(
        "could not locate the native libhat_scan library; "
        "build it with scripts/build_native.ps1 or set LIBHAT_SIGMAKER_DLL"
    )


class NativeSignature:
    """Owns one parsed native signature handle."""

    __slots__ = ("_engine", "_handle", "size_bytes", "pattern", "values", "masks")

    def __init__(
        self,
        engine_obj: "LibhatEngine",
        handle: int,
        pattern: str,
        values: bytes,
        masks: bytes,
        size_bytes: int | None = None,
    ) -> None:
        self._engine = engine_obj
        self._handle = handle
        self.pattern = pattern
        self.values = values
        self.masks = masks
        self.size_bytes = len(values) if size_bytes is None else int(size_bytes)

    @property
    def handle(self) -> int:
        return self._handle

    def close(self) -> None:
        handle = self._handle
        if handle:
            self._handle = 0
            self._engine._free_signature(handle)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class LibhatEngine:
    """Thin, validated wrapper around ``libhat_scan``."""

    def __init__(self, library_path: pathlib.Path | None = None) -> None:
        self.path = library_path or _find_library()
        self._lib = ctypes.CDLL(str(self.path))
        self._configure()

    def _configure(self) -> None:
        lib = self._lib

        lib.libhat_scan_version.argtypes = []
        lib.libhat_scan_version.restype = ctypes.c_char_p
        lib.libhat_scan_status_string.argtypes = [ctypes.c_int]
        lib.libhat_scan_status_string.restype = ctypes.c_char_p

        lib.libhat_scan_create_signature.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.libhat_scan_create_signature.restype = ctypes.c_int
        lib.libhat_scan_parse_signature.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.libhat_scan_parse_signature.restype = ctypes.c_int
        lib.libhat_scan_free_signature.argtypes = [ctypes.c_void_p]
        lib.libhat_scan_free_signature.restype = None
        lib.libhat_scan_signature_size.argtypes = [ctypes.c_void_p]
        lib.libhat_scan_signature_size.restype = ctypes.c_size_t

        lib.libhat_scan_count.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.libhat_scan_count.restype = ctypes.c_int
        lib.libhat_scan_find_all.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.libhat_scan_find_all.restype = ctypes.c_int
        lib.libhat_scan_find_first.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        lib.libhat_scan_find_first.restype = ctypes.c_int

        lib.libhat_scan_build_byte_index.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.libhat_scan_build_byte_index.restype = ctypes.c_int
        lib.libhat_scan_seed_offsets.argtypes = [
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        lib.libhat_scan_seed_offsets.restype = ctypes.c_size_t
        lib.libhat_scan_refine_offsets.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint8,
            ctypes.c_uint8,
        ]
        lib.libhat_scan_refine_offsets.restype = ctypes.c_size_t
        lib.libhat_scan_filter_offsets.argtypes = [
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        lib.libhat_scan_filter_offsets.restype = ctypes.c_size_t

        # Optional entry points added after 0.1.0. They are feature-detected so
        # a stale DLL keeps working through the older count/find_all pair.
        self._find_all_alloc = getattr(lib, "libhat_scan_find_all_alloc", None)
        self._free_result = getattr(lib, "libhat_scan_free_result", None)
        if self._find_all_alloc is not None and self._free_result is not None:
            self._find_all_alloc.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_size_t,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.POINTER(ctypes.c_uint64)),
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.POINTER(ctypes.c_int),
            ]
            self._find_all_alloc.restype = ctypes.c_int
            self._free_result.argtypes = [ctypes.POINTER(ctypes.c_uint64)]
            self._free_result.restype = None
        else:
            self._find_all_alloc = None
            self._free_result = None

        self._verify_offsets = getattr(lib, "libhat_scan_verify_offsets", None)
        if self._verify_offsets is not None:
            self._verify_offsets.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint64),
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_size_t,
            ]
            self._verify_offsets.restype = ctypes.c_size_t

        version = lib.libhat_scan_version()
        self.version = version.decode("utf-8") if version else "unknown"

    def _status(self, status: int) -> None:
        if status == 0:
            return
        message = self._lib.libhat_scan_status_string(status)
        text = message.decode("utf-8") if message else f"status {status}"
        raise LibhatNativeError(f"libhat_scan: {text}")

    def create_signature(self, pattern: str) -> NativeSignature:
        parsed = parse_pattern(pattern)
        return self.create_signature_from_bytes(
            parsed.values, parsed.masks, pattern=parsed.canonical
        )

    def create_signature_from_bytes(
        self, values: bytes, masks: bytes, *, pattern: str = ""
    ) -> NativeSignature:
        if len(values) != len(masks):
            raise ValueError("values and masks must have the same length")
        if not values:
            raise ValueError("signature must not be empty")

        handle = ctypes.c_void_p()
        status = self._lib.libhat_scan_create_signature(
            bytes(values), bytes(masks), len(values), ctypes.byref(handle)
        )
        self._status(status)
        if not handle.value:
            raise LibhatNativeError("libhat_scan returned a null signature")
        return NativeSignature(self, int(handle.value), pattern, bytes(values), bytes(masks))

    def parse_signature(self, pattern: str) -> NativeSignature:
        """Parse using libhat's own grammar (nibble and binary wildcards)."""
        handle = ctypes.c_void_p()
        status = self._lib.libhat_scan_parse_signature(
            pattern.encode("utf-8"), ctypes.byref(handle)
        )
        self._status(status)
        if not handle.value:
            raise LibhatNativeError("libhat_scan returned a null signature")
        size = int(self._lib.libhat_scan_signature_size(handle))
        return NativeSignature(
            self, int(handle.value), pattern, b"", b"", size_bytes=size
        )

    def _free_signature(self, handle: int) -> None:
        self._lib.libhat_scan_free_signature(ctypes.c_void_p(handle))

    @staticmethod
    def _buffer(data) -> tuple[ctypes.c_void_p, int, object]:
        if isinstance(data, bytes):
            return ctypes.cast(data, ctypes.c_void_p), len(data), data
        if isinstance(data, bytearray):
            array_view = (ctypes.c_ubyte * len(data)).from_buffer(data)
            return ctypes.cast(array_view, ctypes.c_void_p), len(data), array_view
        if isinstance(data, memoryview):
            if data.readonly:
                owned = data.tobytes()
                return ctypes.cast(owned, ctypes.c_void_p), len(owned), owned
            view = data.cast("B")
            array_view = (ctypes.c_ubyte * len(view)).from_buffer(view)
            return ctypes.cast(array_view, ctypes.c_void_p), len(view), (array_view, view)
        if isinstance(data, ctypes.Array):
            size = ctypes.sizeof(data)
            array_view = (ctypes.c_ubyte * size).from_buffer(data)
            return ctypes.cast(array_view, ctypes.c_void_p), size, array_view
        raise TypeError(f"unsupported buffer type: {type(data)!r}")

    def count(
        self,
        signature: NativeSignature,
        data,
        *,
        alignment: int = 1,
        hints: int = 0,
        limit: int = 0,
    ) -> int:
        pointer, size, keepalive = self._buffer(data)
        count = ctypes.c_size_t()
        status = self._lib.libhat_scan_count(
            signature.handle, pointer, size, alignment, hints, limit, ctypes.byref(count)
        )
        self._status(status)
        return int(count.value)

    def find_all(
        self,
        signature: NativeSignature,
        data,
        *,
        alignment: int = 1,
        hints: int = 0,
        limit: int = 0,
        max_matches: int = 4_000_000,
    ) -> tuple[array.array, bool]:
        """Return ``(offsets, truncated)`` for every match, optionally capped."""
        if self._find_all_alloc is not None:
            return self._find_all_single_pass(
                signature,
                data,
                alignment=alignment,
                hints=hints,
                limit=limit,
                max_matches=max_matches,
            )

        total = self.count(
            signature, data, alignment=alignment, hints=hints, limit=limit
        )
        if total == 0:
            return array.array("Q"), False

        truncated = False
        if max_matches and total > max_matches:
            total = max_matches
            truncated = True

        offsets = array.array("Q", [0]) * total
        pointer, size, keepalive = self._buffer(data)
        out_count = ctypes.c_size_t()
        out = (ctypes.c_uint64 * total).from_buffer(offsets)
        status = self._lib.libhat_scan_find_all(
            signature.handle,
            pointer,
            size,
            out,
            total,
            alignment,
            hints,
            ctypes.byref(out_count),
        )
        self._status(status)
        if out_count.value != total:
            # The second pass returned fewer matches than the count pass. Treat
            # that as truncation too, otherwise callers could trust a partial
            # candidate list without knowing it.
            truncated = True
            del offsets[out_count.value :]
        return offsets, truncated

    def _find_all_single_pass(
        self,
        signature: NativeSignature,
        data,
        *,
        alignment: int,
        hints: int,
        limit: int,
        max_matches: int,
    ) -> tuple[array.array, bool]:
        """One scan that both sizes and fills the result buffer.

        The older ``count`` + ``find_all`` pair walked the whole buffer twice,
        which doubled the cost of the hot uniqueness check (``limit=2``).
        """
        pointer, size, keepalive = self._buffer(data)
        out = ctypes.POINTER(ctypes.c_uint64)()
        count = ctypes.c_size_t()
        truncated = ctypes.c_int()
        status = self._find_all_alloc(
            signature.handle,
            pointer,
            size,
            alignment,
            hints,
            limit,
            max_matches,
            ctypes.byref(out),
            ctypes.byref(count),
            ctypes.byref(truncated),
        )
        try:
            self._status(status)
            total = int(count.value)
            if total == 0:
                return array.array("Q"), False
            offsets = array.array("Q")
            offsets.frombytes(ctypes.string_at(out, total * 8))
            if sys.byteorder != "little":
                offsets.byteswap()
            return offsets, bool(truncated.value)
        finally:
            if out:
                self._free_result(out)

    def verify_offsets(
        self,
        data,
        candidates: array.array,
        count: int,
        values: bytes,
        masks: bytes,
        start_index: int = 0,
    ) -> int:
        """Keep only candidates whose whole masked pattern matches.

        Returns the new candidate count, compacted in place. This replaces a
        chain of per-byte :meth:`refine_offsets` calls with one pass over the
        working set.
        """
        if self._verify_offsets is None:
            raise LibhatNativeError(
                "the loaded libhat_scan library does not implement verify_offsets"
            )
        if count == 0:
            return 0
        pointer, size, keepalive = self._buffer(data)
        candidates_view = (ctypes.c_uint64 * len(candidates)).from_buffer(candidates)
        return int(
            self._verify_offsets(
                pointer,
                size,
                candidates_view,
                count,
                bytes(values),
                bytes(masks),
                len(values),
                start_index,
            )
        )

    @property
    def supports_single_pass_find_all(self) -> bool:
        return self._find_all_alloc is not None

    @property
    def supports_verify_offsets(self) -> bool:
        return self._verify_offsets is not None

    def find_first(
        self, signature: NativeSignature, data, *, alignment: int = 1, hints: int = 0
    ) -> int | None:
        pointer, size, keepalive = self._buffer(data)
        offset = ctypes.c_uint64()
        status = self._lib.libhat_scan_find_first(
            signature.handle, pointer, size, alignment, hints, ctypes.byref(offset)
        )
        self._status(status)
        if offset.value == 0xFFFFFFFFFFFFFFFF:
            return None
        return int(offset.value)

    def build_byte_index(self, data) -> tuple[array.array, array.array]:
        pointer, size, keepalive = self._buffer(data)
        if size < 2:
            raise ValueError("byte index requires at least two bytes")
        if size - 1 > 0xFFFFFFFF:
            raise ValueError(
                "byte index requires a buffer no larger than 4 GiB"
            )
        heads = array.array("I", [0]) * 65537
        positions = array.array("I", [0]) * (size - 1)
        heads_view = (ctypes.c_uint32 * len(heads)).from_buffer(heads)
        positions_view = (ctypes.c_uint32 * len(positions)).from_buffer(positions)
        status = self._lib.libhat_scan_build_byte_index(
            pointer, size, heads_view, positions_view
        )
        self._status(status)
        return heads, positions

    def seed_offsets(
        self,
        raw: array.array,
        seed_offset: int,
        pattern_size: int,
        buffer_size: int,
    ) -> tuple[array.array, int]:
        capacity = len(raw) + 1
        candidates = array.array("Q", [0]) * capacity
        raw_view = (ctypes.c_uint32 * len(raw)).from_buffer(raw) if raw else None
        candidate_view = (ctypes.c_uint64 * capacity).from_buffer(candidates)
        count = self._lib.libhat_scan_seed_offsets(
            raw_view,
            len(raw),
            seed_offset,
            pattern_size,
            buffer_size,
            candidate_view,
            capacity,
        )
        return candidates, int(count)

    def refine_offsets(
        self,
        data,
        candidates: array.array,
        count: int,
        index: int,
        value: int,
        mask: int,
    ) -> int:
        if count == 0:
            return 0
        pointer, size, keepalive = self._buffer(data)
        candidates_view = (ctypes.c_uint64 * len(candidates)).from_buffer(candidates)
        return int(
            self._lib.libhat_scan_refine_offsets(
                pointer, size, candidates_view, count, index, value, mask
            )
        )

    def filter_offsets(
        self,
        candidates: array.array,
        count: int,
        pattern_size: int,
        range_starts,
        range_ends,
    ) -> int:
        if count == 0:
            return 0
        starts = (ctypes.c_uint64 * len(range_starts))(*range_starts)
        ends = (ctypes.c_uint64 * len(range_ends))(*range_ends)
        candidates_view = (ctypes.c_uint64 * len(candidates)).from_buffer(candidates)
        return int(
            self._lib.libhat_scan_filter_offsets(
                candidates_view,
                count,
                pattern_size,
                starts,
                ends,
                len(range_starts),
            )
        )


_ENGINE_LOCK = threading.Lock()
_ENGINE: LibhatEngine | None = None
_ENGINE_ERROR: str | None = None


def get_engine() -> LibhatEngine:
    """Load (once) and return the native engine, raising on failure."""
    global _ENGINE, _ENGINE_ERROR
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE
        try:
            _ENGINE = LibhatEngine()
            _ENGINE_ERROR = None
            return _ENGINE
        except Exception as exc:
            _ENGINE_ERROR = str(exc)
            raise


def engine_status() -> tuple[LibhatEngine | None, str | None]:
    """Return ``(engine, error)`` without raising; used by the plugin UI."""
    global _ENGINE, _ENGINE_ERROR
    with _ENGINE_LOCK:
        return _ENGINE, _ENGINE_ERROR


def engine() -> LibhatEngine | None:
    try:
        return get_engine()
    except Exception:
        return None
