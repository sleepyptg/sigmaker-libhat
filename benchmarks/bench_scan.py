"""Microbenchmarks for the libhat_scan bridge (no IDA required).

Measures the pieces the sigmaker generation loop actually uses:

* single-pass ``find_all`` versus the old ``count`` + ``find_all`` pair
* the uniqueness probe (``limit=2``) that dominates signature generation
* ``build_byte_index`` and the seed/refine pipeline
* fused ``verify_offsets`` versus one ``refine_offsets`` call per byte

Usage:

    python benchmarks/bench_scan.py [buffer MiB]

The buffer is built from real Windows system binaries when they are present
and falls back to synthetic code-like bytes elsewhere. Numbers quoted in the
README were produced with 64 MiB on an AVX2-only i7-13620H.
"""

import array
import importlib.util
import pathlib
import sys
import time
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

# Load libhat_native without importing the package __init__ (which needs IDA).
_pkg = types.ModuleType("libhat_sigmaker")
_pkg.__path__ = [str(SRC / "libhat_sigmaker")]
sys.modules["libhat_sigmaker"] = _pkg
_spec = importlib.util.spec_from_file_location(
    "libhat_sigmaker.libhat_native", SRC / "libhat_sigmaker" / "libhat_native.py"
)
_native = importlib.util.module_from_spec(_spec)
sys.modules["libhat_sigmaker.libhat_native"] = _native
_spec.loader.exec_module(_native)

get_engine = _native.get_engine
parse_pattern = _native.parse_pattern

BUFFER_MB = int(sys.argv[1]) if len(sys.argv) > 1 else 64

SYSTEM_BINARIES = [
    r"C:\Windows\System32\windows.storage.dll",
    r"C:\Windows\System32\shell32.dll",
    r"C:\Windows\System32\ntoskrnl.exe",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\KERNELBASE.dll",
    r"C:\Windows\System32\explorer.exe",
    r"C:\Windows\System32\win32kfull.sys",
]


def real_code_buffer(target_bytes):
    """Concatenate real binaries so the byte distribution is realistic."""
    parts = []
    total = 0
    sources = [path for path in map(pathlib.Path, SYSTEM_BINARIES) if path.is_file()]
    if sources:
        index = 0
        while total < target_bytes:
            data = sources[index % len(sources)].read_bytes()
            parts.append(data)
            total += len(data)
            index += 1
    else:
        # No system binaries (non-Windows host): high-entropy bytes keep the
        # scan/refine work realistic instead of collapsing into a tiny pool.
        import random

        parts.append(random.Random(1234).randbytes(target_bytes))
    return b"".join(parts)[:target_bytes]


def timed(label, fn, iters=3):
    best = None
    out = None
    for _ in range(iters):
        t0 = time.perf_counter()
        out = fn()
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
    print(f"{label:<52} {best * 1e3:9.2f} ms")
    return out, best


def make_pattern(data, offset, length=24, wildcards=5):
    values = list(data[offset : offset + length])
    masks = [0xFF] * length
    for k in range(wildcards):
        pos = 10 + k * 3
        if pos + 4 <= length:
            for j in range(4):
                masks[pos + j] = 0
    pattern = " ".join(
        "??" if masks[i] == 0 else f"{values[i]:02X}" for i in range(length)
    )
    return pattern


def main():
    print(f"building {BUFFER_MB} MiB real-code buffer...")
    data = real_code_buffer(BUFFER_MB << 20)
    print(f"buffer: {len(data) / (1 << 20):.1f} MiB")

    engine = get_engine()
    print("engine:", engine.version, engine.path)

    offset = len(data) // 3
    pattern = make_pattern(data, offset)
    print("pattern:", pattern)

    parsed = parse_pattern(pattern)
    sig = engine.create_signature_from_bytes(
        parsed.values, parsed.masks, pattern=parsed.canonical
    )

    print()
    print("=== whole-buffer scans ===")
    offsets, t_find_all = timed(
        "find_all single-pass", lambda: engine.find_all(sig, data)
    )
    print(f"  hits: {len(offsets)}")
    saved_alloc = engine._find_all_alloc
    engine._find_all_alloc = None
    try:
        _old, t_find_all_old = timed(
            "find_all old count+scan", lambda: engine.find_all(sig, data)
        )
    finally:
        engine._find_all_alloc = saved_alloc
    print(f"  old/new: {t_find_all_old / max(t_find_all, 1e-9):.2f}x")

    # Uniqueness probe: the hot path for signature generation.
    upattern = " ".join(pattern.split()[:11])
    uparsed = parse_pattern(upattern)
    usig = engine.create_signature_from_bytes(uparsed.values, uparsed.masks)
    c, t_count2 = timed(
        "count(limit=2) 11-byte prefix", lambda: engine.count(usig, data, limit=2)
    )
    print(f"  count: {c}")
    uoffsets, t_findall2 = timed(
        "find_all(limit=2) 11-byte prefix (single pass)",
        lambda: engine.find_all(usig, data, limit=2),
    )
    print(f"  hits: {len(uoffsets)}")
    engine._find_all_alloc = None
    try:
        _uold, t_findall2_old = timed(
            "find_all(limit=2) 11-byte prefix (old)",
            lambda: engine.find_all(usig, data, limit=2),
        )
    finally:
        engine._find_all_alloc = saved_alloc
    print(
        f"  old total {1e3 * (t_count2 + t_findall2_old):.2f} ms -> "
        f"new total {1e3 * t_findall2:.2f} ms"
    )

    genuine = bytes(data[offset : offset + 64])
    longpattern = " ".join(f"{b:02X}" for b in genuine)
    lparsed = parse_pattern(longpattern)
    lsig = engine.create_signature_from_bytes(lparsed.values, lparsed.masks)
    c, t_countlong = timed(
        "count(limit=2) 64-byte exact (unique)",
        lambda: engine.count(lsig, data, limit=2),
    )
    print(f"  count: {c}")
    loffsets, t_findalllong = timed(
        "find_all(limit=2) 64-byte exact (single pass)",
        lambda: engine.find_all(lsig, data, limit=2),
    )
    print(f"  hits: {len(loffsets)}")
    engine._find_all_alloc = None
    try:
        _lold, t_findalllong_old = timed(
            "find_all(limit=2) 64-byte exact (old scan)",
            lambda: engine.find_all(lsig, data, limit=2),
        )
    finally:
        engine._find_all_alloc = saved_alloc
    print(
        f"  uniqueness probe total: old "
        f"{1000 * (t_countlong + t_findalllong_old):.2f} ms, "
        f"new {1000 * t_findalllong:.2f} ms, "
        f"{((t_countlong + t_findalllong_old) / max(t_findalllong, 1e-9)):.2f}x"
    )

    print()
    print("=== byte index ===")
    (heads, positions), _t_index = timed(
        "build_byte_index", lambda: engine.build_byte_index(data), iters=2
    )
    print(
        f"  positions: {len(positions) / 1e6:.1f}M uint32 "
        f"({len(positions) * 4 / (1 << 20):.0f} MiB)"
    )

    print()
    print("=== seed + refine chain ===")
    print("picking a seed like _select_seed_run does (rarest 2-byte run)...")
    best = None
    for j in range(len(parsed.values) - 1):
        if parsed.masks[j] and parsed.masks[j + 1]:
            key = (parsed.values[j] << 8) | parsed.values[j + 1]
            size = heads[key + 1] - heads[key]
            if best is None or size < best[0]:
                best = (size, j, key)
    if best is None:
        print("no exact pair")
        return
    seed_size, seed_off, key = best
    print(f"  seed offset={seed_off} key=0x{key:04X} bucket={seed_size}")
    raw = positions[heads[key] : heads[key + 1]]
    values = parsed.values
    masks = parsed.masks

    def seed_and_refine():
        cands, count = engine.seed_offsets(raw, seed_off, len(values), len(data))
        for j in range(len(values)):
            if j == seed_off or j == seed_off + 1 or not masks[j]:
                continue
            count = engine.refine_offsets(data, cands, count, j, values[j], 0xFF)
        return count

    count, _t_chain = timed(
        f"seed_offsets + {sum(1 for m in masks if m)} per-byte refines",
        seed_and_refine,
    )
    print(f"  survivors: {count}")

    # Worst case seeding: force a common byte pair as the seed (48 89).
    print()
    print("=== forced common seed (48 89) ===")
    ckey = (0x48 << 8) | 0x89
    craw = positions[heads[ckey] : heads[ckey + 1]]
    print(f"  bucket={len(craw)}")
    ex_pattern = (
        "48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? "
        "48 85 C0 74 ?? 48 8B 08 48 8B 01 FF 50 18 48 8B 5C 24 30"
    )
    eparsed = parse_pattern(ex_pattern)
    evals = eparsed.values
    emasks = eparsed.masks
    verify = getattr(engine, "verify_offsets", None)

    def chain2():
        cands, n = engine.seed_offsets(craw, 0, len(evals), len(data))
        for j in range(len(evals)):
            if j in (0, 1) or not emasks[j]:
                continue
            n = engine.refine_offsets(data, cands, n, j, evals[j], 0xFF)
        return n

    n2, t_chain2 = timed(
        f"seed + {sum(1 for i, m in enumerate(emasks) if m and i not in (0, 1))} refines",
        chain2,
    )
    print(f"  survivors: {n2}")
    if verify is not None:
        def fused():
            cands, n = engine.seed_offsets(craw, 0, len(evals), len(data))
            return verify(data, cands, n, evals, emasks, 0)

        n3, t_fused = timed("seed + fused verify", fused)
        print(f"  survivors: {n3}")
        print(f"  speedup: {t_chain2 / max(t_fused, 1e-9):.1f}x")
    else:
        print("  (verify_offsets not available)")

    print()
    print("summary:")
    print(f"  find_all whole buffer: {t_find_all * 1e3:.1f} ms "
          f"(was {t_find_all_old * 1e3:.1f} ms)")
    print(f"  uniqueness probe:      {t_findalllong * 1e3:.1f} ms "
          f"(was {(t_countlong + t_findalllong_old) * 1e3:.1f} ms)")


if __name__ == "__main__":
    main()
