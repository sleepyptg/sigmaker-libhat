# SigMaker (libhat)

An IDA Pro 9+ plugin for generating and searching binary signatures. It keeps
ida-sigmaker's generation algorithm and output formats, but replaces the
optional Cython scan backend with **libhat**'s SIMD scanner, and adds libhat
scan hints, alignment, and extended signature syntax.

## Features

- **Signature generation**: shortest unique signature for an address, function,
  xref set, or selected code range, with operand wildcarding.
- **libhat SIMD search engine**: fast `count`/`find_all`/`find_first` over
  segment or file buffers, with scan alignment (x1/x4/x16) and hints
  (auto/x86_64/AArch64/PAIR0).
- **Extended syntax**: IDA, x64dbg, C byte arrays + masks (x/? and 0b),
  nibble wildcards, 8-bit binary tokens, and libhat C++ wrappers
  (`"..."_sig`, `hat::compile_signature<"...">()`,
  `hat::parse_signature("...")`).
- **Output formats**: IDA, x64dbg, C byte array + mask, C bytes + bitmask,
  libhat pattern, and libhat C++ `compile_signature` codegen.
- **Compact dialog**: the main window is split into *Action* / *Output* /
  *Scan* / *Options* tabs, so it stays small enough for a small IDA window
  (450x389 px instead of 450x894 px).
- **Fast, cancellable searches**: the database is copied into memory once and
  reused while it does not change, so only the first operation pays for the
  copy. Copying and scanning run in chunks, so IDA stays responsive and the
  wait box's Cancel button works while a large binary is processed.
- Pure Python plugin (IDA 9+). The native part is a small `libhat_scan.dll`
  loaded through `ctypes`; no IDA SDK compilation required.

## Performance

The fork reworks how the plugin drives libhat's scanner. Numbers below come
from a 64 MiB buffer of concatenated Windows system binaries (`ntdll.dll`,
`shell32.dll`, `ntoskrnl.exe`, ...), best of three runs, on an AVX2-only
i7-13620H:

| Operation | Before | After | Gain |
| --- | ---: | ---: | ---: |
| `find_all` over the whole buffer | 6.7 ms | 3.2 ms | 2.1x |
| Uniqueness probe (`limit=2`, 64-byte exact pattern) | 9.9 ms | 3.2 ms | 3.1x |
| Seed + 30-byte refine, 627,960-candidate seed | 6.2 ms | 4.7 ms | 1.3x |
| `build_byte_index` (64 MiB) | 223 ms | 223 ms | - |

What changed:

- **Single-pass `find_all`.** The old path called `count()` to size the result
  buffer and then scanned the whole buffer again with `find_all()`.
  `libhat_scan_find_all_alloc` now grows its own result buffer during one scan
  and reports truncation exactly by collecting one extra match. Uniqueness
  checks (`limit=2`) gain the most, because they used to pay for two full
  scans just to learn "at least two matches".
- **Fused masked verification.** Growing a signature used to call
  `refine_offsets` once per pattern byte, so every candidate was re-read from a
  different cache line for each byte. `libhat_scan_verify_offsets` compares
  8-byte masked words in one native call per pattern growth, bailing on the
  first mismatching word and falling back to byte compares only for the tail.
- **Cheaper index build.** The byte-index builder keeps its 65537-entry cursor
  table in thread-local storage, so it no longer zero-fills it on every call.
- **Correct range filtering.** One-byte seed buckets are grouped by the second
  byte, so their candidate offsets are not sorted. The range filter used to
  walk a monotonic cursor (and stop early) over that array, which could drop
  real matches in gapped multi-segment buffers and make a non-unique pattern
  look unique. It now matches each candidate against its range directly, with a
  single-range fast path for whole-buffer searches.

The libhat scan kernel itself is unchanged; these are all wins in how the
plugin drives it. The new entry points are optional: `libhat_native` probes
for them with `getattr`, so an older `libhat_scan.dll` keeps working through
the two-pass fallback.

## Install (manual)

0. Clone the repository:

   ```powershell
   git clone https://github.com/sleepyptg/sigmaker-libhat.git
   cd sigmaker-libhat
   ```

1. Build the native bridge (or use the prebuilt DLL in `src/libhat_sigmaker/`):

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\build_native.ps1
   ```

2. Copy the `src/libhat_sigmaker` package into IDA's Python site-packages, e.g.:

   ```powershell
   Copy-Item -Recurse src\libhat_sigmaker "$env:APPDATA\Hex-Rays\IDA Pro\venv\Lib\site-packages\"
   ```

3. Create a wrapper named `libhat_sigmaker_plugin.py` in your IDA user
   `plugins` directory. The repository does not ship this file; its content
   depends on how the package is installed.

   If you followed step 2 and the package is importable:

   ```python
   import libhat_sigmaker

   def PLUGIN_ENTRY():
       return libhat_sigmaker.PLUGIN_ENTRY()
   ```

   For a source checkout, add its `src` directory to `sys.path` first:

   ```python
   import os, sys
   _src = r"C:\path\to\sigmaker-libhat\src"
   if os.path.isdir(_src) and _src not in sys.path:
       sys.path.insert(0, _src)
   import libhat_sigmaker

   def PLUGIN_ENTRY():
       return libhat_sigmaker.PLUGIN_ENTRY()
   ```

   The `ida-plugin.json` `entryPoint` (`src/libhat_sigmaker/__init__.py`) is
   used by IDA's plugin tooling; the manual wrapper above is what IDA loads
   when the package is installed by hand.

4. Restart IDA. The plugin appears as **Signature Maker (libhat)** (hotkey
   `Ctrl-Alt-L`).

## Development

- Unit tests: `python -m unittest discover -s tests -p "test_*.py" -v`
- Parser smoke: `python tests/smoke_parser.py`
- Native DLL smoke: `python tests/smoke_native.py`
- Scan benchmark: `python benchmarks/bench_scan.py 64`
- Native build: `scripts/build_native.ps1`

## Credits

- Signature generation core forked from
  [ida-sigmaker](https://github.com/mahmoudimus/ida-sigmaker) (MIT) by
  Mahmoud Abdelkader.
- SIMD scanner from [libhat](https://github.com/BasedInc/libhat) (MIT) by
  Brady Hahn.
- libhat integration, native bridge, and scan-path optimizations maintained at
  [sleepyptg/sigmaker-libhat](https://github.com/sleepyptg/sigmaker-libhat).

## License

MIT. See `LICENSE`, `LICENSE-ida-sigmaker`, and `LICENSE-libhat`.
