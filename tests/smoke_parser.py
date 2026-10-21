import importlib.util
import sys
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "src" / "libhat_sigmaker" / "libhat_native.py"
spec = importlib.util.spec_from_file_location("libhat_native", path)
module = importlib.util.module_from_spec(spec)
sys.modules["libhat_native"] = module
spec.loader.exec_module(module)

cases = [
    "48 8B 05 ? ? ? ?",
    "48 8B 05 ?? ?? ?? ??",
    "48 8B 4? ?F",
    "488B05??4??F",
    "0x48 0x8B 0x05 0x00",
    r"\x48\x8B\x05\x00",
    r"\x48\x8B\x00\x00 x?xx",
    "0x48, 0x8B, 0x00, 0x00 0b1011",
    '"48 8B ? ?"_sig',
    'inline constexpr auto sig = "48 8B ? ?"_sig;',
    'hat::compile_signature<"48 8B ? ?">()',
    'hat::parse_signature("48 8B ? ?")',
    "11110000 1111???? 10101010",
    "0b11110000",
    "?",
    "??",
    "4?",
    "?F",
]

for case in cases:
    try:
        parsed = module.parse_pattern(case)
        print(f"{case!r:65} -> {parsed.canonical:35} masks={parsed.masks.hex()} values={parsed.values.hex()}")
    except Exception as exc:
        print(f"{case!r:65} -> ERROR {exc}")
