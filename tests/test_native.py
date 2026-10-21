import array
import ctypes
import random
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401

native = sys.modules["libhat_sigmaker.libhat_native"]
backend = sys.modules["libhat_sigmaker.libhat_backend"]


def naive_find_all(data: bytes, values: bytes, masks: bytes, alignment: int = 1):
    hits = []
    size = len(data)
    pattern_size = len(values)
    for start in range(0, max(0, size - pattern_size + 1), alignment):
        for index, (value, mask) in enumerate(zip(values, masks)):
            if (data[start + index] & mask) != (value & mask):
                break
        else:
            hits.append(start)
    return hits


class NativeScanTests(unittest.TestCase):
    def setUp(self):
        self.engine = native.get_engine()

    def signature(self, pattern):
        parsed = native.parse_pattern(pattern)
        return self.engine.create_signature_from_bytes(
            parsed.values, parsed.masks, pattern=parsed.canonical
        )

    def scan(self, pattern, data, alignment=1, hints=0, limit=0):
        parsed = native.parse_pattern(pattern)
        sig = self.engine.create_signature_from_bytes(
            parsed.values, parsed.masks, pattern=parsed.canonical
        )
        try:
            offsets, truncated = self.engine.find_all(
                sig, data, alignment=alignment, hints=hints, limit=limit
            )
            first = self.engine.find_first(
                sig, data, alignment=alignment, hints=hints
            )
            count = self.engine.count(
                sig, data, alignment=alignment, hints=hints, limit=limit
            )
        finally:
            sig.close()
        return offsets, truncated, first, count, parsed

    def test_exact_and_wildcards(self):
        data = b"\x90" * 7 + bytes.fromhex("488B050000000090") + b"\x90" * 5
        offsets, truncated, first, count, parsed = self.scan(
            "48 8B 05 ?? ?? ?? ??", data
        )
        self.assertEqual(list(offsets), [7])
        self.assertFalse(truncated)
        self.assertEqual(first, 7)
        self.assertEqual(count, 1)
        self.assertEqual(parsed.canonical, "48 8B 05 ?? ?? ?? ??")

    def test_nibble_wildcards(self):
        # 4? ?2 matches the byte pair (0x4X, 0xX2): 0x41 0x42 at offset 1.
        data = bytes.fromhex("40414243444546474849")
        offsets, _, _, _, _ = self.scan("4? ?2", data)
        self.assertEqual(list(offsets), [1])

        data = bytes.fromhex("404142904952")
        offsets, _, _, _, _ = self.scan("4? ?2", data)
        self.assertEqual(list(offsets), [1, 4])

    def test_binary_masks(self):
        data = bytes.fromhex("A0B09090A2B2")
        offsets, _, _, _, parsed = self.scan("1010???? 1011????", data)
        self.assertEqual(list(offsets), [0, 4])
        self.assertEqual(parsed.canonical, "A? B?")

    def test_alignment(self):
        data = bytes.fromhex("90909090DEADBEEF90909090DEADBEEF")
        offsets, _, _, _, _ = self.scan("DE AD BE EF", data, alignment=1)
        self.assertEqual(list(offsets), [4, 12])
        offsets, _, _, _, _ = self.scan("DE AD BE EF", data, alignment=4)
        self.assertEqual(list(offsets), [4, 12])
        offsets, _, _, _, _ = self.scan("DE AD BE EF", data, alignment=16)
        self.assertEqual(list(offsets), [])

    def test_limit(self):
        data = b"ABCD" * 1000
        offsets, truncated, _, count, _ = self.scan("41 42 43 44", data, limit=2)
        self.assertEqual(list(offsets), [0, 4])
        self.assertEqual(count, 2)
        self.assertFalse(truncated)

    def test_truncation_flag_is_reported(self):
        data = b"\x90" * 10
        sig = self.signature("90")
        try:
            offsets, truncated = self.engine.find_all(sig, data, max_matches=3)
        finally:
            sig.close()
        self.assertEqual(len(offsets), 3)
        self.assertTrue(truncated)

    def test_randomized_against_naive(self):
        rng = random.Random(0xC0FFEE)
        for _ in range(200):
            size = rng.randrange(0, 400)
            data = bytes(rng.randrange(256) for _ in range(size))
            length = rng.randrange(1, 9)
            values = bytearray(rng.randrange(256) for _ in range(length))
            masks = bytearray()
            for _ in range(length):
                choices = [0, 0x0F, 0xF0, 0xFF, rng.randrange(256)]
                masks.append(rng.choice(choices))
            values = bytes(v & m for v, m in zip(values, masks))
            pattern = " ".join(
                "??" if m == 0 else (f"{v:02X}" if m == 0xFF else format_token(v, m))
                for v, m in zip(values, masks)
            )
            alignment = rng.choice([1, 1, 1, 4, 16])
            expected = naive_find_all(data, values, masks, alignment)
            try:
                offsets, _, first, count, _ = self.scan(
                    pattern, data, alignment=alignment
                )
            except ValueError:
                # Ambiguous tokens such as an all-hex 8-character string are
                # interpreted as compact hex by the user-facing parser; skip.
                continue
            self.assertEqual(list(offsets), expected, (pattern, data.hex(), alignment))
            self.assertEqual(first, expected[0] if expected else None)
            self.assertEqual(count, len(expected))

    def test_byte_index_and_refine(self):
        data = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        heads, positions = self.engine.build_byte_index(data)
        self.assertEqual(len(heads), 65537)
        key = (data[4] << 8) | data[5]
        self.assertEqual(heads[key + 1] - heads[key], 1)
        self.assertEqual(positions[heads[key]], 4)

        raw = positions[heads[key] : heads[key + 1]]
        candidates, count = self.engine.seed_offsets(raw, 4, 3, len(data))
        self.assertEqual(candidates.typecode, "Q")
        self.assertEqual(count, 1)
        self.assertEqual(candidates[0], 0)
        count = self.engine.refine_offsets(data, candidates, count, 0, 0x00, 0xFF)
        self.assertEqual(count, 1)
        count = self.engine.refine_offsets(data, candidates, count, 0, 0xFF, 0xFF)
        self.assertEqual(count, 0)

    def test_q_candidates_refine_every_match(self):
        # Regression for the Q->uint32 view bug: the only match after the
        # appended byte sits in the second half of the seed list. With the old
        # bridge, refine only examined the first half and returned count 1.
        hits = [93, 154, 182, 265, 287, 330, 451, 559]
        data = bytearray(b"\x90" * 600)
        for position in hits:
            data[position] = 0
            data[position + 1] = 2
        for position in (93, 287):
            data[position + 2] = 3

        candidates = array.array("Q", hits)
        count = self.engine.refine_offsets(
            memoryview(data), candidates, len(candidates), 2, 3, 0xFF
        )
        self.assertEqual(count, 2)
        self.assertEqual(list(candidates[:count]), [93, 287])

    def test_verify_offsets_matches_naive(self):
        rng = random.Random(0x5EED)
        for _ in range(150):
            size = rng.randrange(0, 512)
            data = bytes(rng.randrange(256) for _ in range(size))
            # Occasionally exceed the 256-byte inline word budget so the tail
            # loop is exercised too.
            length = rng.choice([rng.randrange(1, 40), rng.randrange(250, 320)])
            masks = bytes(
                rng.choice([0x00, 0xFF, 0xF0, 0x0F, rng.randrange(256)])
                for _ in range(length)
            )
            values = bytes(rng.randrange(256) & mask for mask in masks)
            starts = list(range(max(0, size - length + 1)))
            rng.shuffle(starts)
            starts = starts[: rng.randrange(0, len(starts) + 1)]
            starts += [size, size + 3]
            candidates = array.array("Q", starts)
            expected = [
                start
                for start in starts
                if start + length <= size
                and all(
                    (data[start + index] & masks[index])
                    == (values[index] & masks[index])
                    for index in range(length)
                )
            ]
            count = self.engine.verify_offsets(
                data, candidates, len(candidates), values, masks
            )
            self.assertEqual(list(candidates[:count]), expected)

    def test_verify_offsets_start_index(self):
        data = bytes.fromhex("00112233445566778899")
        candidates = array.array("Q", [0, 2, 4])
        values = bytes.fromhex("0011223344556677")
        masks = b"\xFF" * 8
        count = self.engine.verify_offsets(
            data, candidates, len(candidates), values, masks, 2
        )
        # Only bytes 2..7 are compared, so start 0 matches while 2 and 4 do not.
        self.assertEqual(list(candidates[:count]), [0])

    def test_verify_offsets_zero_masks_match_anywhere(self):
        data = b"\x01\x02\x03\x04"
        candidates = array.array("Q", [0, 1])
        values = b"\x00\x00"
        masks = b"\x00\x00"
        count = self.engine.verify_offsets(
            data, candidates, len(candidates), values, masks
        )
        self.assertEqual(list(candidates[:count]), [0, 1])

    def test_single_pass_find_all_limits(self):
        data = b"\x90" * 100
        sig = self.signature("90")
        try:
            offsets, truncated = self.engine.find_all(sig, data, limit=2)
            self.assertEqual(len(offsets), 2)
            self.assertFalse(truncated)

            offsets, truncated = self.engine.find_all(
                sig, data, limit=5, max_matches=3
            )
            self.assertEqual(len(offsets), 3)
            self.assertTrue(truncated)

            offsets, truncated = self.engine.find_all(sig, data, max_matches=100)
            self.assertEqual(len(offsets), 100)
            self.assertFalse(truncated)

            offsets, truncated = self.engine.find_all(sig, data, max_matches=99)
            self.assertEqual(len(offsets), 99)
            self.assertTrue(truncated)
        finally:
            sig.close()

    def test_backend_hides_verify_offsets_without_native_support(self):
        with mock.patch.dict(backend.__dict__):
            backend.__dict__.pop("verify_offsets", None)
            with mock.patch.object(native, "engine", return_value=None):
                self.assertIsNone(getattr(backend, "verify_offsets", None))
            # A supporting engine publishes the callable and caches it.
            self.assertIs(
                getattr(backend, "verify_offsets", None),
                backend._verify_offsets_impl,
            )

    def test_filter_ranges(self):
        candidates = array.array("Q", [0, 4, 8, 12, 16])
        count = self.engine.filter_offsets(
            candidates, len(candidates), 4, [4, 12], [8, 16]
        )
        self.assertEqual(count, 2)
        self.assertEqual(list(candidates[:count]), [4, 12])

    def test_parse_signature_reports_size(self):
        data = b"\x90" * 3 + bytes.fromhex("488B0500000000") + b"\x90"
        sig = self.engine.parse_signature("48 8B 05 ?? ?? ?? ??")
        try:
            self.assertEqual(sig.size_bytes, 7)
            self.assertEqual(self.engine.find_first(sig, data), 3)
            offsets, _truncated = self.engine.find_all(sig, data)
            self.assertEqual(list(offsets), [3])
        finally:
            sig.close()

    def test_byte_index_rejects_oversized_buffer(self):
        fake_buffer = (ctypes.c_void_p(), 0x1_0000_0001, None)
        with mock.patch.object(
            native.LibhatEngine,
            "_buffer",
            staticmethod(lambda _data: fake_buffer),
        ):
            with self.assertRaises(ValueError):
                self.engine.build_byte_index(b"")

    def test_backend_raises_when_scan_is_truncated(self):
        class TruncatedEngine:
            def find_all(self, *_args, **_kwargs):
                return array.array("Q", [1]), True

        sig = types.SimpleNamespace(size_bytes=1)
        with mock.patch.object(
            backend, "_engine_or_raise", return_value=TruncatedEngine()
        ):
            with self.assertRaises(backend.LibhatScanTruncated):
                backend.find_all(b"\x90", sig)

    def test_backend_reports_missing_engine(self):
        with mock.patch.object(
            native,
            "get_engine",
            side_effect=native.LibhatNativeError("missing"),
        ):
            self.assertFalse(backend.available())


def format_token(value: int, mask: int) -> str:
    return "".join(
        "?" if not (mask & (1 << (7 - i))) else ("1" if value & (1 << (7 - i)) else "0")
        for i in range(8)
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
