"""Differential correctness tests for the optimized scan path.

These tests answer one question: can the fast path ever disagree with a
brute-force matcher (or with the pre-optimization code) about which offsets
match a pattern? Generation decides "unique" from exactly this set, so a
disagreement here would be a wrong signature.

Covered:

* ``libhat_scan_verify_offsets`` against a naive masked matcher, with every
  possible candidate start, random ``start_index`` values, arbitrary byte
  masks, and patterns longer than the 256-byte inline word budget.
* The verify + search-range-filter composition used by
  ``_refine_candidate_offsets`` against brute force.
* Single-pass ``find_all`` against the old count+scan path and against brute
  force, across the ``limit`` / ``max_matches`` matrix (offset list and
  truncation flag).
* Incremental growth (seed once, verify one byte at a time with
  ``start_index``) against brute force at every prefix length, which is the
  exact sequence generation uses to decide uniqueness.
"""

import array
import ast
import random
import sys
import unittest
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bootstrap  # noqa: F401

native = sys.modules["libhat_sigmaker.libhat_native"]
backend = sys.modules["libhat_sigmaker.libhat_backend"]


def naive_matches(data, values, masks, start_index=0):
    """Every start where bytes [start_index, len) match, honoring masks."""
    size = len(data)
    pattern_size = len(values)
    hits = []
    for start in range(size - pattern_size + 1):
        for index in range(start_index, pattern_size):
            if (data[start + index] & masks[index]) != (values[index] & masks[index]):
                break
        else:
            hits.append(start)
    return hits


def random_pattern(rng, length):
    masks = bytes(
        rng.choice([0x00, 0xFF, 0xF0, 0x0F, rng.randrange(256)])
        for _ in range(length)
    )
    values = bytes(rng.randrange(256) & mask for mask in masks)
    return values, masks


class VerifyOffsetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = native.get_engine()
        if not cls.engine.supports_verify_offsets:
            raise unittest.SkipTest("libhat_scan lacks verify_offsets")

    def test_every_candidate_matches_bruteforce(self):
        rng = random.Random(0xA11CE)
        for _ in range(140):
            size = rng.randrange(0, 600)
            data = bytes(rng.randrange(256) for _ in range(size))
            length = rng.choice(
                [rng.randrange(1, 50), rng.randrange(250, 330)]
            )
            values, masks = random_pattern(rng, length)
            start_index = rng.randrange(0, length + 1)

            candidates = array.array("Q", range(size + 2))  # includes OOB starts
            expected = naive_matches(data, values, masks, start_index)
            count = self.engine.verify_offsets(
                data, candidates, len(candidates), values, masks, start_index
            )
            self.assertEqual(
                list(candidates[:count]),
                expected,
                (size, length, start_index, masks.hex()),
            )

    def test_verify_then_filter_matches_bruteforce(self):
        rng = random.Random(0xF17E)
        for _ in range(120):
            size = rng.randrange(0, 700)
            data = bytes(rng.randrange(256) for _ in range(size))
            length = rng.randrange(1, 40)
            values, masks = random_pattern(rng, length)
            start_index = rng.randrange(0, length + 1)

            if size >= 2 and rng.random() < 0.6:
                split = rng.randrange(1, size)
                gap = rng.randrange(0, 5)
                ranges = [(0, split), (min(size, split + gap), size)]
                ranges = [(s, e) for s, e in ranges if s < e]
            else:
                ranges = [(0, size)]

            # Gapped multi-segment buffers are the interesting case: the
            # filter must find the right range for every candidate even when
            # the candidate array is not sorted.
            candidates = list(range(size))
            rng.shuffle(candidates)
            expected = [
                start
                for start in candidates
                if any(
                    begin <= start and start + length <= end
                    for begin, end in ranges
                )
                and all(
                    (data[start + index] & masks[index])
                    == (values[index] & masks[index])
                    for index in range(start_index, length)
                )
            ]

            candidates = array.array("Q", candidates)

            count = self.engine.verify_offsets(
                data, candidates, len(candidates), values, masks, start_index
            )
            starts = array.array("Q", (s for s, _e in ranges))
            ends = array.array("Q", (e for _s, e in ranges))
            if ranges:
                count = self.engine.filter_offsets(
                    candidates, count, length, starts, ends
                )
            else:
                count = 0
            self.assertEqual(
                list(candidates[:count]),
                expected,
                (size, length, start_index, ranges),
            )


class FindAllEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = native.get_engine()

    def _both_paths(self, sig, data, **kwargs):
        new = self.engine.find_all(sig, data, **kwargs)
        saved = self.engine._find_all_alloc
        self.engine._find_all_alloc = None
        try:
            old = self.engine.find_all(sig, data, **kwargs)
        finally:
            self.engine._find_all_alloc = saved
        return new, old

    def test_limits_and_truncation_match_old_path_and_bruteforce(self):
        rng = random.Random(0xBEEF)
        cases = [(0, 0), (2, 0), (0, 3), (5, 3), (3, 3), (1, 0), (4, 4)]
        for _ in range(60):
            size = rng.randrange(0, 160)
            data = bytes(rng.randrange(256) for _ in range(size))
            length = rng.randrange(1, 5)
            values, masks = random_pattern(rng, length)
            expected = naive_matches(data, values, masks)
            sig = self.engine.create_signature_from_bytes(values, masks)
            try:
                for limit, max_matches in cases:
                    (new_offsets, new_truncated), (old_offsets, old_truncated) = (
                        self._both_paths(
                            sig,
                            data,
                            limit=limit,
                            max_matches=max_matches,
                        )
                    )
                    visible = expected if limit == 0 else expected[:limit]
                    want = visible[:max_matches] if max_matches else visible
                    want_truncated = bool(max_matches) and len(visible) > max_matches

                    self.assertEqual(
                        list(new_offsets),
                        list(old_offsets),
                        (size, length, limit, max_matches),
                    )
                    self.assertEqual(new_truncated, old_truncated)
                    self.assertEqual(list(new_offsets), want)
                    self.assertEqual(new_truncated, want_truncated)
            finally:
                sig.close()


class GrowthPipelineTests(unittest.TestCase):
    """Replays the seed-then-verify sequence used while growing a signature."""

    @classmethod
    def setUpClass(cls):
        cls.engine = native.get_engine()
        if not cls.engine.supports_verify_offsets:
            raise unittest.SkipTest("libhat_scan lacks verify_offsets")

    def test_incremental_growth_matches_bruteforce(self):
        rng = random.Random(0x6E0)
        for _ in range(30):
            size = 2048
            data = bytearray(rng.randrange(256) for _ in range(size))
            # Plant repeated blocks so prefixes are non-unique and the
            # candidate set actually has to be pruned.
            source = rng.randrange(0, size - 64)
            block = bytes(data[source : source + 40])
            for _copy in range(2):
                target = rng.randrange(0, size - 40)
                data[target : target + 40] = block
            data = bytes(data)

            length = rng.randrange(8, 24)
            masks = bytearray(b"\xFF" * length)
            for index in rng.sample(range(length), k=2):
                masks[index] = 0
            masks = bytes(masks)
            values = bytes(data[source + i] & masks[i] for i in range(length))

            # Seed a 4-byte prefix through the byte index, exactly like
            # _seed_via_index: exact pair bucket -> candidate starts -> verify.
            prefix = 4
            seed_index = next(
                i for i in range(prefix - 1) if masks[i] and masks[i + 1]
            )
            heads, positions = backend.build_byte_index(data)
            key = (values[seed_index] << 8) | values[seed_index + 1]
            raw = positions[heads[key] : heads[key + 1]]
            candidates, count = backend.seed_offsets(
                raw, seed_index, prefix, size
            )
            self.assertGreater(count, 0)
            count = backend.verify_offsets(
                data, candidates, count, values[:prefix], masks[:prefix], 0
            )
            self.assertEqual(list(candidates[:count]), naive_matches(
                data, values[:prefix], masks[:prefix]
            ))

            # Grow one byte at a time; start_index is the previous length,
            # matching _refine_candidate_offsets.
            for prefix in range(5, length + 1):
                count = backend.verify_offsets(
                    data,
                    candidates,
                    count,
                    values[:prefix],
                    masks[:prefix],
                    prefix - 1,
                )
                expected = naive_matches(data, values[:prefix], masks[:prefix])
                self.assertEqual(
                    list(candidates[:count]),
                    expected,
                    (length, prefix, masks[:prefix].hex()),
                )


class SignatureEncodingTests(unittest.TestCase):
    """The fused kernel indexes values/masks by absolute pattern position."""

    @staticmethod
    def _load_helper():
        # Extract the shipped helper without importing the plugin, which needs
        # IDA at import time.
        source = Path(__file__).resolve().parents[1] / "src" / "libhat_sigmaker"
        tree = ast.parse((source / "__init__.py").read_text(encoding="utf-8"))
        node = next(
            item
            for item in tree.body
            if isinstance(item, ast.FunctionDef)
            and item.name == "_signature_value_mask_bytes"
        )
        module = ast.Module(body=[node], type_ignores=[])
        namespace = {"Signature": list}
        exec(compile(module, str(source), "exec"), namespace)
        return namespace["_signature_value_mask_bytes"]

    def test_wildcards_become_zero_value_zero_mask(self):
        SignatureByte = namedtuple("SignatureByte", "value is_wildcard")
        helper = self._load_helper()
        signature = [
            SignatureByte(0x48, False),
            SignatureByte(0xCC, True),  # wildcard value must be discarded
            SignatureByte(0x8B, False),
            SignatureByte(0x00, True),
        ]
        values, masks = helper(signature)
        self.assertEqual(values, b"\x48\x00\x8b\x00")
        self.assertEqual(masks, b"\xff\x00\xff\x00")


class FilterOffsetTests(unittest.TestCase):
    """Range filtering must not depend on candidate order.

    One-byte seed buckets are grouped by the second byte, so a filtered
    candidate array is not globally sorted. A monotonic range cursor used to
    drop valid hits in gapped (multi-segment) buffers, which could make a
    non-unique pattern look unique.
    """

    @classmethod
    def setUpClass(cls):
        cls.engine = native.get_engine()

    def test_unsorted_candidates_keep_every_in_range_hit(self):
        candidates = array.array("Q", [250, 50, 220, 10, 299, 297])
        count = self.engine.filter_offsets(
            candidates, len(candidates), 4, [0, 200], [100, 300]
        )
        self.assertEqual(list(candidates[:count]), [250, 50, 220, 10])

    def test_shuffled_candidates_match_bruteforce(self):
        rng = random.Random(0xF11)
        for _ in range(80):
            size = rng.randrange(20, 400)
            pattern_size = rng.randrange(1, 8)
            ranges = []
            cursor = 0
            for _range in range(rng.randrange(1, 4)):
                length = rng.randrange(1, size // 2)
                ranges.append((cursor, min(size, cursor + length)))
                cursor = ranges[-1][1] + rng.randrange(0, 10)
                if cursor >= size:
                    break
            candidates = list(range(size))
            rng.shuffle(candidates)
            expected = [
                start
                for start in candidates
                if any(
                    begin <= start and start + pattern_size <= end
                    for begin, end in ranges
                )
            ]
            array_candidates = array.array("Q", candidates)
            count = self.engine.filter_offsets(
                array_candidates,
                len(array_candidates),
                pattern_size,
                [begin for begin, _end in ranges],
                [end for _begin, end in ranges],
            )
            self.assertEqual(list(array_candidates[:count]), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
