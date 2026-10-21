import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "libhat_sigmaker"

package = types.ModuleType("libhat_sigmaker")
package.__path__ = [str(SOURCE)]
sys.modules.setdefault("libhat_sigmaker", package)

spec = importlib.util.spec_from_file_location(
    "libhat_sigmaker.scanchunk", SOURCE / "scanchunk.py"
)
scanchunk = importlib.util.module_from_spec(spec)
sys.modules["libhat_sigmaker.scanchunk"] = scanchunk
spec.loader.exec_module(scanchunk)


class ChunkRangesTests(unittest.TestCase):
    def test_single_chunk_when_range_is_small(self):
        self.assertEqual(
            list(scanchunk.chunk_ranges(0, 100, 4, 1000)),
            [(0, 100, 0)],
        )

    def test_chunks_cover_the_whole_range(self):
        chunks = list(scanchunk.chunk_ranges(0, 1000, 4, 100))
        self.assertEqual(chunks[0][0], 0)
        self.assertEqual(chunks[-1][1], 1000)
        for (_, prev_end, _), (next_start, _, _) in zip(chunks, chunks[1:]):
            self.assertLessEqual(next_start, prev_end)

    def test_chunks_overlap_by_one_pattern_length(self):
        chunks = list(scanchunk.chunk_ranges(0, 1000, 8, 100))
        (_, prev_end, _), (next_start, _, next_claim) = chunks[0], chunks[1]
        self.assertEqual(next_start, prev_end - 7)
        self.assertEqual(next_claim, prev_end - 7)

    def test_chunk_size_never_shrinks_below_the_pattern(self):
        chunks = list(scanchunk.chunk_ranges(0, 100, 64, 8))
        for _, chunk_end, _ in chunks:
            self.assertGreater(chunk_end, 0)
        self.assertEqual(chunks[-1][1], 100)

    def test_empty_range_yields_nothing(self):
        self.assertEqual(list(scanchunk.chunk_ranges(10, 10, 4, 100)), [])

    def test_a_match_spanning_a_boundary_is_claimed_exactly_once(self):
        # Every match of a 4-byte pattern must belong to exactly one chunk.
        # The claim_start field is what lets the caller suppress the wider
        # overlap that alignment rounding can introduce.
        start, end, pattern_size = 0, 500, 4
        chunks = list(scanchunk.chunk_ranges(start, end, pattern_size, 64))
        for match in range(start, end - pattern_size + 1):
            owners = [
                (scan_start, chunk_end)
                for scan_start, chunk_end, claim_start in chunks
                if claim_start <= match and match + pattern_size <= chunk_end
            ]
            self.assertEqual(len(owners), 1, f"match at {match}: {owners}")

    def test_alignment_keeps_scan_starts_on_the_global_grid(self):
        start, end, pattern_size = 0, 1000, 4
        chunks = list(
            scanchunk.chunk_ranges(start, end, pattern_size, 100, alignment=4)
        )
        for scan_start, _, _ in chunks:
            self.assertEqual((scan_start - start) % 4, 0)
        # Coverage is unchanged even though later chunks start earlier.
        for match in range(start, end - pattern_size + 1):
            owners = [
                (scan_start, chunk_end)
                for scan_start, chunk_end, claim_start in chunks
                if claim_start <= match and match + pattern_size <= chunk_end
            ]
            self.assertEqual(len(owners), 1, f"match at {match}: {owners}")

    def test_alignment_with_nonzero_range_start(self):
        start, end, pattern_size = 7, 1007, 4
        chunks = list(
            scanchunk.chunk_ranges(start, end, pattern_size, 100, alignment=16)
        )
        for scan_start, _, _ in chunks:
            self.assertEqual((scan_start - start) % 16, 0)


if __name__ == "__main__":
    unittest.main()
