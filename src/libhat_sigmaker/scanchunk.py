"""Chunk boundaries for the interruptible native scan.

The native (SIMD) scan reports only matches that fit entirely inside the
buffer it is handed, so a scan that is split into chunks has to overlap
consecutive chunks by one pattern length. Without that overlap a match that
straddles a chunk boundary would be missed. Aligning later chunk starts to the
original range's grid can widen the overlap, so each chunk also reports the
first offset it owns (``claim_start``) and the caller discards the duplicates.
"""

from __future__ import annotations

import typing

__all__ = ["chunk_ranges"]


def chunk_ranges(
    start: int,
    end: int,
    pattern_size: int,
    chunk_size: int,
    alignment: int = 1,
) -> typing.Iterator[tuple[int, int, int]]:
    """Yield ``(scan_start, chunk_end, claim_start)`` triples.

    ``scan_start`` may be before the previous chunk's end so that a match
    spanning the boundary is still found. When ``alignment`` is greater than
    one, the scan start is rounded down to a position congruent with ``start``
    modulo ``alignment``. libhat applies the alignment relative to the start of
    the buffer it is given, so without this rounding the second and later
    chunks would scan a differently-aligned subset of addresses.

    Rounding down can widen the overlap beyond ``pattern_size - 1``. A match
    therefore belongs to this chunk only when
    ``claim_start <= match < match + pattern_size <= chunk_end``; anything
    before ``claim_start`` was already fully inside the previous chunk.
    """

    if end <= start or pattern_size <= 0:
        return
    alignment = max(1, int(alignment))
    step = max(chunk_size, pattern_size)
    position = start
    while position < end:
        if position == start:
            scan_start = start
        else:
            scan_start = max(start, position - (pattern_size - 1))
            # Keep every chunk on the same grid as the original range. This is
            # what makes x4/x16 chunked scans equivalent to one big scan.
            scan_start -= (scan_start - start) % alignment
        chunk_end = min(position + step, end)
        if position == start:
            claim_start = start
        else:
            # Every start below this value fits entirely in the previous
            # chunk, so it was already reported there.
            claim_start = position - (pattern_size - 1)
        yield scan_start, chunk_end, claim_start
        position = chunk_end
