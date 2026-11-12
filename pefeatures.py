"""Bounded interval feature extraction from PE section and overlay data.

This module builds on top of :mod:`pefile` to compute byte-level statistics
(Shannon entropy and zero-byte ratio) for the on-disk ranges described by a
PE's section table and for its overlay (data appended past every described
region), together with section permission flags and declared raw/virtual
size relations. Every statistic keeps the file range it was computed from.

The interface is meant for automated sample-analysis pipelines that feed
these numbers into their own heuristics. The values are reverse-engineering
clues only: this module deliberately does **not** label a file as "packed"
or "malicious".

Resource bounds against hostile declarations
--------------------------------------------

* Declared ``VirtualAddress``/``Misc_VirtualSize`` values are reported but
  never used to size allocations or reads; memory and I/O do not scale with
  them, only with bytes physically present in the file.
* Declared raw ranges are clamped to the actual file size. Truncated
  sections are analysed over the bytes physically present; missing bytes
  are *not* zero-padded up to the declared length before statistics are
  computed.
* Overlapping sections are decomposed into disjoint segments. Each unique
  physical byte range is read and histogrammed exactly once, so I/O and
  per-byte work grow with the number of unique physical bytes, not with the
  number of sections claiming them. Per-section statistics are reassembled
  from segment histograms (histograms are additive, so the per-section
  values stay exact); sections covering identical segment sets share a
  single combined histogram.
* Index memory is bounded by ``max_sections``: the segment/coverage indexes
  grow with sections x segments. Sections beyond the limit are skipped and
  reported via ``sections_skipped`` and ``notes``. That is the one place
  where exact, complete per-section statistics are traded for bounded
  resource use; every other statistic remains exact.
"""

import collections
import dataclasses
import math
import os

import pefile

__all__ = [
    "IntervalFeatures",
    "OverlayFeatures",
    "SectionFeatures",
    "SegmentStat",
    "extract_interval_features",
]

DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_SECTIONS = 512
DEFAULT_HEADER_READ_CAP = 4 * 1024 * 1024
MAX_SHARED_RANGES_PER_SECTION = 64

# IMAGE_SCN_MEM_* values from the PE specification.
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000

_OVERLAY_SOURCE_ID = -1


@dataclasses.dataclass
class SegmentStat:
    """Statistics for one disjoint physical file range.

    ``sources`` names every described region covering the range, e.g.
    ``["section[0]", "section[1]"]`` for bytes shared by two sections, or
    ``["overlay"]`` for appended data. ``shared`` is True when more than
    one source covers the range.
    """

    start: int
    end: int
    size: int
    entropy: float
    zero_ratio: float
    sources: list
    shared: bool


@dataclasses.dataclass
class SectionFeatures:
    """Per-section statistics.

    ``entropy``/``zero_ratio`` refer to ``file_range`` only: the declared
    raw range clamped to the bytes physically present in the file. Both are
    None when the section contributes no on-disk bytes. ``shared_ranges``
    lists the sub-ranges of ``file_range`` also claimed by at least one
    other source (capped at ``MAX_SHARED_RANGES_PER_SECTION`` entries; see
    ``shared_ranges_capped``).
    """

    index: int
    name: str
    characteristics: int
    can_read: bool
    can_write: bool
    can_execute: bool
    virtual_address: int
    virtual_size: int
    raw_size_declared: int
    raw_size_actual: int
    declared_range: tuple
    file_range: tuple
    truncated: bool
    declared_bytes_missing: int
    entropy: float
    zero_ratio: float
    virtual_larger_than_raw: bool
    raw_larger_than_virtual: bool
    shared_byte_count: int
    shared_ranges: list
    shared_ranges_capped: bool


@dataclasses.dataclass
class OverlayFeatures:
    """Statistics for appended data past every described region."""

    present: bool
    start: int = 0
    end: int = 0
    size: int = 0
    entropy: float = None
    zero_ratio: float = None


@dataclasses.dataclass
class IntervalFeatures:
    """Result of :func:`extract_interval_features`.

    ``bytes_read`` counts bytes pulled from the underlying source (zero for
    in-memory sources). ``unique_bytes_scanned`` counts the physical bytes
    actually histogrammed; ``declared_raw_bytes`` sums the declared raw
    sizes of all parsed sections as a contrast figure. ``notes`` records
    boundedness trade-offs applied during extraction.
    """

    file_size: int
    sections: list
    sections_skipped: int
    overlay: OverlayFeatures
    segments: list
    bytes_read: int
    unique_bytes_scanned: int
    declared_raw_bytes: int
    chunk_size: int
    max_sections: int
    header_read_cap: int
    notes: list


class _RangeReader:
    """Fetches byte ranges from a source, counting bytes actually pulled.

    Ranges fully inside ``cached_prefix`` are served from the prefix without
    touching the underlying source again.
    """

    def __init__(self, size, fetch, cached_prefix=b"", initial_bytes_read=0):
        self.size = size
        self._fetch = fetch
        self._prefix = cached_prefix
        self.bytes_read = initial_bytes_read

    def read_at(self, offset, size):
        size = min(size, self.size - offset)
        if size <= 0:
            return b""
        prefix_len = len(self._prefix)
        if offset + size <= prefix_len:
            return self._prefix[offset : offset + size]
        if offset < prefix_len:
            head = self._prefix[offset:]
            tail = self._fetch(prefix_len, size - len(head))
            self.bytes_read += len(tail)
            return head + tail
        data = self._fetch(offset, size)
        self.bytes_read += len(data)
        return data


def _from_file_object(fp, header_read_cap, notes):
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    fp.seek(0)
    prefix = fp.read(min(size, header_read_cap))
    if size > len(prefix):
        notes.append(
            "file exceeds header_read_cap; PE structures were parsed from "
            "the first %d bytes" % len(prefix)
        )
    pe = pefile.PE(data=prefix, fast_load=True)

    def fetch(offset, length):
        fp.seek(offset)
        return fp.read(length)

    reader = _RangeReader(
        size=size, fetch=fetch, cached_prefix=prefix, initial_bytes_read=len(prefix)
    )
    return pe, reader


def _open_source(source, header_read_cap):
    """Normalise ``source`` into (pe, reader, closer, notes)."""
    notes = []
    if isinstance(source, pefile.PE):
        data = getattr(source, "__data__", None)
        if data is None:
            raise ValueError("the provided pefile.PE instance holds no data")
        reader = _RangeReader(size=len(data), fetch=None, cached_prefix=bytes(data))
        return source, reader, None, notes
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        pe = pefile.PE(data=data, fast_load=True)
        reader = _RangeReader(size=len(data), fetch=None, cached_prefix=data)
        return pe, reader, None, notes
    if isinstance(source, (str, os.PathLike)):
        fp = open(source, "rb")
        try:
            pe, reader = _from_file_object(fp, header_read_cap, notes)
        except Exception:
            fp.close()
            raise
        return pe, reader, fp.close, notes
    if hasattr(source, "read") and hasattr(source, "seek"):
        pe, reader = _from_file_object(source, header_read_cap, notes)
        return pe, reader, None, notes
    raise TypeError("unsupported source type: %r" % type(source))


def _overlay_start(pe, file_size):
    """Offset where appended data starts, mirroring pefile's own rule.

    Only declared extents that end within the real file size are considered,
    so truncated declarations cannot move the overlay boundary.
    """
    largest = (0, 0)

    def update(offset_and_size):
        nonlocal largest
        if sum(largest) < sum(offset_and_size) <= file_size:
            largest = offset_and_size

    optional_header = getattr(pe, "OPTIONAL_HEADER", None)
    if optional_header is not None:
        update(
            (
                optional_header.get_file_offset(),
                pe.FILE_HEADER.SizeOfOptionalHeader,
            )
        )
    for section in getattr(pe, "sections", None) or []:
        update((section.PointerToRawData or 0, section.SizeOfRawData or 0))
    security_directory = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    directories = getattr(optional_header, "DATA_DIRECTORY", None) or []
    for idx, directory in enumerate(directories):
        if idx == security_directory:
            continue
        try:
            update((pe.get_offset_from_rva(directory.VirtualAddress), directory.Size))
        except Exception:
            continue
    return sum(largest)


def _build_segments(intervals):
    """Decompose (start, end, source_id) intervals into disjoint segments."""
    events = []
    for start, end, source_id in intervals:
        events.append((start, True, source_id))
        events.append((end, False, source_id))
    events.sort(key=lambda event: (event[0], event[1]))
    segments = []
    active = set()
    last = None
    for position, is_start, source_id in events:
        if last is not None and position > last and active:
            segments.append((last, position, tuple(sorted(active))))
        if is_start:
            active.add(source_id)
        else:
            active.discard(source_id)
        last = position
    return segments


def _scan_segment(reader, start, end, chunk_size):
    """Histogram the bytes of [start, end) reading at most chunk_size at once."""
    hist = [0] * 256
    offset = start
    while offset < end:
        chunk = reader.read_at(offset, min(chunk_size, end - offset))
        if not chunk:
            break
        for byte, count in collections.Counter(chunk).items():
            hist[byte] += count
        offset += len(chunk)
    return hist


def _entropy(hist, total):
    if total <= 0:
        return None
    entropy = 0.0
    for count in hist:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def _zero_ratio(hist, total):
    if total <= 0:
        return None
    return hist[0] / total


def _source_label(source_id):
    if source_id == _OVERLAY_SOURCE_ID:
        return "overlay"
    return "section[%d]" % source_id


def _section_name(section):
    name = getattr(section, "Name", b"") or b""
    if isinstance(name, bytes):
        return name.rstrip(b"\x00").decode("utf-8", "replace")
    return str(name).rstrip("\x00")


def extract_interval_features(
    source,
    *,
    chunk_size=DEFAULT_CHUNK_SIZE,
    max_sections=DEFAULT_MAX_SECTIONS,
    header_read_cap=DEFAULT_HEADER_READ_CAP,
):
    """Extract bounded per-interval byte statistics from a PE file.

    ``source`` may be a filesystem path, a binary file-like object, ``bytes``,
    or an existing :class:`pefile.PE` instance. ``chunk_size`` bounds the
    size of each read; ``max_sections`` bounds index memory (sections beyond
    the limit are skipped and reported); ``header_read_cap`` bounds how many
    leading bytes of a stream are used to parse PE structures.

    Returns an :class:`IntervalFeatures`. The statistics describe only bytes
    physically present in the file and are heuristic clues, not verdicts.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    if max_sections < 1:
        raise ValueError("max_sections must be >= 1")
    if header_read_cap < 1:
        raise ValueError("header_read_cap must be >= 1")
    pe, reader, closer, notes = _open_source(source, header_read_cap)
    try:
        return _extract(
            pe,
            reader,
            chunk_size=chunk_size,
            max_sections=max_sections,
            header_read_cap=header_read_cap,
            notes=notes,
        )
    finally:
        if closer is not None:
            closer()


def _extract(pe, reader, *, chunk_size, max_sections, header_read_cap, notes):
    file_size = reader.size
    all_sections = list(getattr(pe, "sections", None) or [])
    sections = all_sections[:max_sections]
    sections_skipped = len(all_sections) - len(sections)
    if sections_skipped:
        notes.append(
            "%d section(s) beyond max_sections=%d were skipped; their "
            "statistics are omitted so index memory stays bounded (bounded "
            "memory was chosen over complete per-section coverage)"
            % (sections_skipped, max_sections)
        )
    notes.append(
        "statistics cover only bytes physically present in the file; "
        "declared ranges truncated by end-of-file are not zero-padded"
    )
    notes.append(
        "entropy, zero-byte ratio and size relations are reverse-engineering "
        "clues only; no packed/malicious determination is made"
    )

    declared_raw_bytes = sum(section.SizeOfRawData or 0 for section in all_sections)

    intervals = []
    section_ranges = []
    for idx, section in enumerate(sections):
        raw_start = section.PointerToRawData or 0
        raw_declared = section.SizeOfRawData or 0
        declared_end = raw_start + raw_declared
        eff_start = min(raw_start, file_size)
        eff_end = min(declared_end, file_size)
        section_ranges.append((raw_start, raw_declared, eff_start, eff_end))
        if eff_end > eff_start:
            intervals.append((eff_start, eff_end, idx))

    overlay_range = None
    overlay_offset = _overlay_start(pe, file_size)
    if overlay_offset < file_size:
        overlay_range = (overlay_offset, file_size)
        intervals.append((overlay_offset, file_size, _OVERLAY_SOURCE_ID))

    raw_segments = _build_segments(intervals)
    histograms = [
        _scan_segment(reader, start, end, chunk_size)
        for start, end, _ in raw_segments
    ]

    coverage = {}
    for seg_idx, (_, _, sources) in enumerate(raw_segments):
        for source_id in sources:
            if source_id != _OVERLAY_SOURCE_ID:
                coverage.setdefault(source_id, []).append(seg_idx)

    # Sections covering identical segment sets have identical statistics;
    # combine each distinct coverage pattern once and share the result.
    group_stats = {}

    def stats_for(segment_ids):
        if segment_ids not in group_stats:
            hist = [0] * 256
            total = 0
            for seg_idx in segment_ids:
                seg_start, seg_end, _ = raw_segments[seg_idx]
                seg_hist = histograms[seg_idx]
                for byte in range(256):
                    hist[byte] += seg_hist[byte]
                total += seg_end - seg_start
            group_stats[segment_ids] = (
                _entropy(hist, total),
                _zero_ratio(hist, total),
            )
        return group_stats[segment_ids]

    section_features = []
    for idx, section in enumerate(sections):
        raw_start, raw_declared, eff_start, eff_end = section_ranges[idx]
        segment_ids = tuple(coverage.get(idx, ()))
        entropy, zero_ratio = stats_for(segment_ids)

        shared_ranges = []
        shared_byte_count = 0
        shared_ranges_capped = False
        for seg_idx in segment_ids:
            seg_start, seg_end, sources = raw_segments[seg_idx]
            if len(sources) > 1:
                shared_byte_count += seg_end - seg_start
                if len(shared_ranges) < MAX_SHARED_RANGES_PER_SECTION:
                    shared_ranges.append((seg_start, seg_end))
                else:
                    shared_ranges_capped = True

        virtual_size = section.Misc_VirtualSize or 0
        characteristics = section.Characteristics or 0
        raw_actual = eff_end - eff_start
        # pefile sorts pe.sections by VirtualAddress; report the original
        # section-table index when it is available.
        original_index = getattr(section, "index_in_file", None)
        section_features.append(
            SectionFeatures(
                index=original_index if original_index is not None else idx,
                name=_section_name(section),
                characteristics=characteristics,
                can_read=bool(characteristics & _IMAGE_SCN_MEM_READ),
                can_write=bool(characteristics & _IMAGE_SCN_MEM_WRITE),
                can_execute=bool(characteristics & _IMAGE_SCN_MEM_EXECUTE),
                virtual_address=section.VirtualAddress or 0,
                virtual_size=virtual_size,
                raw_size_declared=raw_declared,
                raw_size_actual=raw_actual,
                declared_range=(raw_start, raw_start + raw_declared)
                if raw_declared
                else None,
                file_range=(eff_start, eff_end) if raw_actual else None,
                truncated=raw_declared > raw_actual,
                declared_bytes_missing=raw_declared - raw_actual,
                entropy=entropy,
                zero_ratio=zero_ratio,
                virtual_larger_than_raw=virtual_size > raw_declared,
                raw_larger_than_virtual=raw_declared > virtual_size,
                shared_byte_count=shared_byte_count,
                shared_ranges=shared_ranges,
                shared_ranges_capped=shared_ranges_capped,
            )
        )

    if overlay_range is not None:
        overlay_segment_ids = tuple(
            seg_idx
            for seg_idx, (_, _, sources) in enumerate(raw_segments)
            if _OVERLAY_SOURCE_ID in sources
        )
        overlay_entropy, overlay_zero_ratio = stats_for(overlay_segment_ids)
        overlay = OverlayFeatures(
            present=True,
            start=overlay_range[0],
            end=overlay_range[1],
            size=overlay_range[1] - overlay_range[0],
            entropy=overlay_entropy,
            zero_ratio=overlay_zero_ratio,
        )
    else:
        overlay = OverlayFeatures(present=False)

    segments = [
        SegmentStat(
            start=start,
            end=end,
            size=end - start,
            entropy=_entropy(histograms[seg_idx], end - start),
            zero_ratio=_zero_ratio(histograms[seg_idx], end - start),
            sources=[_source_label(source_id) for source_id in sources],
            shared=len(sources) > 1,
        )
        for seg_idx, (start, end, sources) in enumerate(raw_segments)
    ]

    return IntervalFeatures(
        file_size=file_size,
        sections=section_features,
        sections_skipped=sections_skipped,
        overlay=overlay,
        segments=segments,
        bytes_read=reader.bytes_read,
        unique_bytes_scanned=sum(end - start for start, end, _ in raw_segments),
        declared_raw_bytes=declared_raw_bytes,
        chunk_size=chunk_size,
        max_sections=max_sections,
        header_read_cap=header_read_cap,
        notes=notes,
    )
