"""Tests for pefeatures.extract_interval_features using synthetic PE samples."""

import collections
import io
import math
import random
import struct

import pytest

import pefile
import pefeatures


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def build_pe(sections, overlay=b"", file_alignment=0x200, section_alignment=0x1000):
    """Build a minimal synthetic PE image.

    ``sections`` is a list of dicts with keys: ``name``, ``characteristics``,
    ``virtual_size``, ``virtual_address``, ``raw_size``, ``raw_ptr``
    (optional; auto-laid-out when omitted) and ``data`` (bytes written at
    ``raw_ptr``; may be shorter than ``raw_size`` to simulate truncation).
    """
    e_lfanew = 0x80
    num = len(sections)
    header_end = e_lfanew + 4 + 20 + 0xE0 + 40 * num
    size_of_headers = _align(header_end, file_alignment)

    next_ptr = size_of_headers
    records = []
    writes = []
    for spec in sections:
        raw_size = spec.get("raw_size", 0)
        if raw_size:
            raw_ptr = spec.get("raw_ptr", next_ptr)
            next_ptr = max(next_ptr, _align(raw_ptr + raw_size, file_alignment))
        else:
            raw_ptr = spec.get("raw_ptr", 0)
        records.append((spec, raw_ptr))
        if spec.get("data"):
            writes.append((raw_ptr, spec["data"]))

    size_of_image = section_alignment
    va_default = section_alignment
    vas = []
    for spec, _ in records:
        va = spec.get("virtual_address", va_default)
        vas.append(va)
        span = max(spec.get("virtual_size", 0), spec.get("raw_size", 0), 1)
        va_default = va + _align(span, section_alignment)
        size_of_image = max(size_of_image, va_default)
    size_of_image = min(size_of_image, 0xFFFFFFFF)

    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    coff = struct.pack("<HHIIIHH", 0x14C, num, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
    struct.pack_into("<I", opt, 32, section_alignment)
    struct.pack_into("<I", opt, 36, file_alignment)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, size_of_headers)
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes

    section_table = bytearray()
    for (spec, raw_ptr), va in zip(records, vas):
        name = spec.get("name", b".sec")[:8].ljust(8, b"\x00")
        section_table += struct.pack(
            "<8sIIIIIIHHI",
            name,
            spec.get("virtual_size", 0),
            va & 0xFFFFFFFF,
            spec.get("raw_size", 0),
            raw_ptr,
            0,
            0,
            0,
            0,
            spec.get("characteristics", 0x40000040),
        )

    image = bytearray(dos + b"PE\0\0" + coff + bytes(opt) + section_table)
    image.extend(b"\x00" * (size_of_headers - len(image)))
    for offset, data in writes:
        if len(image) < offset:
            image.extend(b"\x00" * (offset - len(image)))
        end = offset + len(data)
        if len(image) < end:
            image.extend(b"\x00" * (end - len(image)))
        image[offset:end] = data
    image.extend(overlay)
    return bytes(image)


def ref_entropy(data):
    if not data:
        return None
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def ref_zero_ratio(data):
    if not data:
        return None
    return data.count(0) / len(data)


class CountingFile:
    """File-like object recording how many bytes are actually read."""

    def __init__(self, data):
        self._fp = io.BytesIO(data)
        self.bytes_read = 0
        self.read_calls = 0

    def seek(self, offset, whence=0):
        return self._fp.seek(offset, whence)

    def tell(self):
        return self._fp.tell()

    def read(self, size=-1):
        data = self._fp.read(size)
        self.bytes_read += len(data)
        self.read_calls += 1
        return data


def test_zero_filled_section_has_zero_entropy():
    image = build_pe(
        [
            {
                "name": b".zeros",
                "raw_size": 0x400,
                "virtual_size": 0x400,
                "data": b"\x00" * 0x400,
            }
        ]
    )
    features = pefeatures.extract_interval_features(image)
    section = features.sections[0]
    assert section.entropy == 0.0
    assert section.zero_ratio == 1.0
    assert section.raw_size_actual == 0x400
    assert section.file_range == (0x200, 0x600)
    assert not section.truncated


def test_uniform_byte_distribution_has_max_entropy():
    data = bytes(range(256)) * 8
    image = build_pe(
        [{"name": b".unif", "raw_size": len(data), "virtual_size": len(data), "data": data}]
    )
    features = pefeatures.extract_interval_features(image)
    section = features.sections[0]
    assert section.entropy == pytest.approx(8.0)
    assert section.zero_ratio == pytest.approx(1 / 256)


def test_random_section_has_high_entropy():
    rng = random.Random(42)
    data = bytes(rng.getrandbits(8) for _ in range(0x4000))
    image = build_pe(
        [{"name": b".rand", "raw_size": len(data), "virtual_size": len(data), "data": data}]
    )
    features = pefeatures.extract_interval_features(image)
    section = features.sections[0]
    assert section.entropy == pytest.approx(ref_entropy(data))
    assert section.entropy > 7.5
    assert section.zero_ratio == pytest.approx(ref_zero_ratio(data))


def test_huge_virtual_size_does_not_drive_allocation():
    image = build_pe(
        [
            {
                "name": b".vast",
                "raw_size": 0x200,
                "virtual_size": 0x40000000,  # 1 GiB declared in memory
                "virtual_address": 0x70000000,
                "data": b"\x90" * 0x200,
            }
        ]
    )
    counting = CountingFile(image)
    features = pefeatures.extract_interval_features(counting)
    section = features.sections[0]
    assert section.virtual_size == 0x40000000
    assert section.virtual_address == 0x70000000
    assert section.virtual_larger_than_raw
    assert section.raw_size_actual == 0x200
    # Reads track the real file, not the declared virtual size.
    assert counting.bytes_read <= len(image)
    assert features.unique_bytes_scanned == 0x200


def test_truncated_section_is_not_zero_padded():
    present = b"\x41" * 0x100  # only 0x100 of a declared 0x1000 reach the file
    image = build_pe(
        [
            {
                "name": b".trunc",
                "raw_size": 0x1000,
                "virtual_size": 0x1000,
                "data": present,
            }
        ]
    )
    features = pefeatures.extract_interval_features(image)
    section = features.sections[0]
    assert section.truncated
    assert section.declared_bytes_missing == 0x1000 - 0x100
    assert section.raw_size_actual == 0x100
    assert section.declared_range == (0x200, 0x1200)
    assert section.file_range == (0x200, 0x300)
    # Statistics reflect the actual bytes, not a zero-padded declared range.
    assert section.entropy == pytest.approx(ref_entropy(present))
    assert section.zero_ratio == pytest.approx(ref_zero_ratio(present))
    assert section.zero_ratio == 0.0


def test_overlapping_sections_report_shared_bytes():
    image = build_pe(
        [
            {
                "name": b".a",
                "raw_ptr": 0x200,
                "raw_size": 0x200,
                "virtual_size": 0x200,
                "data": b"\x41" * 0x100 + b"\x42" * 0x100,
            },
            {
                "name": b".b",
                "raw_ptr": 0x300,
                "raw_size": 0x200,
                "virtual_size": 0x200,
                "data": b"\x42" * 0x100 + b"\x43" * 0x100,
            },
        ]
    )
    features = pefeatures.extract_interval_features(image)
    sec_a, sec_b = features.sections

    # The shared physical range is scanned once and attributed to both.
    shared_segments = [s for s in features.segments if s.shared]
    assert [(s.start, s.end) for s in shared_segments] == [(0x300, 0x400)]
    assert sorted(shared_segments[0].sources) == ["section[0]", "section[1]"]
    assert sec_a.shared_byte_count == 0x100
    assert sec_b.shared_byte_count == 0x100
    assert sec_a.shared_ranges == [(0x300, 0x400)]
    assert sec_b.shared_ranges == [(0x300, 0x400)]

    # Per-section statistics match a reference over each section's own bytes.
    assert sec_a.entropy == pytest.approx(ref_entropy(image[0x200:0x400]))
    assert sec_b.entropy == pytest.approx(ref_entropy(image[0x300:0x500]))
    assert sec_a.entropy == pytest.approx(1.0)  # two equally frequent bytes

    # Unique physical bytes, not the sum of declared ranges, are scanned.
    assert features.unique_bytes_scanned == 0x300
    assert features.declared_raw_bytes == 0x400


def test_overlay_statistics():
    overlay = b"\xcc" * 0x100
    image = build_pe(
        [
            {
                "name": b".text",
                "raw_size": 0x200,
                "virtual_size": 0x200,
                "data": b"\x90" * 0x200,
            }
        ],
        overlay=overlay,
    )
    features = pefeatures.extract_interval_features(image)
    assert features.overlay.present
    assert features.overlay.size == 0x100
    assert (features.overlay.start, features.overlay.end) == (
        len(image) - 0x100,
        len(image),
    )
    assert features.overlay.entropy == 0.0
    assert features.overlay.zero_ratio == 0.0
    overlay_segments = [s for s in features.segments if "overlay" in s.sources]
    assert [(s.start, s.end) for s in overlay_segments] == [
        (len(image) - 0x100, len(image))
    ]


def test_no_overlay_when_file_ends_with_sections():
    image = build_pe(
        [{"name": b".text", "raw_size": 0x200, "virtual_size": 0x200, "data": b"\x90" * 0x200}]
    )
    features = pefeatures.extract_interval_features(image)
    assert not features.overlay.present


def _multi_section_sample():
    rng = random.Random(7)
    random_data = bytes(rng.getrandbits(8) for _ in range(0x500))
    uniform_data = bytes(range(256)) * 2
    return build_pe(
        [
            {"name": b".z", "raw_size": 0x300, "virtual_size": 0x300, "data": b"\x00" * 0x300},
            {"name": b".u", "raw_size": 0x200, "virtual_size": 0x200, "data": uniform_data},
            {"name": b".r", "raw_size": 0x500, "virtual_size": 0x500, "data": random_data},
        ],
        overlay=b"\xcc" * 0x80,
    )


def test_chunked_extraction_matches_single_pass_and_reference():
    image = _multi_section_sample()
    chunked = pefeatures.extract_interval_features(image, chunk_size=64)
    single = pefeatures.extract_interval_features(image, chunk_size=1 << 30)

    for sec_chunked, sec_single in zip(chunked.sections, single.sections):
        assert sec_chunked.entropy == sec_single.entropy
        assert sec_chunked.zero_ratio == sec_single.zero_ratio
    for seg_chunked, seg_single in zip(chunked.segments, single.segments):
        assert seg_chunked.entropy == seg_single.entropy
        assert seg_chunked.zero_ratio == seg_single.zero_ratio
    assert chunked.overlay.entropy == single.overlay.entropy

    # And both match a one-shot reference computed straight from the bytes.
    for section in chunked.sections:
        start, end = section.file_range
        assert section.entropy == pytest.approx(ref_entropy(image[start:end]))
        assert section.zero_ratio == pytest.approx(ref_zero_ratio(image[start:end]))
    assert chunked.overlay.entropy == pytest.approx(ref_entropy(image[-0x80:]))


def _hostile_sample(num_overlapping=40):
    num_sections = num_overlapping + 1
    headers_size = _align(0x80 + 4 + 20 + 0xE0 + 40 * num_sections, 0x200)
    raw_ptr = headers_size
    sections = [
        {
            "name": b".ov%02d" % (i % 100),
            "raw_ptr": raw_ptr,
            "raw_size": 0x2000,
            "virtual_size": 0x1000000,  # 16 MiB each, never materialised
            "data": b"\x5a" * 0x2000 if i == 0 else None,
        }
        for i in range(num_overlapping)
    ]
    sections.append(
        {
            "name": b".trunc",
            "raw_ptr": raw_ptr + 0x2000,
            "raw_size": 0x10000000,  # 256 MiB declared, nothing on disk
            "virtual_size": 0x10000000,
        }
    )
    return build_pe(sections), raw_ptr


def test_reads_bounded_by_real_file_not_declared_sizes():
    image, raw_ptr = _hostile_sample()
    counting = CountingFile(image)
    features = pefeatures.extract_interval_features(counting, chunk_size=512)

    # The whole file fits under the header cap, so it is read exactly once;
    # declared sizes (40 x 8 KiB overlapping + 256 MiB truncated) add nothing.
    assert counting.bytes_read == len(image)
    assert features.bytes_read == len(image)
    assert features.unique_bytes_scanned == 0x2000
    assert features.declared_raw_bytes == 40 * 0x2000 + 0x10000000
    assert features.declared_raw_bytes > 2500 * features.unique_bytes_scanned

    truncated = [s for s in features.sections if s.name == ".trunc"][0]
    assert truncated.truncated
    assert truncated.raw_size_actual == 0
    assert truncated.entropy is None
    assert truncated.file_range is None

    # One shared segment covers the overlapping region for all 40 sections.
    assert len(features.segments) == 1
    segment = features.segments[0]
    assert (segment.start, segment.end) == (raw_ptr, raw_ptr + 0x2000)
    assert len(segment.sources) == 40
    assert segment.entropy == 0.0
    for section in features.sections:
        if section.name == ".trunc":
            continue
        assert section.entropy == 0.0
        assert section.shared_byte_count == 0x2000


def test_many_overlapping_sections_share_interval_statistics():
    image, _ = _hostile_sample(num_overlapping=300)
    counting = CountingFile(image)
    features = pefeatures.extract_interval_features(counting, chunk_size=4096)

    assert len(features.sections) == 301
    assert len(features.segments) == 1
    assert counting.bytes_read == len(image)
    assert features.unique_bytes_scanned == 0x2000
    overlapping = [s for s in features.sections if s.name != ".trunc"]
    assert {s.entropy for s in overlapping} == {0.0}
    # pefile sorts pe.sections by VirtualAddress; the reported index keeps
    # the original section-table order.
    assert sorted(s.index for s in features.sections) == list(range(301))


def test_max_sections_bounds_index_memory():
    image, _ = _hostile_sample()
    features = pefeatures.extract_interval_features(image, max_sections=10)
    assert len(features.sections) == 10
    assert features.sections_skipped == 31
    assert any("skipped" in note for note in features.notes)
    # The covered region is still scanned once.
    assert features.unique_bytes_scanned == 0x2000


def test_section_permissions_decoded():
    rwx = 0x20000000 | 0x40000000 | 0x80000000
    image = build_pe(
        [
            {"name": b".rwx", "raw_size": 0x200, "virtual_size": 0x200,
             "data": b"\x90" * 0x200, "characteristics": rwx},
            {"name": b".ro", "raw_size": 0x200, "virtual_size": 0x200,
             "data": b"\x90" * 0x200, "characteristics": 0x40000040},
        ]
    )
    features = pefeatures.extract_interval_features(image)
    sec_rwx, sec_ro = features.sections
    assert (sec_rwx.can_read, sec_rwx.can_write, sec_rwx.can_execute) == (True, True, True)
    assert (sec_ro.can_read, sec_ro.can_write, sec_ro.can_execute) == (True, False, False)
    assert sec_rwx.characteristics == rwx


def test_size_relation_flags():
    image = build_pe(
        [
            {"name": b".bss", "raw_size": 0, "virtual_size": 0x2000},
            {"name": b".pad", "raw_size": 0x400, "virtual_size": 0x100,
             "data": b"\x00" * 0x400},
        ]
    )
    features = pefeatures.extract_interval_features(image)
    bss, pad = features.sections
    assert bss.virtual_larger_than_raw
    assert bss.raw_size_actual == 0
    assert bss.entropy is None
    assert pad.raw_larger_than_virtual
    assert not pad.virtual_larger_than_raw


def test_accepts_pe_instance_and_path(tmp_path):
    image = _multi_section_sample()
    from_bytes = pefeatures.extract_interval_features(image)

    pe = pefile.PE(data=image, fast_load=True)
    from_pe = pefeatures.extract_interval_features(pe)
    assert [s.entropy for s in from_pe.sections] == [s.entropy for s in from_bytes.sections]

    path = tmp_path / "sample.bin"
    path.write_bytes(image)
    from_path = pefeatures.extract_interval_features(str(path))
    assert [s.entropy for s in from_path.sections] == [s.entropy for s in from_bytes.sections]
    assert from_path.file_size == len(image)


def test_statistics_carry_file_ranges_and_no_verdicts():
    image = _multi_section_sample()
    features = pefeatures.extract_interval_features(image)
    for section in features.sections:
        assert section.file_range is not None
        start, end = section.file_range
        assert 0 <= start < end <= features.file_size
    for segment in features.segments:
        assert 0 <= segment.start < segment.end <= features.file_size
    # The result carries clues, not classifications.
    assert not hasattr(features, "is_packed")
    assert not hasattr(features, "is_malicious")
    assert any("no packed/malicious determination" in note for note in features.notes)
