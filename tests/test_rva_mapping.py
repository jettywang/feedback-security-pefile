"""Evidence-based RVA mapping tests using synthetic PEs.

The tests deliberately do not rely on the bundled corpus: every fixture is a
small, hand-built PE32 image whose section table and raw data are fully
controlled.
"""

import struct

import pytest

import pefile


OFFSET_FILE_HEADER = 0x44
OFFSET_OPTIONAL_HEADER = 0x58
OFFSET_SECTION_TABLE = OFFSET_OPTIONAL_HEADER + 0xE0


def _section_header(name, virtual_size, virtual_address, raw_size, raw_pointer):
    return struct.pack(
        "<8sIIIIIIHHI",
        name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        0,
        0,
        0,
        0,
        0x60000020,
    )


def _build_pe(
    sections,
    *,
    file_size=0x800,
    size_of_headers=0x200,
    size_of_image=0x3000,
    entry_point=0x1000,
    import_directory=None,
    section_alignment=0x1000,
    file_alignment=0x200,
):
    """Build a minimal PE32 image with the given section headers.

    ``sections`` is a list of ``(name, VirtualSize, VirtualAddress,
    SizeOfRawData, PointerToRawData)`` tuples in table order.
    """

    data = bytearray(file_size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        OFFSET_FILE_HEADER,
        0x014C,
        len(sections),
        0,
        0,
        0,
        0xE0,
        0x0102,
    )

    opt = OFFSET_OPTIONAL_HEADER
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, entry_point)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into(
        "<II", data, opt + 32, section_alignment, file_alignment
    )
    struct.pack_into("<I", data, opt + 56, size_of_image)
    struct.pack_into("<I", data, opt + 60, size_of_headers)
    struct.pack_into("<H", data, opt + 68, 2)
    struct.pack_into("<I", data, opt + 92, 16)
    if import_directory is not None:
        import_rva, import_size = import_directory
        struct.pack_into(
            "<II",
            data,
            opt + 96 + 8,
            import_rva,
            import_size,
        )

    for index, section in enumerate(sections):
        start = OFFSET_SECTION_TABLE + 40 * index
        data[start : start + 40] = _section_header(*section)

    return data


def _with_payload(data, offset, payload):
    data = bytearray(data)
    data[offset : offset + len(payload)] = payload
    return bytes(data)


def _mapping_signature(mapping):
    return tuple(candidate.signature for candidate in mapping.candidates)


def _candidate_evidence(candidate):
    """Presentation-independent fields used to compare candidate sets."""
    return (
        candidate.kind,
        candidate.address_basis,
        candidate.section_name,
        candidate.virtual_address,
        candidate.pointer_to_raw_data,
        candidate.virtual_size,
        candidate.size_of_raw_data,
        candidate.span_range,
        candidate.file_range,
        candidate.zero_fill_range,
        candidate.missing_file_range,
        candidate.raw_only_range,
        candidate.data,
        candidate.flags,
    )


def test_overlapping_sections_expose_two_byte_interpretations():
    data = _build_pe(
        [
            (b".alpha\0\0", 0x200, 0x1000, 0x200, 0x200),
            (b".beta\0\0\0", 0x200, 0x1000, 0x200, 0x400),
        ],
        file_size=0x600,
        size_of_image=0x2000,
    )
    data = _with_payload(data, 0x200, b"A" * 0x20)
    data = _with_payload(data, 0x400, b"B" * 0x20)

    pe = pefile.PE(data=data)
    mapping = pe.get_rva_mapping(0x1000, 0x20)

    assert mapping.ambiguous
    assert "overlapping_sections" in mapping.reasons
    assert "conflicting_bytes" in mapping.reasons
    assert mapping.unique_file_offset is None
    assert {candidate.section_name for candidate in mapping.candidates} == {
        b".alpha",
        b".beta",
    }
    assert {candidate.data[:1] for candidate in mapping.candidates} == {
        b"A",
        b"B",
    }
    assert {candidate.file_offset for candidate in mapping.candidates} == {
        0x200,
        0x400,
    }
    assert {candidate.file_range for candidate in mapping.candidates} == {
        (0x200, 0x220),
        (0x400, 0x420),
    }


def test_swapping_section_table_entries_does_not_change_candidate_set():
    sections = [
        (b".alpha\0\0", 0x200, 0x1000, 0x200, 0x200),
        (b".beta\0\0\0", 0x200, 0x1000, 0x200, 0x400),
    ]
    data = _build_pe(sections, file_size=0x600, size_of_image=0x2000)
    data = _with_payload(data, 0x200, b"A" * 0x20)
    data = _with_payload(data, 0x400, b"B" * 0x20)

    first = pefile.PE(data=data).get_rva_mapping(0x1000, 0x20)

    swapped = bytearray(data)
    start = OFFSET_SECTION_TABLE
    swapped[start : start + 40], swapped[start + 40 : start + 80] = (
        swapped[start + 40 : start + 80],
        swapped[start : start + 40],
    )
    second = pefile.PE(data=bytes(swapped)).get_rva_mapping(0x1000, 0x20)

    assert first.candidates == second.candidates
    assert _mapping_signature(first) == _mapping_signature(second)
    assert tuple(
        _candidate_evidence(candidate) for candidate in first.candidates
    ) == tuple(
        _candidate_evidence(candidate) for candidate in second.candidates
    )
    assert first.reasons == second.reasons

    # The legacy lookup does depend on table order; the new API must not.
    legacy_first = pefile.PE(data=data).get_offset_from_rva(0x1000)
    legacy_second = pefile.PE(data=bytes(swapped)).get_offset_from_rva(0x1000)
    assert legacy_first != legacy_second
    assert first.unique_file_offset is None
    assert second.unique_file_offset is None


def test_normal_pe_entry_point_and_import_directory_map_uniquely():
    sections = [
        (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200),
        (b".idata\0\0", 0x100, 0x2000, 0x200, 0x400),
    ]
    data = _build_pe(
        sections,
        size_of_image=0x3000,
        import_directory=(0x2000, 0x40),
    )
    data = _with_payload(data, 0x200, b"\x55\x8b\xec\x83\xec\x70")
    data = _with_payload(data, 0x400, b"\xC0\x01\x00\x00" + b"\0" * 0x3C)
    data = _with_payload(data, 0x5C0, b"\x00" * 0x20)

    pe = pefile.PE(data=data)

    entry_mapping = pe.get_rva_mapping(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 5)
    assert entry_mapping.unique_candidate is not None
    assert entry_mapping.unique_file_offset == 0x200
    assert entry_mapping.candidates[0].data == b"\x55\x8b\xec\x83\xec"
    assert pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 5) == (
        entry_mapping.candidates[0].data
    )

    import_mapping = pe.get_directory_mapping("IMAGE_DIRECTORY_ENTRY_IMPORT")
    assert import_mapping.directory_name == "IMAGE_DIRECTORY_ENTRY_IMPORT"
    assert import_mapping.directory_rva == 0x2000
    assert import_mapping.unique_candidate is not None
    assert import_mapping.unique_file_offset == 0x400
    assert import_mapping.candidates[0].data[:4] == b"\xC0\x01\x00\x00"
    assert import_mapping.candidates[0].section_name == b".idata"


def test_header_rva_is_a_candidate_when_a_section_also_claims_it():
    data = _build_pe(
        [(b".tiny\0\0\0", 0x400, 0x100, 0x100, 0x200)],
        file_size=0x400,
        size_of_headers=0x200,
        size_of_image=0x1000,
    )

    pe = pefile.PE(data=data)
    mapping = pe.get_rva_mapping(0x100)

    assert "header_section_overlap" in mapping.reasons
    assert {candidate.kind for candidate in mapping.candidates} == {
        "header",
        "section",
    }
    header = [c for c in mapping.candidates if c.kind == "header"][0]
    assert header.file_offset == 0x100
    assert header.section is None


def test_virtual_size_exceeding_raw_size_reports_zero_fill():
    data = _build_pe(
        [(b".bss\0\0\0\0", 0x2000, 0x1000, 0x200, 0x200)],
        file_size=0x400,
        size_of_image=0x4000,
    )

    pe = pefile.PE(data=data)

    in_raw = pe.get_rva_mapping(0x1100, 8)
    assert in_raw.unique_candidate is not None
    assert in_raw.candidates[0].file_range == (0x300, 0x308)
    assert in_raw.candidates[0].zero_fill_range is None

    in_zero = pe.get_rva_mapping(0x1300, 8)
    assert in_zero.unique_candidate is not None
    candidate = in_zero.candidates[0]
    assert candidate.file_offset is None
    assert candidate.file_range is None
    assert candidate.zero_fill_range == (0x1300, 0x1308)
    assert candidate.zero_fill_extent == (0x1200, 0x3000)
    assert candidate.data == b"\0" * 8
    assert "virtual_zero_fill" in in_zero.reasons
    assert "virtual_size_exceeds_raw_size" in in_zero.reasons


def test_raw_size_exceeding_virtual_size_reports_raw_only_tail():
    data = _build_pe(
        [(b".text\0\0\0", 0x100, 0x1000, 0x200, 0x200)],
        file_size=0x500,
        size_of_image=0x2000,
    )
    data = _with_payload(data, 0x200, b"\x11" * 0x100)
    data = _with_payload(data, 0x300, b"\x22" * 0x100)

    pe = pefile.PE(data=data)

    mapping = pe.get_rva_mapping(0x1100, 4)
    assert mapping.unique_candidate is not None
    candidate = mapping.candidates[0]
    assert candidate.file_offset == 0x300
    assert candidate.file_range == (0x300, 0x304)
    assert candidate.raw_only_range == (0x1100, 0x1104)
    assert candidate.data == b"\x22" * 4
    assert "raw_size_exceeds_virtual_size" in mapping.reasons


def test_directory_past_section_extent_is_reported_not_guessed():
    data = _build_pe(
        [(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200)],
        file_size=0x400,
        size_of_image=0x2000,
        import_directory=(0x1000, 0x800),
    )

    pe = pefile.PE(data=data)
    mapping = pe.get_directory_mapping(1)

    assert "directory_span_truncated" in mapping.reasons
    assert "candidate_span_truncated" in mapping.reasons
    assert mapping.candidates
    assert mapping.candidates[0].truncated
    assert mapping.candidates[0].file_range == (0x200, 0x400)
    assert mapping.unique_file_offset is None


def test_directory_raw_bytes_past_eof_are_reported():
    data = _build_pe(
        [(b".text\0\0\0", 0x400, 0x1000, 0x400, 0x200)],
        file_size=0x400,
        size_of_image=0x2000,
        import_directory=(0x1000, 0x400),
    )

    pe = pefile.PE(data=data)
    mapping = pe.get_directory_mapping(1)

    assert "directory_file_data_missing" in mapping.reasons
    assert "file_data_missing" in mapping.reasons
    assert mapping.candidates[0].missing_file_range == (0x1200, 0x1400)
    assert mapping.candidates[0].file_range == (0x200, 0x400)
    assert mapping.unique_file_offset is None


def test_directory_outside_size_of_image_is_reported():
    data = _build_pe(
        [(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200)],
        file_size=0x400,
        size_of_image=0x1000,
        import_directory=(0x5000, 0x40),
    )

    pe = pefile.PE(data=data)
    mapping = pe.get_directory_mapping(1)

    assert "directory_rva_out_of_bounds" in mapping.reasons
    assert "directory_rva_outside_sections" in mapping.reasons
    assert mapping.candidates == ()


def test_empty_directory_reports_no_candidate():
    data = _build_pe([(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200)])

    mapping = pefile.PE(data=data).get_directory_mapping(
        "IMAGE_DIRECTORY_ENTRY_IMPORT"
    )

    assert mapping.candidates == ()
    assert mapping.reasons == ("directory_empty",)
    assert mapping.unique_file_offset is None


def test_invalid_queries_are_rejected():
    data = _build_pe([(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200)])
    pe = pefile.PE(data=data)

    with pytest.raises(ValueError):
        pe.get_rva_mapping(-1)
    with pytest.raises(ValueError):
        pe.get_rva_mapping(0x1000, -1)
    with pytest.raises(ValueError):
        pe.get_directory_mapping(99)


def test_legacy_single_value_interface_still_works():
    data = _build_pe([(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200)])
    data = _with_payload(data, 0x200, b"\x90" * 0x20)
    pe = pefile.PE(data=data)

    assert pe.get_offset_from_rva(0x1010) == 0x210
    assert pe.get_data(0x1010, 4) == b"\x90" * 4

def test_declared_basis_keeps_unaligned_section_visible():
    # VirtualAddress 0x2500 is misaligned for SectionAlignment 0x1000, so
    # pefile rounds it down to 0x2000.  The declared and adjusted bases are
    # both real static interpretations and both must stay visible.
    data = _build_pe(
        [(b".text\0\0\0", 0x100, 0x2500, 0x100, 0x200)],
        file_size=0x400,
        size_of_image=0x4000,
    )
    data = _with_payload(data, 0x200, b"Q" * 0x100)

    pe = pefile.PE(data=data)

    declared = pe.get_rva_mapping(0x2500, 4)
    assert declared.unique_candidate is not None
    candidate = declared.candidates[0]
    assert candidate.address_basis == "declared"
    assert candidate.file_offset == 0x200
    assert candidate.data == b"Q" * 4
    assert "address_basis_declared" in candidate.flags

    adjusted = pe.get_rva_mapping(0x2000, 4)
    assert adjusted.unique_candidate is not None
    assert adjusted.candidates[0].address_basis == "adjusted"
    assert adjusted.candidates[0].file_offset == 0x200

    # The legacy lookup only uses the adjusted basis.
    assert pe.get_section_by_rva(0x2500) is None


def test_large_query_is_capped_but_ranges_are_complete():
    data = _build_pe(
        [(b".text\0\0\0", 0x100000, 0x1000, 0x100000, 0x200)],
        file_size=0x100050,
        size_of_image=0x200000,
    )

    pe = pefile.PE(data=data)
    mapping = pe.get_rva_mapping(0x1000, 0x100000)

    candidate = mapping.candidates[0]
    assert candidate.covered_range == (0x1000, 0x101000)
    assert len(candidate.data) == pefile.MAX_RVA_MAPPING_DATA
    assert "data_truncated" in candidate.flags
    assert candidate.truncated is False

def test_directory_structure_argument_is_supported():
    data = _build_pe(
        [(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200)],
        file_size=0x400,
    )
    pe = pefile.PE(data=data)
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]

    mapping = pe.get_directory_mapping(entry)
    assert mapping.directory_index == 1
    assert mapping.directory_name == "IMAGE_DIRECTORY_ENTRY_IMPORT"

def test_agreeing_candidates_remain_explicitly_ambiguous():
    # Two sections claim the same RVA and resolve to the same bytes.  The
    # mapping must still report both interpretations instead of collapsing to
    # the single offset the legacy lookup returns.
    data = _build_pe(
        [
            (b".one\0\0\0\0", 0x200, 0x1000, 0x200, 0x200),
            (b".two\0\0\0\0", 0x200, 0x1000, 0x200, 0x200),
        ],
        file_size=0x400,
        size_of_image=0x2000,
    )
    data = _with_payload(data, 0x200, b"Z" * 0x20)

    pe = pefile.PE(data=data)
    mapping = pe.get_rva_mapping(0x1000, 0x20)

    assert len(mapping.candidates) == 2
    assert not mapping.conflicting_bytes
    assert mapping.unique_file_offset is None
    assert "overlapping_sections" in mapping.reasons
    assert "ambiguous_mapping" in mapping.reasons

