"""Tests for the non-destructive relocation view.

These tests build minimal PE32 / PE32+ images in memory so they do not depend
on the (encrypted, external) regression corpus. They cover:

* every supported relocation type on 32 and 64 bit images,
* images without a relocation directory,
* out-of-bounds relocation targets and failures half-way through a table,
* the guarantee that the original sample object is never mutated,
* independent recomputation for consecutive bases,
* equivalence with a freshly parsed image after a failed request.
"""

import struct

import pytest

import pefile


SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
HEADERS_RAW_SIZE = 0x200
SECTION_RAW_OFFSET = 0x200
SECTION_VA = 0x1000
DEFAULT_IMAGE_BASE = 0x400000

# Layout of the single .rdata-like section (offsets relative to the section).
EXPORT_DIR_OFF = 0x00
EXPORT_DIR_SIZE = 40
EXPORT_DLLNAME_OFF = 0x28
EXPORT_EAT_OFF = 0x40
EXPORT_AN_OFF = 0x48
EXPORT_AO_OFF = 0x50
EXPORT_FUNCNAME_OFF = 0x58
RELOC_DIR_OFF = 0x100
RELOC_ENTRIES_OFF = RELOC_DIR_OFF + 8
SECTION_RAW_SIZE = 0x400

# Relocation type ids (high nibble of a relocation word).
ABSOLUTE = 0
HIGH = 1
LOW = 2
HIGHLOW = 3
HIGHADJ = 4
DIR64 = 10


def _reloc_word(reloc_type, offset):
    return ((reloc_type & 0xF) << 12) | (offset & 0xFFF)


def _build_pe(
    machine=0x14C,
    image_base=DEFAULT_IMAGE_BASE,
    reloc_types=(HIGHLOW,),
    include_reloc_directory=True,
    bad_reloc_offset=None,
):
    """Build a minimal PE image with one data section.

    The section holds an export directory (used to prove parsed structures and
    raw export bytes stay untouched) and a base-relocation block.

    ``reloc_types`` lists the relocation types emitted, each targeting a
    distinct, section-relative word/dword/qword slot. When
    ``bad_reloc_offset`` is given, an extra HIGHLOW entry targeting a
    section-relative offset past the raw data is appended, producing an
    out-of-bounds target.
    """

    is_64 = machine == 0x8664
    magic = 0x20B if is_64 else 0x10B
    size_of_optional_header = 240 if is_64 else 224

    section = bytearray(SECTION_RAW_SIZE)

    # --- Export directory ---------------------------------------------------
    dll_name = b"sample.dll\x00"
    func_name = b"ExportedFunc\x00"
    section[EXPORT_DLLNAME_OFF : EXPORT_DLLNAME_OFF + len(dll_name)] = dll_name
    section[EXPORT_FUNCNAME_OFF : EXPORT_FUNCNAME_OFF + len(func_name)] = func_name

    export_rva = SECTION_VA + EXPORT_DIR_OFF
    struct.pack_into(
        "<IIHHIIIIIII",
        section,
        EXPORT_DIR_OFF,
        0,  # Characteristics
        0,  # TimeDateStamp
        0,  # MajorVersion
        0,  # MinorVersion
        SECTION_VA + EXPORT_DLLNAME_OFF,  # Name
        1,  # Base ordinal
        1,  # NumberOfFunctions
        1,  # NumberOfNames
        SECTION_VA + EXPORT_EAT_OFF,  # AddressOfFunctions
        SECTION_VA + EXPORT_AN_OFF,  # AddressOfNames
        SECTION_VA + EXPORT_AO_OFF,  # AddressOfNameOrdinals
    )
    # One export pointing at a function RVA inside the section.
    struct.pack_into("<I", section, EXPORT_EAT_OFF, SECTION_VA + 0x80)
    struct.pack_into(
        "<I", section, EXPORT_AN_OFF, SECTION_VA + EXPORT_FUNCNAME_OFF
    )
    struct.pack_into("<H", section, EXPORT_AO_OFF, 0)

    # --- Base relocation block ---------------------------------------------
    # One slot per relocation type, laid out after the export structures.
    slot_offsets = {}
    next_slot = 0x80
    for reloc_type in reloc_types:
        slot_size = 8 if reloc_type == DIR64 else 4
        slot_offsets[reloc_type] = next_slot
        next_slot += slot_size

    entries = [
        _reloc_word(reloc_type, slot_offsets[reloc_type])
        for reloc_type in reloc_types
    ]
    if HIGHADJ in reloc_types:
        # HIGHADJ consumes the following ABSOLUTE entry as its trailing word.
        highadj_index = reloc_types.index(HIGHADJ)
        entries.insert(highadj_index + 1, _reloc_word(ABSOLUTE, 0))

    if bad_reloc_offset is not None:
        entries.append(_reloc_word(HIGHLOW, bad_reloc_offset))

    # Terminate with padding so the block keeps a dword-aligned size.
    if len(entries) % 2:
        entries.append(_reloc_word(ABSOLUTE, 0))

    block_size = 8 + 2 * len(entries)
    struct.pack_into(
        "<II", section, RELOC_DIR_OFF, SECTION_VA, block_size
    )
    for index, word in enumerate(entries):
        struct.pack_into(
            "<H", section, RELOC_ENTRIES_OFF + 2 * index, word
        )

    # --- Data directories ---------------------------------------------------
    directories = [(0, 0)] * 16
    directories[0] = (export_rva, EXPORT_DIR_SIZE)
    if include_reloc_directory:
        directories[5] = (SECTION_VA + RELOC_DIR_OFF, block_size)

    if is_64:
        optional = struct.pack(
            "<HBBII",
            magic,
            14,  # MajorLinkerVersion
            0,  # MinorLinkerVersion
            SECTION_RAW_SIZE,  # SizeOfCode
            0,  # SizeOfInitializedData
        )
        optional += struct.pack("<I", 0)  # SizeOfUninitializedData
        optional += struct.pack("<II", SECTION_VA, SECTION_VA)  # EP, BaseOfCode
        optional += struct.pack("<Q", image_base)
        optional += struct.pack(
            "<II", SECTION_ALIGNMENT, FILE_ALIGNMENT
        )
        optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        optional += struct.pack("<I", 0)  # Win32VersionValue
        optional += struct.pack(
            "<II", 2 * SECTION_ALIGNMENT, HEADERS_RAW_SIZE
        )
        optional += struct.pack("<IHH", 0, 2, 0x8100)
        optional += struct.pack(
            "<QQQQII",
            0x100000,  # SizeOfStackReserve
            0x1000,  # SizeOfStackCommit
            0x100000,  # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
            0,  # LoaderFlags
            16,  # NumberOfRvaAndSizes
        )
    else:
        optional = struct.pack(
            "<HBBIII",
            magic,
            14,
            0,
            SECTION_RAW_SIZE,
            0,
            0,
        )
        optional += struct.pack(
            "<III", SECTION_VA, SECTION_VA, SECTION_VA
        )  # EP, BaseOfCode, BaseOfData
        optional += struct.pack("<I", image_base)
        optional += struct.pack(
            "<II", SECTION_ALIGNMENT, FILE_ALIGNMENT
        )
        optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        optional += struct.pack("<I", 0)
        optional += struct.pack(
            "<II", 2 * SECTION_ALIGNMENT, HEADERS_RAW_SIZE
        )
        optional += struct.pack("<IHH", 0, 2, 0x8100)
        optional += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        optional += struct.pack("<II", 0, 16)

    for rva, size in directories:
        optional += struct.pack("<II", rva, size)
    assert len(optional) == size_of_optional_header

    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        0x0102,  # Characteristics
    )

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00\x00",
        SECTION_RAW_SIZE,  # Misc_VirtualSize
        SECTION_VA,
        SECTION_RAW_SIZE,  # SizeOfRawData
        SECTION_RAW_OFFSET,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 0x40)

    headers = (
        bytes(dos)
        + b"PE\x00\x00"
        + file_header
        + optional
        + section_header
    )
    headers = headers.ljust(SECTION_RAW_OFFSET, b"\x00")
    return bytes(headers) + bytes(section), slot_offsets


def _section_bytes(pe):
    return bytes(pe.sections[0].get_data())


def _export_bytes(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        pe.parse_data_directories(directories=[0])
    export = pe.DIRECTORY_ENTRY_EXPORT
    struct_offset = export.struct.get_file_offset()
    return bytes(pe.__data__[struct_offset : struct_offset + EXPORT_DIR_SIZE])


# ---------------------------------------------------------------------------
# Relocation type coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("machine", "reloc_types"),
    [
        (0x14C, (HIGH, LOW, HIGHLOW, HIGHADJ)),
        (0x8664, (DIR64,)),
    ],
)
def test_supported_relocation_types_apply_the_base_delta(machine, reloc_types):
    raw, slot_offsets = _build_pe(machine=machine, reloc_types=reloc_types)
    pe = pefile.PE(data=raw)
    original_base = pe.OPTIONAL_HEADER.ImageBase
    new_base = original_base + 0x12340000
    delta = new_base - original_base

    view = pe.get_relocated_image(new_base)

    assert view.OPTIONAL_HEADER.ImageBase == new_base
    assert pe.OPTIONAL_HEADER.ImageBase == original_base

    section = view.sections[0]
    for reloc_type in reloc_types:
        offset = slot_offsets[reloc_type]
        if reloc_type == DIR64:
            original = struct.unpack_from("<Q", raw, SECTION_RAW_OFFSET + offset)[0]
            relocated = section.get_data()[offset : offset + 8]
            assert struct.unpack("<Q", relocated)[0] == (original + delta) & (
                (1 << 64) - 1
            )
        elif reloc_type == HIGHLOW:
            original = struct.unpack_from("<I", raw, SECTION_RAW_OFFSET + offset)[0]
            relocated = section.get_data()[offset : offset + 4]
            assert struct.unpack("<I", relocated)[0] == (original + delta) & 0xFFFFFFFF
        elif reloc_type == HIGH:
            original = struct.unpack_from("<H", raw, SECTION_RAW_OFFSET + offset)[0]
            relocated = section.get_data()[offset : offset + 2]
            expected = ((original + delta) >> 16) & 0xFFFF
            assert struct.unpack("<H", relocated)[0] == expected
        elif reloc_type == LOW:
            original = struct.unpack_from("<H", raw, SECTION_RAW_OFFSET + offset)[0]
            relocated = section.get_data()[offset : offset + 2]
            expected = (original + delta) & 0xFFFF
            assert struct.unpack("<H", relocated)[0] == expected
        elif reloc_type == HIGHADJ:
            original = struct.unpack_from("<H", raw, SECTION_RAW_OFFSET + offset)[0]
            relocated = section.get_data()[offset : offset + 2]
            expected = (
                (((original << 16) + delta) & 0xFFFF0000) >> 16
            )
            assert struct.unpack("<H", relocated)[0] == expected

    view.close()


# ---------------------------------------------------------------------------
# Non-destructive contract
# ---------------------------------------------------------------------------


def test_consecutive_bases_are_computed_from_the_original_state():
    raw, slot_offsets = _build_pe(reloc_types=(HIGHLOW,))
    pe = pefile.PE(data=raw)
    original_base = pe.OPTIONAL_HEADER.ImageBase
    slot = slot_offsets[HIGHLOW]
    original_dword = struct.unpack_from("<I", raw, SECTION_RAW_OFFSET + slot)[0]

    first_base = original_base + 0x10000
    second_base = original_base + 0x70000
    first = pe.get_relocated_image(first_base)
    second = pe.get_relocated_image(second_base)

    first_value = struct.unpack(
        "<I", first.sections[0].get_data()[slot : slot + 4]
    )[0]
    second_value = struct.unpack(
        "<I", second.sections[0].get_data()[slot : slot + 4]
    )[0]

    # Each view is relative to the *original* image, not to the previous view.
    assert first_value == (original_dword + 0x10000) & 0xFFFFFFFF
    assert second_value == (original_dword + 0x70000) & 0xFFFFFFFF
    assert second_value - first_value == 0x60000

    # The two views and the source PE do not share backing storage.
    assert first.__data__ is not second.__data__
    assert first.__data__ is not pe.__data__
    first.close()
    second.close()


def test_original_object_bytes_and_export_structure_never_change():
    raw, _ = _build_pe(reloc_types=(HIGHLOW, DIR64))
    pe = pefile.PE(data=raw)
    # Force the export directory to be parsed so structure mutation would show.
    pe.parse_data_directories(directories=[0])
    original_export_bytes = _export_bytes(pe)
    original_section = _section_bytes(pe)
    original_base = pe.OPTIONAL_HEADER.ImageBase

    for base in (original_base + 0x10000, original_base + 0xABC0000):
        view = pe.get_relocated_image(base)
        view.close()

    assert bytes(pe.__data__) == raw
    assert _section_bytes(pe) == original_section
    assert pe.OPTIONAL_HEADER.ImageBase == original_base
    assert _export_bytes(pe) == original_export_bytes
    export = pe.DIRECTORY_ENTRY_EXPORT
    assert export.struct.Name == SECTION_VA + EXPORT_DLLNAME_OFF
    assert export.symbols[0].name == b"ExportedFunc"
    assert export.symbols[0].address == SECTION_VA + 0x80


def test_missing_relocation_directory_raises_and_leaves_source_intact():
    raw, _ = _build_pe(include_reloc_directory=False)
    pe = pefile.PE(data=raw)
    snapshot = bytes(pe.__data__)
    original_base = pe.OPTIONAL_HEADER.ImageBase

    with pytest.raises(pefile.RelocationError):
        pe.get_relocated_image(original_base + 0x10000)

    assert bytes(pe.__data__) == snapshot
    assert pe.OPTIONAL_HEADER.ImageBase == original_base
    assert not pe.has_relocs()


def test_out_of_bounds_target_raises_without_mutating_the_source():
    # The target RVA lies one word inside the last dword of the raw data,
    # so a full dword cannot be read from the section and relocation fails.
    raw, _ = _build_pe(
        reloc_types=(HIGHLOW,), bad_reloc_offset=SECTION_RAW_SIZE - 3
    )
    pe = pefile.PE(data=raw)
    snapshot = bytes(pe.__data__)
    original_base = pe.OPTIONAL_HEADER.ImageBase

    with pytest.raises(pefile.RelocationError):
        pe.get_relocated_image(original_base + 0x10000)

    assert bytes(pe.__data__) == snapshot
    assert pe.OPTIONAL_HEADER.ImageBase == original_base
    assert _section_bytes(pe) == bytes(raw[SECTION_RAW_OFFSET:])


def test_failure_halfway_through_table_does_not_partially_relocate_source():
    # The valid entry is processed first on the throwaway copy; the second
    # entry then fails. The source must not retain the first entry's fixup.
    raw, slot_offsets = _build_pe(
        reloc_types=(HIGHLOW,), bad_reloc_offset=SECTION_RAW_SIZE - 3
    )
    pe = pefile.PE(data=raw)
    good_slot = slot_offsets[HIGHLOW]
    original_value = struct.unpack_from(
        "<I", raw, SECTION_RAW_OFFSET + good_slot
    )[0]

    with pytest.raises(pefile.RelocationError):
        pe.get_relocated_image(pe.OPTIONAL_HEADER.ImageBase + 0x20000)

    surviving = struct.unpack(
        "<I", pe.sections[0].get_data()[good_slot : good_slot + 4]
    )[0]
    assert surviving == original_value


def test_dangling_highadj_entry_raises_and_leaves_source_intact():
    # A HIGHADJ entry must be followed by the word it adjusts. Hand-craft a
    # block where the HIGHADJ is the last entry, making the table corrupt.
    raw, _ = _build_pe(reloc_types=(ABSOLUTE,))
    pe = pefile.PE(data=raw)
    snapshot = bytes(pe.__data__)
    base = pe.OPTIONAL_HEADER.ImageBase

    section = bytearray(raw[SECTION_RAW_OFFSET:])
    entries = [_reloc_word(HIGHADJ, 0x80)]
    block_size = 8 + 2 * len(entries)
    struct.pack_into("<II", section, RELOC_DIR_OFF, SECTION_VA, block_size)
    struct.pack_into("<H", section, RELOC_ENTRIES_OFF, entries[0])
    corrupt_raw = raw[:SECTION_RAW_OFFSET] + bytes(section)
    corrupt_pe = pefile.PE(data=corrupt_raw)

    with pytest.raises(pefile.RelocationError):
        corrupt_pe.get_relocated_image(base + 0x20000)

    # Both parsers keep their original bytes and image base.
    assert bytes(corrupt_pe.__data__) == corrupt_raw
    assert corrupt_pe.OPTIONAL_HEADER.ImageBase == base
    assert bytes(pe.__data__) == snapshot


def test_analysis_after_failure_matches_a_fresh_parser():
    good_raw, _ = _build_pe(reloc_types=(HIGHLOW,))
    corrupt_raw, _ = _build_pe(
        reloc_types=(HIGHLOW,), bad_reloc_offset=SECTION_RAW_SIZE - 3
    )
    pe = pefile.PE(data=good_raw)
    base = pe.OPTIONAL_HEADER.ImageBase

    # A deliberately failing request against a different, corrupt sample must
    # not leave any state behind on the parser used for analysis.
    with pytest.raises(pefile.RelocationError):
        pefile.PE(data=corrupt_raw).get_relocated_image(base + 0x20000)

    # The analysis on the good sample after that failure equals a view produced
    # from a brand new parser over the same bytes.
    recovered = pe.get_relocated_image(base + 0x50000)
    fresh = pefile.PE(data=good_raw).get_relocated_image(base + 0x50000)

    assert recovered.OPTIONAL_HEADER.ImageBase == fresh.OPTIONAL_HEADER.ImageBase
    assert bytes(recovered.__data__) == bytes(fresh.__data__)
    assert recovered.get_memory_mapped_image() == fresh.get_memory_mapped_image()
    recovered.close()
    fresh.close()


# ---------------------------------------------------------------------------
# Interleaved scenario requested in the task
# ---------------------------------------------------------------------------


def test_interleaved_two_bases_and_one_failure():
    raw, slot_offsets = _build_pe(reloc_types=(HIGHLOW,))
    corrupt_raw, _ = _build_pe(
        reloc_types=(HIGHLOW,), bad_reloc_offset=SECTION_RAW_SIZE - 3
    )
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    slot = slot_offsets[HIGHLOW]
    original_dword = struct.unpack_from(
        "<I", raw, SECTION_RAW_OFFSET + slot
    )[0]
    original_export_bytes = _export_bytes(pe)
    assert pe.DIRECTORY_ENTRY_EXPORT.symbols[0].name == b"ExportedFunc"

    base_a = base + 0x10000
    base_b = base + 0x90000

    view_a = pe.get_relocated_image(base_a)
    value_a = struct.unpack(
        "<I", view_a.sections[0].get_data()[slot : slot + 4]
    )[0]

    # Deliberate failing request, interleaved between the two valid ones. It
    # runs on its own corrupt sample so the analyzed object is only observed,
    # never modified.
    with pytest.raises(pefile.RelocationError):
        pefile.PE(data=corrupt_raw).get_relocated_image(base + 0x30000)

    view_b = pe.get_relocated_image(base_b)
    value_b = struct.unpack(
        "<I", view_b.sections[0].get_data()[slot : slot + 4]
    )[0]

    # Valid pointers move by exactly the requested base deltas.
    assert value_a == (original_dword + 0x10000) & 0xFFFFFFFF
    assert value_b == (original_dword + 0x90000) & 0xFFFFFFFF
    assert value_b - value_a == base_b - base_a

    # The original sample's export bytes and structures stay unchanged.
    assert bytes(pe.__data__) == raw
    assert pe.OPTIONAL_HEADER.ImageBase == base
    assert _export_bytes(pe) == original_export_bytes
    assert pe.DIRECTORY_ENTRY_EXPORT.symbols[0].name == b"ExportedFunc"

    view_a.close()
    view_b.close()


# ---------------------------------------------------------------------------
# Legacy in-place entry point and memory-mapped convenience wrapper
# ---------------------------------------------------------------------------


def test_relocate_image_remains_in_place_and_lenient():
    raw, _ = _build_pe(
        reloc_types=(HIGHLOW,), bad_reloc_offset=SECTION_RAW_SIZE - 3
    )
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase

    # The legacy entry must not raise; it records a warning instead. The
    # failure occurs before the image base is committed, so the base stays
    # put even though the first, in-bounds entry was already rewritten.
    pe.relocate_image(base + 0x10000)
    assert pe.OPTIONAL_HEADER.ImageBase == base
    assert any("Relocating image failed" in w for w in pe.get_warnings())
    assert pe.get_dword_at_rva(0x1000 + 0x80) == 0x10000


def test_memory_mapped_image_rebase_is_non_destructive():
    raw, _ = _build_pe(reloc_types=(HIGHLOW,))
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    before = pe.get_memory_mapped_image()

    rebased = pe.get_memory_mapped_image(ImageBase=base + 0x10000)

    assert pe.OPTIONAL_HEADER.ImageBase == base
    assert pe.get_memory_mapped_image() == before
    assert rebased != before


def test_memory_mapped_image_without_reloc_directory_returns_original():
    raw, _ = _build_pe(include_reloc_directory=False)
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase

    mapped = pe.get_memory_mapped_image(ImageBase=base + 0x10000)

    assert mapped == pe.get_memory_mapped_image()
    assert pe.OPTIONAL_HEADER.ImageBase == base
    assert pe.get_warnings()
