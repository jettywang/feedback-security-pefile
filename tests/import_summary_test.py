"""Tests for the auditable import summary and imphash compatibility.

These tests build minimal, fully self-contained PE32 images in memory (no
external corpus). Three families of synthetic samples are used:

* a normal import table mixing named imports, a duplicate import and an
  ordinal import resolved through a synthetic fallback;
* an ordinal-only table that references an unknown DLL;
* a truncated image whose import directory loses a whole descriptor's thunk
  data, leaving a small but parseable fragment.

They assert that the traditional imphash keeps its value, that the new
summary can independently recompute that hash from its declared items, and
that an incomplete summary can never be mistaken for a trustworthy
same-family signal.
"""

import struct
from hashlib import md5

import pytest

from export_test import PE_32

import pefile

# The template's single .rdata section maps RVA == file offset, which makes
# hand-laying import structures straightforward.
_DESC_RVA = 0x200
_ILT_RVA = 0x240
_IAT_RVA = 0x300
_STRING_RVA = 0x400
_ORDINAL_FLAG = pefile.IMAGE_ORDINAL_FLAG
_DATA_DIRECTORY_OFFSET = 200 + 96 + pefile.DIRECTORY_ENTRY[
    "IMAGE_DIRECTORY_ENTRY_IMPORT"
] * 8


def _build_pe(imports_per_dll):
    """Assemble a PE32 image from ``(dll, [(name, ordinal), ...])`` groups.

    A ``None`` name with an ordinal produces an import-by-ordinal thunk.
    """

    data = bytearray(PE_32)
    cursor = _STRING_RVA

    def place(blob):
        nonlocal cursor
        rva = cursor
        data[cursor : cursor + len(blob)] = blob
        cursor += len(blob)
        return rva

    descriptors = []
    ilt_rva = _ILT_RVA
    iat_rva = _IAT_RVA
    for dll, symbols in imports_per_dll:
        dll_rva = place(dll + b"\x00")
        table_start = ilt_rva
        iat_start = iat_rva
        thunk_rva = ilt_rva
        for name, ordinal in symbols:
            if ordinal is not None:
                value = _ORDINAL_FLAG | (ordinal & 0xFFFF)
            else:
                value = place(b"\x00\x00" + name + b"\x00")
            data[thunk_rva : thunk_rva + 4] = struct.pack("<I", value)
            data[iat_rva : iat_rva + 4] = struct.pack("<I", value)
            thunk_rva += 4
            iat_rva += 4
        data[thunk_rva : thunk_rva + 4] = b"\x00" * 4
        data[iat_rva : iat_rva + 4] = b"\x00" * 4
        iat_rva += 4
        ilt_rva = thunk_rva + 4
        descriptors.append((table_start, dll_rva, iat_start))

    descriptor_rva = _DESC_RVA
    for original_first_thunk, name_rva, first_thunk in descriptors:
        data[descriptor_rva : descriptor_rva + 20] = struct.pack(
            "<IIIII", original_first_thunk, 0, 0, name_rva, first_thunk
        )
        descriptor_rva += 20
    data[descriptor_rva : descriptor_rva + 20] = b"\x00" * 20

    data[_DATA_DIRECTORY_OFFSET : _DATA_DIRECTORY_OFFSET + 8] = struct.pack(
        "<II", _DESC_RVA, len(descriptors) * 20
    )
    return bytes(data)


def _section_raw_size_field_offset(image):
    pe = pefile.PE(data=image)
    section = pe.sections[0]
    # get_field_absolute_offset already returns an absolute file offset.
    offset = section.get_field_absolute_offset("SizeOfRawData")
    pointer_to_raw_data = section.PointerToRawData
    pe.close()
    return offset, pointer_to_raw_data


def _truncate(image, cut_at):
    """Shorten an image and shrink its section to keep the fragment valid."""

    raw_size_offset, pointer_to_raw_data = _section_raw_size_field_offset(image)
    blob = bytearray(image[:cut_at])
    blob[raw_size_offset : raw_size_offset + 4] = struct.pack(
        "<I", cut_at - pointer_to_raw_data
    )
    return bytes(blob)


@pytest.fixture(scope="module")
def normal_image():
    return _build_pe(
        [
            (
                b"kernel32.dll",
                [
                    (b"CreateFileA", None),
                    (b"CloseHandle", None),
                    (b"CloseHandle", None),  # deliberate duplicate
                ],
            ),
            (
                b"mylib.ocx",
                [
                    (None, 7),  # unknown DLL ordinal -> synthetic "ord7"
                    (b"DoThing", None),
                ],
            ),
        ]
    )


@pytest.fixture(scope="module")
def ordinal_only_image():
    return _build_pe(
        [(b"unknownlib.dll", [(None, 1), (None, 2)])]
    )


@pytest.fixture(scope="module")
def truncated_image():
    full = _build_pe(
        [
            (b"kernel32.dll", [(b"CreateFileA", None), (b"CloseHandle", None)]),
            (
                b"advapi32.dll",
                [
                    (b"RegOpenKeyA", None),
                    (b"RegCloseKey", None),
                    (b"RegQueryValueA", None),
                ],
            ),
        ]
    )
    # Keep descriptor A and its data but cut descriptor B's thunk/name region.
    return _truncate(full, 0x430)


def test_imphash_is_unchanged_and_recomputable(normal_image):
    pe = pefile.PE(data=normal_image)
    legacy = pe.get_imphash()
    summary = pe.get_import_summary()

    assert isinstance(legacy, str) and len(legacy) == 32
    # The summary preserves the traditional result byte for byte.
    assert summary.imphash == legacy
    # And the declared hash can be rebuilt from the audited normalized items.
    assert summary.recompute_imphash() == legacy
    pe.close()


def test_normal_summary_is_complete_and_fully_audited(normal_image):
    pe = pefile.PE(data=normal_image)
    summary = pe.get_import_summary()

    assert summary.complete is True
    assert summary.truncated is False
    assert summary.events == []
    assert summary.unresolved == []

    canonicals = [entry.canonical for entry in summary.entries]
    assert canonicals == [
        "kernel32.createfilea",
        "kernel32.closehandle",
        "kernel32.closehandle",
        "mylib.ord7",
        "mylib.dothing",
    ]
    # Ordering is the canonical, never re-sorted, order; indices follow it.
    assert [entry.index for entry in summary.entries] == list(range(5))
    # The duplicate is retained but reported, never silently de-duplicated.
    assert summary.duplicate_count == 1

    ordinal_entry = summary.entries[3]
    assert ordinal_entry.by_ordinal is True
    assert ordinal_entry.ordinal == 7
    assert ordinal_entry.ordinal_resolved is False  # unknown DLL fallback
    assert ordinal_entry.name_offset is None
    assert ordinal_entry.thunk_offset is not None

    named_entry = summary.entries[0]
    assert named_entry.by_ordinal is False
    assert named_entry.ordinal_resolved is True
    assert named_entry.name_offset is not None
    assert named_entry.source_dll_offset is not None
    pe.close()


def test_ordinal_only_unknown_dll_still_hashes_and_is_complete(ordinal_only_image):
    pe = pefile.PE(data=ordinal_only_image)
    legacy = pe.get_imphash()
    summary = pe.get_import_summary()

    assert summary.imphash == legacy
    assert summary.recompute_imphash() == legacy
    assert summary.complete is True
    assert summary.truncated is False
    assert [entry.canonical for entry in summary.entries] == [
        "unknownlib.ord1",
        "unknownlib.ord2",
    ]
    assert all(entry.by_ordinal for entry in summary.entries)
    assert all(not entry.ordinal_resolved for entry in summary.entries)
    assert all(entry.name_offset is None for entry in summary.entries)
    pe.close()


def test_truncated_fragment_is_not_marked_complete(truncated_image):
    pe = pefile.PE(data=truncated_image)
    legacy = pe.get_imphash()
    summary = pe.get_import_summary()

    # A hash still exists, but it only covers the surviving fragment.
    assert summary.imphash == legacy
    assert summary.recompute_imphash() == legacy
    assert [entry.canonical for entry in summary.entries] == [
        "kernel32.createfilea",
        "kernel32.closehandle",
    ]

    # The trust gate must reject this as a same-family basis.
    assert summary.complete is False
    assert summary.truncated is True
    assert summary.events, "a truncation must produce an audit event"
    assert any(
        event.kind == "name_unreadable" for event in summary.events
    )
    for event in summary.events:
        assert event.rva is not None
    pe.close()


def test_incomplete_summary_blocks_family_decision(truncated_image, normal_image):
    """Caller-facing guard: never cluster on an incomplete summary."""

    intact_pe = pefile.PE(data=normal_image)
    damaged_pe = pefile.PE(data=truncated_image)
    intact = intact_pe.get_import_summary()
    damaged = damaged_pe.get_import_summary()

    # Even though both carry a non-empty hash, only the intact one is usable.
    assert intact.imphash and damaged.imphash
    assert intact.complete is True
    assert damaged.complete is False
    # The explicit guard a caller would write before treating the hash as a
    # trustworthy same-family signal.
    assert not damaged.complete
    intact_pe.close()
    damaged_pe.close()


def test_descriptor_truncation_without_parsed_directory_is_untrusted():
    full = _build_pe(
        [
            (b"kernel32.dll", [(b"CreateFileA", None), (b"CloseHandle", None)]),
            (b"advapi32.dll", [(b"RegOpenKeyA", None)]),
        ]
    )
    # Cut inside the second descriptor so the parser cannot build any import
    # directory at all, while the data directory still declares one.
    image = _truncate(full, 0x214)
    pe = pefile.PE(data=image)
    summary = pe.get_import_summary()

    assert not hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
    assert pe.get_imphash() == ""
    assert summary.imphash == ""
    assert summary.recompute_imphash() == ""
    assert summary.entries == []
    assert summary.complete is False
    assert summary.truncated is True
    assert summary.events
    pe.close()


def test_non_utf8_name_is_reported_and_clears_trust():
    image = _build_pe(
        [(b"kernel32.dll", [(b"GoodName", None), (b"Ba\xd8Name", None)])]
    )
    pe = pefile.PE(data=image)
    summary = pe.get_import_summary()

    # The malformed entry is excluded from the hash but not hidden.
    assert [entry.canonical for entry in summary.entries] == [
        "kernel32.goodname"
    ]
    assert summary.complete is False
    assert summary.truncated is False  # present, just malformed
    assert any(event.kind == "invalid_name" for event in summary.events)
    assert summary.recompute_imphash() == pe.get_imphash()
    pe.close()


def test_missing_import_directory_is_empty_but_complete():
    pe = pefile.PE(data=bytes(PE_32))
    summary = pe.get_import_summary()

    assert pe.get_imphash() == ""
    assert summary.imphash == ""
    assert summary.recompute_imphash() == ""
    assert summary.entries == []
    assert summary.complete is True
    assert summary.truncated is False
    pe.close()


def test_normalized_items_match_imphash_algorithm(normal_image):
    """The audited tokens must be the literal strings fed to MD5."""

    pe = pefile.PE(data=normal_image)
    summary = pe.get_import_summary()
    joined = ",".join(entry.canonical for entry in summary.entries)

    assert md5(joined.encode()).hexdigest() == pe.get_imphash()
    pe.close()


def _demo_samples():
    normal = _build_pe(
        [
            (
                b"kernel32.dll",
                [(b"CreateFileA", None), (b"CloseHandle", None)],
            ),
            (b"mylib.ocx", [(None, 7), (b"DoThing", None)]),
        ]
    )
    ordinal_only = _build_pe([(b"unknownlib.dll", [(None, 1), (None, 2)])])
    truncated = _truncate(
        _build_pe(
            [
                (b"kernel32.dll", [(b"CreateFileA", None), (b"CloseHandle", None)]),
                (
                    b"advapi32.dll",
                    [(b"RegOpenKeyA", None), (b"RegCloseKey", None)],
                ),
            ]
        ),
        0x430,
    )
    return normal, ordinal_only, truncated


if __name__ == "__main__":
    for label, image in zip(
        ("normal", "ordinal-only", "truncated"), _demo_samples()
    ):
        pe = pefile.PE(data=image)
        result = pe.get_import_summary()
        print(f"== {label} ==")
        print(f"  legacy imphash        : {pe.get_imphash()}")
        print(f"  summary imphash       : {result.imphash}")
        print(f"  recomputed from items : {result.recompute_imphash()}")
        print(
            "  trustworthy (complete):"
            f" {result.complete} (truncated={result.truncated},"
            f" events={len(result.events)})"
        )
        for entry in result.entries:
            print(
                "    item"
                f" #{entry.index} {entry.canonical} thunk@0x{entry.thunk_offset:x}"
            )
        for event in result.events:
            print(f"    event {event.kind}: {event.detail}")
        pe.close()

