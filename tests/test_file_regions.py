"""Tests for the structural file-region view (PE.get_file_regions).

The region view must keep the PE headers, section raw data, the Attribute
Certificate Table (security directory), unclaimed gaps and the genuine trailing
overlay apart. These tests build minimal synthetic PEs so they do not depend on
the (encrypted) external test corpus. They only inspect structure: signatures
are never validated and a certificate table never implies trust.
"""

import struct

import pytest

import pefile


# --------------------------------------------------------------------------
# Minimal synthetic PE builder
# --------------------------------------------------------------------------

def _win_certificate(dw_length, revision=0x0200, cert_type=0x0002, payload=b""):
    body = struct.pack("<IHH", dw_length, revision, cert_type) + payload
    if len(body) > dw_length:
        raise ValueError("payload larger than dwLength")
    return body + b"\x00" * (dw_length - len(body))


def build_pe(sections, file_size, security_dir=(0, 0)):
    """Build a minimal 32-bit PE.

    ``sections`` is a list of ``(name, raw_offset, raw_size)``.
    ``security_dir`` is the ``(VirtualAddress, Size)`` pair placed in data
    directory index 4; for that directory ``VirtualAddress`` is a raw file
    offset, not an RVA.
    """
    e_lfanew = 0x80
    size_of_optional_header = 0xE0
    size_of_headers = 0x200

    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0, 0x5A4D)
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    out = bytearray(b"\x00" * e_lfanew)
    out[:0x40] = dos

    nt = struct.pack("<I", 0x00004550)
    nt += struct.pack(
        "<HHIIIHH",
        0x14C,
        len(sections),
        0,
        0,
        0,
        size_of_optional_header,
        0x0102,
    )

    opt = struct.pack("<HBBIII", 0x10B, 0, 0, 0x200, 0, 0)
    opt += struct.pack(
        "<IIIII", 0x1000, 0x200, 0x400, 0x400000, 0x1000
    )
    opt += struct.pack("<I", 0x200)
    opt += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<II", 0x10000, size_of_headers)
    opt += struct.pack("<IH", 0, 3)
    opt += struct.pack("<H", 0)
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)

    directories = [b"\x00" * 8] * 16
    directories[4] = struct.pack("<II", security_dir[0], security_dir[1])
    opt += b"".join(directories)
    assert len(opt) == size_of_optional_header

    nt += opt
    for index, (name, raw_offset, raw_size) in enumerate(sections):
        section_header = name.encode().ljust(8, b"\x00")
        section_header += struct.pack("<I", raw_size)
        section_header += struct.pack("<I", 0x1000 * (index + 1))
        section_header += struct.pack("<I", raw_size)
        section_header += struct.pack("<I", raw_offset)
        section_header += struct.pack("<II", 0, 0)
        section_header += struct.pack("<HHI", 0, 0, 0x60000020)
        nt += section_header

    out += nt
    out += b"\x00" * (size_of_headers - len(out))
    out += b"\x00" * (file_size - len(out))
    return bytes(out[:file_size])


def _assert_ranges_read_back(data, view):
    for region in view.regions:
        assert region.start <= region.end <= len(data)
        assert region.data() == data[region.start:region.end]
        assert view.read_region(region) == data[region.start:region.end]


# --------------------------------------------------------------------------
# Required scenarios
# --------------------------------------------------------------------------

def test_normal_certificate_table_is_not_overlay():
    entry_one = _win_certificate(0x10, payload=b"AAAA")
    entry_two = _win_certificate(0x18, payload=b"BBBBBBBB")
    certificate = entry_one + entry_two
    assert len(certificate) == 0x28

    data = bytearray(
        build_pe([(".text", 0x200, 0x200)], 0x428, security_dir=(0x400, 0x28))
    )
    data[0x400:0x428] = certificate
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    assert view.anomaly_codes() == []
    assert view.overlay is None
    assert view.gaps == []

    table = view.certificate_table
    assert (table.start, table.end) == (0x400, 0x428)
    assert table.source == "DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_SECURITY]"

    assert len(view.certificate_entries) == 2
    first, second = view.certificate_entries
    assert (first.file_offset, first.dwLength) == (0x400, 0x10)
    assert (second.file_offset, second.dwLength) == (0x410, 0x18)
    assert first.wCertificateType == pefile.WIN_CERT_TYPE_PKCS_SIGNED_DATA
    assert first.certificate_type_name == "WIN_CERT_TYPE_PKCS_SIGNED_DATA"
    assert first.region.data() == entry_one
    assert second.region.data() == entry_two


def test_appended_data_after_certificate_is_the_only_overlay():
    entry_one = _win_certificate(0x10, payload=b"AAAA")
    entry_two = _win_certificate(0x18, payload=b"BBBBBBBB")
    certificate = entry_one + entry_two
    appended = b"OVERLAY-PAYLOAD-12345"

    data = bytearray(
        build_pe(
            [(".text", 0x200, 0x200)],
            0x428 + len(appended),
            security_dir=(0x400, 0x28),
        )
    )
    data[0x400:0x428] = certificate
    data[0x428:] = appended
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    assert view.anomaly_codes() == []
    assert len(view.certificate_entries) == 2
    overlay = view.overlay
    assert (overlay.start, overlay.end) == (0x428, len(data))
    assert view.get_overlay_data() == appended
    assert view.certificate_table.end == 0x428


def test_forged_overlapping_certificate_directory_is_flagged():
    entry_one = _win_certificate(0x10, payload=b"AAAA")
    entry_two = _win_certificate(0x18, payload=b"BBBBBBBB")
    certificate = entry_one + entry_two

    data = bytearray(
        build_pe([(".text", 0x200, 0x400)], 0x600, security_dir=(0x300, 0x40))
    )
    data[0x300:0x300 + len(certificate)] = certificate
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    codes = view.anomaly_codes()
    assert pefile.REGION_ANOMALY_CERTIFICATE_OVERLAPS_SECTION in codes
    # The conflict is attached to both the certificate table and the section.
    table = view.certificate_table
    section = view.sections[0]
    assert any(
        anomaly.code == pefile.REGION_ANOMALY_CERTIFICATE_OVERLAPS_SECTION
        for anomaly in table.anomalies
    )
    assert any(
        anomaly.code == pefile.REGION_ANOMALY_CERTIFICATE_OVERLAPS_SECTION
        for anomaly in section.anomalies
    )
    # No bytes are mislabeled as overlay while the section covers them.
    assert view.overlay is None


# --------------------------------------------------------------------------
# Security directory semantics and malformed structures
# --------------------------------------------------------------------------

def test_security_directory_out_of_bounds():
    data = build_pe(
        [(".text", 0x200, 0x200)], 0x400, security_dir=(0x500, 0x100)
    )
    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    codes = view.anomaly_codes()
    assert pefile.REGION_ANOMALY_SECURITY_DIR_OUT_OF_BOUNDS in codes
    table = view.certificate_table
    assert (table.declared_start, table.declared_end) == (0x500, 0x600)
    assert table.size == 0  # nothing readable, yet the claim is retained
    assert view.certificate_entries == []


def test_certificate_entry_extends_past_eof():
    data = bytearray(
        build_pe([(".text", 0x200, 0x200)], 0x418, security_dir=(0x400, 0x20))
    )
    data[0x400:0x418] = _win_certificate(0x20, payload=b"X" * 16)[:0x18]
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    codes = view.anomaly_codes()
    assert pefile.REGION_ANOMALY_SECURITY_DIR_OUT_OF_BOUNDS in codes
    assert pefile.REGION_ANOMALY_CERT_ENTRY_OUT_OF_BOUNDS in codes
    entry = view.certificate_entries[0]
    assert (entry.region.declared_start, entry.region.declared_end) == (
        0x400,
        0x420,
    )
    assert (entry.region.start, entry.region.end) == (0x400, 0x418)


def test_truncated_certificate_header_is_explicit():
    data = bytearray(
        build_pe([(".text", 0x200, 0x200)], 0x406, security_dir=(0x400, 0x28))
    )
    data[0x400:0x406] = b"\x10\x00\x00\x00\x00\x02"
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    codes = view.anomaly_codes()
    assert pefile.REGION_ANOMALY_CERT_ENTRY_TRUNCATED_HEADER in codes
    assert pefile.REGION_ANOMALY_SECURITY_DIR_OUT_OF_BOUNDS in codes
    assert view.certificate_entries == []


def test_misaligned_certificate_entry_is_flagged():
    entry_one = _win_certificate(0x10, payload=b"AAAA")
    entry_two = _win_certificate(0x14, payload=b"C" * 12)
    certificate = entry_one + entry_two + b"\x00" * 4  # table total 0x30

    data = bytearray(
        build_pe([(".text", 0x200, 0x200)], 0x438, security_dir=(0x400, 0x30))
    )
    data[0x400:0x430] = certificate
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    assert pefile.REGION_ANOMALY_CERT_ENTRY_NOT_ALIGNED in view.anomaly_codes()
    assert len(view.certificate_entries) == 2


def test_certificate_overlapping_multiple_sections_reports_each():
    # The certificate table sorts between two sections, exercising both
    # orderings of the pairwise overlap check.
    data = build_pe(
        [(".first", 0x200, 0x200), (".second", 0x500, 0x200)],
        0x700,
        security_dir=(0x300, 0x300),
    )
    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    section_overlaps = [
        anomaly
        for anomaly in view.anomalies
        if anomaly.code == pefile.REGION_ANOMALY_CERTIFICATE_OVERLAPS_SECTION
    ]
    assert len(section_overlaps) == 2
    named = {message for message in (anomaly.message for anomaly in section_overlaps)}
    assert any(".first" in message for message in named)
    assert any(".second" in message for message in named)


def test_certificate_overlapping_header_is_flagged():
    data = build_pe(
        [(".text", 0x200, 0x200)], 0x400, security_dir=(0x100, 0x20)
    )
    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    assert pefile.REGION_ANOMALY_CERTIFICATE_OVERLAPS_HEADER in view.anomaly_codes()


def test_unclaimed_gap_is_distinct_from_overlay():
    # Header [0,0x200), hole [0x200,0x400), section [0x400,0x600),
    # certificate [0x600,0x610), trailing overlay [0x610,0x800).
    data = build_pe(
        [(".text", 0x400, 0x200)], 0x800, security_dir=(0x600, 0x10)
    )
    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    gaps = view.gaps
    assert len(gaps) == 1
    assert (gaps[0].start, gaps[0].end) == (0x200, 0x400)
    assert (view.overlay.start, view.overlay.end) == (0x610, 0x800)


def test_no_overlay_when_file_ends_with_section():
    data = build_pe([(".text", 0x200, 0x200)], 0x400)
    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    assert view.overlay is None
    assert view.certificate_table is None
    assert view.anomaly_codes() == []


def test_out_of_bounds_section_is_reported_not_swallowed():
    data = build_pe([(".text", 0x200, 0x400)], 0x400)  # declares up to 0x600
    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    assert pefile.REGION_ANOMALY_SECTION_OUT_OF_BOUNDS in view.anomaly_codes()
    section = view.sections[0]
    assert (section.declared_start, section.declared_end) == (0x200, 0x600)
    assert (section.start, section.end) == (0x200, 0x400)
    assert section.is_truncated


def test_presence_of_certificate_table_does_not_mark_trusted():
    # The view exposes structure only; there is no trust/validity attribute.
    entry = _win_certificate(0x10, payload=b"AAAA")
    data = bytearray(
        build_pe([(".text", 0x200, 0x200)], 0x410, security_dir=(0x400, 0x10))
    )
    data[0x400:0x410] = entry
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    assert not hasattr(view, "trusted")
    assert not hasattr(view, "signature_valid")
    assert len(view.certificate_entries) == 1
    assert view.anomaly_codes() == []


def test_region_view_covers_full_file_without_double_counting_overlay():
    entry_one = _win_certificate(0x10, payload=b"AAAA")
    entry_two = _win_certificate(0x18, payload=b"BBBBBBBB")
    certificate = entry_one + entry_two
    appended = b"EXTRA"

    data = bytearray(
        build_pe(
            [(".text", 0x200, 0x200)],
            0x428 + len(appended),
            security_dir=(0x400, 0x28),
        )
    )
    data[0x400:0x428] = certificate
    data[0x428:] = appended
    data = bytes(data)

    view = pefile.PE(data=data).get_file_regions()
    _assert_ranges_read_back(data, view)

    covered = bytearray(len(data))
    for region in view.regions:
        if region.kind == pefile.REGION_KIND_CERTIFICATE_ENTRY:
            continue  # entries live inside the table region
        covered[region.start:region.end] = b"\x01" * region.size
    assert bytes(covered) == b"\x01" * len(data)
