import struct

import pefile

IMAGE_BASE_32 = 0x400000
IMAGE_BASE_64 = 0x140000000

# name, VirtualAddress, Misc_VirtualSize, PointerToRawData, SizeOfRawData, Characteristics
SECTIONS = (
    (b".text", 0x1000, 0x200, 0x200, 0x200, 0x60000020),  # code, execute, read
    (b".rdata", 0x2000, 0x200, 0x400, 0x200, 0x40000040),  # initialized data, read
    (b".data", 0x3000, 0x1000, 0x600, 0x200, 0xC0000040),  # initialized data, read, write
)
SIZE_OF_IMAGE = 0x4000
TLS_DIR_RVA = 0x2000
TLS_DIR_FILE_OFFSET = 0x400
CALLBACKS_RVA = 0x2100
CALLBACKS_FILE_OFFSET = 0x500

# Two normal callbacks (.text), one target in a non-executable section
# (.rdata), one target beyond the image, one duplicate of the first, and
# one target in the zero-filled tail of .data.
CALLBACK_RVAS = (0x1010, 0x1020, 0x2080, 0x5000, 0x1010, 0x3800)


def _build_pe(
    pe_plus=False,
    callbacks_rva=CALLBACKS_RVA,
    callback_rvas=CALLBACK_RVAS,
    terminator=True,
    with_tls=True,
):
    image_base = IMAGE_BASE_64 if pe_plus else IMAGE_BASE_32
    pointer_size = 8 if pe_plus else 4
    machine = 0x8664 if pe_plus else 0x14C
    magic = 0x20B if pe_plus else 0x10B
    opt_size = 0xF0 if pe_plus else 0xE0
    characteristics = 0x22 if pe_plus else 0x102

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    file_header = struct.pack(
        "<HHIIIHH", machine, len(SECTIONS), 0, 0, 0, opt_size, characteristics
    )

    directories = [(0, 0)] * 16
    if with_tls:
        directories[9] = (TLS_DIR_RVA, 40 if pe_plus else 24)

    if pe_plus:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            magic, 0, 0,
            0x200, 0x400, 0,
            0x1000,
            0x1000,
            image_base,
            0x1000, 0x200,
            6, 0, 0, 0, 6, 0,
            0,
            SIZE_OF_IMAGE, 0x200,
            0,
            3, 0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            magic, 0, 0,
            0x200, 0x400, 0,
            0x1000,
            0x1000, 0x2000,
            image_base,
            0x1000, 0x200,
            6, 0, 0, 0, 6, 0,
            0,
            SIZE_OF_IMAGE, 0x200,
            0,
            3, 0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )
    opt += b"".join(struct.pack("<II", rva, size) for rva, size in directories)
    assert len(opt) == opt_size

    section_headers = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            name, vsize, va, raw_size, raw_ptr, 0, 0, 0, 0, chars,
        )
        for name, va, vsize, raw_ptr, raw_size, chars in SECTIONS
    )

    data = bytearray(0x800)
    data[:0x80] = dos
    headers = b"PE\0\0" + file_header + opt + section_headers
    data[0x80 : 0x80 + len(headers)] = headers

    # Fill section raw contents with recognizable bytes.
    for offset in (0x200, 0x400, 0x600):
        data[offset : offset + 0x200] = bytes(
            (offset + i) & 0xFF for i in range(0x200)
        )

    if with_tls:
        callbacks_va = image_base + callbacks_rva
        if pe_plus:
            tls = struct.pack(
                "<QQQQII",
                image_base + 0x3000,
                image_base + 0x3010,
                image_base + 0x3010,
                callbacks_va,
                0,
                0,
            )
        else:
            tls = struct.pack(
                "<IIIIII",
                image_base + 0x3000,
                image_base + 0x3010,
                image_base + 0x3010,
                callbacks_va,
                0,
                0,
            )
        data[TLS_DIR_FILE_OFFSET : TLS_DIR_FILE_OFFSET + len(tls)] = tls

        # Only place the array when it lands in .rdata's raw data.
        if 0x2000 <= callbacks_rva < 0x2200:
            fmt = "<Q" if pe_plus else "<I"
            array = b"".join(
                struct.pack(fmt, image_base + rva) for rva in callback_rvas
            )
            if terminator:
                array += b"\0" * pointer_size
            offset = TLS_DIR_FILE_OFFSET + (callbacks_rva - TLS_DIR_RVA)
            data[offset : offset + len(array)] = array

    return bytes(data)


def test_tls_callbacks_pe32():
    data = _build_pe()
    pe = pefile.PE(data=data)
    result = pe.get_tls_callbacks()

    assert result is not None
    assert result.pointer_size == 4
    assert result.callbacks_va == IMAGE_BASE_32 + CALLBACKS_RVA
    assert result.callbacks_rva == CALLBACKS_RVA
    assert not result.truncated
    assert result.truncation_reason is None
    assert len(result.callbacks) == len(CALLBACK_RVAS)

    callbacks = result.callbacks

    # Two normal callbacks: targets in the executable .text section.
    for index, rva in enumerate((0x1010, 0x1020)):
        cb = callbacks[index]
        assert cb.index == index
        assert cb.va == IMAGE_BASE_32 + rva
        assert cb.rva == rva
        # Raw byte evidence: the slot contents exactly as stored.
        assert cb.raw == struct.pack("<I", IMAGE_BASE_32 + rva)
        assert cb.raw == data[CALLBACKS_FILE_OFFSET + 4 * index :][:4]
        assert cb.slot_rva == CALLBACKS_RVA + 4 * index
        assert cb.slot_file_offset == CALLBACKS_FILE_OFFSET + 4 * index
        assert cb.file_offset == 0x200 + (rva - 0x1000)
        assert cb.in_image
        assert not cb.in_zero_fill
        assert not cb.duplicate
        assert cb.section_name == b".text"
        assert cb.permissions == {"read": True, "write": False, "execute": True}
        assert cb.executable is True

    # Target in a non-executable section.
    cb = callbacks[2]
    assert cb.rva == 0x2080
    assert cb.raw == struct.pack("<I", IMAGE_BASE_32 + 0x2080)
    assert cb.section_name == b".rdata"
    assert cb.permissions == {"read": True, "write": False, "execute": False}
    assert cb.executable is False
    assert cb.in_image
    assert cb.file_offset == 0x480

    # Target beyond the image: nothing may be claimed about executability.
    cb = callbacks[3]
    assert cb.rva == 0x5000
    assert cb.raw == struct.pack("<I", IMAGE_BASE_32 + 0x5000)
    assert not cb.in_image
    assert cb.section_name is None
    assert cb.permissions is None
    assert cb.executable is None
    assert cb.file_offset is None

    # Duplicate of the first callback.
    cb = callbacks[4]
    assert cb.va == IMAGE_BASE_32 + 0x1010
    assert cb.duplicate
    assert not callbacks[0].duplicate

    # Target in the zero-filled tail of .data (past SizeOfRawData).
    cb = callbacks[5]
    assert cb.rva == 0x3800
    assert cb.in_image
    assert cb.in_zero_fill
    assert cb.file_offset is None
    assert cb.section_name == b".data"
    assert cb.permissions == {"read": True, "write": True, "execute": False}
    assert cb.executable is False


def test_tls_callbacks_pe64():
    data = _build_pe(pe_plus=True)
    pe = pefile.PE(data=data)
    result = pe.get_tls_callbacks()

    assert result is not None
    assert result.pointer_size == 8
    assert result.callbacks_va == IMAGE_BASE_64 + CALLBACKS_RVA
    assert result.callbacks_rva == CALLBACKS_RVA
    assert not result.truncated
    assert len(result.callbacks) == len(CALLBACK_RVAS)

    callbacks = result.callbacks
    for index, rva in enumerate(CALLBACK_RVAS):
        assert callbacks[index].va == IMAGE_BASE_64 + rva
        assert callbacks[index].rva == rva
        assert callbacks[index].raw == struct.pack("<Q", IMAGE_BASE_64 + rva)
        assert callbacks[index].raw == data[CALLBACKS_FILE_OFFSET + 8 * index :][:8]

    assert callbacks[0].executable is True
    assert callbacks[2].executable is False
    assert callbacks[3].executable is None
    assert callbacks[4].duplicate
    assert callbacks[5].in_zero_fill


def test_tls_callbacks_imagebase_adjustment():
    pe = pefile.PE(data=_build_pe())
    before = pe.get_tls_callbacks()

    new_image_base = 0x500000
    difference = new_image_base - IMAGE_BASE_32
    # Adjust the image base and the VAs stored in the TLS directory (the
    # same fields relocate_image() fixes up when a relocation directory
    # is present).
    pe.OPTIONAL_HEADER.ImageBase = new_image_base
    tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
    tls_struct.AddressOfCallBacks += difference
    # Apply the base-relocation fixups the loader would apply to the slots.
    for cb in before.callbacks:
        pe.set_dword_at_rva(cb.slot_rva, cb.va + difference)

    after = pe.get_tls_callbacks()
    assert after.callbacks_va == new_image_base + CALLBACKS_RVA
    assert after.callbacks_rva == CALLBACKS_RVA
    assert len(after.callbacks) == len(before.callbacks)
    for old, new in zip(before.callbacks, after.callbacks):
        # VAs follow the new ImageBase; RVAs and mappings stay put.
        assert new.va == old.va + difference
        assert new.rva == old.rva
        assert new.raw == struct.pack("<I", old.va + difference)
        assert new.section_name == old.section_name
        assert new.permissions == old.permissions
        assert new.executable == old.executable
        assert new.in_image == old.in_image
        assert new.in_zero_fill == old.in_zero_fill
        assert new.duplicate == old.duplicate


def test_tls_callbacks_truncated_by_limit():
    pe = pefile.PE(data=_build_pe())
    result = pe.get_tls_callbacks(max_callbacks=3)

    assert result.truncated
    assert result.truncation_reason == "limit"
    assert len(result.callbacks) == 3


def test_tls_callbacks_unreadable_array():
    # The callback array VA points beyond the image: the first slot
    # cannot be mapped to file contents.
    pe = pefile.PE(data=_build_pe(callbacks_rva=0x6000))
    result = pe.get_tls_callbacks()

    assert result.truncated
    assert result.truncation_reason == "unreadable"
    assert result.callbacks == []


def test_tls_callbacks_array_in_zero_fill():
    # The array itself lies in the zero-filled tail of .data: it reads
    # as zero, i.e. an immediate terminator.
    pe = pefile.PE(data=_build_pe(callbacks_rva=0x3800))
    result = pe.get_tls_callbacks()

    assert not result.truncated
    assert result.truncation_reason is None
    assert result.callbacks == []


def test_tls_callbacks_no_tls_directory():
    pe = pefile.PE(data=_build_pe(with_tls=False))
    assert pe.get_tls_callbacks() is None
