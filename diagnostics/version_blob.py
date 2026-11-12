"""Construct VS_VERSIONINFO blobs with byte-level control.

The layout follows the documented Windows version-information resource:

    VS_VERSIONINFO { wLength, wValueLength, wType, szKey "VS_VERSION_INFO",
                     VS_FIXEDFILEINFO, children: StringFileInfo / VarFileInfo }
    StringFileInfo { ..., szKey, children: StringTable }
    StringTable    { ..., szKey "hhhhhhhh", children: String }
    String         { wLength, wValueLength, wType, szKey, value (UTF-16) }
    VarFileInfo    { ..., szKey, children: Var }
    Var            { wLength, wValueLength, wType, szKey "Translation",
                     DWORD pairs (langID, charsetID) }

Every block is DWORD aligned. A manifest of (block path -> field file offsets)
is returned so test cases can patch individual length fields after the fact.
"""
from __future__ import annotations

import struct

FIXED_SIZE = 52
HEADER_SIZE = 6  # wLength, wValueLength, wType


def _pad4(buf: bytearray) -> None:
    while len(buf) % 4:
        buf.append(0)


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


class BlobBuilder:
    """Accumulates a version blob and records absolute field offsets."""

    def __init__(self):
        self.buf = bytearray()
        # path -> {"block": off, "wLength": off, "wValueLength": off+2, ...}
        self.map: dict[str, dict] = {}

    def align(self) -> None:
        _pad4(self.buf)

    def pos(self) -> int:
        return len(self.buf)

    def write(self, data: bytes) -> None:
        self.buf += data

    def record_header(self, path: str, block_off: int) -> None:
        self.map[path] = {
            "block": block_off,
            "wLength": block_off,
            "wValueLength": block_off + 2,
            "wType": block_off + 4,
        }

    def patch_u16(self, offset: int, value: int) -> None:
        struct.pack_into("<H", self.buf, offset, value & 0xFFFF)


def _block_header_and_key(bb: BlobBuilder, path: str, key: str,
                          value_length: int, block_type: int = 1) -> int:
    off = bb.pos()
    # Reserve header, then key. wLength patched by caller when block closes.
    bb.write(b"\x00" * HEADER_SIZE)
    bb.record_header(path, off)
    bb.patch_u16(off + 2, value_length)
    bb.patch_u16(off + 4, block_type)
    bb.write(_u16(key))
    bb.align()
    return off


def _close_block(bb: BlobBuilder, block_off: int) -> None:
    length = bb.pos() - block_off
    bb.patch_u16(block_off, length)


def fixed_fileinfo(file_version=(1, 0, 0, 0), product_version=(1, 0, 0, 0)):
    def dword(quad):
        return (quad[0] << 16) | quad[1], (quad[2] << 16) | quad[3]

    fms, fls = dword(file_version)
    pms, pls = dword(product_version)
    return struct.pack(
        "<IIIIIIIIIIIII",
        0xFEEF04BD,          # signature
        0x00010000,          # StrucVersion
        fms, fls, pms, pls,
        0x3F,                # FileFlagsMask
        0x0,                 # FileFlags
        0x40004,             # FileOS: NT_WINDOWS32
        0x1,                 # FileType: VFT_APP
        0x0,                 # FileSubtype
        0x0, 0x0,            # FileDate
    )


def string_entry(bb: BlobBuilder, table_path: str, index: int,
                 key: str, value: str) -> None:
    path = f"{table_path}/String[{index}]:{key}"
    value_u16 = value.encode("utf-16-le")
    # wValueLength counts 16-bit words of the value (excluding terminator).
    block_off = _block_header_and_key(
        bb, path, key, len(value_u16) // 2, block_type=1)
    value_off = bb.pos()
    bb.write(value_u16)
    bb.write(b"\x00\x00")  # explicit NUL
    bb.align()
    bb.map[path]["value"] = value_off
    bb.map[path]["value_bytes"] = len(value_u16) + 2
    _close_block(bb, block_off)


def string_table(bb: BlobBuilder, sfi_path: str, lang_key: str,
                 entries: list[tuple[str, str]], index: int) -> None:
    path = f"{sfi_path}/StringTable[{index}]({lang_key})"
    block_off = _block_header_and_key(bb, path, lang_key, 0, block_type=1)
    bb.map[path]["lang_key"] = bb.pos() - (len(lang_key) + 1) * 2
    for i, (key, value) in enumerate(entries):
        string_entry(bb, path, i, key, value)
    _close_block(bb, block_off)


def string_file_info(bb: BlobBuilder, tables: list[tuple[str, list]],
                     index: int = 0) -> None:
    path = f"StringFileInfo[{index}]"
    block_off = _block_header_and_key(bb, path, "StringFileInfo", 0, 1)
    for i, (lang_key, entries) in enumerate(tables):
        string_table(bb, path, lang_key, entries, i)
    _close_block(bb, block_off)


def var_file_info(bb: BlobBuilder, translations: list[tuple[int, int]],
                  index: int = 0) -> None:
    path = f"VarFileInfo[{index}]/Var[0]:Translation"
    vfi_off = bb.pos()
    bb.write(b"\x00" * HEADER_SIZE)
    bb.record_header("VarFileInfo[0]", vfi_off)
    bb.patch_u16(vfi_off + 2, 0)
    bb.patch_u16(vfi_off + 4, 1)
    bb.write(_u16("VarFileInfo"))
    bb.align()
    # The Var child is part of the VarFileInfo block, so keep the block open
    # until the child has been written.

    payload = b"".join(struct.pack("<HH", lang, cs) for lang, cs in translations)
    var_off = bb.pos()
    bb.write(b"\x00" * HEADER_SIZE)
    bb.record_header(path, var_off)
    bb.patch_u16(var_off + 2, len(payload))
    bb.patch_u16(var_off + 4, 1)
    bb.write(_u16("Translation"))
    bb.align()
    bb.map[path]["payload"] = bb.pos()
    bb.map[path]["pairs"] = translations
    bb.write(payload)
    bb.align()
    _close_block(bb, var_off)
    _close_block(bb, vfi_off)


def build_version_blob(tables: list[tuple[str, list]],
                       translations: list[tuple[int, int]],
                       file_version=(1, 0, 0, 0)) -> tuple[bytearray, dict]:
    """Build a complete RT_VERSION blob.

    tables: [(lang_key_8hex, [(key, value), ...]), ...]
    translations: [(langID, charsetID), ...]
    Returns (blob_bytes, offset_map).
    """
    bb = BlobBuilder()
    root_off = bb.pos()
    bb.write(b"\x00" * HEADER_SIZE)
    bb.record_header("VS_VERSIONINFO", root_off)
    bb.patch_u16(root_off + 2, FIXED_SIZE)
    bb.patch_u16(root_off + 4, 0)  # root block type is binary (0)
    bb.write(_u16("VS_VERSION_INFO"))
    bb.align()
    bb.map["VS_VERSIONINFO"]["fixed"] = bb.pos()
    bb.write(fixed_fileinfo(file_version=file_version))
    bb.align()

    string_file_info(bb, tables, 0)
    var_file_info(bb, translations, 0)

    _close_block(bb, root_off)
    return bytes(bb.buf), bb.map


def lang_key(lang_id: int, charset_id: int) -> str:
    return f"{lang_id:04x}{charset_id:04x}"
