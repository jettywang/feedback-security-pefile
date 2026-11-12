"""Minimal PE32 builder that embeds arbitrary RT_VERSION resource blobs.

The goal is byte-exact control of the version-information resource for
forensic experiments, not a runnable program. Everything is built with the
standard library only. The produced file is a well-formed PE32 as far as the
header/section/resource walk that pefile performs is concerned.
"""
from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# Resource directory tree (.rsrc)
# ---------------------------------------------------------------------------


class _Node:
    """A node in the resource directory tree.

    Leaves carry (blob, language_id) and become data entries.
    """

    def __init__(self, name=None, ident=None):
        self.name = name
        self.ident = ident
        self.children: list[_Node] = []
        self.blob: bytes | None = None
        self.lang_id: int | None = None
        self.name_id: int | None = None

    def add_child(self, node: "_Node") -> "_Node":
        self.children.append(node)
        return node

    def is_leaf(self) -> bool:
        return self.blob is not None


def build_rsrc(version_leaves: list[tuple[int, int, bytes]],
               rsrc_rva: int) -> tuple[bytes, list[dict]]:
    """Build a .rsrc section image.

    version_leaves: list of (name_id, language_id, version_blob).
    All leaves are grouped under RT_VERSION (id 16). Multiple name_id values
    produce sibling name nodes, which lets us exercise the parser's
    "first name entry only" behaviour.

    Returns (section_bytes, leaf_layout) where leaf_layout gives the section
    offset and RVA of every version blob, in input order.
    """
    # Resource tree: root -> Type(RT_VERSION=16) -> Name -> Language(leaf).
    root = _Node()
    type_node = root.add_child(_Node(ident=16))
    for name_id, lang_id, blob in version_leaves:
        name_node = next(
            (c for c in type_node.children if c.ident == name_id), None)
        if name_node is None:
            name_node = type_node.add_child(_Node(ident=name_id))
        leaf = _Node(ident=lang_id)
        leaf.blob = blob
        leaf.lang_id = lang_id
        leaf.name_id = name_id
        name_node.add_child(leaf)

    # Pass 1: assign non-overlapping offsets to every directory node in
    # pre-order. Each directory occupies 16 + 8*entries bytes.
    dir_offsets: dict[int, int] = {}
    cursor = 0

    def assign(node: _Node) -> None:
        nonlocal cursor
        if node.is_leaf():
            return
        dir_offsets[id(node)] = cursor
        cursor += 16 + 8 * len(node.children)
        for child in node.children:
            assign(child)

    assign(root)

    # Pass 2: place one IMAGE_RESOURCE_DATA_ENTRY per leaf, then the blobs.
    leaves_in_order: list[_Node] = []

    def collect(node: _Node) -> None:
        for child in node.children:
            if child.is_leaf():
                leaves_in_order.append(child)
            else:
                collect(child)

    collect(type_node)

    data_entry_off: dict[int, int] = {}
    blob_off: dict[int, int] = {}
    blob_cursor = cursor + 16 * len(leaves_in_order)
    for leaf in leaves_in_order:
        data_entry_off[id(leaf)] = cursor
        cursor += 16
        blob_off[id(leaf)] = blob_cursor
        blob_cursor += len(leaf.blob)
    section_size = blob_cursor

    section = bytearray(section_size)

    def emit_dir(node: _Node) -> None:
        if node.is_leaf():
            return
        off = dir_offsets[id(node)]
        n_named = sum(1 for c in node.children if c.name is not None)
        n_id = len(node.children) - n_named
        struct.pack_into("<IIHHHH", section, off,
                         0, 0, 0, 0, n_named, n_id)
        entry = off + 16
        for child in node.children:
            if child.is_leaf():
                target = data_entry_off[id(child)]  # no high bit
            else:
                target = 0x80000000 | dir_offsets[id(child)]
            struct.pack_into("<II", section, entry,
                             child.ident if child.ident is not None else 0,
                             target)
            entry += 8
            emit_dir(child)

    emit_dir(root)

    layout: list[dict] = []
    for leaf in leaves_in_order:
        de_off = data_entry_off[id(leaf)]
        b_off = blob_off[id(leaf)]
        rva = rsrc_rva + b_off
        struct.pack_into("<IIII", section, de_off, rva, len(leaf.blob), 0, 0)
        section[b_off:b_off + len(leaf.blob)] = leaf.blob
        layout.append({
            "name_id": leaf.name_id,
            "language_id": leaf.lang_id,
            "section_offset": b_off,
            "rva": rva,
            "size": len(leaf.blob),
        })

    order = {(n, l): i for i, (n, l, _) in enumerate(version_leaves)}
    layout.sort(key=lambda item: order[(item["name_id"], item["language_id"])])
    return bytes(section), layout


# ---------------------------------------------------------------------------
# Minimal PE32 container
# ---------------------------------------------------------------------------

DOS_STUB = (
    b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    + b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    + b"PE minimal resource test\x00".ljust(64 - 28, b"\x00")
)


def _section_header(name: bytes, vaddr: int, vsize: int, rawsize: int,
                    rawptr: int, characteristics: int) -> bytes:
    # IMAGE_SECTION_HEADER: Name, VirtualSize, VirtualAddress,
    # SizeOfRawData, PointerToRawData, PointerToRelocations,
    # PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers,
    # Characteristics.
    return struct.pack(
        "<8sIIIIIIHHI",
        name[:8].ljust(8, b"\x00"),
        vsize, vaddr, rawsize, rawptr,
        0, 0, 0, 0, characteristics,
    )


def build_pe(version_blobs: list[tuple[int, int, bytes]]
             ) -> tuple[bytes, dict]:
    """Wrap version blobs (name_id, lang_id, blob) into a minimal PE32.

    Returns (image_bytes, layout) where layout describes the section RVA and
    the per-blob positions inside .rsrc.
    """
    file_align = 0x200
    sect_align = 0x200

    # A trivial executable stub so the optional-header entry point is sane.
    text = b"\xC3"  # ret
    text_rawsize = file_align

    headers_size = 0x200
    text_rawptr = headers_size
    text_rva = sect_align
    rsrc_rva = text_rva + sect_align
    rsrc_rawptr = text_rawptr + text_rawsize

    rsrc, leaf_layout = build_rsrc(version_blobs, rsrc_rva)
    rsrc_rawsize = (len(rsrc) + file_align - 1) // file_align * file_align

    size_of_image = rsrc_rva + rsrc_rawsize
    layout = {
        "rsrc_rva": rsrc_rva,
        "rsrc_rawptr": rsrc_rawptr,
        "rsrc_virtual_size": len(rsrc),
        "rsrc_raw_size": rsrc_rawsize,
        "leaves": leaf_layout,
    }

    # PE signature + COFF header.
    coff = struct.pack(
        "<HHIIIHH",
        0x14C,          # i386
        2,              # two sections
        0,              # timestamp
        0, 0,           # no symbol table
        0xE0,           # size of optional header
        0x0102,         # characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    data_dirs = [b"\x00" * 8 for _ in range(16)]
    data_dirs[2] = struct.pack("<II", rsrc_rva, len(rsrc))  # resource directory

    optional = struct.pack(
        "<HBBIIIIII",
        0x10B,              # PE32 magic
        0, 0,               # linker versions
        text_rawsize,       # SizeOfCode
        0, 0,               # SizeOfInitializedData / UninitializedData
        text_rva,           # AddressOfEntryPoint
        text_rva,           # BaseOfCode
        0,                  # BaseOfData
    )
    assert len(optional) == 28
    optional += struct.pack(
        "<IIIIIHH",
        0x400000,           # ImageBase
        sect_align, file_align,
        4, 0,               # OS / image versions
        4, 0,               # subsystem version
    )
    optional += struct.pack(
        "<IIII",
        0,                  # Win32VersionValue
        size_of_image,
        headers_size,
        0,                  # checksum
    )
    optional += struct.pack(
        "<HH",
        3,                  # WINDOWS_CUI subsystem
        0,                  # DLL characteristics
    )
    optional += struct.pack(
        "<IIII",
        0x100000,           # SizeOfStackReserve
        0x1000,             # SizeOfStackCommit
        0x100000,           # SizeOfHeapReserve
        0x1000,             # SizeOfHeapCommit
    )
    optional += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    optional += b"".join(data_dirs)

    assert len(optional) == 0xE0, len(optional)

    sect_text = _section_header(
        b".text", text_rva, len(text), text_rawsize, text_rawptr,
        0x60000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
    )
    sect_rsrc = _section_header(
        b".rsrc", rsrc_rva, len(rsrc), rsrc_rawsize, rsrc_rawptr,
        0x40000040,  # CNT_INITIALIZED_DATA | MEM_READ
    )

    dos = DOS_STUB.ljust(0x80, b"\x00")
    headers = dos + b"PE\x00\x00" + coff + optional + sect_text + sect_rsrc
    headers = headers.ljust(headers_size, b"\x00")

    image = headers
    image += text.ljust(text_rawsize, b"\x00")
    image += rsrc.ljust(rsrc_rawsize, b"\x00")
    return image, layout
