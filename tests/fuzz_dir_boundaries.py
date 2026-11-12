#!/usr/bin/env python3
"""Lightweight target-reachable fuzzing regressor for pefile.

Focus: boundary combinations across the export, import and base-relocation
data directories (IMAGE_DIRECTORY_ENTRY_EXPORT / IMPORT / BASERELOC).

How it works:

* A stdlib-only generator builds small PE32 files in memory.  Each case
  mutates directory sizes or internal pointers of one *target* directory and
  then *fixes the outer mapping* (section headers, data-directory entries,
  SizeOfImage) so the sample still reaches the intended parser.
* Every case is parsed twice with pefile.  The run records the seed, the
  directories actually reached, and the parser warnings.
* Outcomes are classified separately:
    - ``clean_reject``        pefile.PEFormatError raised (normal rejection)
    - ``unexpected_exception``  any other exception (failure)
    - ``over_budget``         parse exceeded the time budget (failure)
    - ``contradiction``       parsed object contradicts itself/headers (failure)
    - ``parsed_ok``           parsed without problems
* Parsing the same input twice must give a stable result and must not modify
  the input bytes.
* Failing samples are minimized while keeping the target directory reachable,
  and stored next to a human-readable layout description (layout.txt), not
  just raw bytes.
* ``selftest`` verifies that at least one deliberately broken
  bounds-check version of pefile is caught by the harness.

Samples are only ever parsed as data.  They are never executed, and this
harness never writes or runs executable code.

Usage:
    python tests/fuzz_dir_boundaries.py run [--random N] [--seed S] [--budget S]
    python tests/fuzz_dir_boundaries.py selftest
"""

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import random
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pefile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
SECTION_RVA = 0x1000
SIZE_OF_HEADERS = 0x200
E_LFANEW = 0x80

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_BASERELOC = 5

TARGET_PARSERS = {
    "export": "parse_export_directory",
    "import": "parse_import_directory",
    "reloc": "parse_relocations_directory",
}

CLASS_PARSED_OK = "parsed_ok"
CLASS_CLEAN_REJECT = "clean_reject"
CLASS_UNEXPECTED = "unexpected_exception"
CLASS_OVER_BUDGET = "over_budget"
CLASS_CONTRADICTION = "contradiction"

FAILURE_CLASSES = (CLASS_UNEXPECTED, CLASS_OVER_BUDGET, CLASS_CONTRADICTION)

DEFAULT_BUDGET = 2.0  # seconds per parse; these tiny samples parse in ms


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


# ---------------------------------------------------------------------------
# Case parameters
# ---------------------------------------------------------------------------


@dataclass
class Params:
    """Mutation knobs.  ``None`` / ``"valid"`` means the benign baseline."""

    # export directory
    exp_dir_size: object = None  # None -> real size (40)
    exp_num_names: object = None  # None -> actual (2)
    exp_num_functions: object = None  # None -> actual (2)
    exp_addr_names: str = "valid"  # valid|at_end|straddle|unmapped|into_header
    exp_addr_ordinals: str = "valid"
    exp_addr_functions: str = "valid"
    exp_base: int = 1
    # import directory
    imp_dir_size: object = None  # None -> real size
    imp_descriptors: int = 2
    imp_terminator: bool = True  # null descriptor present
    imp_name_mode: str = "valid"
    imp_oft_mode: str = "valid"  # valid|zero|at_end|unmapped|into_header
    imp_thunk_terminator: bool = True
    imp_forwarder_chain: int = 0
    # base relocation directory
    rel_dir_size: str = "valid"  # valid|minus1|header_only|huge
    rel_sob: str = "valid"  # valid|minus2|plus2|zero|eight|huge
    rel_va: str = "valid"  # valid|image_end|beyond_image
    rel_entries: int = 3
    rel_second_block: bool = True


@dataclass
class Case:
    seed: int
    label: str
    target: str  # "export" | "import" | "reloc" | "all"
    params: Params

    @property
    def case_id(self):
        return f"{self.seed:04d}-{self.target}-{self.label}"

    @property
    def target_dirs(self):
        if self.target == "all":
            return ["export", "import", "reloc"]
        return [self.target]

    def mutations(self):
        defaults = Params()
        out = {}
        for f in dataclasses.fields(Params):
            value = getattr(self.params, f.name)
            if value != getattr(defaults, f.name):
                out[f.name] = value
        return out


# ---------------------------------------------------------------------------
# PE generator (stdlib only)
# ---------------------------------------------------------------------------


@dataclass
class Region:
    name: str
    off: int  # offset within the section
    size: int
    note: str = ""


class SectionBuilder:
    def __init__(self):
        self.data = bytearray()
        self.regions = []

    @staticmethod
    def rva(off):
        return SECTION_RVA + off

    def alloc(self, blob, name, note="", align_to=1):
        while len(self.data) % align_to:
            self.data.append(0)
        off = len(self.data)
        self.data += blob
        self.regions.append(Region(name, off, len(blob), note))
        return off

    def patch(self, off, blob):
        self.data[off : off + len(blob)] = blob


@dataclass
class Layout:
    regions: list
    directories: dict  # name -> (rva, size)
    size_of_image: int
    size_of_headers: int
    raw_size: int
    virtual_size: int


def _ptr_value(mode, target_off, end_off, size_of_image):
    """Resolve a pointer mutation mode to an RVA."""
    if mode == "valid":
        return SECTION_RVA + target_off
    if mode == "zero":  # field forced to 0 (e.g. OriginalFirstThunk)
        return 0
    if mode == "at_end":  # one byte past the last section byte
        return SECTION_RVA + end_off
    if mode == "straddle":  # table starts near the end and runs past it
        return SECTION_RVA + max(end_off - 2, 0)
    if mode == "unmapped":  # beyond every section and beyond SizeOfImage
        return size_of_image + 0x1000
    if mode == "into_header":  # points into the DOS header area
        return 0x40
    raise ValueError(f"unknown pointer mode: {mode}")


def build_case(params):
    """Build one PE sample.  Returns (bytes, Layout).

    Internal directory pointers/sizes are mutated first; afterwards the outer
    mapping (section header, data directories, SizeOfImage) is recomputed so
    the sample consistently reaches the target parser.
    """
    sb = SectionBuilder()
    deferred = []  # (field_off, mode, target_off, note)

    def defer_ptr(field_off, mode, target_off):
        deferred.append((field_off, mode, target_off))

    # ---- export region -------------------------------------------------
    exp_dir_off = sb.alloc(b"\0" * 40, "export.dir", "IMAGE_EXPORT_DIRECTORY", 4)
    funcs_off = sb.alloc(
        struct.pack("<II", SECTION_RVA + 0x40, SECTION_RVA + 0x50),
        "export.functions",
        "AddressOfFunctions[2]",
        4,
    )
    names_tab_off = sb.alloc(b"\0" * 8, "export.name_ptrs", "AddressOfNames[2]", 4)
    ords_off = sb.alloc(struct.pack("<HH", 0, 1), "export.ordinals", "AddressOfNameOrdinals[2]", 2)
    name0_off = sb.alloc(b"ExpAlpha\0", "export.name[0]")
    name1_off = sb.alloc(b"ExpBeta\0", "export.name[1]")
    dllname_off = sb.alloc(b"sample.dll\0", "export.dll_name")
    sb.patch(names_tab_off, struct.pack("<II", sb.rva(name0_off), sb.rva(name1_off)))

    num_names = 2 if params.exp_num_names is None else params.exp_num_names
    num_funcs = 2 if params.exp_num_functions is None else params.exp_num_functions

    # ---- import region --------------------------------------------------
    dlls = [(b"alpha.dll\0", b"AlphaFunc\0"), (b"beta.dll\0", b"BetaFunc\0")][
        : params.imp_descriptors
    ]
    desc_refs = []
    for dll_name, func_name in dlls:
        hn_off = sb.alloc(struct.pack("<H", 0) + func_name, "import.hint_name", func_name.decode().strip("\0"), 2)
        thunk = struct.pack("<I", sb.rva(hn_off))
        tail = b"\0" * 4 if params.imp_thunk_terminator else b""
        ilt_off = sb.alloc(thunk + tail, "import.ilt", "terminator" if tail else "NO terminator", 4)
        iat_off = sb.alloc(thunk + tail, "import.iat", "terminator" if tail else "NO terminator", 4)
        dll_off = sb.alloc(dll_name, "import.dll_name")
        desc_refs.append((ilt_off, iat_off, dll_off))
    n_desc = len(desc_refs)
    desc_off = sb.alloc(
        b"\0" * (20 * n_desc + (20 if params.imp_terminator else 0)),
        "import.descriptors",
        f"{n_desc} descriptor(s)" + ("+null" if params.imp_terminator else ", NO null terminator"),
        4,
    )
    for i, (ilt_off, iat_off, dll_off) in enumerate(desc_refs):
        base = desc_off + 20 * i
        if i == 0 and params.imp_oft_mode != "valid":
            defer_ptr(base + 0, params.imp_oft_mode, ilt_off)
        else:
            sb.patch(base + 0, struct.pack("<I", sb.rva(ilt_off)))
        sb.patch(base + 8, struct.pack("<I", params.imp_forwarder_chain & 0xFFFFFFFF))
        if i == 0 and params.imp_name_mode != "valid":
            defer_ptr(base + 12, params.imp_name_mode, dll_off)
        else:
            sb.patch(base + 12, struct.pack("<I", sb.rva(dll_off)))
        sb.patch(base + 16, struct.pack("<I", sb.rva(iat_off)))

    # ---- base relocation region -----------------------------------------
    entries1 = [0x3000 | (0x100 + 4 * i) for i in range(params.rel_entries)]
    sob1_actual = 8 + 2 * len(entries1)
    blk1_off = sb.alloc(
        b"\0" * 8 + struct.pack(f"<{len(entries1)}H", *entries1),
        "reloc.block1",
        f"{len(entries1)} entries",
        4,
    )
    blk2_off = None
    sob2_actual = 0
    if params.rel_second_block:
        entries2 = [0x3000 | 0x180, 0x3000 | 0x184]
        sob2_actual = 8 + 2 * len(entries2)
        blk2_off = sb.alloc(
            b"\0" * 8 + struct.pack("<2H", *entries2), "reloc.block2", "2 entries", 4
        )
    reloc_total = len(sb.data) - blk1_off

    # ---- filler: distinct reloc-looking words right after the directory --
    filler = struct.pack(
        "<64H", *[0x3000 | ((0x200 + 4 * i) & 0xFFF) for i in range(64)]
    )
    sb.alloc(filler, "filler.reloc_like", "64 distinct reloc-looking words")

    # ---- finalize: fix the outer mapping --------------------------------
    virtual_size = len(sb.data)
    size_of_image = align(SECTION_RVA + virtual_size, SECTION_ALIGN)

    def rel_sob_value():
        if params.rel_sob == "valid":
            return sob1_actual
        if params.rel_sob == "minus2":
            return sob1_actual - 2
        if params.rel_sob == "plus2":
            return sob1_actual + 2
        if params.rel_sob == "zero":
            return 0
        if params.rel_sob == "eight":
            return 8
        if params.rel_sob == "huge":
            return size_of_image + 8
        raise ValueError(params.rel_sob)

    def rel_va_value():
        if params.rel_va == "valid":
            return SECTION_RVA
        if params.rel_va == "image_end":
            return size_of_image
        if params.rel_va == "beyond_image":
            return size_of_image + 0x1000
        raise ValueError(params.rel_va)

    def rel_dir_size_value():
        if params.rel_dir_size == "valid":
            return reloc_total
        if params.rel_dir_size == "minus1":
            return reloc_total - 1
        if params.rel_dir_size == "header_only":
            return 8
        if params.rel_dir_size == "huge":
            return 0xFFFFFFFF
        raise ValueError(params.rel_dir_size)

    # reloc block headers
    sb.patch(blk1_off + 0, struct.pack("<I", rel_va_value() & 0xFFFFFFFF))
    sb.patch(blk1_off + 4, struct.pack("<I", rel_sob_value() & 0xFFFFFFFF))
    if blk2_off is not None:
        sb.patch(blk2_off + 0, struct.pack("<I", SECTION_RVA))
        sb.patch(blk2_off + 4, struct.pack("<I", sob2_actual))

    # export directory header
    exp_dir_size = 40 if params.exp_dir_size is None else params.exp_dir_size
    struct.pack_into(
        "<IIHHIIIIIII",
        sb.data,
        exp_dir_off,
        0,  # Characteristics
        0,  # TimeDateStamp
        0,
        0,  # version
        sb.rva(dllname_off),  # Name
        params.exp_base & 0xFFFFFFFF,  # Base
        num_funcs & 0xFFFFFFFF,
        num_names & 0xFFFFFFFF,
        0,  # AddressOfFunctions (patched below)
        0,  # AddressOfNames
        0,  # AddressOfNameOrdinals
    )
    defer_ptr(exp_dir_off + 28, params.exp_addr_functions, funcs_off)
    defer_ptr(exp_dir_off + 32, params.exp_addr_names, names_tab_off)
    defer_ptr(exp_dir_off + 36, params.exp_addr_ordinals, ords_off)

    # apply deferred pointer mutations now that the section end is known
    end_off = len(sb.data)
    for field_off, mode, target_off in deferred:
        value = _ptr_value(mode, target_off, end_off, size_of_image)
        sb.patch(field_off, struct.pack("<I", value & 0xFFFFFFFF))

    imp_dir_size = (
        20 * n_desc if params.imp_dir_size is None else params.imp_dir_size
    )
    directories = {
        "EXPORT": (sb.rva(exp_dir_off), exp_dir_size),
        "IMPORT": (sb.rva(desc_off), imp_dir_size),
        "BASERELOC": (sb.rva(blk1_off), rel_dir_size_value()),
    }

    # ---- assemble the file ----------------------------------------------
    raw_size = align(len(sb.data), FILE_ALIGN)
    dos = bytearray(E_LFANEW)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, E_LFANEW)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32
    struct.pack_into("<I", opt, 16, SECTION_RVA)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, SECTION_ALIGN)
    struct.pack_into("<I", opt, 36, FILE_ALIGN)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, SIZE_OF_HEADERS)
    struct.pack_into("<H", opt, 68, 3)  # subsystem: console
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    dir_index = {"EXPORT": DIR_EXPORT, "IMPORT": DIR_IMPORT, "BASERELOC": DIR_BASERELOC}
    for name, (rva, size) in directories.items():
        struct.pack_into("<II", opt, 96 + dir_index[name] * 8, rva, size & 0xFFFFFFFF)
    sh = struct.pack(
        "<8sIIIIIIHHI",
        b".dirs\0\0\0",
        virtual_size,
        SECTION_RVA,
        raw_size,
        SIZE_OF_HEADERS,
        0,
        0,
        0,
        0,
        0x40000040,  # initialized data, readable
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sh
    headers = headers.ljust(SIZE_OF_HEADERS, b"\0")
    blob = headers + bytes(sb.data).ljust(raw_size, b"\0")

    layout = Layout(
        regions=list(sb.regions),
        directories=directories,
        size_of_image=size_of_image,
        size_of_headers=SIZE_OF_HEADERS,
        raw_size=raw_size,
        virtual_size=virtual_size,
    )
    return blob, layout


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


def enumerated_cases():
    cases = []

    def add(label, target, **kw):
        cases.append(Case(seed=len(cases), label=label, target=target, params=Params(**kw)))

    add("base", "all")

    # export boundary variations
    for v in (0, 1, 3, 0x10000, 0xFFFFFFFF):
        add(f"exp_num_names={v:#x}", "export", exp_num_names=v)
    for v in (0, 1, 3, 0x10000):
        add(f"exp_num_functions={v:#x}", "export", exp_num_functions=v)
    for m in ("at_end", "straddle", "unmapped", "into_header"):
        add(f"exp_addr_names={m}", "export", exp_addr_names=m)
    for m in ("at_end", "straddle", "unmapped"):
        add(f"exp_addr_ordinals={m}", "export", exp_addr_ordinals=m)
    for m in ("at_end", "straddle", "unmapped"):
        add(f"exp_addr_functions={m}", "export", exp_addr_functions=m)
    for v in (0, 1, 39, 41, 0xFFFFFFFF):
        add(f"exp_dir_size={v:#x}", "export", exp_dir_size=v)
    for v in (0, 0xFFFF):
        add(f"exp_base={v:#x}", "export", exp_base=v)

    # import boundary variations
    add("imp_descriptors=1", "import", imp_descriptors=1)
    add("imp_no_terminator", "import", imp_terminator=False)
    for m in ("at_end", "straddle", "unmapped", "into_header"):
        add(f"imp_name_mode={m}", "import", imp_name_mode=m)
    for m in ("zero", "at_end", "unmapped", "into_header"):
        add(f"imp_oft_mode={m}", "import", imp_oft_mode=m)
    add("imp_thunk_no_terminator", "import", imp_thunk_terminator=False)
    add("imp_forwarder_chain=0xffffffff", "import", imp_forwarder_chain=0xFFFFFFFF)
    for v in (0, 20, 0xFFFFFFFF):
        add(f"imp_dir_size={v:#x}", "import", imp_dir_size=v)

    # relocation boundary variations
    for m in ("minus1", "header_only", "huge"):
        add(f"rel_dir_size={m}", "reloc", rel_dir_size=m)
    for m in ("minus2", "plus2", "zero", "eight", "huge"):
        add(f"rel_sob={m}", "reloc", rel_sob=m)
    for m in ("image_end", "beyond_image"):
        add(f"rel_va={m}", "reloc", rel_va=m)
    for v in (0, 1):
        add(f"rel_entries={v}", "reloc", rel_entries=v)
    add("rel_single_block", "reloc", rel_second_block=False)

    # a few cross-directory boundary combinations
    add(
        "combo_exp_huge_names+straddle",
        "export",
        exp_num_names=0x10000,
        exp_addr_names="straddle",
    )
    add(
        "combo_imp_no_term+thunk_no_term",
        "import",
        imp_terminator=False,
        imp_thunk_terminator=False,
    )
    add("combo_rel_huge_sob+huge_dir", "reloc", rel_sob="huge", rel_dir_size="huge")
    add(
        "combo_rel_zero_sob+header_only",
        "reloc",
        rel_sob="zero",
        rel_dir_size="header_only",
    )
    return cases


RANDOM_SPACE = {
    "export": [
        ("exp_num_names", [0, 1, 3, 4, 0x1000, 0x10000, 0xFFFFFFFF]),
        ("exp_num_functions", [0, 1, 3, 4, 0x1000, 0xFFFFFFFF]),
        ("exp_addr_names", ["at_end", "straddle", "unmapped", "into_header"]),
        ("exp_addr_ordinals", ["at_end", "straddle", "unmapped"]),
        ("exp_addr_functions", ["at_end", "straddle", "unmapped", "into_header"]),
        ("exp_dir_size", [0, 1, 20, 39, 41, 0x1000, 0xFFFFFFFF]),
        ("exp_base", [0, 2, 0xFFFF, 0xFFFFFFFF]),
    ],
    "import": [
        ("imp_descriptors", [1, 2]),
        ("imp_terminator", [False]),
        ("imp_name_mode", ["at_end", "straddle", "unmapped", "into_header"]),
        ("imp_oft_mode", ["zero", "at_end", "unmapped", "into_header"]),
        ("imp_thunk_terminator", [False]),
        ("imp_forwarder_chain", [1, 0xFFFFFFFF]),
        ("imp_dir_size", [0, 1, 20, 0xFFFFFFFF]),
    ],
    "reloc": [
        ("rel_dir_size", ["minus1", "header_only", "huge"]),
        ("rel_sob", ["minus2", "plus2", "zero", "eight", "huge"]),
        ("rel_va", ["image_end", "beyond_image"]),
        ("rel_entries", [0, 1, 2, 5]),
        ("rel_second_block", [False]),
    ],
}


def random_cases(seed, count):
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        target = rng.choice(sorted(RANDOM_SPACE))
        params = Params()
        picked = rng.sample(RANDOM_SPACE[target], rng.randint(1, 3))
        parts = []
        for field_name, values in picked:
            value = rng.choice(values)
            setattr(params, field_name, value)
            parts.append(f"{field_name}={value!r}")
        cases.append(
            Case(
                seed=seed + i,
                label=f"random[{seed}#{i}]:" + ",".join(parts),
                target=target,
                params=params,
            )
        )
    return cases


# ---------------------------------------------------------------------------
# Parsing / classification
# ---------------------------------------------------------------------------


@dataclass
class ParseOutcome:
    classification: str
    reached: list
    warnings: list
    elapsed: float
    detail: str = ""
    state: object = None


def _summarize(pe):
    """JSON-able digest of the parsed directory objects."""
    out = {}
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        out["export"] = sorted(
            [
                (
                    s.ordinal,
                    s.address,
                    s.name.hex() if isinstance(s.name, bytes) else None,
                    s.forwarder.hex() if isinstance(s.forwarder, bytes) else None,
                )
                for s in exp.symbols
            ],
            key=repr,
        )
    imp = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if imp is not None:
        out["import"] = sorted(
            [
                (
                    desc.dll.hex() if isinstance(desc.dll, bytes) else None,
                    len(desc.imports),
                    tuple(
                        (
                            s.name.hex() if isinstance(s.name, bytes) else None,
                            s.ordinal,
                        )
                        for s in desc.imports
                    ),
                )
                for desc in imp
            ],
            key=repr,
        )
    rel = getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None)
    if rel is not None:
        out["reloc"] = [
            (
                blk.struct.VirtualAddress,
                blk.struct.SizeOfBlock,
                len(blk.entries),
                tuple(e.rva for e in blk.entries[:8]),
            )
            for blk in rel
        ]
    return out


def _check_invariants(pe):
    """Self-contradiction checks on a successfully parsed object."""
    problems = []
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage

    rel = getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None)
    if rel is not None:
        for i, blk in enumerate(rel):
            sob = blk.struct.SizeOfBlock
            if sob > size_of_image:
                problems.append(
                    f"reloc block {i}: SizeOfBlock {sob:#x} > SizeOfImage {size_of_image:#x}"
                )
            if blk.struct.VirtualAddress > size_of_image:
                problems.append(
                    f"reloc block {i}: VirtualAddress {blk.struct.VirtualAddress:#x} "
                    f"> SizeOfImage {size_of_image:#x}"
                )
            if 8 <= sob < 8 + 2 * len(blk.entries):
                problems.append(
                    f"reloc block {i}: {len(blk.entries)} entries do not fit in "
                    f"SizeOfBlock {sob:#x}"
                )

    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        n_names = exp.struct.NumberOfNames
        n_funcs = exp.struct.NumberOfFunctions
        if len(exp.symbols) > n_names + n_funcs:
            problems.append(
                f"export: {len(exp.symbols)} symbols > NumberOfNames({n_names}) "
                f"+ NumberOfFunctions({n_funcs})"
            )
        base = exp.struct.Base
        for s in exp.symbols:
            if s.ordinal is not None and not (base <= s.ordinal < base + max(n_funcs, 1)):
                problems.append(
                    f"export: ordinal {s.ordinal:#x} outside [Base={base:#x}, "
                    f"Base+NumberOfFunctions={base + n_funcs:#x})"
                )

    imp = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if imp is not None:
        for i, desc in enumerate(imp):
            if not desc.dll or not isinstance(desc.dll, bytes):
                problems.append(f"import descriptor {i}: empty/invalid dll name")

    return problems


def parse_once(module, data, budget):
    """Parse once with the given pefile module; record reached directories."""
    reached = []
    originals = {}
    for key, meth in TARGET_PARSERS.items():
        original = getattr(module.PE, meth)
        originals[meth] = original

        def make_wrapper(orig, key=key):
            def wrapper(*args, **kwargs):
                reached.append(key)
                return orig(*args, **kwargs)

            return wrapper

        setattr(module.PE, meth, make_wrapper(original))
    try:
        start = time.monotonic()
        pe = None
        try:
            pe = module.PE(data=data)
        except module.PEFormatError as exc:
            elapsed = time.monotonic() - start
            if elapsed > budget:
                return ParseOutcome(CLASS_OVER_BUDGET, reached, [], elapsed,
                                    f"budget exceeded during rejection: {exc}")
            return ParseOutcome(CLASS_CLEAN_REJECT, reached, [], elapsed, str(exc))
        except Exception as exc:  # noqa: BLE001 - classification is the point
            elapsed = time.monotonic() - start
            return ParseOutcome(
                CLASS_UNEXPECTED, reached, [], elapsed, f"{type(exc).__name__}: {exc}"
            )
        elapsed = time.monotonic() - start
        if elapsed > budget:
            return ParseOutcome(CLASS_OVER_BUDGET, reached, [], elapsed)
        warnings = list(pe.get_warnings())
        problems = _check_invariants(pe)
        if problems:
            return ParseOutcome(
                CLASS_CONTRADICTION, reached, warnings, elapsed, "; ".join(problems)
            )
        return ParseOutcome(
            CLASS_PARSED_OK, reached, warnings, elapsed, state=_summarize(pe)
        )
    finally:
        for meth, original in originals.items():
            setattr(module.PE, meth, original)


@dataclass
class CaseResult:
    case_id: str
    seed: int
    target: str
    label: str
    mutations: dict
    classification: str
    reached: list
    warnings: list
    elapsed_ms: float
    detail: str
    deterministic: bool
    input_unchanged: bool
    size: int
    sha256: str

    @property
    def failed(self):
        return (
            self.classification in FAILURE_CLASSES
            or not self.deterministic
            or not self.input_unchanged
        )

    def to_json(self):
        return {
            "case_id": self.case_id,
            "seed": self.seed,
            "target": self.target,
            "label": self.label,
            "mutations": self.mutations,
            "classification": self.classification,
            "reached": sorted(set(self.reached)),
            "warnings": self.warnings,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "detail": self.detail,
            "deterministic": self.deterministic,
            "input_unchanged": self.input_unchanged,
            "size": self.size,
            "sha256": self.sha256,
        }


def evaluate_case(module, case, data, budget):
    """Parse the same input twice: check stability and input immutability."""
    buf = bytearray(data)
    hash_before = hashlib.sha256(bytes(buf)).hexdigest()
    first = parse_once(module, buf, budget)
    hash_mid = hashlib.sha256(bytes(buf)).hexdigest()
    second = parse_once(module, buf, budget)
    hash_after = hashlib.sha256(bytes(buf)).hexdigest()

    deterministic = (
        first.classification == second.classification
        and first.warnings == second.warnings
        and first.state == second.state
        and sorted(first.reached) == sorted(second.reached)
        and first.detail == second.detail
    )
    input_unchanged = hash_before == hash_mid == hash_after
    return CaseResult(
        case_id=case.case_id,
        seed=case.seed,
        target=case.target,
        label=case.label,
        mutations=case.mutations(),
        classification=first.classification,
        reached=first.reached,
        warnings=first.warnings,
        elapsed_ms=max(first.elapsed, second.elapsed) * 1000.0,
        detail=first.detail,
        deterministic=deterministic,
        input_unchanged=input_unchanged,
        size=len(data),
        sha256=hash_before,
    )


# ---------------------------------------------------------------------------
# Minimizer (keeps the target directory reachable)
# ---------------------------------------------------------------------------


def minimize(module, data, target_dirs, classification, budget):
    """Shrink a failing sample while the same failure class reproduces and
    the target directory parser is still reached."""

    def predicate(candidate):
        outcome = parse_once(module, bytearray(candidate), budget)
        return (
            outcome.classification == classification
            and all(t in outcome.reached for t in target_dirs)
        )

    current = bytearray(data)
    if not predicate(current):
        return bytes(current), False

    # zero out chunks of the section data (headers stay intact)
    for chunk in (256, 128, 64, 16, 4):
        for _ in range(2):
            changed = False
            off = SIZE_OF_HEADERS
            while off < len(current):
                trial = bytearray(current)
                trial[off : off + chunk] = b"\0" * min(chunk, len(current) - off)
                if trial != current and predicate(trial):
                    current = trial
                    changed = True
                off += chunk
            if not changed:
                break

    # truncate the tail
    for step in (64, 16, 4):
        while len(current) - step >= SIZE_OF_HEADERS:
            trial = current[: len(current) - step]
            if predicate(trial):
                current = bytearray(trial)
            else:
                break

    return bytes(current), True


# ---------------------------------------------------------------------------
# Layout rendering (human-readable failure artifacts)
# ---------------------------------------------------------------------------


def render_layout(case, layout, data, result=None):
    lines = []
    add = lines.append
    add(f"Case: {case.case_id}")
    add(f"Seed: {case.seed}  Target directory: {case.target}")
    mutations = case.mutations()
    add("Mutations vs benign baseline:")
    if mutations:
        for key, value in mutations.items():
            add(f"  {key} = {value!r}")
    else:
        add("  (none - benign baseline)")
    add("")
    add("== PE headers ==")
    add(f"  e_lfanew={E_LFANEW:#x} Machine=0x14c Sections=1 SizeOfOptionalHeader=0xe0")
    add(f"  SizeOfHeaders={layout.size_of_headers:#x} SizeOfImage={layout.size_of_image:#x}")
    add(f"  SectionAlignment={SECTION_ALIGN:#x} FileAlignment={FILE_ALIGN:#x}")
    add("")
    add("== Sections ==")
    add(
        f"  .dirs VirtualAddress={SECTION_RVA:#x} VirtualSize={layout.virtual_size:#x} "
        f"PointerToRawData={layout.size_of_headers:#x} SizeOfRawData={layout.raw_size:#x}"
    )
    add("")
    add("== Data directories (outer mapping, fixed up after mutation) ==")
    for name, (rva, size) in layout.directories.items():
        file_off = rva - SECTION_RVA + layout.size_of_headers
        add(f"  {name:<9} RVA={rva:#x} Size={size:#x} (file offset {file_off:#x})")
    add("")
    add("== Directory layout inside section .dirs ==")
    add(f"  {'file off':>9} {'RVA':>9} {'size':>6}  name / note")
    for region in layout.regions:
        add(
            f"  {layout.size_of_headers + region.off:#9x} "
            f"{SECTION_RVA + region.off:#9x} {region.size:>6}  "
            f"{region.name}  {region.note}"
        )
    add("")
    add(f"== Sample ==")
    add(f"  size={len(data)} sha256={hashlib.sha256(bytes(data)).hexdigest()}")
    if result is not None:
        add("")
        add("== Outcome ==")
        add(f"  classification: {result.classification}")
        add(f"  directories reached: {sorted(set(result.reached))}")
        add(f"  deterministic: {result.deterministic}")
        add(f"  input unchanged after parsing: {result.input_unchanged}")
        if result.detail:
            add(f"  detail: {result.detail}")
        if result.warnings:
            add("  parser warnings:")
            for warning in result.warnings:
                add(f"    - {warning}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Corpus runner
# ---------------------------------------------------------------------------


def run_corpus(module, cases, budget=DEFAULT_BUDGET, artifacts_dir=None,
               do_minimize=True, progress=None):
    results = []
    report_path = None
    if artifacts_dir is not None:
        artifacts_dir = Path(artifacts_dir)
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        report_path = artifacts_dir / "report.jsonl"
        report_path.write_text("")

    for case in cases:
        data, layout = build_case(case.params)
        result = evaluate_case(module, case, data, budget)
        results.append((case, data, layout, result))
        if progress:
            progress(case, result)
        if report_path is not None:
            with report_path.open("a") as fh:
                fh.write(json.dumps(result.to_json()) + "\n")
        if result.failed and artifacts_dir is not None:
            case_dir = artifacts_dir / f"case-{case.case_id}"
            case_dir.mkdir(parents=True, exist_ok=True)
            (case_dir / "sample.bin").write_bytes(bytes(data))
            (case_dir / "layout.txt").write_text(
                render_layout(case, layout, data, result)
            )
            if do_minimize:
                minimized, ok = minimize(
                    module, data, case.target_dirs, result.classification, budget
                )
                if ok and len(minimized) < len(data):
                    (case_dir / "minimized.bin").write_bytes(minimized)
                    with (case_dir / "minimized.txt").open("w") as fh:
                        fh.write(
                            f"minimized from {len(data)} to {len(minimized)} bytes; "
                            f"failure class '{result.classification}' still reproduces "
                            f"and target {case.target_dirs} is still reached\n"
                        )
    return results


def summarize_results(results):
    counts = {}
    failures = []
    unstable = []
    for case, _data, _layout, result in results:
        counts[result.classification] = counts.get(result.classification, 0) + 1
        if result.classification in FAILURE_CLASSES:
            failures.append(result)
        if not result.deterministic or not result.input_unchanged:
            unstable.append(result)
    return {
        "total": len(results),
        "counts": counts,
        "failures": failures,
        "unstable": unstable,
    }


# ---------------------------------------------------------------------------
# Self-test: deliberately broken bounds checks must be caught
# ---------------------------------------------------------------------------

BREAKS = {
    "reloc_sizeofblock_unbounded": {
        "description": "remove the SizeOfBlock <= SizeOfImage sanity check",
        "anchor": "    if rlc.SizeOfBlock > self.OPTIONAL_HEADER.SizeOfImage:",
        "replacement": "    if False:  # BREAK: SizeOfBlock bound check removed",
    },
    "reloc_entries_ignore_block_size": {
        "description": "parse relocation entries past the end of the block",
        "anchor": (
            "    def parse_relocations(self, data_rva, rva, size):\n"
            '        """Parse relocations."""\n'
            "\n"
            "        try:\n"
            "            data = self.get_data(data_rva, size)"
        ),
        "replacement": (
            "    def parse_relocations(self, data_rva, rva, size):\n"
            '        """Parse relocations."""\n'
            "\n"
            "        try:\n"
            "            data = self.get_data(data_rva)  # BREAK: ignore SizeOfBlock"
        ),
    },
}


def load_broken_module(break_name, workdir):
    """Create a copy of pefile with one bounds check deliberately broken."""
    spec_def = BREAKS[break_name]
    source = Path(pefile.__file__).read_text()
    if source.count(spec_def["anchor"]) != 1:
        raise RuntimeError(
            f"anchor for break '{break_name}' not found exactly once in pefile.py "
            "(pefile version changed?)"
        )
    broken = source.replace(spec_def["anchor"], spec_def["replacement"])
    path = Path(workdir) / f"pefile_broken_{break_name}.py"
    path.write_text(broken)
    module_name = f"pefile_broken_{break_name}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def selftest(artifacts_dir=None, budget=DEFAULT_BUDGET, quiet=True):
    """Run the corpus against intact and deliberately broken pefile copies."""
    cases = enumerated_cases()

    def noop(_case, _result):
        return None

    progress = None if quiet else _print_progress
    intact = summarize_results(
        run_corpus(pefile, cases, budget=budget, progress=progress)
    )
    outcome = {
        "intact": intact,
        "intact_failures": intact["failures"] + intact["unstable"],
        "breaks": {},
    }

    with tempfile.TemporaryDirectory(prefix="pefile_fuzz_selftest_") as tmp:
        for break_name, spec_def in BREAKS.items():
            module = load_broken_module(break_name, tmp)
            broken_results = run_corpus(module, cases, budget=budget)
            broken_summary = summarize_results(broken_results)
            intact_bad = {r.case_id for r in outcome["intact_failures"]}
            caught_by = [
                r
                for _c, _d, _l, r in broken_results
                if r.failed and r.case_id not in intact_bad
            ]
            outcome["breaks"][break_name] = {
                "description": spec_def["description"],
                "caught": bool(caught_by),
                "caught_by": [r.case_id for r in caught_by],
                "summary": broken_summary["counts"],
            }
            if caught_by and artifacts_dir is not None:
                artifacts_dir = Path(artifacts_dir)
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                for case, data, layout, result in broken_results:
                    if result in caught_by:
                        case_dir = artifacts_dir / f"broken-{break_name}" / f"case-{case.case_id}"
                        case_dir.mkdir(parents=True, exist_ok=True)
                        (case_dir / "sample.bin").write_bytes(bytes(data))
                        (case_dir / "layout.txt").write_text(
                            render_layout(case, layout, data, result)
                        )
    return outcome


def _print_progress(case, result):
    flag = "FAIL" if result.failed else "ok  "
    print(
        f"[{flag}] {case.case_id}: {result.classification} "
        f"reached={sorted(set(result.reached))} warnings={len(result.warnings)}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run the corpus against intact pefile")
    run_p.add_argument("--random", type=int, default=0, metavar="N",
                       help="add N seeded random cases")
    run_p.add_argument("--seed", type=int, default=1337, help="base random seed")
    run_p.add_argument("--budget", type=float, default=DEFAULT_BUDGET,
                       help="per-parse time budget in seconds")
    run_p.add_argument("--artifacts", default="fuzz_artifacts",
                       help="directory for report.jsonl and failure artifacts")
    run_p.add_argument("--quiet", action="store_true")

    self_p = sub.add_parser("selftest", help="verify broken bounds checks are caught")
    self_p.add_argument("--budget", type=float, default=DEFAULT_BUDGET)
    self_p.add_argument("--artifacts", default=None,
                        help="optional directory for caught-failure artifacts")
    self_p.add_argument("--quiet", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "run":
        cases = enumerated_cases()
        if args.random:
            cases += random_cases(args.seed, args.random)
        progress = None if args.quiet else _print_progress
        results = run_corpus(
            pefile, cases, budget=args.budget,
            artifacts_dir=Path(args.artifacts), progress=progress,
        )
        summary = summarize_results(results)
        print(f"\n{summary['total']} cases: {summary['counts']}")
        if summary["unstable"]:
            print(f"unstable/mutating cases: {[r.case_id for r in summary['unstable']]}")
        if summary["failures"]:
            print(f"FAILURES: {[r.case_id for r in summary['failures']]}")
            print(f"artifacts written under {args.artifacts}/")
            return 1
        print(f"no failures (report: {Path(args.artifacts) / 'report.jsonl'})")
        return 0

    if args.command == "selftest":
        outcome = selftest(
            artifacts_dir=args.artifacts, budget=args.budget, quiet=args.quiet
        )
        print(f"intact pefile: {outcome['intact']['counts']}")
        ok = True
        if outcome["intact_failures"]:
            ok = False
            print("INTACT BASELINE HAS FAILURES: "
                  f"{[r.case_id for r in outcome['intact_failures']]}")
        for name, info in outcome["breaks"].items():
            verdict = "CAUGHT" if info["caught"] else "MISSED"
            print(f"break '{name}' ({info['description']}): {verdict}")
            if info["caught"]:
                print(f"  caught by: {info['caught_by'][:6]}"
                      f"{' ...' if len(info['caught_by']) > 6 else ''}")
            else:
                ok = False
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
