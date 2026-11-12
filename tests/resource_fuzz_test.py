"""Structured fuzzing for pefile's IMAGE_RESOURCE_DIRECTORY parser.

The fuzzer never starts from random bytes. It builds a small set of *synthetic
but legal* resource trees, embeds them into a PE file with a fully valid DOS /
NT / section header (so the loader logic reaches the resource directory) and
only then mutates resource-internal fields:

* relative directory offsets (``OffsetToDirectory``),
* name strings and their 16-bit Pascal length,
* the directory entry counts (``NumberOfNamed/IdEntries``).

Three structural shapes are covered on purpose:

1. a plain tree,
2. a tree with a *shared* sub-directory (one node reached from two parents,
   which is not a back-edge and must keep being parsed),
3. trees that contain genuine *back-edges* (self loop / mutual loop) and an
   over-deep chain, exercising the cycle and depth guards.

Every case records the target path (the chain of RVAs the mutation aimed at)
and a bounded measure of parsing work (directory visits, entry reads, deepest
level). A run is flagged only when the work leaves the finite envelope the
guards promise, an uncaught exception escapes, or the hard work cap trips - not
merely because a warning was emitted.

The module also proves it can detect a removed guard: it recompiles a mutated
copy of ``pefile.py`` in a subprocess with (a) the ancestor back-edge check,
(b) the depth bound or (c) the short-structure length check neutralised and
asserts the corresponding seed blows the bounded-work envelope / raises.

The report for the smallest failing sample contains its full resource
reference graph with shared nodes and back-edges classified, rather than a raw
traceback.
"""

import os
import struct
import sys
import subprocess
from dataclasses import dataclass, field

import pytest

import pefile


# ---------------------------------------------------------------------------
# Limits mirrored from pefile.py; the tests intentionally do not import the
# private names so a refactor of constants does not silently desync them.
# ---------------------------------------------------------------------------
MAX_RESOURCE_DEPTH = 32
HARNESS_WORK_CAP = 20_000          # absolute stop-the-run parse-work bound
SOFT_BUDGET_SLOP = 8               # slack around the unmutated seed's work
SEED = 0x5EC9_0067                 # fixed seed -> byte-identical campaigns
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200


# ---------------------------------------------------------------------------
# Minimal, but fully valid, PE32 file builder.
# ---------------------------------------------------------------------------
DOS_STUB_SIZE = 0x40


def _build_pe_shell(resource_rva, resource_raw_size, resource_va_size):
    """Return (file_bytes, headers_size, resource_raw_ptr).

    The shell keeps every mandatory header well-formed: MZ magic, e_lfanew,
    PE\\0\\0 signature, a PE32 COFF header, a full optional header and one
    ``.rsrc`` section whose data directory points at ``resource_rva``. Only
    the section payload is filled in by the caller, so every mutated sample
    still passes the DOS / NT header checks and reaches resource parsing.
    """
    e_lfanew = DOS_STUB_SIZE
    file_alignment = FILE_ALIGNMENT
    section_alignment = SECTION_ALIGNMENT

    dos = bytearray(b"\x4d\x5a") + bytearray(58) + struct.pack("<I", e_lfanew)
    assert len(dos) == DOS_STUB_SIZE

    coff = struct.pack(
        "<HHIIIHH",
        0x14C,          # Machine: i386
        1,              # NumberOfSections
        0,              # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        0xE0,           # SizeOfOptionalHeader (PE32)
        0x0102,         # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    headers_size = e_lfanew + 4 + len(coff) + 0xE0 + 40
    headers_raw = (
        ((headers_size + file_alignment - 1) // file_alignment)
        * file_alignment
    )
    resource_raw_ptr = headers_raw
    size_of_image = resource_rva + (
        (resource_va_size + section_alignment - 1) // section_alignment
    ) * section_alignment

    # Full PE32 IMAGE_OPTIONAL_HEADER (224 bytes incl. 16 data directories).
    dd_entries = [(0, 0)] * 16
    dd_entries[IMAGE_DIRECTORY_ENTRY_RESOURCE] = (resource_rva,
                                                  resource_va_size)
    dd_blob = b"".join(
        struct.pack("<II", rva, size) for rva, size in dd_entries)
    assert len(dd_blob) == 128

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,          # Magic PE32
        1,              # MajorLinkerVersion
        0,              # MinorLinkerVersion
        resource_raw_size,   # SizeOfCode (irrelevant, keep nonzero-able)
        0,              # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        0,              # AddressOfEntryPoint
        0,              # BaseOfCode
        0x1000,         # BaseOfData
        0x00400000,     # ImageBase
        section_alignment,
        file_alignment,
        4, 0,           # OS version
        0, 0,           # Image version
        4, 0,           # Subsystem version
        0,              # Win32VersionValue
        size_of_image,
        headers_raw,    # SizeOfHeaders
        0,              # CheckSum
        3,              # Subsystem: CONSOLE
        0,              # DllCharacteristics
        0x100000,       # SizeOfStackReserve
        0x1000,         # SizeOfStackCommit
        0x100000,       # SizeOfHeapReserve
        0x1000,         # SizeOfHeapCommit
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    )
    assert len(optional) == 224 - 128

    section_name = b".rsrc\x00\x00\x00"
    section = struct.pack(
        "<8sIIIIIIHHI",
        section_name,
        resource_va_size,                       # VirtualSize
        resource_rva,                          # VirtualAddress
        resource_raw_size,                     # SizeOfRawData
        resource_raw_ptr,                      # PointerToRawData
        0, 0,                                  # PointerToRelocations / LineNumbers
        0, 0,                                  # NumberOfRelocations / LineNumbers
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    )
    assert len(section) == 40

    headers = dos + b"PE\x00\x00" + coff + optional + dd_blob + section
    headers += b"\x00" * (headers_raw - len(headers))
    assert len(headers) == headers_raw
    return headers, headers_raw, resource_raw_ptr


# ---------------------------------------------------------------------------
# Synthetic resource tree builder.
# ---------------------------------------------------------------------------
@dataclass
class RNode:
    """A node of the logical resource graph.

    ``children`` maps entry name/id -> child RNode. A child may be referenced
    by several parents (shared sub-directory); ``back_target`` turns an entry
    into an explicit back-edge towards an already allocated directory.
    """
    node_id: int
    named: bool = False
    name_text: str = ""
    is_data: bool = False
    data_size: int = 4
    children: dict = field(default_factory=dict)
    back_target: object = None          # RNode already laid out (back-edge)


@dataclass
class Patch:
    """A mutable byte range inside the .rsrc payload."""
    kind: str               # "offset" | "name_length" | "count" | "data_size"
    file_off: int
    fmt: str
    value: int
    path: tuple             # logical target path (RVA chain, filled later)


@dataclass
class BuiltResource:
    blob: bytes
    patches: list
    nodes: dict             # node_id -> RNode
    root_id: int
    entry_rva: dict         # node_id -> rva of its IMAGE_RESOURCE_DIRECTORY
    raw_ptr: int
    rsrc_rva: int
    target_paths: dict      # node_id -> tuple of entry-name path strings


class ResourceBuilder:
    """Lays a logical resource graph out as a contiguous .rsrc payload.

    Directories are allocated breadth-first. Back-edges simply point at an
    already allocated directory RVA, which is exactly how a malformed loop or
    a legitimate shared node is encoded at the byte level.
    """

    def __init__(self):
        self._next_id = 0
        self.nodes = {}

    def new_dir(self, named=False, name_text=""):
        node = RNode(node_id=self._next_id, named=named, name_text=name_text)
        self._next_id += 1
        self.nodes[node.node_id] = node
        return node

    def new_data(self, name_text="", data_size=4):
        node = RNode(node_id=self._next_id, is_data=True,
                     named=bool(name_text), name_text=name_text,
                     data_size=data_size)
        self._next_id += 1
        self.nodes[node.node_id] = node
        return node

    @staticmethod
    def link(parent, key, child):
        parent.children[key] = child

    @staticmethod
    def link_back(parent, key, target):
        back = RNode(node_id=-1, back_target=target)
        parent.children[key] = back
        return back

    def build(self, root, rsrc_rva, raw_ptr):
        # BFS allocation order, skipping back-edge placeholders.
        order = []
        queued = set()
        queue = [root]
        while queue:
            node = queue.pop(0)
            if node.node_id in queued or node.is_data or node.back_target:
                continue
            queued.add(node.node_id)
            order.append(node)
            for child in node.children.values():
                if not child.is_data and not child.back_target and \
                        child.node_id not in queued:
                    queue.append(child)

        dir_sizes = {}
        for node in order:
            dir_sizes[node.node_id] = 16 + 8 * len(node.children)

        # Assign directory RVAs.
        cursor = 0
        entry_rva = {}
        for node in order:
            entry_rva[node.node_id] = cursor
            cursor += dir_sizes[node.node_id]
        dirs_end = cursor

        # Name string region.
        name_blob = bytearray()
        name_rva = {}
        for node in order:
            for key, child in node.children.items():
                target = child.back_target if child.back_target else child
                if target.named and target.node_id not in name_rva:
                    encoded = target.name_text.encode("utf-16-le")
                    name_rva[target.node_id] = dirs_end + len(name_blob)
                    name_blob += struct.pack("<H", len(target.name_text))
                    name_blob += encoded
                    name_blob += b"\x00\x00"
        names_end = dirs_end + len(name_blob)

        # Data entries region (one per data leaf), then payload bytes.
        data_entry_rva = {}
        data_blob = bytearray()
        data_cursor = names_end
        for node in self.nodes.values():
            if node.is_data and node.node_id not in data_entry_rva:
                data_entry_rva[node.node_id] = data_cursor
                data_cursor += 16
        payload_start = data_cursor
        data_payload_rva = {}
        for node in self.nodes.values():
            if node.is_data:
                data_payload_rva[node.node_id] = payload_start + len(data_blob)
                data_blob += bytes((node.node_id & 0xFF,)) * node.data_size
        total_size = payload_start + len(data_blob)

        blob = bytearray(total_size)
        patches = []
        target_paths = {}

        def foff(rva):
            return raw_ptr + rva

        for node in order:
            base = entry_rva[node.node_id]
            n_named = sum(
                1 for c in node.children.values()
                if (c.back_target if c.back_target else c).named)
            n_id = len(node.children) - n_named
            blob[base + 12:base + 14] = struct.pack("<H", n_named)
            blob[base + 14:base + 16] = struct.pack("<H", n_id)
            patches.append(Patch("count", foff(base + 14), "<H", n_id, ()))
            if n_named:
                patches.append(Patch("count", foff(base + 12), "<H",
                                     n_named, ()))

            entry_off = base + 16
            for key, child in node.children.items():
                target = child.back_target if child.back_target else child
                if target.named:
                    name_field = 0x80000000 | name_rva[target.node_id]
                    patches.append(Patch(
                        "name_length",
                        foff(name_rva[target.node_id]), "<H",
                        len(target.name_text), ()))
                else:
                    name_field = key & 0xFFFFFFFF

                if child.back_target:
                    offset_field = 0x80000000 | entry_rva[target.node_id]
                elif target.is_data:
                    offset_field = data_entry_rva[target.node_id]
                else:
                    offset_field = 0x80000000 | entry_rva[target.node_id]

                blob[entry_off:entry_off + 4] = struct.pack("<I", name_field)
                blob[entry_off + 4:entry_off + 8] = struct.pack(
                    "<I", offset_field)
                if not target.is_data:
                    patches.append(Patch(
                        "offset", foff(entry_off + 4), "<I",
                        offset_field & 0x7FFFFFFF, ()))
                entry_off += 8

        # IMAGE_RESOURCE_DATA_ENTRY structures.
        for node in self.nodes.values():
            if node.is_data:
                base = data_entry_rva[node.node_id]
                blob[base:base + 4] = struct.pack(
                    "<I", rsrc_rva + data_payload_rva[node.node_id])
                blob[base + 4:base + 8] = struct.pack("<I", node.data_size)
                blob[base + 8:base + 12] = struct.pack("<I", 0)
                blob[base + 12:base + 16] = struct.pack("<I", 0)
                patches.append(Patch("data_size", foff(base + 4), "<I",
                                     node.data_size, ()))

        blob[dirs_end:dirs_end + len(name_blob)] = bytes(name_blob)

        # Human-readable target paths keyed by directory node id.
        def walk(node, path):
            target_paths[node.node_id] = tuple(path)
            for key, child in node.children.items():
                if child.back_target:
                    continue
                label = child.name_text if child.named else f"id:{key}"
                if not child.is_data:
                    walk(child, path + [label])
        walk(root, [])

        # Attach target paths to patches (path of the directory they live in).
        # This is resolved by offset-to-owning-directory below.
        rva_to_path = {
            entry_rva[node.node_id]: target_paths[node.node_id]
            for node in order}
        for patch in patches:
            rva = patch.file_off - raw_ptr
            owner = max((r for r in entry_rva.values() if r <= rva),
                        default=0)
            patch.path = rva_to_path.get(owner, ())

        return BuiltResource(
            blob=bytes(blob), patches=patches, nodes=self.nodes,
            root_id=root.node_id, entry_rva=entry_rva, raw_ptr=raw_ptr,
            rsrc_rva=rsrc_rva, target_paths=target_paths)


# ---------------------------------------------------------------------------
# Seed graph factory: a small set of synthetic, structurally distinct trees.
# ---------------------------------------------------------------------------
def _plain_tree(builder):
    root = builder.new_dir()
    type_ico = builder.new_dir()
    type_ver = builder.new_dir()
    builder.link(root, 3, type_ico)                 # RT_ICON
    builder.link(root, 16, type_ver)               # RT_VERSION
    name_a = builder.new_dir(named=True, name_text="RES_A")
    builder.link(type_ico, 1, name_a)
    leaf1 = builder.new_data()
    leaf2 = builder.new_data(data_size=8)
    builder.link(name_a, 1033, leaf1)
    name_b = builder.new_dir(named=True, name_text="RES_B")
    builder.link(type_ver, 1, name_b)
    leaf3 = builder.new_data(data_size=12)
    builder.link(name_b, 1033, leaf3)
    return root


def _shared_subdir_tree(builder):
    """One directory reached from two parents: sharing, *not* a back-edge."""
    root = builder.new_dir()
    type_a = builder.new_dir()
    type_b = builder.new_dir()
    builder.link(root, 4, type_a)                  # RT_MENU
    builder.link(root, 5, type_b)                  # RT_DIALOG
    shared = builder.new_dir(named=True, name_text="SHARED")
    builder.link(type_a, 1, shared)
    builder.link(type_b, 1, shared)                # legitimate second parent
    leaf = builder.new_data(data_size=6)
    builder.link(shared, 1033, leaf)
    return root


def _self_loop_tree(builder):
    root = builder.new_dir()
    child = builder.new_dir()
    builder.link(root, 10, child)
    builder.link_back(child, 11, child)            # child -> child back-edge
    leaf = builder.new_data()
    builder.link(child, 1033, leaf)
    return root


def _mutual_loop_tree(builder):
    root = builder.new_dir()
    a = builder.new_dir()
    b = builder.new_dir()
    builder.link(root, 10, a)
    builder.link(a, 1, b)
    builder.link_back(b, 2, a)                     # b -> a back-edge
    leaf = builder.new_data()
    builder.link(b, 1033, leaf)
    return root


def _deep_chain_tree(builder, depth=MAX_RESOURCE_DEPTH * 2):
    """A strictly nested chain longer than the promised depth envelope."""
    root = builder.new_dir()
    current = root
    for level in range(depth):
        nxt = builder.new_dir()
        builder.link(current, level + 1, nxt)
        current = nxt
    leaf = builder.new_data()
    builder.link(current, 1033, leaf)
    return root


SEED_FACTORIES = {
    "plain_tree": _plain_tree,
    "shared_subdir": _shared_subdir_tree,
    "self_loop": _self_loop_tree,
    "mutual_loop": _mutual_loop_tree,
    "deep_chain": _deep_chain_tree,
}


def build_seed(seed_name):
    """Assemble a complete, header-valid PE for one synthetic seed."""
    builder = ResourceBuilder()
    root = SEED_FACTORIES[seed_name](builder)
    # First pass with a placeholder RVA to measure the payload size.
    probe = builder.build(root, SECTION_ALIGNMENT, 0)
    raw_size = ((len(probe.blob) + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) \
        * FILE_ALIGNMENT
    va_size = ((len(probe.blob) + SECTION_ALIGNMENT - 1) // SECTION_ALIGNMENT) \
        * SECTION_ALIGNMENT
    resource_rva = SECTION_ALIGNMENT
    headers, headers_raw, raw_ptr = _build_pe_shell(
        resource_rva, raw_size, va_size)
    built = builder.build(root, resource_rva, raw_ptr)
    payload = bytearray(raw_size)
    payload[:len(built.blob)] = built.blob
    return bytearray(headers) + bytes(payload), built


# ---------------------------------------------------------------------------
# Reference-graph analysis: distinguish shared nodes from true back-edges.
# ---------------------------------------------------------------------------
@dataclass
class RefEdge:
    parent: int
    child: int
    kind: str               # "tree" | "shared" | "back"
    via: str


@dataclass
class RefGraph:
    edges: list
    nodes: set
    back_edges: list
    shared_nodes: set
    leaves: dict


def analyze_reference_graph(built):
    """Walk the *logical* graph with an ancestor stack.

    An edge whose target is on the current ancestor stack is a true back-edge
    (a cycle). An edge to a node already finished through another branch is a
    shared sub-directory, which is legal and must not be confused with a loop.
    """
    nodes = {nid: node for nid, node in built.nodes.items()}
    root = nodes[built.root_id]
    edges, back_edges = [], []
    shared, leaves = set(), {}
    seen_finished = set()

    # Pre-compute directory in-degree. A directory referenced by more than one
    # parent is a *shared* sub-directory; every inbound edge to it is a sharing
    # edge (true back-edges are classified separately during the walk).
    in_degree = {}
    for node in nodes.values():
        for child in node.children.values():
            target = child.back_target if child.back_target else child
            if not target.is_data:
                in_degree[target.node_id] = in_degree.get(target.node_id, 0) + 1
    shared_targets = {nid for nid, degree in in_degree.items() if degree > 1}

    def dfs(node, ancestors):
        for key, child in node.children.items():
            if child.back_target:
                target = child.back_target
                via = f"id:{key}->back"
                kind = "back" if target.node_id in ancestors else "shared"
                edge = RefEdge(node.node_id, target.node_id, kind, via)
                edges.append(edge)
                if kind == "back":
                    back_edges.append(edge)
                else:
                    shared.add(target.node_id)
                continue
            via = child.name_text if child.named else f"id:{key}"
            if child.is_data:
                leaves[child.node_id] = node.node_id
                edges.append(RefEdge(node.node_id, child.node_id, "tree", via))
                continue
            if child.node_id in ancestors:
                edge = RefEdge(node.node_id, child.node_id, "back", via)
                edges.append(edge)
                back_edges.append(edge)
                continue
            if child.node_id in shared_targets or \
                    child.node_id in seen_finished:
                shared.add(child.node_id)
                edges.append(RefEdge(node.node_id, child.node_id,
                                     "shared", via))
                if child.node_id not in seen_finished:
                    dfs(child, ancestors | {child.node_id})
                continue
            edges.append(RefEdge(node.node_id, child.node_id, "tree", via))
            dfs(child, ancestors | {child.node_id})
        seen_finished.add(node.node_id)

    dfs(root, {root.node_id})
    return RefGraph(edges=edges, nodes=set(nodes), back_edges=back_edges,
                    shared_nodes=shared, leaves=leaves)


# ---------------------------------------------------------------------------
# Structured mutator: only touches resource-internal fields.
# ---------------------------------------------------------------------------
class ResourceMutator:
    def __init__(self, seed_name, rng, built):
        self.seed_name = seed_name
        self.rng = rng
        self.built = built
        self.rsrc_rva = built.rsrc_rva
        self.raw_ptr = built.raw_ptr
        self.blob_len = len(built.blob)

    def mutate(self, image, count=1):
        """Apply ``count`` structured mutations, never touching PE headers."""
        chosen = self.rng.sample(self.built.patches,
                                 min(count, len(self.built.patches)))
        applied = []
        for patch in chosen:
            new_value = self._new_value(patch)
            self._write(image, patch, new_value)
            applied.append((patch, new_value))
        return applied

    def _new_value(self, patch):
        rng = self.rng
        if patch.kind == "offset":
            choice = rng.randrange(6)
            if choice == 0:     # point back at the resource root (loop)
                return 0
            if choice == 1:     # self reference of the owning directory
                return patch.value
            if choice == 2:     # small relative delta inside the section
                return max(0, (patch.value + rng.choice((-16, -8, 8, 16)))
                           % self.blob_len)
            if choice == 3:     # run past the payload (range violation)
                return self.blob_len + rng.randrange(1, 0x80)
            if choice == 4:     # arbitrary in-section relative offset
                return rng.randrange(0, self.blob_len)
            return rng.choice((0, 4, 8, 12, 16))   # tiny offset cluster
        if patch.kind == "name_length":
            return rng.choice((0, 1, patch.value + 1, 0xFFFF,
                               self.blob_len, max(1, patch.value - 1)))
        if patch.kind == "count":
            return rng.choice((0, 1, patch.value + 1, 0xFF, 0xFFFF,
                               max(1, patch.value * 2)))
        # data_size
        return rng.choice((0, 1, patch.value, 0xFFFF, 0x10000))

    def _write(self, image, patch, value):
        packed = struct.pack(patch.fmt, value & 0xFFFFFFFF)
        image[patch.file_off:patch.file_off + len(packed)] = packed


# ---------------------------------------------------------------------------
# Instrumented parser: bounded, observable execution of one sample.
# ---------------------------------------------------------------------------
class WorkBudgetExceeded(RuntimeError):
    """Raised when a parse walks past the finite envelope the guards promise."""


@dataclass
class Outcome:
    seed_name: str
    target_path: tuple
    reached_resources: bool
    dir_visits: int
    entry_reads: int
    max_level: int
    finding: str = ""          # "" means: guarded, finite behaviour
    error_type: str = ""
    warnings_count: int = 0
    sha256: str = ""
    header_valid: bool = False  # DOS/NT headers accepted (not rejected early)

    @property
    def is_finding(self):
        return bool(self.finding)


class InstrumentedPE(pefile.PE):
    """PE subclass counting resource work and tripping a hard work cap."""

    work_cap = HARNESS_WORK_CAP

    def __init__(self, data, *args, **kwargs):
        self.harness_dir_visits = 0
        self.harness_entry_reads = 0
        self.harness_max_level = 0
        super().__init__(data=data, *args, **kwargs)

    def parse_resources_directory(self, rva, size=0, base_rva=None,
                                  level=0, dirs=None):
        self.harness_dir_visits += 1
        self.harness_max_level = max(self.harness_max_level, level)
        if self.harness_dir_visits > self.work_cap:
            raise WorkBudgetExceeded(
                f"resource directory visits exceeded {self.work_cap}")
        return super().parse_resources_directory(
            rva, size=size, base_rva=base_rva, level=level, dirs=dirs)

    def parse_resource_entry(self, rva):
        self.harness_entry_reads += 1
        if self.harness_entry_reads > self.work_cap:
            raise WorkBudgetExceeded(
                f"resource entry reads exceeded {self.work_cap}")
        return super().parse_resource_entry(rva)


def run_sample(seed_name, image, soft_budget, target_path=()):
    """Parse one sample and classify the result against the finite envelope."""
    import hashlib
    outcome = Outcome(
        seed_name=seed_name,
        target_path=target_path,
        reached_resources=False,
        dir_visits=0,
        entry_reads=0,
        max_level=0,
        sha256=hashlib.sha256(bytes(image)).hexdigest()[:16],
    )
    pe = None
    try:
        pe = InstrumentedPE(bytes(image))
    except WorkBudgetExceeded as exc:
        outcome.finding = "work_cap"
        outcome.error_type = type(exc).__name__
        return outcome
    except Exception as exc:  # noqa: BLE001 - the harness must classify all
        outcome.finding = "uncaught_exception"
        outcome.error_type = type(exc).__name__
        return outcome

    outcome.reached_resources = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
    # The DOS/NT headers were accepted; even if a corrupt resource table is
    # then rejected, the sample was not turned away at the DOS header.
    outcome.header_valid = True
    outcome.dir_visits = pe.harness_dir_visits
    outcome.entry_reads = pe.harness_entry_reads
    outcome.max_level = pe.harness_max_level
    outcome.warnings_count = len(pe.get_warnings())

    if pe.harness_dir_visits > soft_budget or \
            pe.harness_entry_reads > soft_budget:
        outcome.finding = "budget_overflow"
    elif pe.harness_max_level > MAX_RESOURCE_DEPTH + 1:
        outcome.finding = "depth_breach"
    pe.close()
    return outcome


def baseline_work(seed_name, image):
    """Work the unmutated seed needs; defines the seed-specific soft budget."""
    outcome = run_sample(seed_name, image, HARNESS_WORK_CAP)
    assert not outcome.is_finding, (
        f"baseline seed {seed_name} must parse inside the envelope, "
        f"got {outcome.finding}")
    return max(64, outcome.dir_visits + outcome.entry_reads) + SOFT_BUDGET_SLOP


# ---------------------------------------------------------------------------
# Fixed-seed fuzz campaign over the synthetic seed corpus.
# ---------------------------------------------------------------------------
@dataclass
class CampaignResult:
    outcomes: list
    reachable: int
    total: int
    by_seed: dict
    findings: list
    header_valid: int = 0


def adversarial_mutations(built):
    """Deterministic, structurally targeted mutations per seed.

    Unlike the random mutator these always aim at a meaningful resource
    sub-graph edge: a back-edge to root/self, an offset past the section, a
    bloated entry count or an oversized name length. Every output keeps the
    PE headers intact, so the samples still reach the resource directory.
    """
    blob_len = len(built.blob)
    scenarios = []

    offset_patches = [p for p in built.patches if p.kind == "offset"]
    if offset_patches:
        first = offset_patches[0]
        scenarios.append(("backedge_to_root", [(first, 0)]))
        scenarios.append(("self_relative_offset",
                          [(first, first.value)]))
        scenarios.append(("offset_past_section",
                          [(first, FILE_ALIGNMENT)]))
        scenarios.append(("offset_far_out_of_range",
                          [(first, blob_len + 0x1000)]))

    count_patches = [p for p in built.patches if p.kind == "count"]
    if count_patches:
        scenarios.append(("inflated_directory_count",
                          [(count_patches[0], 0xFFFF)]))

    name_patches = [p for p in built.patches if p.kind == "name_length"]
    if name_patches:
        scenarios.append(("oversized_name_length",
                          [(name_patches[0], 0xFFFF)]))
        scenarios.append(("zero_name_length",
                          [(name_patches[0], 0)]))

    size_patches = [p for p in built.patches if p.kind == "data_size"]
    if size_patches:
        scenarios.append(("huge_data_size",
                          [(size_patches[0], 0x7FFFFFFF)]))
    return scenarios


def _apply_scenario(image, patch_values):
    target = ()
    for patch, value in patch_values:
        packed = struct.pack(patch.fmt, value & 0xFFFFFFFF)
        image[patch.file_off:patch.file_off + len(packed)] = packed
        target = patch.path
    return target


def run_campaign(samples_per_seed=24, mutations_per_sample=2,
                 include_adversarial=True):
    import random
    rng = random.Random(SEED)
    outcomes = []
    by_seed = {}

    for seed_name in SEED_FACTORIES:
        base_image, built = build_seed(seed_name)
        budget = baseline_work(seed_name, base_image)
        by_seed[seed_name] = {"budget": budget, "graph": built}
        mutator = ResourceMutator(seed_name, rng, built)

        if include_adversarial:
            for label, patch_values in adversarial_mutations(built):
                image = bytearray(base_image)
                target = _apply_scenario(image, patch_values)
                outcome = run_sample(seed_name, image, budget,
                                     tuple(list(target) + [label]))
                outcomes.append(outcome)

        for _ in range(samples_per_seed):
            image = bytearray(base_image)
            applied = mutator.mutate(image, mutations_per_sample)
            target = applied[0][0].path if applied else ()
            outcomes.append(run_sample(seed_name, image, budget, target))

    reachable = sum(1 for o in outcomes if o.reached_resources)
    header_valid = sum(1 for o in outcomes if o.header_valid)
    findings = [o for o in outcomes if o.is_finding]
    return CampaignResult(outcomes, reachable, len(outcomes),
                          by_seed, findings, header_valid)


# ---------------------------------------------------------------------------
# Mutation-testing proof: neutralise a guard in a recompiled pefile copy.
# ---------------------------------------------------------------------------
PEFILE_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "pefile.py")

MUTANT_SPECS = {
    # (anchor source, replacement, human description)
    "no_cycle_check": (
        "if base_rva + res.OffsetToDirectory in dirs:",
        "if False and base_rva + res.OffsetToDirectory in dirs:",
        "ancestor back-edge (cycle) detection removed",
    ),
    "no_depth_check": (
        "if level > MAX_RESOURCE_DEPTH:",
        "if False and level > MAX_RESOURCE_DEPTH:",
        "MAX_RESOURCE_DEPTH bound removed",
    ),
    "no_length_check": (
        "elif len(data) < self.__format_length__:",
        "elif False and len(data) < self.__format_length__:",
        "short-structure length (range) check removed",
    ),
}

_CHILD_RUNNER = r'''
import json, sys, types

# Load a mutated copy of pefile from the path given in argv.
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    source = handle.read()
module = types.ModuleType("mutated_pefile")
module.__file__ = sys.argv[1]
sys.modules["mutated_pefile"] = module
exec(compile(source, sys.argv[1], "exec"), module.__dict__)

sample_path = sys.argv[2]
with open(sample_path, "rb") as handle:
    data = handle.read()

WORK_CAP = 20000

class Guard(module.PE):
    def __init__(self, blob):
        self.visits = 0
        self.reads = 0
        self.level = 0
        super().__init__(data=blob)

    def parse_resources_directory(self, rva, size=0, base_rva=None,
                                  level=0, dirs=None):
        self.visits += 1
        self.level = max(self.level, level)
        if self.visits > WORK_CAP:
            raise RuntimeError("WORK_CAP_TRIPPED")
        return super().parse_resources_directory(
            rva, size=size, base_rva=base_rva, level=level, dirs=dirs)

    def parse_resource_entry(self, rva):
        self.reads += 1
        if self.reads > WORK_CAP:
            raise RuntimeError("WORK_CAP_TRIPPED")
        return super().parse_resource_entry(rva)

result = {"finding": "", "error_type": "", "visits": 0, "reads": 0,
          "level": 0, "reached": False}
sys.setrecursionlimit(4000)
try:
    pe = Guard(data)
except RecursionError as exc:
    # Unbounded descent: every structural guard that should have terminated
    # the walk has been neutralised.
    result["finding"] = "unbounded_recursion"
    result["error_type"] = type(exc).__name__
except RuntimeError as exc:
    result["finding"] = "work_cap" if "WORK_CAP" in str(exc) else "runtime"
    result["error_type"] = type(exc).__name__
except Exception as exc:  # noqa: BLE001
    result["finding"] = "uncaught_exception"
    result["error_type"] = type(exc).__name__
else:
    result["visits"] = pe.visits
    result["reads"] = pe.reads
    result["level"] = pe.level
    result["reached"] = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
    if pe.visits > WORK_CAP or pe.reads > WORK_CAP:
        result["finding"] = "work_cap"
    elif pe.level > 32 + 1:
        result["finding"] = "depth_breach"
    pe.close()
print(json.dumps(result))
'''


def _make_mutant_source(mutant_name):
    anchor, replacement, _desc = MUTANT_SPECS[mutant_name]
    with open(PEFILE_PATH, "r", encoding="utf-8") as handle:
        source = handle.read()
    assert source.count(anchor) == 1, (
        f"mutant anchor for {mutant_name} not unique")
    return source.replace(anchor, replacement)


def _make_combined_mutant_source(mutant_names):
    """Apply several guard removals to one pefile source (defence-in-depth)."""
    with open(PEFILE_PATH, "r", encoding="utf-8") as handle:
        source = handle.read()
    for name in mutant_names:
        anchor, replacement, _desc = MUTANT_SPECS[name]
        assert source.count(anchor) == 1, f"anchor for {name} not unique"
        source = source.replace(anchor, replacement)
    return source


def run_under_mutant(mutant_name, image, tmp_path, timeout=60,
                     mutant_source=None, label=None):
    """Recompile a mutated pefile and parse ``image`` in a fresh subprocess.

    ``mutant_name`` selects a single guard removal; pass ``mutant_source`` to
    run an explicitly combined mutant instead.
    """
    tag = label or mutant_name
    mutant_dir = tmp_path / "mutants"
    mutant_dir.mkdir(exist_ok=True)
    mutant_path = mutant_dir / f"{tag}_pefile.py"
    source = mutant_source if mutant_source is not None \
        else _make_mutant_source(mutant_name)
    mutant_path.write_text(source, encoding="utf-8")
    sample_path = mutant_dir / f"{tag}_sample.bin"
    sample_path.write_bytes(bytes(image))
    runner_path = mutant_dir / "child_runner.py"
    runner_path.write_text(_CHILD_RUNNER, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(runner_path), str(mutant_path),
         str(sample_path)],
        cwd=os.path.dirname(PEFILE_PATH),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if proc.returncode != 0:
        return {
            "finding": "child_crash",
            "error_type": f"returncode={proc.returncode}",
            "stderr": proc.stderr.decode("utf-8", "replace")[-400:],
            "visits": 0, "reads": 0, "level": 0, "reached": False,
        }
    import json
    return json.loads(proc.stdout.decode("utf-8").strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# Failure reduction: keep the same resource sub-graph while shrinking work.
# ---------------------------------------------------------------------------
def reduce_finding(seed_name, image, budget, built):
    """Greedily drop mutations while the finding persists in the same graph.

    The candidate must still reach the resource directory and must keep the
    same set of directory RVAs (the same resource sub-graph); only field
    values change. This prevents "reduction" into an unrelated early reject.
    """
    original = run_sample(seed_name, image, budget)
    if not original.is_finding:
        return image, original

    best = bytearray(image)
    best_outcome = original
    baseline_dir_rvas = set(built.entry_rva.values())

    # Only fields that currently differ from the seed value can be reduced.
    differing = []
    for patch in built.patches:
        width = struct.calcsize(patch.fmt)
        seed_bytes = struct.pack(patch.fmt, patch.value & 0xFFFFFFFF)
        if bytes(best[patch.file_off:patch.file_off + width]) != seed_bytes:
            differing.append(patch)

    for patch in differing:
        candidate = bytearray(best)
        # Restore this single field to its seed value.
        packed = struct.pack(patch.fmt, patch.value & 0xFFFFFFFF)
        candidate[patch.file_off:patch.file_off + len(packed)] = packed
        outcome = run_sample(seed_name, candidate, budget, patch.path)
        same_graph = _keeps_resource_subgraph(candidate, built,
                                              baseline_dir_rvas)
        if outcome.is_finding and same_graph and outcome.reached_resources:
            best = candidate
            best_outcome = outcome
    return best, best_outcome


def _keeps_resource_subgraph(image, built, baseline_dir_rvas):
    """Parse and confirm the reachable directory RVAs are still the seed's."""
    try:
        pe = InstrumentedPE(bytes(image))
    except Exception:  # noqa: BLE001
        return False
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return False
    observed = _collect_dir_rvas(pe.DIRECTORY_ENTRY_RESOURCE, built.raw_ptr)
    pe.close()
    return observed.issubset(baseline_dir_rvas) and bool(observed)


def _collect_dir_rvas(resource_root, raw_ptr):
    """Return the set of resource-relative directory RVAs actually parsed."""
    rvas = set()
    stack = [resource_root]
    while stack:
        current = stack.pop()
        directory_struct = getattr(current, "struct", None)
        if directory_struct is not None:
            file_offset = getattr(directory_struct,
                                  "__file_offset__", None)
            if file_offset is not None:
                rvas.add(file_offset - raw_ptr)
        for entry in getattr(current, "entries", []):
            directory = getattr(entry, "directory", None)
            if directory is not None:
                stack.append(directory)
    return rvas


# ---------------------------------------------------------------------------
# Reference-graph report for the smallest failing sample (no raw traceback).
# ---------------------------------------------------------------------------
def render_graph_report(seed_name, built, outcome, reduced_image=None):
    graph = analyze_reference_graph(built)
    lines = [
        f"resource reference graph for minimal sample (seed={seed_name})",
        f"  finding          : {outcome.finding or 'none'} "
        f"({outcome.error_type or 'guarded'})",
        f"  target path      : {' -> '.join(outcome.target_path) or '<root>'}",
        f"  directory visits : {outcome.dir_visits}",
        f"  entry reads      : {outcome.entry_reads}",
        f"  deepest level    : {outcome.max_level}",
        f"  nodes={len(graph.nodes)} leaves={len(graph.leaves)} "
        f"edges={len(graph.edges)}",
        "  edges:",
    ]
    for edge in graph.edges:
        lines.append(
            f"    [{edge.kind:6}] node {edge.parent} --{edge.via}--> "
            f"node {edge.child}")
    if graph.back_edges:
        lines.append("  back-edges (true cycles):")
        for edge in graph.back_edges:
            lines.append(f"    node {edge.parent} -> node {edge.child} "
                         f"via {edge.via}")
    else:
        lines.append("  back-edges (true cycles): none")
    if graph.shared_nodes:
        lines.append("  shared sub-directories (legal, not cycles): "
                     + ", ".join(str(n) for n in sorted(graph.shared_nodes)))
    else:
        lines.append("  shared sub-directories: none")
    lines.append("  leaf ownership (leaf -> parent directory):")
    for leaf, parent in sorted(graph.leaves.items()):
        lines.append(f"    leaf {leaf} belongs to directory {parent}")
    if reduced_image is not None:
        lines.append(f"  reduced sample size: {len(reduced_image)} bytes")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pytest cases
# ---------------------------------------------------------------------------
def test_seeds_are_valid_pe_and_reach_resources():
    """Every seed keeps a legal PE header and a reachable resource root."""
    for seed_name in SEED_FACTORIES:
        image, built = build_seed(seed_name)
        assert image[:2] == b"MZ"
        outcome = run_sample(seed_name, image, HARNESS_WORK_CAP)
        assert not outcome.is_finding, (
            f"{seed_name}: baseline must be finite, got {outcome.finding}")
        assert outcome.reached_resources, (
            f"{seed_name}: resource directory must be reached, not rejected "
            "at the DOS/NT header")


def test_seed_reference_graphs_classify_edges_correctly():
    """Shared nodes and genuine back-edges must not be conflated."""
    _, shared = build_seed("shared_subdir")
    shared_graph = analyze_reference_graph(shared)
    assert shared_graph.shared_nodes, "a shared sub-directory must be marked"
    assert not shared_graph.back_edges, "sharing is not a cycle"

    _, loop = build_seed("self_loop")
    loop_graph = analyze_reference_graph(loop)
    assert loop_graph.back_edges, "self loop must be classified as back-edge"

    _, mutual = build_seed("mutual_loop")
    mutual_graph = analyze_reference_graph(mutual)
    assert mutual_graph.back_edges, "mutual loop must be a back-edge"


def test_fuzz_campaign_mostly_reaches_resources_and_stays_bounded():
    """Fixed-seed campaign: legal PE shells, reachable resources, finite work."""
    result = run_campaign(samples_per_seed=24, mutations_per_sample=2)

    # The core requirement: mutations never corrupt the DOS/NT headers, so no
    # sample is rejected at the DOS header. Every parse accepts the PE shell.
    assert result.header_valid == result.total, (
        f"{result.total - result.header_valid} samples were rejected at the "
        "DOS/NT header; fuzzing must stay inside a legal PE shell")

    # The large majority also retain a reachable resource root; the only
    # samples allowed to lose it are resource-layer guards (e.g. the 4096
    # entry cap), which still parse the PE headers successfully.
    reach_ratio = result.reachable / result.total
    assert reach_ratio >= 0.9, (
        f"only {result.reachable}/{result.total} samples reached resources")

    # Every finding must be an envelope violation with a classified cause and
    # target path - never a bare traceback with no structural context.
    for finding in result.findings:
        assert finding.finding in {
            "work_cap", "budget_overflow", "depth_breach",
            "uncaught_exception"}
        assert finding.error_type or finding.finding != "uncaught_exception"
        assert finding.target_path


def test_fuzz_campaign_is_reproducible_with_fixed_seed():
    """Re-running the deterministic campaign yields identical outcomes."""
    first = run_campaign(samples_per_seed=12, mutations_per_sample=2)
    second = run_campaign(samples_per_seed=12, mutations_per_sample=2)
    first_keys = [(o.seed_name, o.sha256, o.finding) for o in first.outcomes]
    second_keys = [(o.seed_name, o.sha256, o.finding) for o in second.outcomes]
    assert first_keys == second_keys


def test_removed_cycle_check_amplifies_work_and_is_ultimately_detected(tmp_path):
    """Removing the ancestor back-edge check must not stay silently finite.

    pefile implements two layers of defence: the ancestor check (``dirs``)
    stops an actual cycle, while ``MAX_RESOURCE_DEPTH`` is the backstop. With
    only the cycle check removed, the walk must measurably descend further
    (the depth backstop becomes the sole terminator); removing *both* guards
    must be caught as genuinely unbounded recursion.
    """
    image, _ = build_seed("self_loop")
    stock_outcome = run_sample("self_loop", image, HARNESS_WORK_CAP)
    assert not stock_outcome.is_finding

    single = run_under_mutant("no_cycle_check", image, tmp_path)
    # The depth backstop still ends it, but the walk is clearly amplified:
    # stock breaks at the first repeated directory (1 visit here); the mutant
    # keeps re-entering until the depth bound fires.
    assert single["visits"] > stock_outcome.dir_visits, single
    assert single["level"] >= MAX_RESOURCE_DEPTH, single

    combined_source = _make_combined_mutant_source(
        ["no_cycle_check", "no_depth_check"])
    combined = run_under_mutant(
        "no_cycle_check", image, tmp_path,
        mutant_source=combined_source, label="combined_cycle_depth")
    assert combined["finding"] in {
        "unbounded_recursion", "work_cap", "uncaught_exception"}, combined


def test_removed_depth_check_is_detected(tmp_path):
    """On an over-deep acyclic chain only MAX_RESOURCE_DEPTH ends the walk."""
    image, _ = build_seed("deep_chain")
    stock_outcome = run_sample("deep_chain", image, HARNESS_WORK_CAP)
    assert not stock_outcome.is_finding
    result = run_under_mutant("no_depth_check", image, tmp_path)
    # Stock stops at the depth envelope (level 33); the mutant walks the whole
    # chain and reports a depth breach past the promised bound.
    assert result["finding"] in {"depth_breach", "work_cap",
                                 "uncaught_exception"}, result
    assert result["level"] > stock_outcome.max_level


def test_removed_length_check_is_detected(tmp_path):
    """Neutralising the short-structure length check must surface a failure.

    The directory offset is aimed past the resource *section* so ``get_data``
    yields an empty buffer. The stock length guard turns that into a graceful
    warning; without it ``struct.unpack`` raises an uncaught ``error``.
    """
    image, built = build_seed("plain_tree")
    offset_patch = next(p for p in built.patches if p.kind == "offset")
    # Relative offset landing beyond the section's raw extent (section is one
    # FileAlignment block; aim a full extra block past the resource base).
    beyond_section = FILE_ALIGNMENT
    struct.pack_into("<I", image, offset_patch.file_off, beyond_section)
    stock_outcome = run_sample("plain_tree", image, HARNESS_WORK_CAP)
    result = run_under_mutant("no_length_check", image, tmp_path)
    assert result["finding"] in {"uncaught_exception", "work_cap",
                                 "child_crash"}, result
    # The same sample does not crash the unmodified library.
    assert stock_outcome.error_type == ""
    assert stock_outcome.reached_resources


def test_reduction_keeps_same_resource_subgraph(tmp_path):
    """Minimisation must preserve the resource sub-graph and reachability.

    The finding is produced against a *finite-work budget*: the mutual-loop
    seed genuinely needs a fixed number of directory visits, so running it
    under a smaller budget is a deterministic budget overflow. A redundant
    ``data_size`` edit that is irrelevant to the finding is layered on top;
    reduction must strip it while keeping the same directory-RVA sub-graph
    and the finding, rather than collapsing into an unrelated early reject.
    """
    image, built = build_seed("mutual_loop")
    full_outcome = run_sample("mutual_loop", image, HARNESS_WORK_CAP)
    assert not full_outcome.is_finding
    tight_budget = max(1, full_outcome.dir_visits - 1)

    mutated = bytearray(image)
    # A structured in-graph edit that the finding does not depend on.
    size_patch = next(p for p in built.patches if p.kind == "data_size")
    struct.pack_into(size_patch.fmt, mutated, size_patch.file_off,
                     0x7FFFFFFF)
    outcome = run_sample("mutual_loop", mutated, tight_budget,
                         ("mutual_loop", "back-edge"))
    assert outcome.finding == "budget_overflow"
    assert outcome.reached_resources

    def edits_vs_seed(candidate):
        return sum(1 for seed_byte, cand_byte in zip(bytes(image), candidate)
                   if seed_byte != cand_byte)

    edits_before = edits_vs_seed(mutated)
    reduced, reduced_outcome = reduce_finding(
        "mutual_loop", mutated, tight_budget, built)
    edits_after = edits_vs_seed(reduced)

    assert reduced_outcome.is_finding
    assert reduced_outcome.reached_resources
    # The redundant edit must actually be removable by the minimiser.
    assert edits_after < edits_before
    baseline_rvas = set(built.entry_rva.values())
    assert _keeps_resource_subgraph(reduced, built, baseline_rvas)


def test_minimal_sample_report_is_structured_graph_not_traceback(tmp_path):
    """The minimal failing sample is reported as a classified reference graph."""
    image, built = build_seed("mutual_loop")
    # The mutual-loop seed already contains a genuine back-edge; present it
    # against a tight finite-work budget to obtain a classified finding while
    # the structural graph (back-edge, leaves) stays fully intact.
    full_outcome = run_sample("mutual_loop", image, HARNESS_WORK_CAP)
    tight_budget = max(1, full_outcome.dir_visits - 1)
    outcome = run_sample("mutual_loop", image, tight_budget,
                         ("mutual_loop", "back-edge"))
    assert outcome.is_finding

    reduced, reduced_outcome = reduce_finding(
        "mutual_loop", bytearray(image), tight_budget, built)
    assert reduced_outcome.is_finding

    report = render_graph_report("mutual_loop", built, reduced_outcome,
                                 reduced)
    # A graph report, not an exception dump:
    assert "Traceback" not in report
    assert "back-edges (true cycles)" in report
    assert "shared sub-directories" in report
    assert "leaf ownership" in report
    assert "target path" in report
    graph = analyze_reference_graph(built)
    assert graph.back_edges  # the mutual loop is present in the report
    (tmp_path / "minimal_resource_graph.txt").write_text(report,
                                                         encoding="utf-8")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
