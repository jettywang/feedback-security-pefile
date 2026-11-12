"""Generate the forensic sample set.

Each sample is a minimal PE32 whose RT_VERSION resource was deliberately
crafted. An offset manifest is emitted next to every PE so the diagnostic
report can tie every observed value to an absolute file offset.

Samples
-------
s0_baseline.exe            clean, single language (control group)
s1_lang_conflict.exe       two StringTables with different CompanyName;
                           Translation advertises a phantom language
s2_duplicate_key.exe       CompanyName / OriginalFilename appear twice in one
                           StringTable; pefile keeps only the last dict value
s3_corrupt_length.exe      wLength=0 silently drops a table tail; an
                           undersized wValueLength truncates another value
s4_hidden_name_node.exe     two RT_VERSION name nodes; pefile only walks the
                           first (parser limitation, demonstrated separately)
"""
from __future__ import annotations

import json
import os
import struct

from pe_builder import build_pe
from version_blob import build_version_blob, lang_key

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "samples")

EN_US = (0x0409, 0x04B0)   # English (US), Unicode
ZH_CN = (0x0804, 0x04B0)   # Chinese (PRC), Unicode
JA_JP = (0x0411, 0x04B0)   # Japanese, Unicode (phantom in Translation only)


def _abs_offset_map(layout: dict, leaf: dict, offmap: dict) -> dict:
    blob_file = layout["rsrc_rawptr"] + leaf["section_offset"]
    offset_keys = {"block", "wLength", "wValueLength", "wType", "value",
                   "payload", "lang_key", "fixed"}
    return {
        path: {
            key: (blob_file + val if key in offset_keys else val)
            for key, val in fields.items()
        }
        for path, fields in offmap.items()
    }, blob_file


def _make_manifest(layout: dict, leaf: dict, offmap: dict,
                   anomaly: str | None = None) -> dict:
    field_offsets, blob_file = _abs_offset_map(layout, leaf, offmap)
    manifest = {
        "name_id": leaf["name_id"],
        "language_id": leaf["language_id"],
        "blob_rva": leaf["rva"],
        "blob_section_offset": leaf["section_offset"],
        "blob_size": leaf["size"],
        "blob_file_offset": blob_file,
        "field_offsets": field_offsets,
    }
    if anomaly:
        manifest["anomaly"] = anomaly
    return manifest


def _write(filename: str, leaves: list, offmaps: list,
           anomalies: list, description: str) -> None:
    pe_bytes, layout = build_pe(leaves)
    path = os.path.join(OUT, filename)
    with open(path, "wb") as fh:
        fh.write(pe_bytes)
    manifests = []
    for leaf, offmap, anomaly in zip(layout["leaves"], offmaps, anomalies):
        manifests.append(_make_manifest(layout, leaf, offmap, anomaly))
    with open(path + ".manifest.json", "w", encoding="utf-8") as fh:
        json.dump({"file": filename, "description": description,
                   "rsrc": {k: v for k, v in layout.items()
                            if k != "leaves"},
                   "blobs": manifests}, fh, indent=2, ensure_ascii=False)
    print(f"wrote {filename} ({len(pe_bytes)} bytes)")


def sample_baseline():
    tables = [
        (lang_key(*EN_US), [
            ("CompanyName", "Acme Corp"),
            ("FileDescription", "Legitimate updater"),
            ("OriginalFilename", "acme_update.exe"),
            ("FileVersion", "1.0.0.0"),
        ]),
    ]
    blob, offmap = build_version_blob(tables, [EN_US])
    _write("s0_baseline.exe", [(1, EN_US[0], blob)], [offmap], [None],
           "Clean single-language control sample")


def sample_lang_conflict():
    tables = [
        (lang_key(*EN_US), [
            ("CompanyName", "Acme Corp, Redmond WA"),
            ("FileDescription", "Acme Updater"),
            ("OriginalFilename", "acme_update.exe"),
            ("FileVersion", "1.0.0.0"),
        ]),
        (lang_key(*ZH_CN), [
            ("CompanyName", "Contoso 伪装有限公司"),
            ("FileDescription", "系统优化服务"),
            ("OriginalFilename", "svchost_helper.exe"),
            ("FileVersion", "9.9.9.9"),
        ]),
    ]
    # Translation advertises EN_US and JA_JP; no Japanese table exists.
    blob, offmap = build_version_blob(tables, [EN_US, JA_JP])
    _write("s1_lang_conflict.exe", [(1, EN_US[0], blob)], [offmap],
           ["two StringTables with conflicting CompanyName; Translation "
            "contains phantom ja-jp (0x0411) with no matching StringTable"],
           "Multi-language conflicting CompanyName + phantom Translation")


def sample_duplicate_key():
    tables = [
        (lang_key(*EN_US), [
            ("CompanyName", "Acme Corp (first, benign-looking)"),
            ("CompanyName", "EVIL OPERATOR SECOND COPY"),
            ("OriginalFilename", "acme_update.exe"),
            ("OriginalFilename", "malware_payload.bin"),
            ("FileVersion", "1.0.0.0"),
        ]),
    ]
    blob, offmap = build_version_blob(tables, [EN_US])
    _write("s2_duplicate_key.exe", [(1, EN_US[0], blob)], [offmap],
           ["duplicate CompanyName / OriginalFilename String blocks; pefile "
            "dict assignment keeps only the last value for each key"],
           "Duplicate version keys within a single StringTable")


def sample_corrupt_length():
    # Table 1: InternalName.wLength is zeroed -> pefile jumps to table end and
    # silently drops InternalName and every block after it.
    tables1 = [
        (lang_key(*EN_US), [
            ("CompanyName", "Acme Corp"),
            ("OriginalFilename", "acme_update.exe"),
            ("FileDescription", "Visible before corruption"),
            ("InternalName", "DROPPED_BECAUSE_LENGTH_ZERO"),
            ("LegalCopyright", "DROPPED_TAIL_1"),
            ("ProductName", "DROPPED_TAIL_2"),
        ]),
    ]
    blob1 = bytearray(build_version_blob(tables1, [EN_US])[0])
    offmap1 = build_version_blob(tables1, [EN_US])[1]
    target = next(p for p in offmap1
                  if p.startswith("StringFileInfo[0]/StringTable[0]")
                  and ":InternalName" in p)
    struct.pack_into("<H", blob1, offmap1[target]["wLength"], 0)

    # Table 2 (own name node so table 1's break cannot mask this effect):
    # FileDescription claims 4 words while 30 are stored -> truncated value.
    tables2 = [
        (lang_key(*ZH_CN), [
            ("CompanyName", "中文公司名完整值ABCDEF"),
            ("FileDescription", "1234567890-truncated-on-purpose"),
        ]),
    ]
    blob2 = bytearray(build_version_blob(tables2, [ZH_CN])[0])
    offmap2 = build_version_blob(tables2, [ZH_CN])[1]
    fd_path = next(p for p in offmap2 if ":FileDescription" in p)
    struct.pack_into("<H", blob2, offmap2[fd_path]["wValueLength"], 4)

    leaves = [(1, EN_US[0], bytes(blob1)), (2, ZH_CN[0], bytes(blob2))]
    _write("s3_corrupt_length.exe", leaves, [offmap1, offmap2],
           ["InternalName.wLength set to 0; pefile discards InternalName and "
            "the two blocks after it without a warning",
            "FileDescription.wValueLength reduced to 4 words (30 stored); "
            "pefile decodes only the first 4 characters"],
           "Corrupt wLength=0 and undersized wValueLength")


def sample_hidden_name_node():
    blob_a, off_a = build_version_blob(
        [(lang_key(*EN_US), [("CompanyName", "FIRST NODE VISIBLE")])],
        [EN_US])
    blob_b, off_b = build_version_blob(
        [(lang_key(*ZH_CN), [
            ("CompanyName", "SECOND NODE HIDDEN BY PARSER"),
            ("OriginalFilename", "hidden_second.exe")])],
        [ZH_CN])
    leaves = [(1, EN_US[0], blob_a), (2, ZH_CN[0], blob_b)]
    _write("s4_hidden_name_node.exe", leaves, [off_a, off_b],
           [None,
            "second RT_VERSION name node never reaches "
            "parse_version_information because the resource walk hardcodes "
            "the first name entry"],
           "Two RT_VERSION name nodes; parser only reads the first")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    sample_baseline()
    sample_lang_conflict()
    sample_duplicate_key()
    sample_corrupt_length()
    sample_hidden_name_node()
    print("all samples written to", OUT)
