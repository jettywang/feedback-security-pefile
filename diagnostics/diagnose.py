"""Forensic comparison: pefile presentation vs lossless evidence view.

For every sample this tool reports:

1. pefile_view   - exactly what pefile exposes (dicts collapse duplicate keys,
                   first-name-node resource walk, silent truncations).
2. evidence_view - every recoverable String block and Translation pair from
                   the raw parser, with absolute file offsets and status.
3. discrepancies - value-level classification: retained / overwritten /
                   dropped / truncated / phantom_translation / hidden_blob.

The CompanyName and OriginalFilename values from resources are explicitly
labelled as attacker-controlled metadata, never as an authenticated identity.
Run:  python3 diagnose.py [--json] [sample ...]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pefile  # noqa: E402

from raw_version_parser import RawVersionParser  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(HERE, "samples")
REPORT_DIR = os.path.join(HERE, "reports")

WATCH_KEYS = ("CompanyName", "OriginalFilename")


def _b(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    return value


def pefile_view(path: str) -> dict:
    pe = pefile.PE(path)
    view = {"warnings": [w for w in pe.get_warnings()
                         if "Byte 0x00" not in w],
            "string_tables": [], "translations": [], "parsed_blobs": 0}

    # Resource tree: show how many RT_VERSION name nodes physically exist,
    # because pefile only parses the first one.
    name_nodes = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if type_entry.id == 16 and hasattr(type_entry, "directory"):
                for name_entry in type_entry.directory.entries:
                    langs = []
                    if hasattr(name_entry, "directory"):
                        langs = [e.id for e in name_entry.directory.entries]
                    name_nodes.append({"name_id": name_entry.id,
                                       "language_ids": langs})
    view["rt_version_name_nodes_on_disk"] = name_nodes

    if not hasattr(pe, "FileInfo"):
        view["parsed_blobs"] = 0
        return view

    for fi in pe.FileInfo:
        for entry in fi:
            if hasattr(entry, "StringTable"):
                for st in entry.StringTable:
                    view["string_tables"].append({
                        "lang_key": _b(st.LangID),
                        "entries": {_b(k): _b(v) for k, v in st.entries.items()},
                    })
            elif hasattr(entry, "Var"):
                for var in entry.Var:
                    if hasattr(var, "entry"):
                        for key, val in var.entry.items():
                            view["translations"].append(
                                {"key": _b(key), "value": val})
    view["parsed_blobs"] = len(pe.FileInfo)
    return view


def evidence_view(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return RawVersionParser(data).parse_all()


def _lang_label(lang_key: str) -> str:
    labels = {
        "0409": "en-US (0x0409)",
        "0804": "zh-CN (0x0804)",
        "0411": "ja-JP (0x0411)",
    }
    return labels.get(lang_key[:4], lang_key[:4]) + f" charset {lang_key[4:]}"


def build_discrepancies(pe_view: dict, ev: dict) -> list[dict]:
    out = []

    # 1. Duplicate keys: raw parser keeps multiple, pefile keeps one.
    for blob in ev["version_blobs"]:
        for table in blob["string_tables"]:
            counts: dict[str, list] = {}
            for entry in table["entries"]:
                counts.setdefault(entry["key"], []).append(entry)
            for key, copies in counts.items():
                if len(copies) > 1:
                    out.append({
                        "type": "duplicate_key_overwritten",
                        "lang_key": table["lang_key"],
                        "key": key,
                        "copies_on_disk": [
                            {"file_offset": c["header_file_offset"],
                             "value": c["value_full_nul_terminated"]}
                            for c in copies],
                        "pefile_value": next(
                            (st["entries"].get(key)
                             for st in pe_view["string_tables"]
                             if st["lang_key"] == table["lang_key"]), None),
                        "explanation": "pefile assigns entries[key]=value in "
                                       "sequence, so earlier copies are "
                                       "overwritten and not exposed anywhere.",
                    })

    # 2. Dropped / truncated entries from corrupt lengths.
    for blob in ev["version_blobs"]:
        for table in blob["string_tables"]:
            for entry in table["entries"]:
                if entry["status"] == "wlength_zero_block_and_tail_dropped":
                    out.append({
                        "type": "wlength_zero_drops_tail",
                        "lang_key": table["lang_key"],
                        "key": entry["key"],
                        "file_offset": entry["header_file_offset"],
                        "explanation": "wLength=0 makes pefile jump to the "
                                       "end of this StringTable after decoding "
                                       "this block's own value; every block "
                                       "following it vanishes with no parsing "
                                       "warning.",
                    })
                elif entry["status"] == "wvaluelength_undersized":
                    out.append({
                        "type": "wvaluelength_truncated",
                        "lang_key": table["lang_key"],
                        "key": entry["key"],
                        "file_offset": entry["header_file_offset"],
                        "declared_words": entry["declared_wvaluelength"],
                        "pefile_value": entry["value_per_declared_length"],
                        "full_value_on_disk":
                            entry["value_full_nul_terminated"],
                        "explanation": "pefile honours the corrupt "
                                       "wValueLength and reads only that many "
                                       "words; the remaining bytes stay on "
                                       "disk but are not decoded.",
                    })

    # 3. Phantom / mismatched translations vs real StringTable keys.
    table_keys = {
        t["lang_key"].lower()
        for blob in ev["version_blobs"] for t in blob["string_tables"]
    }
    for blob in ev["version_blobs"]:
        for trans in blob["translations"]:
            for pair in trans["pairs"]:
                lk = f"{pair['lang_id']:04x}{pair['charset_id']:04x}"
                if lk not in table_keys:
                    out.append({
                        "type": "phantom_translation",
                        "advertised_lang_key": lk,
                        "file_offset": pair["file_offset"],
                        "real_string_table_keys": sorted(table_keys),
                        "explanation": "Translation advertises a language "
                                       "that has no StringTable; tools that "
                                       "enumerate Translation overstate the "
                                       "languages actually present.",
                    })

    # 4. Multiple real tables with conflicting watched keys. A value clash
    # only counts as a language conflict when it comes from *different*
    # StringTables; same-table duplicates were already classified above.
    watched: dict[str, list] = {}
    for blob in ev["version_blobs"]:
        for table in blob["string_tables"]:
            seen_in_table: set[str] = set()
            for entry in table["entries"]:
                if entry["key"] not in WATCH_KEYS:
                    continue
                value = entry.get("value_full_nul_terminated")
                if value is None or entry["key"] in seen_in_table:
                    continue
                seen_in_table.add(entry["key"])
                watched.setdefault(entry["key"], []).append({
                    "lang_key": table["lang_key"],
                    "value": value,
                    "file_offset": entry["value_file_offset"],
                })
    for key, occurrences in watched.items():
        distinct = {o["value"] for o in occurrences}
        lang_keys = {o["lang_key"] for o in occurrences}
        if len(distinct) > 1 and len(lang_keys) > 1:
            out.append({
                "type": "conflicting_values_across_languages",
                "key": key,
                "occurrences": occurrences,
                "explanation": "No single CompanyName/OriginalFilename can be "
                               "treated as authoritative; pefile exposes all "
                               "tables but many consumers read only the first.",
            })

    # 5. Blobs hidden by the first-name-node resource walk.
    on_disk = pe_view["rt_version_name_nodes_on_disk"]
    if len(on_disk) > pe_view["parsed_blobs"]:
        hidden = ev["version_blobs"][pe_view["parsed_blobs"]:]
        out.append({
            "type": "rt_version_name_node_skipped",
            "name_nodes_on_disk": on_disk,
            "pefile_parsed_blobs": pe_view["parsed_blobs"],
            "hidden_blob_offsets": [b["blob_file_offset"] for b in hidden],
            "explanation": "pefile's resource walk hardcodes the first name "
                           "entry; additional RT_VERSION blobs never reach "
                           "parse_version_information.",
        })
    return out


def analyze(path: str) -> dict:
    pe_view = pefile_view(path)
    ev = evidence_view(path)
    return {
        "sample": os.path.basename(path),
        "identity_warning": "CompanyName / OriginalFilename are unauthenticated "
                            "resource strings, not signature-derived identity.",
        "pefile_view": pe_view,
        "evidence_view": ev,
        "discrepancies": build_discrepancies(pe_view, ev),
    }


def render_text(report: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(f"SAMPLE: {report['sample']}")
    lines.append(f"NOTE:   {report['identity_warning']}")
    pv = report["pefile_view"]
    lines.append("-" * 78)
    lines.append("[pefile presentation]")
    lines.append(f"  RT_VERSION name nodes on disk: "
                 f"{[n['name_id'] for n in pv['rt_version_name_nodes_on_disk']]}")
    lines.append(f"  blobs actually parsed by pefile: {pv['parsed_blobs']}")
    lines.append(f"  pefile warnings (resource related): {pv['warnings'] or 'none'}")
    for st in pv["string_tables"]:
        lines.append(f"  StringTable {st['lang_key']} ({_lang_label(st['lang_key'])}):")
        for key, val in st["entries"].items():
            lines.append(f"      {key} = {val!r}")
    for tr in pv["translations"]:
        lines.append(f"  Translation (pefile, last-pair bug): {tr['value']}")

    lines.append("-" * 78)
    lines.append("[lossless evidence view]")
    for bi, blob in enumerate(report["evidence_view"]["version_blobs"]):
        lines.append(f"  blob[{bi}] file_offset={blob['blob_file_offset']:#x} "
                     f"rva={blob['resource_rva']:#x} size={blob['blob_size']}")
        for table in blob["string_tables"]:
            lines.append(f"    StringTable {table['lang_key']} "
                         f"({_lang_label(table['lang_key'])}) "
                         f"header@{table['header_file_offset']:#x}")
            for entry in table["entries"]:
                marker = "" if entry["status"] == "ok" else f" <<{entry['status']}>>"
                if entry["status"] == "wlength_zero_block_and_tail_dropped":
                    lines.append(
                        f"      @{entry['header_file_offset']:#x} "
                        f"{entry['key']} [wLen=0, "
                        f"wValLen={entry['declared_wvaluelength']}]"
                        f" = <block present on disk, not decoded by pefile>"
                        f"{marker}")
                    continue
                lines.append(
                    f"      @{entry['header_file_offset']:#x} "
                    f"{entry['key']} [wLen={entry['declared_wlength']}, "
                    f"wValLen={entry['declared_wvaluelength']}]"
                    f" = {entry['value_full_nul_terminated']!r}{marker}")
                if entry["status"] == "wvaluelength_undersized":
                    lines.append(
                        f"          pefile would decode only: "
                        f"{entry['value_per_declared_length']!r} "
                        f"(value bytes @{entry['value_file_offset']:#x})")
        for trans in blob["translations"]:
            pairs = ", ".join(
                f"0x{p['lang_id']:04x}/0x{p['charset_id']:04x}"
                f"@{p['file_offset']:#x}" for p in trans["pairs"])
            lines.append(f"    Translation pairs (all recovered): {pairs}")
        for issue in blob["issues"]:
            lines.append(f"    ISSUE [{issue['code']}] @{issue['file_offset']:#x}: "
                         f"{issue['message']}")

    lines.append("-" * 78)
    lines.append("[discrepancies: retained / overwritten / dropped / hidden]")
    if not report["discrepancies"]:
        lines.append("  none (clean control sample)")
    for d in report["discrepancies"]:
        lines.append(f"  * {d['type']}: {d['explanation']}")
        if d["type"] == "conflicting_values_across_languages":
            for occ in d["occurrences"]:
                lines.append(
                    f"      {d['key']} @{occ['file_offset']:#x} "
                    f"[{occ['lang_key']} / {_lang_label(occ['lang_key'])}] "
                    f"= {occ['value']!r}")
        if d["type"] == "duplicate_key_overwritten":
            for copy in d["copies_on_disk"]:
                lines.append(f"      on-disk @{copy['file_offset']:#x}: "
                             f"{copy['value']!r}")
            lines.append(f"      pefile exposes only: {d['pefile_value']!r}")
        if d["type"] == "rt_version_name_node_skipped":
            lines.append(f"      hidden blob file offsets: "
                         f"{[hex(o) for o in d['hidden_blob_offsets']]}")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("samples", nargs="*",
                    help="PE files (defaults to all generated samples)")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON only")
    args = ap.parse_args()

    paths = args.samples or sorted(glob.glob(os.path.join(SAMPLE_DIR, "s*.exe")))
    reports = [analyze(p) for p in paths]

    os.makedirs(REPORT_DIR, exist_ok=True)
    json_path = os.path.join(REPORT_DIR, "diagnostic_report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(reports, fh, indent=2, ensure_ascii=False)

    if args.json:
        print(json.dumps(reports, indent=2, ensure_ascii=False))
        return

    text = "\n".join(render_text(r) for r in reports)
    txt_path = os.path.join(REPORT_DIR, "diagnostic_report.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    print(f"JSON report: {json_path}")
    print(f"Text report: {txt_path}")


if __name__ == "__main__":
    main()
