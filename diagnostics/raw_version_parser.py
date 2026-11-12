"""Byte-level, lossless parser for VS_VERSIONINFO resources.

Unlike pefile's high-level view this parser never collapses duplicate keys
into a dictionary and never silently trusts a length field. Every String /
Translation block is reported with:

  * absolute file offsets of the block header, szKey and value bytes
  * the declared wLength / wValueLength versus the bytes actually present
  * a status flag (ok / truncated / zero-length / out-of-bounds / ...)
  * every recoverable value, including duplicate keys

It walks the PE resource directory itself (RT_VERSION, all name nodes and all
languages), so values hidden by pefile's "first name entry only" walk are
still recovered. Standard library only.
"""
from __future__ import annotations

import struct

RT_VERSION = 16
FIXED_SIZE = 52


def _u16(data: bytes, off: int, max_words: int | None = None):
    """Read a NUL-terminated UTF-16LE string. Returns (text, next_offset)."""
    chars = []
    i = off
    end = len(data) if max_words is None else min(len(data), off + max_words * 2)
    while i + 1 < end:
        word = data[i] | (data[i + 1] << 8)
        if word == 0:
            return "".join(chars), i + 2
        chars.append(chr(word))
        i += 2
    # No terminator found inside the allowed window.
    return "".join(chars), i


def _align4(offset: int) -> int:
    return (offset + 3) & ~3


class RawVersionError(Exception):
    pass


class RawVersionParser:
    def __init__(self, data: bytes):
        self.data = data
        self.issues: list[dict] = []

    # -- PE / resource directory walk -------------------------------------

    def _u16_at_file(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32_at_file(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def _rva_to_offset(self, rva: int) -> int:
        pe_off = self.data.find(b"PE\x00\x00")
        if pe_off < 0:
            raise RawVersionError("PE signature not found")
        coff = pe_off + 4
        n_sections = self._u16_at_file(coff + 2)
        opt_size = self._u16_at_file(coff + 16)
        sect_off = coff + 20 + opt_size
        for i in range(n_sections):
            base = sect_off + i * 40
            # Section header order: VirtualSize, VirtualAddress,
            # SizeOfRawData, PointerToRawData.
            vsize, vaddr, rawsize, rawptr = struct.unpack_from(
                "<IIII", self.data, base + 8)
            # File offsets must be valid against the raw data; virtual size can
            # exceed the on-disk size for zero-padded tail pages.
            if vaddr <= rva < vaddr + rawsize:
                return rawptr + (rva - vaddr)
        raise RawVersionError(f"RVA {rva:#x} not inside any section")

    def _read_dir(self, section_off: int, rel: int):
        """Return (directory_entries, raw_header_info).

        Each entry is (id_or_name, is_directory, target_rel_offset).
        """
        base = section_off + rel
        _, _, _, _, n_named, n_id = struct.unpack_from(
            "<IIHHHH", self.data, base)
        entries = []
        entry = base + 16
        for _ in range(n_named + n_id):
            name_or_id, off_to_data = struct.unpack_from("<II", self.data, entry)
            entry += 8
            is_dir = bool(off_to_data & 0x80000000)
            entries.append((name_or_id, is_dir, off_to_data & 0x7FFFFFFF))
        return entries

    def find_version_blobs(self) -> list[dict]:
        """Return every RT_VERSION data entry across all name/language nodes."""
        pe_off = self.data.find(b"PE\x00\x00")
        coff = pe_off + 4
        opt_size = self._u16_at_file(coff + 16)
        opt_off = coff + 20
        # DATA_DIRECTORY[2] = resource. PE32 data directories start at
        # optional-header offset 96; entry 2 is 16 bytes later.
        res_rva, res_size = struct.unpack_from(
            "<II", self.data, opt_off + 96 + 2 * 8)
        section_off = self._rva_to_offset(res_rva)
        blobs = []

        # Explicit three-level walk: Type -> Name -> Language(data entry),
        # so every sibling name node is visited, not just the first.
        for type_id, is_dir, type_rel in self._read_dir(section_off, 0):
            if not is_dir or type_id != RT_VERSION:
                continue
            for name_id, name_is_dir, name_rel in self._read_dir(
                    section_off, type_rel):
                if not name_is_dir:
                    continue
                for lang_id, lang_is_dir, lang_rel in self._read_dir(
                        section_off, name_rel):
                    if lang_is_dir:
                        continue
                    data_entry = section_off + lang_rel
                    rva, size, _, _ = struct.unpack_from(
                        "<IIII", self.data, data_entry)
                    blobs.append({
                        "name_id": name_id,
                        "language_id": lang_id,
                        "resource_rva": rva,
                        "resource_size": size,
                        "data_entry_file_offset": data_entry,
                        "file_offset": self._rva_to_offset(rva),
                    })
        return blobs

    # -- VS_VERSIONINFO walk ----------------------------------------------

    def parse_blob(self, blob_file_off: int, size: int) -> dict:
        data = self.data
        start = blob_file_off
        end = min(len(data), start + size)
        result = {"blob_file_offset": start, "blob_size": size,
                  "string_tables": [], "translations": [], "issues": []}
        issues = result["issues"]

        def issue(code, offset, message):
            rec = {"code": code, "file_offset": offset, "message": message}
            issues.append(rec)
            self.issues.append(rec)

        if end - start < 6:
            issue("blob_too_small", start, "not enough bytes for root header")
            return result

        w_length, w_value_length, w_type = struct.unpack_from(
            "<HHH", data, start)
        root_end = start + w_length if w_length else end
        if w_length == 0:
            issue("root_wlength_zero", start,
                  "root wLength is 0; using resource size as boundary")
            root_end = end
        if root_end > end:
            issue("root_wlength_overflow", start,
                  f"root wLength {w_length} exceeds resource size {size}")
            root_end = end

        key, after_key = _u16(data, start + 6)
        if key != "VS_VERSION_INFO":
            issue("bad_root_key", start + 6, f"unexpected root key {key!r}")
            return result
        fixed_off = _align4(after_key)
        result["fixed_file_offset"] = fixed_off
        if fixed_off + FIXED_SIZE > root_end:
            issue("fixed_truncated", fixed_off,
                  "VS_FIXEDFILEINFO extends past root block")
        else:
            sig = self._u32_at_file(fixed_off)
            result["fixed_signature"] = sig
            if sig != 0xFEEF04BD:
                issue("bad_fixed_signature", fixed_off,
                      f"VS_FIXEDFILEINFO signature {sig:#x}")

        cursor = _align4(fixed_off + FIXED_SIZE)
        while cursor + 6 <= root_end:
            block_start = cursor
            b_len, b_val_len, b_type = struct.unpack_from(
                "<HHH", data, block_start)
            block_key, after_block_key = _u16(data, block_start + 6)

            if b_len == 0:
                issue("child_wlength_zero", block_start,
                      f"{block_key!r} block has wLength=0; pefile stops the "
                      "outer loop here")
                break
            block_end = block_start + b_len
            if block_end > root_end:
                issue("child_overflow", block_start,
                      f"{block_key!r} wLength {b_len} crosses root boundary")
                break

            if block_key.startswith("StringFileInfo"):
                self._parse_string_file_info(
                    block_start, b_len, after_block_key, result, issue)
            elif block_key.startswith("VarFileInfo"):
                self._parse_var_file_info(
                    block_start, b_len, after_block_key, result, issue)
            else:
                issue("unknown_child", block_start,
                      f"unknown top-level child {block_key!r}")
            cursor = _align4(block_end)
        return result

    def _parse_string_file_info(self, sfi_start, sfi_len, after_key,
                                result, issue):
        end = sfi_start + sfi_len
        cursor = _align4(after_key)
        table_index = 0
        while cursor + 6 <= end:
            t_start = cursor
            t_len, t_val_len, t_type = struct.unpack_from(
                "<HHH", self.data, t_start)
            if t_len == 0:
                issue("stringtable_wlength_zero", t_start,
                      "StringTable wLength=0; pefile breaks this table loop")
                break
            t_end = t_start + t_len
            if t_end > end:
                issue("stringtable_overflow", t_start,
                      "StringTable extends past StringFileInfo")
                break
            lang_key, after_lang = _u16(self.data, t_start + 6)
            table = {
                "index": table_index,
                "lang_key": lang_key,
                "header_file_offset": t_start,
                "declared_length": t_len,
                "entries": [],
            }
            entry_cursor = _align4(after_lang)
            while entry_cursor + 6 <= t_end:
                e_start = entry_cursor
                e_len, e_val_len, e_type = struct.unpack_from(
                    "<HHH", self.data, e_start)
                e_key, after_e_key = _u16(self.data, e_start + 6)

                if e_len == 0:
                    # Document the block pefile cannot advance past, plus the
                    # bytes it causes to be skipped. The block's own value was
                    # already decoded before the jump; the blocks after it are
                    # what pefile silently drops.
                    skipped = t_end - e_start
                    issue("string_wlength_zero", e_start,
                          f"{e_key!r} wLength=0; pefile decodes this value then "
                          f"jumps to table end, skipping {skipped} bytes of "
                          "subsequent blocks")
                    table["entries"].append({
                        "key": e_key,
                        "key_file_offset": e_start + 6,
                        "declared_wlength": 0,
                        "declared_wvaluelength": e_val_len,
                        "value": None,
                        "status": "wlength_zero_block_and_tail_dropped",
                        "header_file_offset": e_start,
                    })
                    entry_cursor = t_end
                    break

                e_end = e_start + e_len
                if e_end > t_end:
                    issue("string_overflow", e_start,
                          f"{e_key!r} wLength {e_len} crosses table boundary")
                    break

                value_off = _align4(after_e_key)
                available_words = (e_end - value_off) // 2
                declared_words = e_val_len
                raw_words = min(declared_words, available_words)
                raw_value, _ = _u16(
                    self.data, value_off,
                    max_words=raw_words if raw_words else None)
                # Also recover the full NUL-terminated value ignoring the
                # (possibly corrupt) declared length.
                full_value, full_next = _u16(self.data, value_off)

                status = "ok"
                if declared_words > available_words:
                    status = "wvaluelength_overruns_block"
                    issue("wvaluelength_overrun", e_start + 2,
                          f"{e_key!r} declares {declared_words} words but "
                          f"only {available_words} fit in the block")
                elif declared_words < len(full_value):
                    status = "wvaluelength_undersized"
                    issue("wvaluelength_undersized", e_start + 2,
                          f"{e_key!r} declares {declared_words} words; "
                          f"{len(full_value)} characters are actually stored")

                table["entries"].append({
                    "key": e_key,
                    "key_file_offset": e_start + 6,
                    "header_file_offset": e_start,
                    "declared_wlength": e_len,
                    "declared_wvaluelength": e_val_len,
                    "value_file_offset": value_off,
                    "value_per_declared_length": raw_value,
                    "value_full_nul_terminated": full_value,
                    "available_words_in_block": available_words,
                    "status": status,
                })
                entry_cursor = _align4(e_end)

            result["string_tables"].append(table)
            table_index += 1
            next_cursor = _align4(t_end)
            if next_cursor <= cursor:
                issue("stringtable_no_advance", t_start,
                      "StringTable layout does not advance; stopping")
                break
            cursor = next_cursor
            # Mirror pefile's actual loop test (offset vs SFI Length) so the
            # report can show when a legitimate trailing table is at risk.
            if cursor - sfi_start >= sfi_len:
                break

    def _parse_var_file_info(self, vfi_start, vfi_len, after_key,
                             result, issue):
        end = vfi_start + vfi_len
        cursor = _align4(after_key)
        while cursor + 6 <= end:
            v_start = cursor
            v_len, v_val_len, v_type = struct.unpack_from(
                "<HHH", self.data, v_start)
            if v_len == 0:
                issue("var_wlength_zero", v_start,
                      "Var block wLength=0")
                break
            v_end = v_start + v_len
            if v_end > end:
                issue("var_overflow", v_start, "Var block crosses VarFileInfo")
                break
            var_key, after_var_key = _u16(self.data, v_start + 6)
            payload_off = _align4(after_var_key)
            pairs = []
            p = payload_off
            while p + 4 <= v_end and len(pairs) * 4 < v_val_len:
                lang, charset = struct.unpack_from("<HH", self.data, p)
                pairs.append({"lang_id": lang, "charset_id": charset,
                              "file_offset": p})
                p += 4
            result["translations"].append({
                "key": var_key,
                "header_file_offset": v_start,
                "payload_file_offset": payload_off,
                "declared_wvaluelength": v_val_len,
                "pairs": pairs,
            })
            cursor = _align4(v_end)
            if cursor <= v_start:
                break

    # -- Public entry point ------------------------------------------------

    def parse_all(self) -> dict:
        blobs = self.find_version_blobs()
        parsed_blobs = []
        for blob in blobs:
            parsed = self.parse_blob(blob["file_offset"], blob["resource_size"])
            parsed["resource_rva"] = blob["resource_rva"]
            parsed_blobs.append(parsed)
        return {"version_blobs": parsed_blobs, "issues": self.issues}
