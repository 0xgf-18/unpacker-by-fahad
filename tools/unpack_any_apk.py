#!/usr/bin/env python3
"""Generalized unpacker/rebuilder for 'Proxy/AXB mod' style packed APKs.

Recovers the hidden DEX records stored inside the carrier (classes.dex) of any
APK packed with the same scheme (encrypted DEX chain + XOR trailer), then
rebuilds a working installable APK (dedicated multidex, patched manifest,
zipaligned and signed).

Design decisions
----------------
* The carrier layout is *auto-detected*: we never assume the fixed trailer
  offsets of a specific packer build.  We search for the end of the first
  record near EOF and validate the whole backwards chain cheaply (each step
  derives size + key exactly, and checks the decrypted DEX magic, header
  ``file_size`` and endian tag from just the first bytes).
* The real Application class is discovered from the recovered DEXes
  (a class whose superclass chain reaches ``android.app.Application``).
  The manifest's ``application android:name`` is repointed to it when the
  current value is the packer stub (not present in the payload).  If no
  Application subclass is found, a minimal no-op stub class is generated
  instead.  This keeps the rebuilt APK runnable.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------

def u32(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"out-of-range u32 at 0x{off:x}")
    return struct.unpack_from("<I", buf, off)[0]


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def xor_stream(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    k = len(key)
    out = bytearray(len(data))
    # Simple python xor; fast enough for typical payload sizes.
    for i, b in enumerate(data):
        out[i] = b ^ key[i & (k - 1)]
    return bytes(out)


def decode_mutf8(data: bytes) -> str:
    out = []
    i = 0
    while i < len(data):
        c = data[i]
        if c == 0:
            break
        if c & 0x80 == 0:
            out.append(chr(c))
            i += 1
        elif c & 0xE0 == 0xC0:
            out.append(chr(((c & 0x1F) << 6) | (data[i + 1] & 0x3F)))
            i += 2
        elif c & 0xF0 == 0xE0:
            out.append(chr(((c & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F)))
            i += 3
        else:
            u = (((c & 0x07) << 18) | ((data[i + 1] & 0x3F) << 12) |
                 ((data[i + 2] & 0x3F) << 6) | (data[i + 3] & 0x3F))
            if u > 0x10FFFF:
                u = 0xFFFD
            out.append(chr(u))
            i += 4
    return "".join(out)


def encode_mutf8(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            out += b"\xC0\x80"
        elif cp <= 0x7F:
            out += bytes([cp])
        elif cp <= 0x7FF:
            out += bytes([0xC0 | (cp >> 6), 0x80 | (cp & 0x3F)])
        elif cp <= 0xFFFF:
            out += bytes([0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)])
        else:
            u = cp - 0x10000
            out += bytes([0xF0 | (u >> 18), 0x80 | ((u >> 12) & 0x3F),
                          0x80 | ((u >> 6) & 0x3F), 0x80 | (u & 0x3F)])
    return bytes(out)


# ---------------------------------------------------------------------------
# AXML (binary AndroidManifest) utilities
# ---------------------------------------------------------------------------

RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP = 0x0180
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_TYPE = 0x0003
FLAG_UTF8 = 0x00000100

TYPE_STRING = 0x03

ATTR_ANDROID_NAME = 0x01010003
ATTR_ANDROID_PACKAGE = 0x01010002


class AXML:
    """Lightweight reader for an AXML file (AndroidManifest.xml)."""

    def __init__(self, buf: bytes):
        self.buf = buf
        if u16(buf, 0) != RES_XML_TYPE:
            raise ValueError("not an AXML file (missing XML chunk type)")
        self.xml_size = u32(buf, 4)
        self.pool = self._read_string_pool(buf, 8)
        self.res_map = []
        off = 8 + self.pool["chunk_size"]
        # the resource map (if any) directly follows the string pool
        while off + 8 <= len(buf):
            if u16(buf, off) == RES_XML_RESOURCE_MAP:
                size = u32(buf, off + 4)
                n = (size - 8) // 4
                self.res_map = [u32(buf, off + 8 + i * 4) for i in range(n)]
                off += size
                break
            break
        self.start_ns_off = off

    def resolve_attr_id(self, idx: int) -> int:
        if self.res_map and idx < len(self.res_map):
            return self.res_map[idx]
        return idx

    def _read_string_pool(self, buf, base):
        if u16(buf, base) != RES_STRING_POOL_TYPE:
            raise ValueError("expected string pool chunk")
        header_size = u16(buf, base + 2)
        chunk_size = u32(buf, base + 4)
        string_count = u32(buf, base + 8)
        style_count = u32(buf, base + 12)
        flags = u32(buf, base + 16)
        strings_start = u32(buf, base + 20)
        styles_start = u32(buf, base + 24)
        utf8 = bool(flags & FLAG_UTF8)
        data_base = base + strings_start
        strings = []
        for i in range(string_count):
            off = u32(buf, base + header_size + i * 4)
            pos = data_base + off
            if utf8:
                ln, pos = self._uleb128(pos)
            else:
                ln = u16(buf, pos)
                pos += 2
            if ln < 0 or pos + ln > len(buf):
                strings.append("")
                continue
            raw = buf[pos:pos + ln * (1 if utf8 else 2)]
            if utf8:
                strings.append(decode_mutf8(raw))
            else:
                strings.append(raw.decode("utf-16-le", "replace"))
        return {
            "base": base,
            "header_size": header_size,
            "chunk_size": chunk_size,
            "string_count": string_count,
            "style_count": style_count,
            "flags": flags,
            "strings_start": strings_start,
            "utf8": utf8,
            "strings": strings,
        }

    def _uleb128(self, pos):
        result = 0
        shift = 0
        while True:
            b = self.buf[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, pos

    def _upper_leb(self, pos):  # 16-bit version used by UTF8 string pools
        result = 0
        shift = 0
        while True:
            b = self.buf[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, pos

    def iter_elements(self):
        """Yield (tag, [(ns, attr_resid, raw_value_index, dtype, data, aoff)], raw)
        for each START_ELEMENT chunk.  ``aoff`` is the absolute file offset of
        each attribute's table entry."""
        off = self.start_ns_off
        buf = self.buf
        end = min(self.xml_size, len(buf))
        while off + 8 <= end:
            chunk_type = u16(buf, off)
            header_size = u16(buf, off + 2)
            chunk_size = u32(buf, off + 4)
            if chunk_size < 8:
                break
            if chunk_type == RES_XML_RESOURCE_MAP:
                off += chunk_size
                continue
            if chunk_type == RES_XML_START_ELEMENT:
                base = off + header_size
                name_idx = u32(buf, base + 4)
                attr_start = u16(buf, base + 8)
                attr_size = u16(buf, base + 10)
                attr_count = u16(buf, base + 12)
                tag = self.pool["strings"][name_idx] if name_idx < len(self.pool["strings"]) else "?"
                attrs = []
                aoff0 = base + attr_start
                for i in range(attr_count):
                    aoff = aoff0 + i * attr_size
                    ns = u32(buf, aoff)
                    name_rid = self.resolve_attr_id(u32(buf, aoff + 4))
                    raw_value = u32(buf, aoff + 8)
                    tval_off = aoff + 12
                    dtype = buf[tval_off + 3]
                    data = u32(buf, tval_off + 4)
                    attrs.append((ns, name_rid, raw_value, dtype, data, aoff))
                yield tag, attrs, off
                off += chunk_size
                continue
            off += chunk_size

    def get_application_name(self):
        """Return raw android:name of the <application> element + package."""
        pkg = None
        app_name = None
        for tag, attrs, _ in self.iter_elements():
            if tag == "manifest":
                for ns, rid, raw, dtype, data, _aoff in attrs:
                    if rid == ATTR_ANDROID_PACKAGE and dtype == TYPE_STRING and raw < len(self.pool["strings"]):
                        pkg = self.pool["strings"][raw]
            elif tag == "application":
                for ns, rid, raw, dtype, data, _aoff in attrs:
                    if rid == ATTR_ANDROID_NAME:
                        if dtype == TYPE_STRING and raw < len(self.pool["strings"]):
                            app_name = self.pool["strings"][raw]
                        break
        return pkg, app_name


def patch_axml_application_name(data: bytes, new_name: str) -> bytes:
    """Rewrite the <application> android:name string value to ``new_name``.

    Implements an append-to-string-pool edit:

    * a new 4-byte slot is *inserted* at the end of the offset table so the
      table can grow without clobbering the string data that immediately
      follows it in APK manifests (UTF-16 pools, ``stringsStart`` right after
      the table);
    * the existing string data is shifted with it, so all prior string offsets
      remain valid;
    * the new string is appended after the pool, sizes are bumped, and the
      attribute's raw value + typed data are repointed to the new string.
    """
    ax = AXML(data)
    pool = ax.pool
    if pool["style_count"] or (pool["flags"] & ~FLAG_UTF8) not in (0, FLAG_UTF8):
        raise ValueError("unsupported string pool style/flags")

    pool_base = pool["base"]
    ss_off = pool_base + 20
    chunk_off = pool_base + 4
    count_off = pool_base + 8
    offset_table_off = pool_base + pool["header_size"]
    sc = pool["string_count"]
    utf8 = pool["utf8"]

    utf16_len = len(new_name)
    if utf8:
        enc = encode_mutf8(new_name)
        payload = bytes([utf16_len, len(enc)]) + enc + b"\x00"
    else:
        enc = new_name.encode("utf-16-le")
        payload = struct.pack("<H", utf16_len) + enc + b"\x00\x00"
    pad = (4 - (len(payload) % 4)) % 4
    payload += b"\x00" * pad

    # 1. make room for one new offset-table slot (shifts all string data +4)
    new_data = bytearray(data)
    insert_at = offset_table_off + sc * 4
    new_data[insert_at:insert_at] = b"\x00\x00\x00\x00"

    # 2. update sizes/counts
    new_ss = pool["strings_start"] + 4
    new_chunk = pool["chunk_size"] + 4
    struct.pack_into("<I", new_data, chunk_off, new_chunk + len(payload))
    struct.pack_into("<I", new_data, count_off, sc + 1)
    struct.pack_into("<I", new_data, ss_off, new_ss)
    struct.pack_into("<I", new_data, 4, ax.xml_size + 4 + len(payload))

    # 3. append the new string payload at the end of the pool
    append_pos = pool_base + new_chunk
    new_data[append_pos:append_pos] = payload

    # 4. new string offset: start of payload, relative to stringsStart
    new_index = sc
    struct.pack_into("<I", new_data, offset_table_off + new_index * 4,
                     new_chunk - new_ss)

    # 5. re-locate the attribute on the NEW buffer and repoint it
    target_attr_off = None
    reax = AXML(bytes(new_data))
    for tag, attrs, _elem_off in reax.iter_elements():
        if tag != "application":
            continue
        for ns, name_rid, raw_value, dtype, data, aoff in attrs:
            if name_rid == ATTR_ANDROID_NAME:
                target_attr_off = aoff
                break
        if target_attr_off is not None:
            break
    if target_attr_off is None:
        raise ValueError("application/android:name attribute vanished after mutation")

    struct.pack_into("<I", new_data, target_attr_off + 8, new_index)
    struct.pack_into("<I", new_data, target_attr_off + 12 + 4, new_index)
    return bytes(new_data)


# ---------------------------------------------------------------------------
# Carrier recovery (auto-detected)
# ---------------------------------------------------------------------------

RECORD_HDR_SIZE = 0x44  # 4 (encoded size) + 64 (key)


def peek_record(carrier, block_end):
    """Cheap structural probe of one record whose [size][key] block ends at
    ``block_end``.  Returns (size, payload_off, ok, head) where ``head`` holds
    the decrypted first 0x2C bytes when ``ok``."""
    if block_end < 0x44 or block_end > len(carrier):
        return None, None, False, None
    key = carrier[block_end - 0x40:block_end]
    enc_size = carrier[block_end - 0x44:block_end - 0x40]
    size = int.from_bytes(bytes(a ^ b for a, b in zip(enc_size, key[:4])), "little")
    off = block_end - 0x44 - size
    if size < 0x60 or off < 0 or off + 0x2C > block_end:
        return size, off, False, None
    head = bytes(b ^ key[(i + 0) & 0x3F] for i, b in enumerate(carrier[off:off + 0x2C]))
    ok = (head[:4] == b"dex\n" and u32(head, 0x20) == size
          and u32(head, 0x28) == 0x12345678)
    return size, off, ok, head


def find_first_record_end(carrier: bytes, count: int):
    """Return candidate block-end offsets (best first) for the first record,
    i.e. the position right after the [size][key] block of the record stored
    closest to the trailer / EOF.  The whole chain is walked backwards and
    every link is probed cheaply, so pipes where a following record would not
    decode are rejected early."""
    n = len(carrier)
    candidates = []
    lo = max(0x10, n - 0x300)
    hi = n - 0x10
    for e in range(lo, hi, 4):
        if carrier[e - 4:e] == b"ARKS":
            continue  # unsupported variant marker
        size, off, ok, head = peek_record(carrier, e)
        if not ok:
            continue
        cur = off
        chain_ok = True
        for _ in range(count - 1):  # first peek already covered record 1
            sz2, off2, ok2, _ = peek_record(carrier, cur)
            if not ok2:
                chain_ok = False
                break
            cur = off2
        if not chain_ok:
            continue
        if cur < 0x40:
            continue
        score = 0
        if cur < 0x2000:
            score += 3
        elif cur < 0x20000:
            score += 2
        elif cur < 0x400000:
            score += 1
        if e > n - 0x140:
            score += 1  # first record tail expected near the trailer
        candidates.append((e, cur, score))
    candidates.sort(key=lambda c: c[2], reverse=True)
    return candidates


def recover_records(carrier: bytes):
    n = len(carrier)
    if n < 0x200:
        raise ValueError("carrier too small")
    count = u32(carrier, n - 4)
    if not (1 <= count <= 20000):
        raise ValueError(f"implausible record count: {count}")

    candidates = find_first_record_end(carrier, count)
    last_error = None
    for e, _, _ in candidates:
        records = []
        try:
            pos = e
            for i in range(count):
                if pos < 0x44:
                    raise ValueError(f"record {i}: underflow")
                if carrier[pos - 4:pos] == b"ARKS":
                    raise ValueError("ARKS variant encountered; this extractor "
                                     "targets the normal B2Al carrier chain.")
                key = carrier[pos - 0x40:pos]
                enc_size = carrier[pos - 0x44:pos - 0x40]
                size = int.from_bytes(bytes(a ^ b for a, b in zip(enc_size, key[:4])), "little")
                payload_off = pos - 0x44 - size
                if size < 0x60 or payload_off < 0 or payload_off + size > n:
                    raise ValueError(f"record {i}: bad offset/size")
                plain = xor_stream(carrier[payload_off:payload_off + size], key)
                if plain[:4] != b"dex\n":
                    raise ValueError(f"record {i}: bad DEX magic after full decode")
                if u32(plain, 0x20) != size:
                    raise ValueError(f"record {i}: header file_size mismatch")
                if u32(plain, 0x28) != 0x12345678:
                    raise ValueError(f"record {i}: invalid endian tag")
                records.append({
                    "index": i + 1,
                    "carrier_offset": payload_off,
                    "size": size,
                    "key_sha256": hashlib.sha256(key).hexdigest(),
                    "sha256": hashlib.sha256(plain).hexdigest(),
                    "data": plain,
                })
                pos = payload_off
        except ValueError as exc:
            last_error = exc
            continue
        trailer = {}
        try:
            cursor = n - 0x48
            first_len = int.from_bytes(
                bytes(carrier[cursor + j] ^ carrier[cursor + 4 + j] for j in range(4)), "little")
            if 0 < first_len <= 0x400:
                key0 = carrier[cursor + 4:cursor + 68]
                cursor2 = cursor - first_len
                if cursor2 + 32 <= n:
                    app_class = bytes(carrier[cursor2 + j] ^ key0[j & 0x3F]
                                      for j in range(32)).rstrip(b"\x00")
                    trailer = {
                        "first_len": first_len,
                        "application_class": app_class.decode("ascii", errors="replace"),
                    }
        except Exception:
            pass
        return records, trailer, pos

    if last_error:
        raise ValueError(f"candidate chain failed full validation: {last_error}")
    raise ValueError("could not locate a valid DEX record chain (unsupported variant?)")


def carrier_candidates(zf: zipfile.ZipFile):
    names = zf.namelist()
    preferred = [nm for nm in names if nm.startswith("classes") and nm.endswith(".dex")]
    for nm in (preferred + [nm for nm in names if nm not in preferred]):
        info = zf.getinfo(nm)
        if info.is_dir() or info.file_size < 0x200:
            continue
        data = zf.read(nm)
        if len(data) >= 0x200 and data[:4] == b"dex\n":
            yield nm, data


# ---------------------------------------------------------------------------
# DEX utilities (Application class discovery + minimal stub builder)
# ---------------------------------------------------------------------------

def parse_dex_classes(path_or_bytes):
    b = path_or_bytes if isinstance(path_or_bytes, bytes) else open(path_or_bytes, "rb").read()
    if b[:4] != b"dex\n":
        return []
    ss = u32(b, 0x38); so = u32(b, 0x3C)
    ts = u32(b, 0x40); to = u32(b, 0x44)
    cs = u32(b, 0x60); co = u32(b, 0x64)

    def uleb(o):
        r = 0; sh = 0
        while True:
            x = b[o]; o += 1; r |= (x & 0x7F) << sh
            if x < 0x80: break
            sh += 7
        return r, o

    strs = []
    for i in range(ss):
        off = u32(b, so + i * 4)
        try:
            ln, at = uleb(off)
            strs.append(b[at:at + ln].decode("utf-8", "replace"))
        except Exception:
            strs.append("")
    types = []
    for i in range(ts):
        idx = u32(b, to + i * 4)
        types.append(strs[idx] if idx < len(strs) else "?")
    classes = []
    for i in range(cs):
        off = co + i * 32
        try:
            ci, af, si = struct.unpack_from("<III", b, off)
        except Exception:
            continue
        classes.append((types[ci] if ci < len(types) else "?",
                        types[si] if 0 < si < len(types) else "?"))
    return classes


def find_application_subclasses(dex_data_list):
    """Return descriptors of all classes whose superclass chain reaches
    android.app.Application, plus the owner dex ordinal."""
    sup = {}
    owner = {}
    for ordinal, data in enumerate(dex_data_list):
        for desc, sdesc in parse_dex_classes(data):
            if desc != "?":
                sup.setdefault(desc, sdesc)
                owner.setdefault(desc, ordinal)
    apps = []
    for c in sup:
        cur = c
        seen = set()
        while cur in sup and cur not in seen:
            seen.add(cur)
            nxt = sup[cur]
            if nxt == "Landroid/app/Application;":
                apps.append((c, owner.get(c, 0)))
                break
            cur = nxt
    return apps


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_noop_dex(descriptor: str) -> bytes:
    """Build a minimal valid DEX v035 containing a no-op class extending
    android.app.Application (<init> + onCreate), used when the packed APK's
    real Application class cannot be recovered from the payload."""
    assert descriptor.startswith("L") and descriptor.endswith(";")

    strings = [
        "",                          # 0
        "V",                         # 1 (shorty for ()V)
        descriptor,                  # 2 (class descriptor)
        "Landroid/app/Application;", # 3 (superclass)
        "<init>",                    # 4
        "onCreate",                  # 5
    ]
    blobs = []
    for s in strings:
        enc = encode_mutf8(s)
        blobs.append(_uleb(len(s)) + enc + b"\x00")

    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + 3 * 4
    field_ids_off = proto_ids_off + 12
    method_ids_off = field_ids_off           # 0 field ids
    class_defs_off = method_ids_off + 3 * 12   # 3 method_ids, 12 bytes each
    data_off = class_defs_off + 32

    # data section
    data = bytearray()
    string_data_base = data_off
    blob_offs = []
    for b in blobs:
        blob_offs.append(len(data))
        data += b
    while len(data) % 4:
        data += b"\x00"

    code_init_off = data_off + len(data)
    data += struct.pack("<HHHHII", 1, 1, 1, 0, 0, 4)          # regs/ins/outs/tries/debug/insns_size
    data += struct.pack("<HHHH", 0x0170, 0x0002, 0x0000, 0x000E)  # invoke-direct {p0}, r2 ; return-void

    code_create_off = data_off + len(data)
    data += struct.pack("<HHHHII", 1, 1, 0, 0, 0, 1) + struct.pack("<H", 0x000E)
    while len(data) % 4:
        data += b"\x00"

    class_data_off = data_off + len(data)
    data += b"".join([
        _uleb(0),  # static_fields
        _uleb(0),  # instance_fields
        _uleb(1),  # direct_methods
        _uleb(1),  # virtual_methods
        _uleb(0), _uleb(0x10001), _uleb(code_init_off),   # <init> (public constructor)
        _uleb(1), _uleb(0x1), _uleb(code_create_off),     # onCreate
    ])

    map_off = data_off + len(data)
    # align map_list to 4
    while len(data) % 4:
        data += b"\x00"
        map_off = data_off + len(data)
    import struct as _s
    map_entries = [
        (0x0000, 1, 0),
        (0x0001, 6, string_ids_off),
        (0x0002, 3, type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 3, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x1000, 1, map_off),
        (0x2002, 6, string_data_base),
        (0x2001, 2, code_init_off),
        (0x2000, 1, class_data_off),
    ]
    map_list = b"".join(_s.pack("<HHII", t, 0, s, o) for t, s, o in map_entries)
    data += map_list

    # string_id entries: absolute offsets of each blob
    string_ids = b"".join(_s.pack("<I", string_data_base + o) for o in blob_offs)
    type_ids = struct.pack("<III", 1, 2, 3)                    # V, descriptor, Application
    proto_ids = struct.pack("<III", 1, 0, 0)                   # ()V
    method_ids = struct.pack("<9I",
                             1, 4, 0,  # Lcom/x/App;.<init>()V
                             1, 5, 0,  # Lcom/x/App;.onCreate()V
                             2, 4, 0)  # Landroid/app/Application;.<init>()V
    class_def = struct.pack("<IIIIIIII", 1, 0x1, 2, 0, 0xFFFFFFFF, 0, class_data_off, 0)

    header = (struct.pack("<8sI", b"dex\n035\0", 0) + b"\x00" * 20 +
              struct.pack("<20I",
                          data_off + len(data), 0x70, 0x12345678, 0, 0,
                          map_off, 6, string_ids_off, 3, type_ids_off, 1,
                          proto_ids_off, 0, 0, 3, method_ids_off, 1,
                          class_defs_off, len(data), data_off))
    assert len(header) == 0x70

    bundle = bytearray(header + string_ids + type_ids + proto_ids + method_ids + class_def + data)
    import hashlib as _hl
    import zlib as _zl
    bundle[0x0C:0x20] = _hl.sha1(bytes(bundle[0x0C:])).digest()
    bundle[0x08:0x0C] = struct.pack("<I", _zl.adler32(bytes(bundle[0x0C:])))
    return bytes(bundle)


# ---------------------------------------------------------------------------
# APK rebuild
# ---------------------------------------------------------------------------

def rebuild_apk(src_apk: Path, records, out_apk: Path, patched_manifest: bytes | None,
                extra_dex: bytes | None):
    """Rebuild an installable APK: same entries, carrier replaced by the
    recovered DEXes as multidex, old signature removed."""
    with zipfile.ZipFile(src_apk) as zin:
        infos = zin.infolist()
        payloads = {i.filename: zin.read(i) for i in infos}
        info_map = {i.filename: i for i in infos}

    keep = []
    for name in list(payloads):
        if name.startswith("META-INF/") and name.rsplit("/", 1)[-1].upper() in (
                "MANIFEST.MF", "ANDROID.RSA", "ANDROID.DSA", "ANDROID.EC",
                "CERT.RSA", "CERT.DSA", "CERT.SF", "CERT.EC"):
            del payloads[name]
            continue
        if name == "classes.dex":  # carrier replaced
            del payloads[name]
            continue
        keep.append(name)

    if patched_manifest is not None:
        payloads["AndroidManifest.xml"] = patched_manifest

    out_path = out_apk
    with zipfile.ZipFile(out_path, "w", allowZip64=True) as zout:
        # write all kept entries first, preserving method/compression
        for name in sorted(keep):
            info = info_map[name]
            cdata = payloads.pop(name)
            zi = zipfile.ZipInfo(name, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.comment = info.comment
            zout.writestr(zi, cdata, compress_type=info.compress_type)
        # recovered dexes (uncompressed for mmap)
        total = len(records)
        for i, rec in enumerate(records, 1):
            zi = zipfile.ZipInfo(f"classes.dex" if i == 1 else f"classes{i}.dex",
                                 date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, rec["data"], compress_type=zipfile.ZIP_STORED)
        if extra_dex is not None:
            zi = zipfile.ZipInfo(f"classes{total + 1}.dex", date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, extra_dex, compress_type=zipfile.ZIP_STORED)


# ---------------------------------------------------------------------------
# Tooling lookup / signing
# ---------------------------------------------------------------------------

def find_sdk_tool(name: str) -> str | None:
    roots = [
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk"),
    ]
    for root in roots:
        if not root:
            continue
        bt = Path(root) / "build-tools"
        if not bt.is_dir():
            continue
        vers = sorted([v.name for v in bt.iterdir() if v.is_dir() and v.name[0].isdigit()])
        for v in reversed(vers):
            exe = bt / v / name
            if exe.is_file():
                return str(exe)
    return None


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="Unpack + rebuild B2Al-style packed APKs")
    p.add_argument("apk", nargs="?", help="path to APK or a raw carrier file (classes.dex)")
    p.add_argument("--entry", default=None, help="force carrier entry in the APK")
    p.add_argument("--no-rebuild", action="store_true", help="only recover DEX files")
    p.add_argument("--out-dir", default=None, help="output directory (default: next to input)")
    args = p.parse_args()

    if not args.apk:
        p.print_help()
        return 2

    source = Path(args.apk).expanduser().resolve()
    if not source.is_file():
        print(f"not found: {source}", file=sys.stderr)
        return 2

    out_root = Path(args.out_dir) if args.out_dir else source.parent
    out_dir = out_root / f"{source.stem}_recovered_dex"
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- pick carrier -----------------------------------------------------
    is_apk = source.suffix.lower() == ".apk"
    carriers = []
    if is_apk:
        with zipfile.ZipFile(source) as zf:
            if args.entry:
                try:
                    carriers.append((args.entry, zf.read(args.entry)))
                except KeyError:
                    print(f"entry not found: {args.entry}", file=sys.stderr)
                    return 2
            else:
                carriers = list(carrier_candidates(zf))
        if not carriers:
            print("no carrier (dex) candidate found in APK", file=sys.stderr)
            return 2
    else:
        data = source.read_bytes()
        if data[:4] != b"dex\n":
            print("not a dex carrier file", file=sys.stderr)
            return 2
        carriers.append(("classes.dex", data))

    # --- recover ----------------------------------------------------------
    all_records = None
    carrier_name = None
    trailer = {}
    final_cursor = 0
    errors = []
    for name, data in carriers:
        try:
            all_records, trailer, final_cursor = recover_records(data)
            carrier_name = name
            break
        except ValueError as e:
            errors.append(f"{name}: {e}")
    if all_records is None:
        print("no packer carrier decodable:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        return 1

    manifest = {
        "carrier_entry": carrier_name,
        "carrier_size": sum(len(r["data"]) for r in all_records),
        "record_count": len(all_records),
        "application_class": trailer.get("application_class", ""),
        "final_cursor": final_cursor,
        "records": [],
    }
    for r in all_records:
        i = r["index"]
        name_out = "classes.dex" if i == 1 else f"classes{i}.dex"
        (out_dir / name_out).write_bytes(r["data"])
        manifest["records"].append({k: r[k] for k in r if k != "data"} | {"name": name_out})

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"Carrier entry:     {carrier_name}")
    print(f"Recovered DEXes:   {len(all_records)}")
    print(f"Output directory:  {out_dir}")

    if args.no_rebuild or not is_apk:
        return 0

    # --- rebuild APK ------------------------------------------------------
    print()
    print("Rebuilding installable APK ...")
    dex_bytes = [r["data"] for r in all_records]

    # manifest patch: find real Application class
    apps = find_application_subclasses(dex_bytes)
    patched_manifest = None
    extra_dex = None
    app_change = ""
    with zipfile.ZipFile(source) as zf:
        try:
            manifest_data = bytearray(zf.read("AndroidManifest.xml"))
        except KeyError:
            manifest_data = None

    if manifest_data is not None:
        from_ = {}
        try:
            axm = AXML(bytes(manifest_data))
            pkg, cur_name = axm.get_application_name()
            from_ = {"pkg": pkg, "name": cur_name}
        except Exception as e:
            print(f"  (manifest parse skipped: {e})")

        resolutions = set()
        if from_.get("name"):
            n = from_["name"]
            resolutions.add(n if n.startswith("L") else "L" + n.replace(".", "/") + ";")
            if from_.get("pkg") and n.startswith("."):
                resolutions.add("L" + from_["pkg"] + n + ";")

        current_ok = bool(resolutions & {c for c, _ in apps})
        if not current_ok:
            if apps:
                best = apps[0][0]  # descriptor
                to_name = best[1:-1].replace("/", ".")
                try:
                    patched_manifest = patch_axml_application_name(bytes(manifest_data), to_name)
                    app_change = f"android:name -> {to_name}"
                except Exception as e:
                    print(f"  (manifest patch failed: {e})")
            else:
                # fallback: no-op stub with the current android:name
                name = from_.get("name")
                if name:
                    desc = name if name.startswith("L") else "L" + name.replace(".", "/") + ";"
                    extra_dex = build_noop_dex(desc)
                    if not extra_dex:
                        print("  (no Application subclass found; please verify the app manually)")
                else:
                    print("  (no Application subclass found; please verify the app manually)")

    out_apk = out_root / f"{source.stem}_rebuilt.apk"
    rebuild_apk(source, all_records, out_apk, patched_manifest, extra_dex)

    # --- zipalign + sign --------------------------------------------------
    final_apk = out_root / f"{source.stem}_rebuilt_signed.apk"
    zipalign = find_sdk_tool("zipalign.exe")
    apksigner = find_sdk_tool("apksigner.bat")
    if zipalign and apksigner:
        try:
            aligned = out_root / f"{source.stem}_rebuilt.aligned.apk"
            subprocess.run([zipalign, "-f", "-p", "4", str(out_apk), str(aligned)], check=True)
            keypath = Path(os.environ.get("TEMP", ".")) / "apkrebuild.keystore"
            if not keypath.is_file():
                subprocess.run(["keytool", "-genkeypair", "-v",
                                "-keystore", str(keypath), "-storepass", "apkrebuild",
                                "-keypass", "apkrebuild", "-alias", "apkrebuild",
                                "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                                "-dname", "CN=APK Rebuild, OU=Tools, O=Tools, L=C, S=C, C=US"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([apksigner, "sign", "--ks", str(keypath),
                            "--ks-pass", "pass:apkrebuild", "--key-pass", "pass:apkrebuild",
                            "--ks-key-alias", "apkrebuild",
                            "--out", str(final_apk), str(aligned)], check=True)
            os.replace(aligned, out_apk)
            print(f"Rebuilt APK:       {final_apk}")
            if app_change:
                print(f"Manifest patch:    {app_change}")
            r = subprocess.run([apksigner, "verify", str(final_apk)],
                               capture_output=True, text=True)
            print("Signature verify: " + ("OK" if r.returncode == 0 else r.stderr.strip()))
        except FileNotFoundError as e:
            print(f"signing skipped (tool not found: {e.filename})")
        except subprocess.CalledProcessError as e:
            print(f"signing failed: {e}")
    else:
        print(f"Rebuilt (unsigned): {out_apk}")
        print("  (zipalign/apksigner not found; installing may fail)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())