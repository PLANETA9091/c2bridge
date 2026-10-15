#!/usr/bin/env python3
"""crtok — the SDR cert-validator cold-table bypass (v97).

Barrier (run507 verdict): the engine's GNS rejects the server's 0x23 ConnectOK
with 'Bad cert: CA key %llu is not known to us' when the SDR network config
has not finished loading (the HTTP-504 race) — the CA table is EMPTY and the
first channel dies (run507: #2619305195 dead pre-config-load; #3347368931
connected post-load; BOTH 0x23s carry the IDENTICAL cert => pure race).

Patch: in the cert-validation function, the failure tail prints the message
and returns 0 (invalid). We flip ONLY that tail's 'xor eax,eax' (31 c0) into
'mov al,1' (b0 01) => 'not known to us' returns VALID. The ed25519 signature
verification for KNOWN CAs is a separate return path and stays hard-failing.

Anchors (build-independent, all verified byte-exact or the file is skipped):
  1. the format string  'CA key %llu is not known to us'
  2. exactly ONE rip-relative lea rsi,[rip+d32] targeting that string
     in an executable PT_LOAD:  48 8d 35 <d32>
  3. the tail pattern after the lea:
     48 8d 35 d32 | 4c 89 e2 | 31 c0 | e8 d32 | 31 c0 | 48 83 c4 28 ...
                                    ^^^^^ the patched byte pair
Idempotent: if the byte pair is already b0 01, the file is reported as
already-patched. Any anchor mismatch => the file is skipped (WARN), never
half-patched.
"""
import struct, sys, hashlib

STR = b"CA key %llu is not known to us\x00"


def load_map(data):
    assert data[:4] == b"\x7fELF", "not ELF"
    is64 = data[4] == 2
    assert is64, "not ELF64"
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    loads = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, o)
        p_off, p_vaddr, _pa, p_filesz, _mem = struct.unpack_from("<QQQQQ", data, o + 8)
        if p_type == 1:
            loads.append((p_off, p_vaddr, p_filesz, p_flags))
    return loads


def f2v(loads, foff):
    for p_off, p_vaddr, p_filesz, _fl in loads:
        if p_off <= foff < p_off + p_filesz:
            return p_vaddr + (foff - p_off)
    return None


def v2f(loads, va):
    for p_off, p_vaddr, p_filesz, _fl in loads:
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_off + (va - p_vaddr)
    return None


def find_patch_site(data, loads):
    soff = data.find(STR)
    if soff < 0:
        return None, "format string absent"
    sva = f2v(loads, soff)
    if sva is None:
        return None, "string not in any PT_LOAD"
    xrefs = []
    for p_off, p_vaddr, p_filesz, p_flags in loads:
        if not (p_flags & 1):
            continue
        seg = data[p_off:p_off + p_filesz]
        for i in range(len(seg) - 7):
            if seg[i] == 0x48 and seg[i + 1] == 0x8D and (seg[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", seg, i + 3)[0]
                if p_vaddr + i + 7 + disp == sva:
                    xrefs.append(p_off + i)
    if len(xrefs) != 1:
        return None, f"lea-xrefs={len(xrefs)} (need exactly 1)"
    fo = xrefs[0]
    # tail anchor after the lea (build-tolerant):
    #   mov rdx,<reg64>  ([48|4c] 89 <modrm: mod=11, rm=010(rdx)>)
    #   31 c0            (xor eax,eax — the varargs al=0)
    #   e8 <d32>         (call the spew helper)
    #   31 c0            (xor eax,eax — RETURN 0  <- THE PATCH SITE)
    #   48 83 c4 28      (add rsp,0x28)
    tail = data[fo + 7:fo + 7 + 18]
    if len(tail) != 18:
        return None, "tail truncated"
    if tail[0] not in (0x48, 0x4C) or tail[1] != 0x89 or (tail[2] & 0xC7) != 0xC2:
        return None, f"mov-rdx mismatch: {tail[:3].hex()}"
    if tail[3:5] != b"\x31\xc0" or tail[5] != 0xE8 or tail[10:12] not in (b"\x31\xc0", b"\xb0\x01") or tail[12:16] != b"\x48\x83\xc4\x28":
        return None, f"tail mismatch: {tail.hex()}"
    # sanity: the e8 call target must land inside a mapped segment
    call_at = fo + 7 + 3 + 2
    rel = struct.unpack_from("<i", data, call_at + 1)[0]
    cva = f2v(loads, call_at)
    tgt = cva + 5 + rel
    if v2f(loads, tgt) is None:
        return None, f"spew call target {tgt:#x} unmapped"
    return fo + 7 + 3 + 2 + 5, None  # the second 31 c0


def process(path, apply):
    with open(path, "rb") as f:
        data = f.read()
    loads = load_map(data)
    site, err = find_patch_site(data, loads)
    if site is None:
        return f"SKIP {path}: {err}"
    orig = data[site:site + 2]
    if apply == "restore":
        if orig == b"\x31\xc0":
            return f"CLEAN {path}: site={site:#x} = 31 c0 (no patch present)"
        if orig != b"\xb0\x01":
            return f"SKIP {path}: site={site:#x} unexpected bytes {orig.hex()} (want b0 01)"
        data = bytearray(data)
        data[site:site + 2] = b"\x31\xc0"
        with open(path, "wb") as f:
            f.write(bytes(data))
        return f"RESTORED {path}: site={site:#x} b0 01 -> 31 c0"
    if orig == b"\xb0\x01":
        return f"ALREADY {path}: site={site:#x} = b0 01"
    if orig != b"\x31\xc0":
        return f"SKIP {path}: site={site:#x} unexpected bytes {orig.hex()} (want 31 c0)"
    sha_before = hashlib.sha256(data).hexdigest()[:16]
    if not apply:
        return f"CHECK {path}: site={site:#x} orig=31 c0 -> b0 01 (sha {sha_before})"
    data = bytearray(data)
    data[site:site + 2] = b"\xb0\x01"
    with open(path, "wb") as f:
        f.write(bytes(data))
    return f"PATCHED {path}: site={site:#x} 31 c0 -> b0 01 (sha {sha_before} -> {hashlib.sha256(bytes(data)).hexdigest()[:16]})"


def main():
    args = sys.argv[1:]
    apply = True
    if args and args[0] == "--check":
        apply = False
        args = args[1:]
    elif args and args[0] == "--restore":
        apply = "restore"
        args = args[1:]
    if not args:
        print(__doc__)
        print("usage: patch_crtok.py [--check|--restore] <so-file> [<so-file> ...]")
        return 2
    rc = 0
    for p in args:
        try:
            line = process(p, apply)
        except Exception as e:
            line = f"SKIP {p}: exception {e}"
        print(line, flush=True)
        if line.startswith("SKIP"):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
