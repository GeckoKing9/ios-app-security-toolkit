#!/usr/bin/env python3
"""
protections.py — read the compile-time hardening of a decrypted iOS Mach-O and
report it against MASVS-CODE. Pure Python, no otool / no macOS: it parses the
Mach-O header and load commands directly and byte-scans the slice for the
canary and ARC markers, so it runs anywhere on a binary you pulled with
`ios pull`.

Checks: FairPlay encryption (must be decrypted first), PIE/ASLR, stack canaries,
ARC, an embedded code signature, the debuggable (get-task-allow) entitlement,
and @rpath use. Point it at the main executable inside a pulled .app.

Usage: protections.py <path-to-macho>       (or: ios protections <binary>)
"""
import struct
import sys

# Mach-O magics (as read little-endian off disk).
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC_32 = 0xFEEDFACE
MH_CIGAM_32 = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE  # fat header is big-endian on disk
FAT_MAGIC_64 = 0xCAFEBABF

MH_PIE = 0x00200000

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
LC_RPATH = 0x8000001C

CPU_TYPE_ARM64 = 0x0100000C


class Result:
    def __init__(self):
        self.rows = []          # (label, ok, detail, masvs)
        self.encrypted = False
        self.errors = []

    def add(self, label, ok, detail, masvs):
        self.rows.append((label, ok, detail, masvs))


def _pick_slice(data):
    """Return (offset, size, big_endian) for the arm64 (or first) slice."""
    if len(data) < 4:
        raise ValueError("file too small to be a Mach-O")
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        is64 = magic_be == FAT_MAGIC_64
        nfat = struct.unpack(">I", data[4:8])[0]
        off = 8
        entry = 32 if is64 else 20
        chosen = None
        for _ in range(nfat):
            e = data[off:off + entry]
            if is64:
                cputype, _sub, foff, fsize = struct.unpack(">IIQQ", e[:24])
            else:
                cputype, _sub, foff, fsize = struct.unpack(">IIII", e[:16])
            if cputype == CPU_TYPE_ARM64:
                chosen = (foff, fsize)
                break
            if chosen is None:
                chosen = (foff, fsize)
            off += entry
        return chosen[0], chosen[1], False
    # thin
    return 0, len(data), None


def analyze(path):
    r = Result()
    with open(path, "rb") as fh:
        data = fh.read()

    try:
        off, size, _ = _pick_slice(data)
    except Exception as e:
        r.errors.append(str(e))
        return r
    slice_ = data[off:off + size] if size else data[off:]

    if len(slice_) < 32:
        r.errors.append("slice too small / not a Mach-O")
        return r

    magic = struct.unpack("<I", slice_[:4])[0]
    if magic in (MH_MAGIC_64, MH_MAGIC_32):
        endian = "<"
    elif magic in (MH_CIGAM_64, MH_CIGAM_32):
        endian = ">"
    else:
        r.errors.append(f"not a Mach-O (magic {magic:#x})")
        return r
    is64 = magic in (MH_MAGIC_64, MH_CIGAM_64)

    # mach_header[_64]: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags[, reserved]
    hdr_fmt = endian + ("IiiIIII" + ("I" if is64 else ""))
    hdr_size = struct.calcsize(hdr_fmt)
    fields = struct.unpack(hdr_fmt, slice_[:hdr_size])
    ncmds, flags = fields[4], fields[6]

    r.add("PIE / ASLR", bool(flags & MH_PIE),
          "MH_PIE set" if flags & MH_PIE else "no MH_PIE — image loads at a fixed base",
          "MASVS-CODE-1")

    # Walk load commands.
    has_codesig = False
    rpaths = []
    p = hdr_size
    for _ in range(ncmds):
        if p + 8 > len(slice_):
            break
        cmd, cmdsize = struct.unpack(endian + "II", slice_[p:p + 8])
        if cmdsize < 8:
            break
        body = slice_[p:p + cmdsize]
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cmd, cmdsize, cryptoff, cryptsize, cryptid
            cryptid = struct.unpack(endian + "I", body[16:20])[0]
            r.encrypted = cryptid != 0
        elif cmd == LC_CODE_SIGNATURE:
            has_codesig = True
        elif cmd == LC_RPATH:
            str_off = struct.unpack(endian + "I", body[8:12])[0]
            path_bytes = body[str_off:].split(b"\x00", 1)[0]
            rpaths.append(path_bytes.decode("utf-8", "replace"))
        p += cmdsize

    r.add("FairPlay encryption removed", not r.encrypted,
          "cryptid=0 (decrypted or never encrypted)" if not r.encrypted
          else "cryptid=1 — still encrypted; pull with `ios pull` first, byte checks below are unreliable",
          "MASTG static prerequisite")

    # Byte-level markers. On a decrypted slice these are reliable; on an
    # encrypted one they mean nothing, which is why encryption is checked first.
    def present(*needles):
        return any(n in slice_ for n in needles)

    canary = present(b"__stack_chk_guard", b"__stack_chk_fail")
    arc = present(b"_objc_release", b"_objc_storeStrong", b"_objc_retainAutoreleasedReturnValue")
    debuggable = present(b"get-task-allow", b"get_task_allow")

    r.add("Stack canaries", canary,
          "stack_chk symbols present" if canary else "no stack_chk symbols — built without -fstack-protector",
          "MASVS-CODE-1")
    r.add("ARC (automatic ref counting)", arc,
          "ARC runtime calls present" if arc else "no ARC markers — manual retain/release, more UAF surface",
          "MASVS-CODE-1")
    r.add("Not debuggable", not debuggable,
          "no get-task-allow entitlement" if not debuggable
          else "get-task-allow present — a debugger can attach to a release build",
          "MASVS-CODE-4")
    r.add("Code signature present", has_codesig,
          "LC_CODE_SIGNATURE present" if has_codesig else "no code signature load command",
          "MASVS-RESILIENCE-4")

    if rpaths:
        external = [rp for rp in rpaths if not rp.startswith("@")]
        r.add("@rpath hygiene", not external,
              "all rpaths are @-relative" if not external
              else f"absolute/external rpath(s): {', '.join(external)}",
              "MASVS-CODE-1")
    return r


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 2
    path = argv[0]
    r = analyze(path)
    print(f"[*] Mach-O protections: {path}\n")
    if r.errors:
        for e in r.errors:
            print(f"[!] {e}")
        return 1
    if r.encrypted:
        print("[!] Binary is still FairPlay-encrypted (cryptid=1).")
        print("    Decrypt it on the device first: `ios pull <bundleid>`.\n")
    width = max(len(row[0]) for row in r.rows)
    for label, ok, detail, masvs in r.rows:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label:<{width}}  {detail}   ({masvs})")
    fails = [row for row in r.rows if not row[1]]
    print(f"\n{len(r.rows) - len(fails)}/{len(r.rows)} checks passed.")
    return 0 if not fails else 0  # informational tool: never fail the shell


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
