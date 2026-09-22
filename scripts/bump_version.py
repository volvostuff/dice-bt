#!/usr/bin/env python3
"""Bump the DiCE firmware version field in a .mot image.

The version is stored in the image header (address = 0xFA0000 + offset):
    0xFA0004  version_major  (1 byte)
    0xFA0005  version_minor  (1 byte)
    0xFA0006  (reserved, read as a WORD pair with 0xFA0007 -> 0xFFFF)
    0xFA0007  (reserved)
    0xFA0008  version_build  (1 byte)

Firmware reports MAJOR.MINOR.BUILD (e.g. 5.6.2). Bumping to 5.6.3 only
changes the build byte 02 -> 03.

The consuming code (0xFA27F2..0xFA284D) just reads and compares these
bytes; there is NO checksum over them (the .mot has no stored checksum and
the MCU does not self-verify), so a single-byte edit is safe. Host-side
flash verification (FwdlCS) recomputes from the file you give it.

S2 record encoding is identical to apply_ch05_patch.py:
  count byte INCLUDES the checksum; checksum = (0xFF - sum) & 0xFF.
"""
import argparse
import sys

# reuse the battle-tested S2 encoder/decoder
sys.path.insert(0, r"C:\misc\dice\scripts")
from apply_ch05_patch import parse_s2, s2_line  # noqa: E402

MOT_IN = r"C:\misc\dice\dice_5_6_2.mot"
MOT_OUT = r"C:\misc\dice\dice_5_6_3.mot"
BASE = 0xFA0000

VER_MAJOR = 0xFA0004
VER_MINOR = 0xFA0005
VER_BUILD = 0xFA0008


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="5.6.3",
                    help="target MAJOR.MINOR.BUILD (default 5.6.3)")
    ap.add_argument("--in", dest="inp", default=MOT_IN)
    ap.add_argument("--out", default=MOT_OUT)
    args = ap.parse_args()

    parts = args.version.split(".")
    if len(parts) != 3:
        sys.exit("version must be MAJOR.MINOR.BUILD")
    major, minor, build = (int(p) for p in parts)
    for name, v in (("major", major), ("minor", minor), ("build", build)):
        if not (0 <= v <= 255):
            sys.exit("%s out of byte range: %d" % (name, v))

    edits = {
        VER_MAJOR: major,
        VER_MINOR: minor,
        VER_BUILD: build,
    }

    lines = [l.strip() for l in open(args.inp, errors="replace")]
    rec = {}
    addr_index = {}
    for li, l in enumerate(lines):
        if l.startswith("S2"):
            cnt, addr, data, chk = parse_s2(l)
            rec[li] = [addr, bytearray(data)]
            for i in range(len(data)):
                addr_index.setdefault(addr + i, (li, i))

    # verify + report old values
    for addr, new in edits.items():
        hit = addr_index.get(addr)
        if hit is None:
            sys.exit("%06X not covered by an S2 record" % addr)
        li, off = hit
        old = rec[li][1][off]
        print("%06X  %02X -> %02X" % (addr, old, new))

    # apply
    for addr, new in edits.items():
        li, off = addr_index[addr]
        rec[li][1][off] = new

    out = []
    for li, l in enumerate(lines):
        if l.startswith("S2") and li in rec:
            a, rd = rec[li]
            out.append(s2_line(a, bytes(rd)))
        else:
            out.append(l)
    with open(args.out, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote %s" % args.out)

    # self-check: re-parse, checksums + new bytes
    bad = 0
    amap = {}
    for l in [x.strip() for x in open(args.out, errors="replace")]:
        if l.startswith("S2"):
            cnt, addr, data, chk = parse_s2(l)
            body = ("%02X" % cnt) + ("%06X" % addr) + data.hex().upper()
            s = sum(int(body[i:i + 2], 16) for i in range(0, len(body), 2))
            if (0xFF - (s & 0xFF)) & 0xFF != chk:
                bad += 1
            for i in range(len(data)):
                amap[addr + i] = data[i]
    if bad:
        sys.exit("self-check FAIL: %d bad checksums" % bad)
    for addr, new in edits.items():
        if amap[addr] != new:
            sys.exit("self-check FAIL at %06X" % addr)
    print("self-check OK: version = %d.%d.%d, all S2 checksums valid"
          % (major, minor, build))


if __name__ == "__main__":
    main()
