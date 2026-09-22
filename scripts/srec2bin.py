#!/usr/bin/env python3
"""Parse Motorola S-record .mot file into a raw image and dump aligned bytes.

Usage:
  python srec2bin.py                      -> write dice_5_6_2.bin
  python srec2bin.py --dump 0xfb1500 0x140 -> also hexdump that region
"""
import sys

MOT = r"C:\misc\dice\dice_5_6_2.mot"


def parse_srec(path):
    data = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("S"):
                continue
            n = int(line[1])
            if n in (0, 5, 6, 7):
                continue
            cnt = int(line[2:4], 16)
            # address width in bytes is fixed by record type
            addr_bytes = {1: 2, 2: 3, 3: 4, 8: 4}[n]
            data_bytes = cnt - addr_bytes
            p = 4
            addr = int(line[p:p + 2 * addr_bytes], 16)
            p += 2 * addr_bytes
            raw = bytes.fromhex(line[p:p + 2 * data_bytes])
            # (trailing 2 hex = checksum, ignored)
            for i, b in enumerate(raw):
                data[addr + i] = b
    return data


def to_image(data):
    lo = min(data)
    hi = max(data)
    size = hi - lo + 1
    img = bytearray(size)
    for a, b in data.items():
        img[a - lo] = b
    return lo, bytes(img)


def main():
    data = parse_srec(MOT)
    lo, img = to_image(data)
    print("base=%06x size=%d (%.1f KiB)" % (lo, len(img), len(img) / 1024), file=sys.stderr)

    if not any(a.startswith("--dump") for a in sys.argv):
        out = r"C:\misc\dice\dice_5_6_2.bin"
        with open(out, "wb") as f:
            f.write(img)
        print("wrote %s" % out, file=sys.stderr)
        return

    a = int(sys.argv[sys.argv.index("--dump") + 1], 16)
    n = int(sys.argv[sys.argv.index("--dump") + 2], 16) if len(sys.argv) > sys.argv.index("--dump") + 2 else 0x100
    for off in range(a - lo, min(a - lo + n, len(img)), 16):
        chunk = img[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        print("%06x  %s" % (lo + off, hexs))


if __name__ == "__main__":
    main()
