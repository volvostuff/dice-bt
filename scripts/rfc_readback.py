#!/usr/bin/env python3
"""Read back DiCE flash over RFC and compare it with the .mot images.

Why: the firmware version that DiagApp shows is assembled *by the firmware*
(see 0xFA9D86 "%d.%d.%d" and 0xFA9EA5 "Aug 22 2011" in the image) and is
answered over RFC by the bootloader bank, which is NOT part of the .mot we
patch.  So "5.6.2" in DiagApp is not proof that the CH05 patch is absent --
read the bytes instead.

This uses RfcFWDL32.dll (x64, USB, API described in docs/rfc_bootloader_read.md):

    RfcQuery(int idx, char* buf, int len)    enumerate devices (idx=0)
    RfcOpen(char* name)                      0 = OK  (NAME, not an index!)
    RfcMaxSize(uint16* out)                  FID 1
    FwdlRead(uint32 addr, uint32 len, buf)   FID 0x7B  (read-only)
    RfcClose()

The device must be free: close DiagApp / any J2534 application first.

ВНИМАНИЕ (проверено 22.09.2026): в режиме приложения MCU отвечает на FID 1
(RfcMaxSize = 4200), но на FID 0x7B (FwdlRead) и 0x7D (FwdlCS) возвращает
0xFD -- доступ к флешу разрешён только в режиме обновления, который
активирует FwdlApp.  Поэтому основной способ проверки патча -- либо лог
FwdlApp («Device update OK!» после стирания/записи/верификации), либо
поведенческая проверка (scripts/bt_probe.py: патч отвечает по BT, заводская
-- нет).

Usage:
    python scripts/rfc_readback.py                      # check the CH05 patch regions
    python scripts/rfc_readback.py --full               # + compare whole 0xFA0000..0xFD2000
    python scripts/rfc_readback.py --addr 0xFB0EC2 --len 64
"""
import argparse
import ctypes
import os
import sys

BASE = 0xFA0000
DLL = r"C:\Program Files\DiCE\Tools\RfcFWDL32.dll"
MOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACTORY_MOT = os.path.join(MOT_DIR, "dice_5_6_2.mot")
PATCHED_MOTS = [
    os.path.join(MOT_DIR, "dice_5_6_3_ch05_full.mot"),
    os.path.join(MOT_DIR, "dice_5_6_3_ch05.mot"),
]

# regions touched by the CH05 patch (+ image header)
REGIONS = [
    ("header (ver bytes)", 0xFA0000, 16),
    ("C1 P2.1 set  (op.)", 0xFB12CB, 8),
    ("C2 P2.1 clr  (op.)", 0xFB12DB, 8),
    ("A  JSR bt_at_init", 0xFB13C6, 8),
    ("B  ATD dial", 0xFB15BE, 16),
    ("E  link state", 0xFB16A8, 16),
    ("F  bt_baud_detect", 0xFB0EC2, 48),
]


def load_mot(path):
    """Decode sparse S2 records into {addr: byte}."""
    img = {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("S2"):
                continue
            cnt = int(line[2:4], 16)
            addr = int(line[4:10], 16)
            n = cnt - 4
            data = bytes.fromhex(line[10:10 + 2 * n])
            for i, b in enumerate(data):
                img[addr + i] = b
    return img


def open_rfc(dll):
    """RfcQuery() -> device name; RfcOpen() takes the NAME, not an index.

    Verified 22.09.2026: RfcOpen(0) returns 1 (error), RfcOpen(1) faults
    (dereferences the argument), RfcOpen(b'dice-206751@000000000000') -> 0.
    """
    buf = ctypes.create_string_buffer(1024)
    rc = dll.RfcQuery(0, buf, 1024)
    name = buf.value
    print("RfcQuery() = %d, device = %r" % (rc, name.decode(errors="replace")))
    if not name:
        return None
    rc = dll.RfcOpen(name)
    print("RfcOpen(%r) = %d" % (name.decode(errors="replace"), rc))
    return 0 if rc == 0 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", default=DLL)
    ap.add_argument("--addr", type=lambda x: int(x, 0))
    ap.add_argument("--len", type=int, default=64)
    ap.add_argument("--full", action="store_true", help="read 0xFA0000..0xFD2000 and compare")
    ap.add_argument("--chunk", type=int, default=128)
    args = ap.parse_args()

    if not os.path.exists(args.dll):
        sys.exit("no DLL at %s" % args.dll)
    dll = ctypes.WinDLL(args.dll)
    for fn, restype, argtypes in [
        ("RfcQuery", ctypes.c_int, [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]),
        ("RfcOpen", ctypes.c_int, [ctypes.c_char_p]),
        ("RfcClose", None, []),
        ("RfcMaxSize", ctypes.c_int, [ctypes.POINTER(ctypes.c_ushort)]),
        ("FwdlRead", ctypes.c_int, [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]),
    ]:
        f = getattr(dll, fn)
        f.restype = restype
        f.argtypes = argtypes

    if open_rfc(dll) is None:
        sys.exit("RfcOpen failed -- close DiagApp / J2534 applications and retry")

    mx = ctypes.c_ushort(0)
    if dll.RfcMaxSize(ctypes.byref(mx)) == 0:
        print("RfcMaxSize = %d" % mx.value)
        if mx.value:
            args.chunk = min(args.chunk, mx.value)

    factory = load_mot(FACTORY_MOT)
    patched = [load_mot(p) for p in PATCHED_MOTS if os.path.exists(p)]

    def read(addr, ln):
        out = bytearray()
        while ln > 0:
            n = min(args.chunk, ln)
            buf = ctypes.create_string_buffer(n)
            rc = dll.FwdlRead(addr, n, buf)
            if rc != 0:
                if rc == 0xFD:
                    raise SystemExit(
                        "FwdlRead(0x%06X) = 0xFD: flash commands (FID 0x7B/0x7D) are not\n"
                        "served while the application is running -- flash can only be read in\n"
                        "update mode (FwdlApp activates it and verifies the written bytes\n"
                        "itself via FwdlCS, logging 'Device update OK!' to FwdlApp.exe.log).\n"
                        "See docs/rfc_bootloader_read.md" % addr)
                raise SystemExit("FwdlRead(0x%06X, %d) = 0x%X" % (addr, n, rc))
            out += buf.raw[:n]
            addr += n
            ln -= n
        return bytes(out)

    if args.addr is not None:
        data = read(args.addr, args.len)
        print("0x%06X (%d B): %s" % (args.addr, len(data), data.hex(" ")))
        dll.RfcClose()
        return

    print("\n=== check regions ===")
    for name, addr, ln in REGIONS:
        got = read(addr, ln)
        verdict = "?"
        if bytes(factory.get(addr + i, 0xFF) for i in range(ln)) == got:
            verdict = "FACTORY (dice_5_6_2)"
        for mot, img in zip(PATCHED_MOTS, patched):
            if bytes(img.get(addr + i, 0xFF) for i in range(ln)) == got:
                verdict = "PATCHED (%s)" % os.path.basename(mot)
        print("%-20s @%06X  %s\n%-20s          %s" %
              (name, addr, got.hex(" "), "", verdict))

    if args.full:
        print("\n=== full compare 0xFA0000..0xFD2000 ===")
        start, end = BASE, 0xFD2000
        got = read(start, end - start)
        for label, img in [("factory", factory)] + list(zip(
                [os.path.basename(p) for p in PATCHED_MOTS], patched)):
            same = sum(1 for i, b in enumerate(got)
                       if img.get(start + i, 0xFF) == b)
            print("%-28s match %d / %d bytes" % (label, same, len(got)))
        print("first mismatches vs factory:",
              [hex(start + i) for i, b in enumerate(got)
               if factory.get(start + i, 0xFF) != b][:12])

    dll.RfcClose()
    print("\nRfcClose() ok")


if __name__ == "__main__":
    main()
