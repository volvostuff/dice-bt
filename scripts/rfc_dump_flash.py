#!/usr/bin/env python3
"""Dump the DiCE flash over RFC (RfcFWDL32.dll).

App mode refuses flash commands (FwdlRead -> 0xFD), so the script first puts the
device into programming mode via SysFirmwareDisable() -- no erase/program is
issued, the application image stays intact.  At the end the device is reset
(SysReset) and should boot the application again.

Usage:
    python scripts/rfc_dump_flash.py                       # 0xFA0000..0x1000000
    python scripts/rfc_dump_flash.py --start 0xFF8000 --end 0xFFE000
"""
import argparse
import ctypes
import os
import sys

DLL = r"C:\Program Files\DiCE\Tools\RfcFWDL32.dll"
DEFAULT_OUT = r"C:\misc\dice\tmp\dice_flash_dump.bin"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0xFA0000)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x1000000)
    ap.add_argument("--chunk", type=int, default=512)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--no-prog", action="store_true",
                    help="do not call SysFirmwareDisable (device must be in prog-mode)")
    ap.add_argument("--no-reset", action="store_true")
    args = ap.parse_args()

    d = ctypes.WinDLL(DLL)
    d.RfcQuery.restype = ctypes.c_int
    d.RfcQuery.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    d.RfcOpen.restype = ctypes.c_int
    d.RfcOpen.argtypes = [ctypes.c_char_p]
    d.FwdlRead.restype = ctypes.c_int
    d.FwdlRead.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
    d.RfcClose.restype = None
    d.RfcClose.argtypes = []
    d.SysReset.restype = ctypes.c_int
    d.SysReset.argtypes = []
    d.SysFirmwareDisable.restype = ctypes.c_int
    d.SysFirmwareDisable.argtypes = []

    b = ctypes.create_string_buffer(1024)
    rc = d.RfcQuery(0, b, 1024)
    name = b.value
    print("RfcQuery rc=%d name=%r" % (rc, name.decode(errors="replace")))
    if not name:
        sys.exit("no device found (DiagApp running? cable unplugged?)")
    print("RfcOpen ->", d.RfcOpen(name))

    if not args.no_prog:
        print("SysFirmwareDisable ->", d.SysFirmwareDisable())

    probe = ctypes.create_string_buffer(16)
    rc = d.FwdlRead(0xFA0000, 16, probe)
    print("probe FwdlRead -> %d  %s" % (rc, probe.raw[:16].hex(" ")))
    if rc != 0:
        print("flash access refused -- need programming mode "
              "(SysFirmwareDisable) or the device is busy")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    total = args.end - args.start
    fails = []
    done = 0
    with open(args.out, "wb") as f:
        addr = args.start
        while addr < args.end:
            n = min(args.chunk, args.end - addr)
            # ВАЖНО: длина у FwdlRead задаётся в 16-битных СЛОВАХ (len*2 байт)
            words = (n + 1) // 2
            buf = ctypes.create_string_buffer(words * 2)
            rc = d.FwdlRead(addr, words, buf)
            if rc != 0:
                fails.append((addr, n, rc))
                f.write(b"\xFF" * n)
            else:
                f.write(buf.raw[:n])
            done += n
            addr += n
            if fails and len(fails) <= 5:
                print("  read FAIL 0x%06X len %d rc=0x%X" % fails[-1])
            if (done % (64 * 1024)) == 0 or addr >= args.end:
                print("  %d / %d bytes (0x%06X)" % (done, total, addr), flush=True)
    print("wrote %s (%d bytes, %d failed blocks)"
          % (args.out, total, len(fails)))
    for a, n, rc in fails[:20]:
        print("  FAIL 0x%06X len %d rc=0x%X" % (a, n, rc))

    if not args.no_reset:
        print("SysReset ->", d.SysReset())
    try:
        d.RfcClose()
    except Exception:
        pass


if __name__ == "__main__":
    main()
