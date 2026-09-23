#!/usr/bin/env python3
"""Read raw bytes from the DiCE USB pipes (host channel), without the DLL.

The DICE exposes two "pipes" as reference strings on the same device interface:
    ...\\INTERFACE_0x00\\PIPE_0x00   and   ...\\INTERFACE_0x00\\PIPE_0x01
TSDiCE64.dll opens both (traced via scripts/dll_iat_trace.py) -- one is the
device->host (read) endpoint, the other host->device.

Why: with the BT<->USB bridge firmware, bytes received over Bluetooth are
injected into the host RX ring, so the MCU answers them on the *host* channel.
Reading this pipe lets us see that answer even if the BT-side mirror (P1) does
not work.

Usage:
    python scripts/usb_pipe_read.py --seconds 40
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import time

GUID = "{4e8a43b0-259a-43c2-a025-baee43c02571}"
BASE = (r"\\?\usb#vid_17aa&pid_d1ce#dice-206751@000000000000#" + GUID)
PIPES = [r"\INTERFACE_0x00\PIPE_0x00", r"\INTERFACE_0x00\PIPE_0x01"]


class OV(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD),
                ("hEvent", wt.HANDLE)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=40.0)
    ap.add_argument("--chunk", type=int, default=512)
    args = ap.parse_args()

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = wt.HANDLE
    k.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                              wt.DWORD, wt.DWORD, wt.HANDLE]
    k.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                           ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    k.CreateEventW.restype = wt.HANDLE
    k.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
    k.CloseHandle.argtypes = [wt.HANDLE]

    handles = []
    for suf in PIPES:
        h = k.CreateFileW(BASE + suf, 0xC0000000, 3, None, 3, 0x40000000, None)
        if h in (None, -1):
            print("open %s -> FAIL err=%d" % (suf, ctypes.get_last_error()))
            continue
        print("open %s -> ok" % suf)
        handles.append((suf, h))
    if not handles:
        raise SystemExit("no pipe could be opened (DiagApp holding the device?)")

    events = []
    for suf, h in handles:
        ov = OV()
        ov.hEvent = k.CreateEventW(None, True, False, None)
        buf = ctypes.create_string_buffer(args.chunk)
        n = wt.DWORD(0)
        ok = k.ReadFile(h, buf, args.chunk, ctypes.byref(n), ctypes.byref(ov))
        events.append({"suf": suf, "h": h, "ov": ov, "buf": buf, "n": n,
                       "pending": (not ok and ctypes.get_last_error() == 997)})
        print("  issued read on %s (pending=%s)" % (suf, events[-1]["pending"]))

    deadline = time.time() + args.seconds
    seen = 0
    while time.time() < deadline:
        for ev in events:
            rc = k.WaitForSingleObject(ev["ov"].hEvent, 500)
            if rc != 0:
                continue
            n = wt.DWORD(0)
            k.GetOverlappedResult(ev["h"], ctypes.byref(ev["ov"]),
                                  ctypes.byref(n), False)
            data = ev["buf"].raw[:n.value]
            if data:
                seen += n.value
                print("[%s] RX %d B: %s" % (ev["suf"], n.value, data.hex(" ")))
                print("        |%s|" % "".join(
                    chr(c) if 32 <= c < 127 else "." for c in data))
            # re-arm
            k.ResetEvent(ev["ov"].hEvent)
            k.ReadFile(ev["h"], ev["buf"], args.chunk, ctypes.byref(ev["n"]),
                       ctypes.byref(ev["ov"]))
    print("total bytes received: %d" % seen)
    for _suf, h in handles:
        k.CloseHandle(h)


if __name__ == "__main__":
    main()
