r"""Trace what TSDiCE64.dll actually does: device paths, registry values, BT target.

IAT hooks (no driver, no elevation) on:
  * CreateFileW          -> the exact device/interface path it opens
  * RegQueryValueExW     -> which registry values it reads (and their data)
  * connect (ws2_32)     -> for AF_BTH: the Bluetooth address + RFCOMM channel

Found so far: UsbHardware::Open() builds
  \\.\usb#vid_17aa&pid_d1ce#<Name>@<BtAddress>#{4e8a43b0-...}\INTERFACE_0x00\PIPE_0x00
while the real device instance is DiCE-206751@000000000000 -- so with
BtAddress=002113014D64 the USB path does not exist (err=3) and DiagApp
silently falls back to Bluetooth.

Usage:
    python scripts/dll_iat_trace.py --open            # all hooks, one PassThruOpen
    python scripts/dll_iat_trace.py --open --only file,connect
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import struct

DEFAULT_DLL = r"C:\Program Files\DiCE\Tools\TSDiCE64.dll"


# ---------------------------------------------------------------- PE helpers
def load_pe(path):
    data = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE image"
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    dd = e_lfanew + 24 + (112 if magic == 0x20B else 96)
    imp_rva, _ = struct.unpack_from("<II", data, dd + 8)
    sec_off = e_lfanew + 24 + opt_size
    secs = []
    for i in range(nsec):
        s = data[sec_off + i * 40: sec_off + i * 40 + 40]
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", s, 8)
        secs.append((vaddr, vsize, rawptr, rawsize))
    return data, imp_rva, secs, magic


def rva2off(rva, secs):
    for vaddr, vsize, rawptr, rawsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None


def cstr(data, off):
    if off is None:
        return "<bad rva>"
    end = data.find(b"\0", off)
    return data[off:end if end > 0 else off + 64].decode(errors="replace")


def find_import_slots(data, imp_rva, secs, magic, func_name):
    """-> list of (first_thunk_rva, index, dll_name) for every importing DLL."""
    off = rva2off(imp_rva, secs)
    step = 8 if magic == 0x20B else 4
    out = []
    i = 0
    while True:
        oft, _ts, _fwd, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, off + i * 20)
        if name_rva == 0 and first_thunk == 0:
            return out
        dll_name = cstr(data, rva2off(name_rva, secs))
        thunk_rva = oft or first_thunk
        toff = rva2off(thunk_rva, secs)
        j = 0
        while toff is not None:
            val = int.from_bytes(data[toff + j * step: toff + (j + 1) * step],
                                 "little")
            if val == 0:
                break
            if not (val & (1 << (63 if magic == 0x20B else 31))):
                if cstr(data, rva2off(val + 2, secs)) == func_name:
                    out.append((first_thunk, j, dll_name))
            j += 1
        i += 1


def find_ordinal_slots(data, imp_rva, secs, magic, dll_sub, ordinal):
    """Same, but for imports by ordinal (e.g. WS2_32 #4 = connect)."""
    off = rva2off(imp_rva, secs)
    step = 8 if magic == 0x20B else 4
    out = []
    i = 0
    while True:
        oft, _ts, _fwd, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, off + i * 20)
        if name_rva == 0 and first_thunk == 0:
            return out
        dll_name = cstr(data, rva2off(name_rva, secs))
        if dll_sub.lower() in dll_name.lower():
            toff = rva2off(oft or first_thunk, secs)
            j = 0
            while toff is not None:
                val = int.from_bytes(data[toff + j * step: toff + (j + 1) * step],
                                     "little")
                if val == 0:
                    break
                if val & (1 << (63 if magic == 0x20B else 31)):
                    if (val & 0xFFFF) == ordinal:
                        out.append((first_thunk, j, dll_name))
                j += 1
        i += 1


def patch_slot(k32, slot, new_ptr):
    old = ctypes.c_void_p.from_address(slot).value
    old_prot = wt.DWORD(0)
    k32.VirtualProtect(ctypes.c_void_p(slot), ctypes.c_size_t(8), 0x40,
                       ctypes.byref(old_prot))
    ctypes.c_void_p.from_address(slot).value = new_ptr
    k32.VirtualProtect(ctypes.c_void_p(slot), ctypes.c_size_t(8), old_prot.value,
                       ctypes.byref(old_prot))
    return old


# ------------------------------------------------------------- hook payloads
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", default=DEFAULT_DLL)
    ap.add_argument("--open", action="store_true")
    ap.add_argument("--filter", default="", help="filter CreateFile paths")
    ap.add_argument("--only", default="file,reg,connect")
    args = ap.parse_args()
    want = {s.strip() for s in args.only.split(",")}

    data, imp_rva, secs, magic = load_pe(args.dll)
    dll = ctypes.WinDLL(args.dll)
    k32 = ctypes.windll.kernel32
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    k32.VirtualProtect.restype = wt.BOOL
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD,
                                   ctypes.POINTER(wt.DWORD)]
    base = k32.GetModuleHandleW(args.dll)
    step = 8 if magic == 0x20B else 4

    events = []
    real = {}
    cbs = {}

    CREATE_W = ctypes.WINFUNCTYPE(wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.DWORD,
                                  ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE)
    REGQ = ctypes.WINFUNCTYPE(ctypes.c_long, wt.HKEY, wt.LPCWSTR,
                              ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
                              ctypes.c_void_p, ctypes.POINTER(wt.DWORD))
    CONNECT = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_int)
    WSASEND = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                 wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD,
                                 ctypes.c_void_p, ctypes.c_void_p)
    WRITEFILE = ctypes.WINFUNCTYPE(wt.BOOL, wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                                   ctypes.POINTER(wt.DWORD), ctypes.c_void_p)

    def h_file(path, access, share, sa, disp, flags, tmpl):
        events.append(("file", path, access, share, disp, flags))
        return CREATE_W(real["file"])(path, access, share, sa, disp, flags, tmpl)

    def h_reg(hkey, name, reserved, typ, buf, buflen):
        rc = REGQ(real["reg"])(hkey, name, reserved, typ, buf, buflen)
        val = None
        try:
            if rc == 0 and typ is not None:
                if typ.contents.value == 1:      # REG_SZ
                    val = ctypes.wstring_at(buf)
                elif typ.contents.value == 4:    # REG_DWORD
                    val = ctypes.c_ulong.from_address(buf).value
        except Exception as e:
            val = "<%s>" % e
        events.append(("reg", name, rc, typ.contents.value if typ else None, val))
        return rc

    def h_connect(sock, addr, alen):
        info = None
        try:
            raw = ctypes.string_at(addr, 40)
            fam = struct.unpack_from("<H", raw, 0)[0]
            if fam == 32:                        # AF_BTH
                btaddr = int.from_bytes(raw[8:14], "little")
                port = struct.unpack_from("<I", raw[32:36])[0]
                info = "AF_BTH address=%012X channel=%d raw=%s" % (
                    btaddr, port, raw[:24].hex(" "))
            else:
                info = "AF=%d alen=%d raw=%s" % (fam, alen, raw[:24].hex(" "))
        except Exception as e:
            info = "<%s>" % e
        events.append(("connect", info))
        return CONNECT(real["connect"])(sock, addr, alen)

    def h_send(sock, bufs, cnt, sent, flags, ov, comp):
        try:
            parts = []
            for i in range(cnt):
                base = bufs + i * 16          # WSABUF: ULONG len; (pad); CHAR* buf
                ln = ctypes.c_ulong.from_address(base).value
                ptr = ctypes.c_void_p.from_address(base + 8).value
                parts.append(ctypes.string_at(ptr, ln).hex(" ") if ptr else "?")
            events.append(("send", " | ".join(parts)))
        except Exception as e:
            events.append(("send", "<%s>" % e))
        return WSASEND(real["send"])(sock, bufs, cnt, sent, flags, ov, comp)

    def h_write(handle, buf, n, written, ov):
        try:
            events.append(("write", ctypes.string_at(buf, min(n, 128)).hex(" ")))
        except Exception as e:
            events.append(("write", "<%s>" % e))
        return WRITEFILE(real["write"])(handle, buf, n, written, ov)

    hooks = []
    if "file" in want:
        hooks.append(("CreateFileW", CREATE_W(h_file), "file"))
    if "reg" in want:
        hooks.append(("RegQueryValueExW", REGQ(h_reg), "reg"))
    if "connect" in want:
        hooks.append(("connect", CONNECT(h_connect), "connect"))
    if "send" in want:
        hooks.append(("WSASend", WSASEND(h_send), "send"))
    if "write" in want:
        hooks.append(("WriteFile", WRITEFILE(h_write), "write"))

    for name, cb, tag in hooks:
        cbs[tag] = cb
        found = find_import_slots(data, imp_rva, secs, magic, name)
        if not found and tag == "connect":
            # WS2_32 exports connect as ordinal 3 (4 = getpeername, 22 = socket)
            found = find_ordinal_slots(data, imp_rva, secs, magic, "ws2_32", 3)
            print("connect imported by ordinal: WS2_32 #3 -> %d slot(s)" % len(found))
        if not found:
            print("import not found:", name)
            continue
        for first_thunk, idx, dll_name in found:
            slot = base + first_thunk + idx * step
            real[tag] = patch_slot(k32, slot, ctypes.cast(cb, ctypes.c_void_p).value)
            print("hooked %-18s from %-16s slot=0x%X" % (name, dll_name, slot))

    if args.open:
        o = dll.PassThruOpen
        o.restype = ctypes.c_long
        o.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulong)]
        dev = ctypes.c_ulong(0)
        rc = o(b"DiCE-206751", ctypes.byref(dev))
        print("\nPassThruOpen -> %d (DeviceID %d)" % (rc, dev.value))
        cl = dll.PassThruClose
        cl.restype = ctypes.c_long
        cl.argtypes = [ctypes.c_ulong]
        cl(dev.value)

    print("\n=== events (%d) ===" % len(events))
    for ev in events:
        if ev[0] == "file":
            _, p, access, share, disp, flags = ev
            p = p if isinstance(p, str) else (p or "")
            if args.filter and args.filter.lower() not in str(p).lower():
                continue
            print("[file]    access=0x%08X share=0x%X disp=%d  %s"
                  % (access, share, disp, p))
        elif ev[0] == "reg":
            _, name, rc, typ, val = ev
            print("[reg]     %-28s rc=%d type=%s value=%r" % (name, rc, typ, val))
        elif ev[0] == "send":
            print("[WSASend] %s" % (ev[1],))
        elif ev[0] == "write":
            print("[WriteFile] %s" % (ev[1],))
        else:
            print("[connect] %s" % (ev[1],))


if __name__ == "__main__":
    main()
