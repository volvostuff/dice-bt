#!/usr/bin/env python3
"""Raw RFCOMM probe of the DiCE BT module (bypasses TSDiCE64.dll).

Why: TSDiCE64.dll gives up 2 s after it sends the RFC version request
(log "RfcVersion::Execute() GetReply() pop timeout"), which is too short to
tell "MCU never answers" from "MCU answers late".  This script opens the very
same kind of link the DLL uses -- a WinSock RFCOMM client to the paired
module's BT address -- and just listens, with a configurable timeout.

Note on COM ports: TSDiCE64.dll does NOT use a COM port for Bluetooth (none of
TSDiCE64.dll / TSDiCE32.dll / RfcFWDL32.dll contains the string "Comport" or
"COM%d"; the DLL creates an AF_BTH socket via WSASocketW and connects by
address).  The "Comport" value in
HKLM\\SOFTWARE\\PassThruSupport.04.04\\SETEK - DiCE belongs to the legacy
Laird/Ezurio USB dongle path.

RFC frame (docs/rfc_bootloader_read.md):

    0xB5 | len LE16 | hdr_cs | FID | payload | msg_cs
    len    = 2 + len(payload)          (FID + payload + msg_cs)
    hdr_cs = (len_lo + len_hi + 0x1E) & 0xFF
    msg_cs = (0x69 + FID + sum(payload)) & 0xFF

Modes:
    listen    connect, print everything that arrives, send nothing
    version   send the RFC version request (FID 0x07, no payload)
    frame     send an arbitrary FID (--fid/--payload); read-only FIDs only:
              1 = RfcMaxSize, 6 = SysBootloaderVersion, 7 = RfcVersion,
              0x7B = FwdlRead (needs --payload with addr/len, little endian)

Examples:
    python scripts/bt_probe.py --mode listen --timeout 10
    python scripts/bt_probe.py --mode version --timeout 30
    python scripts/bt_probe.py --scan --mode listen      # find the channel
"""
import argparse
import socket
import sys
import time

BTH = getattr(socket, "AF_BLUETOOTH", None)
RFCOMM = getattr(socket, "BTPROTO_RFCOMM", None)
FRAME_MAGIC = 0xB5


def build_frame(fid, payload=b""):
    ln = 2 + len(payload)
    hdr_cs = ((ln & 0xFF) + ((ln >> 8) & 0xFF) + 0x1E) & 0xFF
    msg_cs = (0x69 + fid + sum(payload)) & 0xFF
    return bytes([FRAME_MAGIC, ln & 0xFF, (ln >> 8) & 0xFF, hdr_cs, fid]) + bytes(payload) + bytes([msg_cs])


def check_frame(buf):
    """Return (ok_hdr, ok_msg, fid, payload) for a complete frame, else None."""
    if len(buf) < 4 or buf[0] != FRAME_MAGIC:
        return None
    ln = buf[1] | (buf[2] << 8)
    total = ln + 4
    if len(buf) < total:
        return None
    hdr_cs = buf[3]
    fid = buf[4]
    payload = buf[5:total - 1]
    msg_cs = buf[total - 1]
    ok_hdr = (hdr_cs == (((ln & 0xFF) + ((ln >> 8) & 0xFF) + 0x1E) & 0xFF))
    ok_msg = (msg_cs == ((0x69 + fid + sum(payload)) & 0xFF))
    return (total, ok_hdr, ok_msg, fid, payload)


def hexdump(data):
    return " ".join("%02X" % b for b in data)


def connect(addr, channel, timeout, attempts=4):
    """Connect with retries: the module sometimes refuses a fresh SPP session
    right after a previous one was closed (HC-05 quirk)."""
    last = None
    for i in range(attempts):
        s = None
        try:
            s = socket.socket(BTH, socket.SOCK_STREAM, RFCOMM)
            s.settimeout(timeout)
            s.connect((addr, channel))
            return s
        except OSError as e:
            last = e
            if s is not None:
                s.close()
            if i + 1 < attempts:
                print("  connect attempt %d failed (%s), retrying..." % (i + 1, e))
                time.sleep(3)
    raise last


def found(addr, channel, timeout, verbose=True):
    """Try to connect; print nothing on failure, keep the socket on success."""
    for ch in range(1, 31):
        if channel and ch != channel:
            continue
        try:
            s = connect(addr, ch, timeout)
        except OSError as e:
            if verbose:
                print("  channel %2d: %s" % (ch, e))
            continue
        if verbose:
            print("  channel %2d: CONNECTED" % ch)
        return ch, s
    return None, None


def main():
    if BTH is None or RFCOMM is None:
        sys.exit("this Python has no AF_BLUETOOTH/BTPROTO_RFCOMM support")

    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default="00:21:13:01:4D:64", help="module BT address")
    ap.add_argument("--channel", type=int, default=1, help="RFCOMM channel (SPP is usually 1)")
    ap.add_argument("--scan", action="store_true", help="probe channels 1..30 until one connects")
    ap.add_argument("--mode", choices=("listen", "version", "frame", "raw"), default="listen")
    ap.add_argument("--fid", type=lambda x: int(x, 0), default=0x07)
    ap.add_argument("--payload", default="", help="hex payload, e.g. 00100000")
    ap.add_argument("--hex", default="", help="raw bytes to send, e.g. 41540D0A ('AT\\r\\n')")
    ap.add_argument("--text", default="", help="raw ASCII to send (adds CRLF with --crlf)")
    ap.add_argument("--crlf", action="store_true")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds to keep reading")
    ap.add_argument("--connect-timeout", type=float, default=8.0)
    ap.add_argument("--attempts", type=int, default=4,
                    help="connect retries (3 s apart) -- useful when the module "
                         "is being power-cycled and is not up yet")
    args = ap.parse_args()

    print("address %s, RFCOMM" % args.addr)
    if args.scan:
        channel, s = found(args.addr, None, args.connect_timeout)
        if s is None:
            sys.exit("no RFCOMM channel accepted a connection")
    else:
        try:
            s = connect(args.addr, args.channel, args.connect_timeout, args.attempts)
        except OSError as e:
            sys.exit("connect failed (channel %d): %s" % (args.channel, e))
        channel = args.channel
        print("connected on channel %d" % channel)

    try:
        if args.mode != "listen":
            if args.mode == "version":
                tx = build_frame(0x07, b"")
            elif args.mode == "frame":
                tx = build_frame(args.fid, bytes.fromhex(args.payload))
            else:  # raw
                if args.hex:
                    tx = bytes.fromhex(args.hex)
                else:
                    tx = args.text.encode()
                    if args.crlf:
                        tx += b"\r\n"
            print("TX (%d B): %s" % (len(tx), hexdump(tx)))
            s.sendall(tx)
        else:
            print("listening (no TX)...")

        deadline = time.time() + args.timeout
        buf = b""
        while time.time() < deadline:
            s.settimeout(max(0.2, deadline - time.time()))
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            except OSError as e:
                print("recv error: %s" % e)
                break
            if not chunk:
                print("peer closed the connection (0 bytes)")
                break
            print("RX %s |%s|" % (hexdump(chunk),
                                  "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
            buf += chunk
            while True:
                f = check_frame(buf)
                if f is None:
                    break
                total, ok_hdr, ok_msg, fid, payload = f
                buf = buf[total:]
                print("  RFC frame: fid=0x%02X payload=%s hdr_cs=%s msg_cs=%s"
                      % (fid, hexdump(payload), "OK" if ok_hdr else "BAD",
                         "OK" if ok_msg else "BAD"))
        if buf:
            print("leftover (incomplete frame?): %s" % hexdump(buf))
        else:
            print("no complete frame received")
    finally:
        s.close()


if __name__ == "__main__":
    main()
