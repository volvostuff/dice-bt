#!/usr/bin/env python3
"""Patch dice_5_6_2.mot for a pre-programmed CH05 BT module.

.mot format: sparse Motorola S2 records (16 data bytes, non-contiguous)
+ S0 header + S8 trailer. Checksum byte = (0xFF - sum(all bytes after 'S2')) & 0xFF.
Logical-image offset = address - 0xFA0000.

Patch model: whole-code-region replacement (same-length old/new), spliced
across whatever S2 records cover the region. Old bytes are NOT re-verified
byte-by-byte against the image except that the whole region must be covered
by S2 records; the output is re-parsed and every patched byte re-checked.

All encodings below are donor-copied from the original image and were
verified in IDA (dice_5_6_2.mot.i64):
  * no external xrefs into any patched region except calls to function
    starts (prologues preserved or replaced in a controlled way);
  * xrefs to ser_boot_state (0x23C9) are exactly:
      fb0f3a/fb0f4e/fb1124 (bt_baud_detect - removed by F),
      fb1676/fb168f (bt_rx_read, read), fb16a8/fb16b6/fb16b9 (sub_FB16A8).
    Nothing else ever writes it; the runtime gate is strictly == 1.

WHY each patch (see docs/ch05_patch.md):

  F  bt_baud_detect (0xFB0EC2..0xFB112B, 618 B)  [MUST]
     Original: 'AT' scan 9600..921600 (8 x ~3.5 s when silent), ATZ,
     then vendor-specific ATS521 probe; on a silent CH05 the UART is left
     at the WRONG baud (921600, last table entry) and ser_boot_state=0.
     Replacement: unconditional bring-up at 460800, no AT at all:
        ser_cur_baud = 460800;
        serial_channel_reset(ser_chan_bt);
        serial_channel_set_config(460800, 0);
        uart_port_init(ser_chan_bt);
        ser_boot_state = 1;
        return 0.
     The only caller that checks R0 (sub_FC0996) immediately overwrites it
     with rfc_media_init's result, so 0 is safe.

  B  sub_FB15BE (0xFB15BE..0xFB161F, 98 B)  [MUST]
     'ATD%s,1101' outbound dial, called on every J2534 Open (fab889 in
     sub_FAB86C, fbf192 in sub_FBF18A); the Open fails if R0L != 0.
     CH05 is an SPP SERVER (Windows dials it), so the MCU must never dial.
     -> 'MOV.B #0,R0L; RTS' + NOP fill.

  E  sub_FB16A8 link-state getter (0xFB16A8..0xFB16BC, 21 B)  [MUST]
     Original: state 0/1 -> state := P5.4 (BT "connected" input, P5.4 is
     configured input at fb7c79; 4/5 sticky). The runtime BT data pump
     (bt_rx_read fb1676, bt_at_tx, sub_FB16C8 fb16cf, link watcher
     fc0aab) all require state == 1, which in the original design happens
     when the connected line goes high. With CH05 (no such line, or it is
     not P5.4) every RX/TX would be blocked.
     -> 'MOV.B #1,R0L; MOV.B R0L,ser_boot_state; RTS' (link always up).

  A  0xFB13C6  CF 65 FD -> DE DE DE  [insurance]
     JSR.W bt_at_init (13-command factory AT config) inside bt_line_probe;
     after F the only reachable caller is the J2534 Open path via
     sub_FB1620. NOP it so factory config is never (re)sent to CH05.

  C1 0xFB12CB  D6 F9 C4 03 -> DE DE DE DE  [optional --with-reset-off]
  C2 0xFB12DB  D6 F1 C4 03 -> DE DE DE DE  [optional --with-reset-off]
     P2.1 200 ms pulse in bt_line_probe (Open path, arg==0/1/2). Keep if
     P2.1 -> CH05 RESET; remove if P2.1 -> CH05 EN (power), where the
     blip would briefly power-cycle the module on every Open.
"""
import argparse
import sys

MOT_IN = r"C:\misc\dice\dice_5_6_2.mot"
MOT_OUT = r"C:\misc\dice\dice_5_6_2_ch05.mot"

NOP = 0xDE
RTS = 0xDF

# BT channel baud used by the replacement bring-up (patch F). The CH05/HC-05
# module must be set to the same value with AT+UART=<baud>,0,0. 460800 matches
# the stock firmware; 115200 is the fallback for clones whose crystal makes
# 460800 unreliable.
BAUD = 460800


def new_baud_detect():
    """Replacement body for bt_baud_detect (F). Every instruction encoding
    is copied verbatim from a donor site in the original image."""
    code = bytes()
    code += bytes([0xEC, 0x00])                       # ENTER #0          (donor fb1508)
    code += bytes.fromhex("b6f11604")                 # MOV.L #<baud>, ser_cur_baud+2
    code += BAUD.to_bytes(4, "little")                #   (donor fb0fe2, only imm changes)
    code += bytes.fromhex("182524")                   # MOV.B ser_chan_bt, R0L
    code += bytes.fromhex("cd9e12fc")                 # JSR.A serial_channel_reset
    code += bytes.fromhex("182524")
    code += bytes.fromhex("a6c11604")                 # PUSH.L ser_cur_baud+2
    code += bytes.fromhex("ae00")                     # PUSH.B #0
    code += bytes.fromhex("cd1a13fc")                 # JSR.A serial_channel_set_config
    code += bytes([0x63])                             # ADD.L #6, SP
    code += bytes.fromhex("182524")
    code += bytes.fromhex("cdd20ffc")                 # JSR.A uart_port_init
    code += bytes.fromhex("182524")
    code += bytes.fromhex("cd4a17fc")                 # JSR.A serial_channel_start (arg in R0L, no stack)
    code += bytes.fromhex("f8a1")                     # MOV.B #1, R0L
    code += bytes.fromhex("10c923")                   # MOV.B R0L, ser_boot_state
    code += bytes.fromhex("02")                       # MOV.B #0, R0L
    code += bytes([0xFC])                             # EXITD
    return code


def new_link_state():
    """Replacement body for sub_FB16A8 (E)."""
    code = bytes.fromhex("f8a1")                      # MOV.B #1, R0L
    code += bytes.fromhex("10c923")                   # MOV.B R0L, ser_boot_state
    code += bytes([RTS])
    return code


# (label, region_start, region_len, new_bytes, mandatory)
PATCHES = []


def _add(label, start, end, new_body, mandatory):
    ln = end - start
    body = new_body + bytes([NOP]) * (ln - len(new_body))
    assert len(body) == ln, label
    PATCHES.append((label, start, ln, body, mandatory))


_add("B: ATD dial -> R0=0;RTS", 0xFB15BE, 0xFB1620,
     bytes.fromhex("02") + bytes([RTS]), True)
_add("F: bt_baud_detect -> 460800 bring-up", 0xFB0EC2, 0xFB112C,
     new_baud_detect(), True)
_add("E: link state getter -> force 1", 0xFB16A8, 0xFB16BD,
     new_link_state(), True)
PATCHES.append(("A: NOP JSR.W bt_at_init", 0xFB13C6, 3,
                bytes.fromhex("dedede"), True))
PATCHES.append(("C1: NOP P2.1 set", 0xFB12CB, 4, bytes.fromhex("dededede"), False))
PATCHES.append(("C2: NOP P2.1 clear", 0xFB12DB, 4, bytes.fromhex("dededede"), False))


def rebuild_f(baud):
    """Regenerate the F patch for another BT channel baud."""
    global BAUD
    BAUD = baud
    for i, (label, start, ln, _body, mand) in enumerate(PATCHES):
        if label.startswith("F:"):
            new = new_baud_detect()
            PATCHES[i] = ("F: bt_baud_detect -> %d bring-up" % baud, start, ln,
                          new + bytes([NOP]) * (ln - len(new)), mand)
            return
    raise SystemExit("F patch not found")


def parse_s2(line):
    n = int(line[1])
    assert n == 2, "expected S2, got S%d" % n
    cnt = int(line[2:4], 16)
    addr = int(line[4:10], 16)
    db = cnt - 4  # count - addr(3) - checksum(1)
    data = bytes.fromhex(line[10:10 + 2 * db])
    chk = int(line[10 + 2 * db:12 + 2 * db], 16)
    return cnt, addr, data, chk


def s2_line(addr, data):
    cnt = 3 + len(data) + 1
    body = ("%02X" % cnt) + ("%06X" % addr) + data.hex().upper()
    s = sum(int(body[i:i + 2], 16) for i in range(0, len(body), 2))
    return "S2" + body + "%02X" % ((0xFF - (s & 0xFF)) & 0xFF)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-reset-off", action="store_true",
                    help="also apply C1/C2 (P2.1 -> EN case)")
    ap.add_argument("--out", default=MOT_OUT)
    ap.add_argument("--baud", type=int, default=BAUD,
                    help="BT channel baud for patch F (default 460800). Set the "
                         "module to the same value: AT+UART=<baud>,0,0")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--keep-dial", action="store_true",
                    help="diagnostic build: keep patch B (the ATD dial) so the "
                         "MCU still transmits on the BT channel on every Open — "
                         "used to prove the MCU->module direction. Open will fail "
                         "as before (no OK from the module).")
    args = ap.parse_args()

    if args.baud != BAUD:
        rebuild_f(args.baud)
        print("patch F rebuilt for baud = %d" % args.baud)

    active = [p for p in PATCHES
              if (p[4] or args.with_reset_off)
              and not (args.keep_dial and p[0].startswith("B:"))]
    if args.keep_dial:
        print("keep-dial: patch B excluded (ATD dial stays in place)")

    lines = [l.strip() for l in open(MOT_IN, errors="replace")]
    rec = {}          # line_index -> [addr, bytearray]
    addr_index = {}   # abs addr -> (line_index, offset)
    for li, l in enumerate(lines):
        if l.startswith("S2"):
            cnt, addr, data, chk = parse_s2(l)
            rec[li] = [addr, bytearray(data)]
            for i in range(len(data)):
                addr_index.setdefault(addr + i, (li, i))

    # ---- every patched byte must be covered by an S2 record ----
    for label, start, ln, new, _ in active:
        for off in range(ln):
            if addr_index.get(start + off) is None:
                sys.exit("%s: %06X not covered by an S2 record"
                         % (label, start + off))
        print("cover  OK  %s @%06X (%d bytes)" % (label, start, ln))

    if args.verify_only:
        print("verify-only: %d active regions covered" % len(active))
        return

    # ---- apply: splice new bytes into each covering record ----
    for label, start, ln, new, _ in active:
        end = start + ln
        for li in sorted(rec):
            a, rd = rec[li]
            b = a + len(rd)
            if b <= start or a >= end:
                continue
            lo = max(a, start)
            hi = min(b, end)
            rd[lo - a:hi - a] = new[lo - start:hi - start]
        print("applied    %s @%06X" % (label, start))

    # ---- emit ----
    out = []
    for li, l in enumerate(lines):
        if l.startswith("S2") and li in rec:
            a, rd = rec[li]
            out.append(s2_line(a, bytes(rd)))
        else:
            out.append(l)
    with open(args.out, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote %s (%d regions)" % (args.out, len(active)))

    # ---- self-check: re-parse output, checksums + new bytes ----
    bad = 0
    out_lines = [x.strip() for x in open(args.out, errors="replace")]
    amap = {}
    for l in out_lines:
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
    for label, start, ln, new, _ in active:
        for a in range(start, start + ln):
            if amap[a] != new[a - start]:
                sys.exit("self-check FAIL %s @%06X" % (label, a))
    print("self-check OK: %d regions present, all S2 checksums valid" % len(active))


if __name__ == "__main__":
    main()
