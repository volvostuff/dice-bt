#!/usr/bin/env python3
"""Bridge patch: mirror the host (USB) serial channel <-> the Bluetooth channel.

Input  (default): C:\\misc\\dice\\dice_5_6_3_ch05_full.mot   (CH05 patch applied)
Output (default): C:\\misc\\dice\\dice_5_6_3_ch05_bridge.mot

Two logical patches, both implemented as a 4-byte "trampoline" in the original
code plus a small body parked in the NOP tomb of the CH05 patch F
(bt_baud_detect, 0xFB0EC2..0xFB112B).  That region is dead code after patch F
(the replacement body ends with EXITD at 0xFB0EF5), so it is used as a code
cave; the generator refuses to run unless it really is 0xDE fill.

  P1  host TX -> BT TX
      sub_FC154C (0xFC154C) is the ONLY producer for all channel TX rings
      (it is the only writer of ser_chan_table = channel TX write index,
      verified over the whole image).  The 4-byte prologue is replaced by
      JMP.A cave1; cave1 re-does ENTER/PUSHM, and when the channel argument
      equals ser_chan_usb it makes a second call to sub_FC154C with
      chan = ser_chan_bt, using a LOCAL copy of the caller's length word so
      the caller's byte counter is not disturbed.  Finally it resumes at
      0xFC1550 with R0L restored to the original channel.

  P2  BT RX -> host RX
      The BT channel (chan 0 = ser_chan_bt) has its own hand-written ISR pair
      (vector table 0xFAA1AC -> 0xFC1E50 TX-empty, 0xFAA1B0 -> 0xFC1E7E RX).
      In the RX ISR the received byte is appended to the BT RX ring by
      0xFC1ED5..0xFC1ED7.  The 4-byte store 0xFC1ED7 (MOV.W R2,word_2683) is
      replaced by JSR.A cave2; cave2 performs that displaced store, then
      re-enters the *generic* per-channel RX-ring append block at 0xFC1E0C
      (inside chan_rx_isr) with chan = ser_chan_usb and the byte in R1L.
      The generic block ends with POPM/EXITD, so it returns straight to the
      BT ISR, which then does its own POPM/REIT.

      Cave2 starts with FCLR I so the read-modify-write of the host channel's
      RX ring index cannot be preempted by the host channel's own RX ISR
      (chan_rx_isr with chan = ser_chan_usb).  REIT restores the flag register,
      so the interrupt mask is not affected beyond the helper.

Every single instruction below is copied from a donor site in the SAME image
(donor address given per line); only the branch displacement and the absolute
JMP.A/JSR.A targets are computed.  Byte offsets in the .mot: address - 0xFA0000.

Use --verify-only to check the input file without writing anything.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from apply_ch05_patch import parse_s2, s2_line          # noqa: E402  (reuse codec)

MOT_IN = r"C:\misc\dice\dice_5_6_3_ch05_full.mot"
MOT_OUT = r"C:\misc\dice\dice_5_6_3_ch05_bridge.mot"

NOP = 0xDE

# ---------------------------------------------------------------- patch sites
P1_SITE = 0xFC154C          # sub_FC154C: ENTER #4; PUSHM R1,R2,R3,A0,A1
P1_ORIG = bytes.fromhex("EC048F7C")
P1_RESUME = 0xFC1550        # MOV.W #0,R1   (first instruction after prologue)

P2_SITE = 0xFC1ED7          # sub_FC1E7E (BT RX ISR): MOV.W R2,word_2683
P2_ORIG = bytes.fromhex("C7CB8326")
P2_TARGET = 0xFC1E0C        # generic RX-ring append block in chan_rx_isr

CAVE1 = 0xFB0F00            # inside the 0xDE tomb of CH05 patch F
CAVE1_LEN = 64
CAVE2 = CAVE1 + CAVE1_LEN   # 0xFB0F40
CAVE2_LEN = 32

# sanity anchors inside the input image (must match byte for byte)
F_PATCH_HEAD = (0xFB0EC2, bytes.fromhex("EC00"))          # CH05 patch F: ENTER #0
F_PATCH_TAIL = (0xFB0EF5, bytes.fromhex("FC"))            # CH05 patch F: EXITD
P1_PROLOGUE_TAIL = (0xFC1550, bytes.fromhex("F9E030FE888F63C1AB"))
BT_RX_ISR_HEAD = (0xFC1E7E, bytes.fromhex("8FF8196E030D0078DA2E"))
# generic RX-ring append block, re-entered by P2 (chan_rx_isr 0xFC1E0C..0xFC1E4F)
RX_APPEND_BLOCK = (0xFC1E0C, bytes.fromhex(
    "30FE888F63C1ABA90B8326E931A90D8926C3CBFC38FEA9068526"
    "9A1089ABF920C1A3852F902680008E3EFC888F63C1AB39FCF920"
    "C1E3A1C27F26C07B953BFC83268E3EFC"))


def jmp_a(target):
    """JMP.A: CC + 24-bit little-endian absolute target (donor 0xFA0000)."""
    return bytes([0xCC]) + target.to_bytes(3, "little")


def jsr_a(target):
    """JSR.A: CD + 24-bit little-endian absolute target (donor 0xFB0E02)."""
    return bytes([0xCD]) + target.to_bytes(3, "little")


def cave1_body():
    """P1: mirror the sub_FC154C call to the BT channel.  40 bytes."""
    c = bytes()
    c += bytes.fromhex("EC04")        # ENTER #4                 donor fc154c
    c += bytes.fromhex("8F7C")        # PUSHM R1,R2,R3,A0,A1     donor fc154e
    c += bytes.fromhex("4E")          # MOV.B R0L,R1L            donor fb1632
    c += bytes.fromhex("182624")      # MOV.B ser_chan_usb,R0L   donor fab806
    c += bytes.fromhex("C8B6")        # CMP.B R1L,R0L            donor fb1636
    # JNE/NZ over the mirror block.  M32C rel8 is relative to insn_addr+1
    # (rule verified against all 3789 short branches of the image);
    # target = end of the mirror block = 0x25 (see the length check below).
    jne_off = 0x0A
    target_off = 0x25
    c += bytes([0x9A, (target_off - jne_off - 1) & 0xFF])   # donor fb1653
    c += bytes.fromhex("C8BB")        # MOV.B R1L,R0L            donor fc1bbb
    c += bytes.fromhex("093908")      # MOV.W [arg_0[FB]],R0     donor fb8507
    c += bytes.fromhex("31FC")        # MOV.W R0,var_4[FB]       donor fa2dcf
    c += bytes.fromhex("A2C10C")      # PUSH.L arg_4[FB]         donor fb1642
    c += bytes.fromhex("D3DAFC")      # MOVA var_4[FB],A0        donor fb0dfa
    c += bytes.fromhex("A081")        # PUSH.L A0                donor fb0dfd
    c += bytes.fromhex("182524")      # MOV.B ser_chan_bt,R0L    donor fb0e16
    c += jsr_a(0xFC154C)              # JSR.A sub_FC154C         donor fb0e02
    c += bytes.fromhex("73")          # ADD.L #8,SP              donor fb0e06
    c += bytes.fromhex("C8BB")        # MOV.B R1L,R0L            donor fc1bbb
    assert len(c) == target_off, "cave1: JNE target %#x, body %#x" % (target_off, len(c))
    c += jmp_a(P1_RESUME)             # JMP.A 0xFC1550           donor fa0000
    return c


def cave2_body():
    """P2: duplicate the BT RX byte into the host channel RX ring."""
    c = bytes()
    c += bytes.fromhex("D3EE")        # FCLR I                   donor fa3515
    c += bytes.fromhex("C7CB8326")    # MOV.W R2,word_2683       donor fc1ed7 (displaced)
    c += bytes.fromhex("EC04")        # ENTER #4                 donor fc154c
    c += bytes.fromhex("8F7C")        # PUSHM R1,R2,R3,A0,A1     donor fc154e
    c += bytes.fromhex("4E")          # MOV.B R0L,R1L            donor fb1632
    c += bytes.fromhex("182624")      # MOV.B ser_chan_usb,R0L   donor fab806
    c += jmp_a(P2_TARGET)             # JMP.A 0xFC1E0C           donor fa0000
    return c


def build(p1=True, p2=True):
    c1 = cave1_body()
    c2 = cave2_body()
    assert len(c1) <= CAVE1_LEN and len(c2) <= CAVE2_LEN
    patches = []
    if p1:
        patches += [
            ("P1 hook  sub_FC154C -> JMP.A cave1", P1_SITE, jmp_a(CAVE1)),
            ("P1 cave1 (mirror host TX -> BT TX)", CAVE1,
             c1 + bytes([NOP]) * (CAVE1_LEN - len(c1))),
        ]
    if p2:
        patches += [
            ("P2 hook  BT RX ISR store -> JSR.A cave2", P2_SITE, jsr_a(CAVE2)),
            ("P2 cave2 (dup BT RX byte -> host RX ring)", CAVE2,
             c2 + bytes([NOP]) * (CAVE2_LEN - len(c2))),
        ]
    return patches, c1, c2


# ---------------------------------------------------------------- donor table
# (encoded bytes, donor address, exact?)  exact=False -> only the opcode byte is
# taken from the donor (the 24-bit JMP.A/JSR.A target and the JNE displacement
# are by definition patch specific).
DONORS = [
    # --- cave1 (P1) ---
    ("EC04",           0xFC154C, True,  "ENTER #4"),
    ("8F7C",           0xFC154E, True,  "PUSHM R1,R2,R3,A0,A1"),
    ("4E",             0xFB1632, True,  "MOV.B R0L,R1L"),
    ("182624",         0xFAB806, True,  "MOV.B ser_chan_usb,R0L"),
    ("C8B6",           0xFB1636, True,  "CMP.B R1L,R0L"),
    ("9A1A",           0xFB1653, False, "JNE/NZ (displacement recomputed)"),
    ("C8BB",           0xFC1BBB, True,  "MOV.B R1L,R0L"),
    ("093908",         0xFB8507, True,  "MOV.W [arg_0[FB]],R0"),
    ("31FC",           0xFA2DCF, True,  "MOV.W R0,var_4[FB]"),
    ("A2C10C",         0xFB1642, True,  "PUSH.L arg_4[FB]"),
    ("D3DAFC",         0xFB0DFA, True,  "MOVA var_4[FB],A0"),
    ("A081",           0xFB0DFD, True,  "PUSH.L A0"),
    ("182524",         0xFB0E16, True,  "MOV.B ser_chan_bt,R0L"),
    ("CD4C15FC",       0xFB0E02, True,  "JSR.A sub_FC154C"),
    ("73",             0xFB0E06, True,  "ADD.L #8,SP"),
    ("CC5015FC",       0xFA0000, False, "JMP.A 0xFC1550"),
    # --- cave2 (P2) ---
    ("D3EE",           0xFA3515, True,  "FCLR I"),
    ("C7CB8326",       0xFC1ED7, True,  "MOV.W R2,word_2683 (displaced)"),
    ("CC0C1EFC",       0xFA0000, False, "JMP.A 0xFC1E0C"),
    # --- hooks ---
    ("CC" + jmp_a(CAVE1)[1:].hex().upper(), 0xFA0000, False, "JMP.A cave1 (P1 hook)"),
    ("CD" + jsr_a(CAVE2)[1:].hex().upper(), 0xFB0E02, False, "JSR.A cave2 (P2 hook)"),
]


def check_donors(img):
    """Every patched instruction must be byte-identical to a donor site."""
    n_exact = n_form = 0
    for hexs, donor, exact, what in DONORS:
        want = bytes.fromhex(hexs)
        got = img(donor, len(want))
        if exact:
            if got != want:
                sys.exit("DONOR FAIL %-42s @%06X want %s got %s"
                         % (what, donor, want.hex().upper(), got.hex().upper()))
            n_exact += 1
        else:
            if got[0] != want[0]:
                sys.exit("DONOR FAIL %-42s @%06X opcode %02X != %02X"
                         % (what, donor, got[0], want[0]))
            n_form += 1
    print("donors OK  %d instructions byte-identical to their donor site, "
          "%d use the donor encoding with a recomputed operand" % (n_exact, n_form))



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="mot_in", default=MOT_IN)
    ap.add_argument("--out", dest="mot_out", default=MOT_OUT)
    ap.add_argument("--verify-only", action="store_true",
                    help="check the input file and print the patch bytes, write nothing")
    ap.add_argument("--no-p1", action="store_true", help="skip P1 (host TX -> BT TX)")
    ap.add_argument("--no-p2", action="store_true", help="skip P2 (BT RX -> host RX)")
    args = ap.parse_args()

    if args.no_p1 and args.no_p2:
        sys.exit("nothing to do: both P1 and P2 disabled")

    patches, c1, c2 = build(p1=not args.no_p1, p2=not args.no_p2)

    lines = [l.strip() for l in open(args.mot_in, errors="replace")]
    rec = {}          # line index -> [addr, bytearray]
    addr_index = {}   # abs addr -> (line index, offset)
    for li, l in enumerate(lines):
        if l.startswith("S2"):
            cnt, addr, data, chk = parse_s2(l)
            rec[li] = [addr, bytearray(data)]
            for i in range(len(data)):
                addr_index.setdefault(addr + i, (li, i))

    def img(addr, n):
        out = bytearray()
        for a in range(addr, addr + n):
            if a not in addr_index:
                sys.exit("input image: no S2 record covers %06X" % a)
            li, off = addr_index[a]
            out.append(rec[li][1][off])
        return bytes(out)

    # ---- preconditions ------------------------------------------------
    for label, addr, exp in (("CH05 patch F head", F_PATCH_HEAD[0], F_PATCH_HEAD[1]),
                             ("CH05 patch F tail", F_PATCH_TAIL[0], F_PATCH_TAIL[1]),
                             ("sub_FC154C prologue", P1_SITE, P1_ORIG),
                             ("sub_FC154C body", P1_PROLOGUE_TAIL[0], P1_PROLOGUE_TAIL[1]),
                             ("BT RX ISR head", BT_RX_ISR_HEAD[0], BT_RX_ISR_HEAD[1]),
                             ("BT RX ISR store site", P2_SITE, P2_ORIG),
                             ("generic RX append block", RX_APPEND_BLOCK[0], RX_APPEND_BLOCK[1])):
        got = img(addr, len(exp))
        if got != exp:
            sys.exit("PRECONDITION FAIL %s @%06X\n  expected %s\n  got      %s"
                     % (label, addr, exp.hex().upper(), got.hex().upper()))
        print("input OK   %-26s @%06X (%d bytes)" % (label, addr, len(exp)))

    for name, base, ln in (("cave1", CAVE1, CAVE1_LEN), ("cave2", CAVE2, CAVE2_LEN)):
        got = img(base, ln)
        if got != bytes([NOP]) * ln:
            bad = [i for i, b in enumerate(got) if b != NOP]
            sys.exit("PRECONDITION FAIL %s @%06X is not 0xDE fill (first bad +%d)"
                     % (name, base, bad[0]))
        print("input OK   %-26s @%06X (%d bytes of 0xDE fill)" % (name, base, ln))

    check_donors(img)

    if not args.no_p1:
        print("\nP1 cave1 @%06X (%d bytes, %d bytes of code):" % (CAVE1, CAVE1_LEN, len(c1)))
        for off in range(0, len(c1), 8):
            print("   %06X  %s" % (CAVE1 + off,
                                   " ".join("%02X" % b for b in c1[off:off + 8])))
    if not args.no_p2:
        print("P2 cave2 @%06X (%d bytes, %d bytes of code):" % (CAVE2, CAVE2_LEN, len(c2)))
        for off in range(0, len(c2), 8):
            print("   %06X  %s" % (CAVE2 + off,
                                   " ".join("%02X" % b for b in c2[off:off + 8])))
    print()

    if args.verify_only:
        print("verify-only: input file satisfies every precondition")
        return

    # ---- coverage -----------------------------------------------------
    for label, start, new in patches:
        for off in range(len(new)):
            if addr_index.get(start + off) is None:
                sys.exit("%s: %06X not covered by an S2 record" % (label, start + off))
        print("cover  OK  %-42s @%06X (%d bytes)" % (label, start, len(new)))

    # ---- apply --------------------------------------------------------
    for label, start, new in patches:
        end = start + len(new)
        for li in sorted(rec):
            a, rd = rec[li]
            b = a + len(rd)
            if b <= start or a >= end:
                continue
            lo, hi = max(a, start), min(b, end)
            rd[lo - a:hi - a] = new[lo - start:hi - start]
        print("applied    %-42s @%06X" % (label, start))

    out = []
    for li, l in enumerate(lines):
        if l.startswith("S2") and li in rec:
            a, rd = rec[li]
            out.append(s2_line(a, bytes(rd)))
        else:
            out.append(l)
    with open(args.mot_out, "w") as f:
        f.write("\n".join(out) + "\n")
    print("\nwrote %s (%d regions)" % (args.mot_out, len(patches)))

    # ---- self-check 1: re-parse output, S2 checksums + patched bytes ---
    bad = 0
    amap = {}
    for l in [x.strip() for x in open(args.mot_out, errors="replace")]:
        if l.startswith("S2"):
            cnt, addr, data, chk = parse_s2(l)
            body = ("%02X" % cnt) + ("%06X" % addr) + data.hex().upper()
            s = sum(int(body[i:i + 2], 16) for i in range(0, len(body), 2))
            if (0xFF - (s & 0xFF)) & 0xFF != chk:
                bad += 1
            for i in range(len(data)):
                amap.setdefault(addr + i, data[i])
    if bad:
        sys.exit("self-check FAIL: %d bad S2 checksums" % bad)
    for label, start, new in patches:
        for off in range(len(new)):
            if amap.get(start + off) != new[off]:
                sys.exit("self-check FAIL %s @%06X" % (label, start + off))

    # ---- self-check 2: full decoded-image diff vs input ----------------
    try:
        import srec2bin
    except ImportError:
        sys.exit("self-check FAIL: cannot import scripts/srec2bin.py")
    lo_i, img_i = srec2bin.to_image(srec2bin.parse_srec(args.mot_in))
    lo_o, img_o = srec2bin.to_image(srec2bin.parse_srec(args.mot_out))
    if (lo_i, len(img_i)) != (lo_o, len(img_o)):
        sys.exit("self-check FAIL: image geometry changed")
    diff = [i for i in range(len(img_i)) if img_i[i] != img_o[i]]
    allowed = set()
    for _label, start, new in patches:
        allowed |= set(range(start - lo_i, start - lo_i + len(new)))
    unexpected = [i for i in diff if i not in allowed]
    if unexpected:
        a = unexpected[0] + lo_i
        sys.exit("self-check FAIL: %d changed bytes outside patched ranges, first @%06X"
                 % (len(unexpected), a))
    print("self-check OK: all S2 checksums valid, %d changed bytes, all inside the "
          "%d patched bytes" % (len(diff), len(allowed)))
    ranges = []
    for i in sorted(diff):
        a = i + lo_i
        if ranges and a == ranges[-1][1]:
            ranges[-1][1] = a + 1
        else:
            ranges.append([a, a + 1])
    for a, b in ranges:
        print("   changed %06X..%06X (%d bytes)" % (a, b - 1, b - a))


if __name__ == "__main__":
    main()
