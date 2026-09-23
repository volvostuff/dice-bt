#!/usr/bin/env python3
"""Заглушка селектора транспорта: sub_FC230C всегда возвращает 0.

Найдено 22.09.2026 (см. docs/bridge_patch.md и отчёт разбора): обёртки
прикладного хост-канала `sub_FBF81C` (TX) / `sub_FBF852` (RX) выбирают
транспорт по `sub_FC230C()`:

    if (transport() == 1) -> media-буферы (dword_496/dword_49E, rfc_media_init)
    else                  -> bt_at_tx / bt_rx_read   (BT-канал ch0)

То есть при значении 1 весь прикладной трафик уходит в media-путь мимо
Bluetooth, и по BT не проходит ни один байт (рукопожатие Open обезврежено
патчем B). Патч форсирует 0 — приложение начинает работать через BT-канал.

    0xFC230C:  MOV.B byte_23DC, R0L ; RTS      (4 байта)
            -> MOV.B #0, R0L ; RTS ; NOP ; NOP

Донорские байты: `02` = MOV.B #0,R0L (apply_ch05_patch.py, патч B),
`DF` = RTS, `DE` = NOP.
"""
import argparse
import sys

sys.path.insert(0, r"C:\misc\dice\scripts")
from apply_ch05_patch import parse_s2, s2_line  # noqa: E402

ADDR = 0xFC230C
NEW = bytes.fromhex("02dfdede")
DEFAULT_IN = r"C:\misc\dice\dice_5_6_3_ch05_full_115200.mot"
DEFAULT_OUT = r"C:\misc\dice\dice_5_6_3_ch05_sel0_115200.mot"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()

    lines = [l.strip() for l in open(args.inp, errors="replace")]
    rec, index = {}, {}
    for li, l in enumerate(lines):
        if l.startswith("S2"):
            cnt, addr, data, _chk = parse_s2(l)
            rec[li] = [addr, bytearray(data)]
            for i in range(len(data)):
                index.setdefault(addr + i, (li, i))

    for off in range(len(NEW)):
        if index.get(ADDR + off) is None:
            sys.exit("%06X not covered by an S2 record" % (ADDR + off))
    old = bytes(rec[index[ADDR + i][0]][1][index[ADDR + i][1]]
                for i in range(len(NEW)))
    print("0x%06X: %s -> %s" % (ADDR, old.hex(" "), NEW.hex(" ")))
    if args.verify_only:
        print("verify-only: covered, nothing written")
        return

    for i, b in enumerate(NEW):
        li, o = index[ADDR + i]
        rec[li][1][o] = b

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

    bad, amap = 0, {}
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
    for i, b in enumerate(NEW):
        if amap[ADDR + i] != b:
            sys.exit("self-check FAIL at %06X" % (ADDR + i))
    print("self-check OK: selector stubbed, all S2 checksums valid")


if __name__ == "__main__":
    main()
