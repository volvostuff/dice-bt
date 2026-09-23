# -*- coding: utf-8 -*-
"""Выгрузить из IDA всё, что нужно для патча «мост BT<->USB» и «версия в BT».

Запуск: IDA -> открыть dice_5_6_2.mot.i64 -> File -> Script file... -> этот файл.
Результат: C:\\misc\\dice\\tmp\\ida_bt_usb.txt  (его я прочитаю сам).

Что выгружается:
  * дизассемблер целевых функций BT/USB/RFC + список xref-ов на каждую;
  * xref-ы на ключевые глобалы каналов;
  * список имён функций, в названии которых есть bt/serial/vchan/rfc/usb.
"""
import idautils
import idc
import idaapi

OUT = r"C:\misc\dice\tmp\ida_bt_usb.txt"

FUNCS = [
    0xFB1676,  # bt_rx_read
    0xFB162E,  # bt_at_tx
    0xFB16C8,  # sub_FB16C8
    0xFB16A8,  # sub_FB16A8 (link state, патч E)
    0xFB0DDA,  # bt_at_send
    0xFC148E,  # sub_FC148E (общий TX драйвер)
    0xFB15BE,  # sub_FB15BE (dial)
    0xFC1CE6,  # UART RX ISR
    0xFC1B92,  # RX ring append
    0xFC0FD2,  # uart_port_init
    0xFC131A,  # serial_channel_set_config
    0xFC174A,  # serial_channel_start
    0xFC16F4,  # serial_channel_get_state
    0xFBDE56,  # usb_host_link_init
    0xFBA29C,  # host_vchan_create
    0xFA2C8E,  # RFC state machine
    0xFA2AE2,  # RFC dispatcher
    0xFA2EB1,  # RFC frame build (app)
    0xFBF74D,  # RFC frame build
]

GLOBALS = [
    0x2425,  # ser_chan_bt
    0x2426,  # ser_chan_usb
    0x2427,  # ser_chan_dbg
    0x23C9,  # ser_boot_state
    0x2677,  # channel table base
    0x0414,  # ser_cur_baud
    0x23D6,  # "связь" flag
    0x0446,  # uart_port_base
]

LIMIT = 200          # максимум инструкций на функцию
NAME_FILTER = ("bt", "serial", "vchan", "rfc", "usb", "host", "chan")


def line(ea):
    return "%06X  %s" % (ea, idc.generate_disasm_line(ea, 0) or "")


def dump_func(out, ea):
    start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    end = idc.get_func_attr(ea, idc.FUNCATTR_END)
    name = idc.get_func_name(ea) or idc.get_name(ea) or "?"
    out.append("\n=== FUNC 0x%06X .. 0x%06X  %s" % (
        start if start != idaapi.BADADDR else ea,
        end if end != idaapi.BADADDR else ea, name))
    out.append("-- xrefs to 0x%06X:" % ea)
    xr = list(idautils.XrefsTo(ea))
    if not xr:
        out.append("   (none)")
    for x in xr:
        out.append("   from %06X  %s  (type %d)" % (
            x.frm, idc.get_func_name(x.frm) or "?", x.type))
    if start == idaapi.BADADDR:
        out.append("   (no function at this address)")
        return
    cur, n = start, 0
    while cur < end and n < LIMIT:
        out.append("   " + line(cur))
        cur = idc.next_head(cur)
        if cur == idaapi.BADADDR:
            break
        n += 1
    if n >= LIMIT:
        out.append("   ... (truncated)")


def main():
    out = ["# dump for BT<->USB bridge patch", "# idb: %s" % idc.get_idb_path()]
    for ea in FUNCS:
        dump_func(out, ea)
    out.append("\n\n=== GLOBALS ===")
    for g in GLOBALS:
        out.append("\n--- 0x%06X  %s" % (g, idc.get_name(g) or "?"))
        xr = list(idautils.XrefsTo(g))
        if not xr:
            out.append("   (no xrefs)")
        for x in xr[:80]:
            out.append("   %s  %06X  %s" % (
                "R" if x.iscode == 0 else "X", x.frm,
                idc.get_func_name(x.frm) or idc.get_name(x.frm) or "?"))
    out.append("\n\n=== FUNCTIONS BY NAME ===")
    for ea in idautils.Functions():
        nm = idc.get_func_name(ea) or ""
        low = nm.lower()
        if any(k in low for k in NAME_FILTER):
            out.append("   %06X  %s" % (ea, nm))

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("written %s (%d lines)" % (OUT, len(out)))


main()
