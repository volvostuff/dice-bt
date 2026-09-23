# -*- coding: utf-8 -*-
"""Найти в базе dice_5_6_2.mot.i64 код, который собирает USB-серийник.

Запуск в IDA: открыть dice_5_6_2.mot.i64 -> File -> Script file... -> этот файл.
Вывод идёт в Output window (и в консоль, если запускать через idat -S).

Ищем xref-ы на:
  0xFA1386 / 0xFA9EC2  — формат "%s-%06lu@%04lX%08lX" (DiCE-<serial>@<BT-адрес>)
  0xFA00EE / 0xFA129A  — шаблон дескриптора "DiCE-000000@000000000000"

Цель: найти инструкции, которые пишут адрес в эту же переменную/буфер —
чтобы расширить CH05-патч (подставлять реальный адрес модуля 002113014D64).
"""
import idautils
import idc
import idaapi

TARGETS = [0xFA1386, 0xFA9EC2, 0xFA00EE, 0xFA129A]
BEFORE, AFTER = 14, 30


def dump(ea):
    name = idc.get_name(ea) or ""
    print("\n=== 0x%06X  %s" % (ea, name))
    try:
        print("    bytes: " + idc.get_bytes(ea, 40).hex(" "))
    except Exception as exc:                                  # noqa: BLE001
        print("    bytes: <%s>" % exc)
    xrefs = list(idautils.XrefsTo(ea))
    if not xrefs:
        print("    xrefs: none")
    for x in xrefs:
        fn = idc.get_func_name(x.frm) or "?"
        print("    xref from 0x%06X in %s (type %d)" % (x.frm, fn, x.type))
        cur = x.frm
        for _ in range(BEFORE):
            prev = idc.prev_head(cur)
            if prev == idaapi.BADADDR:
                break
            cur = prev
        for _ in range(BEFORE + AFTER):
            line = idc.generate_disasm_line(cur, 0) or ""
            print("      %06X  %s" % (cur, line))
            nxt = idc.next_head(cur)
            if nxt == idaapi.BADADDR:
                break
            cur = nxt


print("### USB serial format/template xrefs ###")
for t in TARGETS:
    dump(t)
print("\n### done ###")
