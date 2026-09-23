# FwdlApp / RfcFWDL32: точная последовательность прошивки и попытка оживить MCU (2026-09-22)

Статус: **диагностика выполнена, устройство не отвечает ни на одну RFC-команду**.
Записи/стирания НЕ производились. Нужен аппаратный путь (или донор).

Этот документ **исправляет** таблицу FID в `docs/rfc_bootloader_read.md`
(там FwdlProg=0x78, FwdlErase=0x77 и 2-аргументный `FwdlCS` — неверно).

## 1. Проверенные FID и сигнатуры (`RfcFWDL32.dll` 5.5.3, IDA-база, порт 13339)

| Экспорт | RVA | Сигнатура (x64 fastcall) | FID | Payload |
|---|---|---|---|---|
| `RfcDeviceVersion` | 0x1D00 | `int(u8* maj, u8* min, u8* build)` | 0 | — |
| `RfcVersion` | 0x1DD0 | `int()`; внутри `RfcDeviceVersion`, требует `0x63,2,2` | — | — |
| `RfcMaxSize` | 0x1D80 | `int(u16* out)` | 1 | — |
| `SysReset` | 0x1E60 | `int(u32 magic)` | 2 | 4 B (`0x0BADC0DE`) |
| `SysHardwareVersion` | 0x1FE0 | `int(u8*,u8*,u8*)` | 3 | — |
| `SysFirmwareVersion` | 0x1EB0 | `int(u8*,u8*,u8*,char* name)` | 4 | — |
| `SysFirmwareDisable` | 0x2060 | `int(u32 magic)` | 5 | 4 B (`0x0BADC0DE`) |
| `SysBootloaderVersion` | 0x1F70 | `int(u8*,u8*)` | 6 | — |
| `SysDeviceName` | 0x23A0 | `int(char* name)` | 7 | строка (вход!) |
| `SysUsbProductId` | 0x2410 | `int(u16)` | 8 | 2 B |
| **`FwdlProg`** | 0x20B0 | `int(u32 state)` | **0x77** | 4 B |
| **`FwdlErase`** | 0x2100 | `int(u32 addr)` | **0x79** | 4 B |
| `FwdlLock` | 0x2150 | `int(u32 addr)` | 0x7A | 4 B |
| `FwdlRead` | 0x2200 | `int(u32 addr, u32 len_words, void* buf)` | 0x7B | 8 B |
| `FwdlWrite` | 0x2280 | `int(u32 addr, u32 len_words, void* data)` | 0x7C | 8+2·len |
| `FwdlCS` | 0x21A0 | `int(u32 addr, u32 len_words, u16* out)` | 0x7D | 8 B |

Важные детали, которых нет в старой доке:

* **`FwdlRead`/`FwdlWrite`/`FwdlCS` считают длину в 16-битных СЛОВАХ**:
  `FwdlRead` копирует в буфер `len*2` байт (`lea r8d,[rdi+rdi]` перед `memmove`).
  Для 16 байт данных нужно `len = 8` и буфер ≥16 байт.
* **`FwdlCS` принимает ТРИ аргумента** (`addr`, `len_words`, `&cs`) — сумма
  считается MCU по диапазону `addr..addr+2*len`, а не «от addr до конца».
* `sub_180001C60` (ядро обмена): `0xF8` — устройство не открыто, `0xFF` — кадр
  **отправлен успешно** (синхронный `Write` через vtable, таймаут 5000 мс,
  ошибка записи вернулась бы отдельным кодом) и ответ не пришёл за 30 с,
  `0xFD` — пришёл ответ с другим FID.
  Т.е. 0xFF = «MCU молчит», а не «не смогли записать».
* RFC-кадр: `B5 | len(LE16) | hdr_cs | FID | payload | msg_cs`,
  `hdr_cs = len_lo+len_hi+0x1E`, `msg_cs = 0x69+FID+Σpayload`, len = payload+2.

## 2. Константы prog-mode (из `FwdlApp.exe`, x64, base 0x40000000)

`FwdlApp.exe` — **x64** (`machine=0x8664`, `magic=0x20B`), поэтому строки
адресуются `lea reg,[rip+disp32]`, а не абсолютными 4-байтными ссылками.
Разбор сделан статически: `ndisasm -b64 -o 0x40001000` по `.text`
(`tmp/fwdlapp_xref.py`, `tmp/fwdlapp_imports.py`, `tmp/fwdlapp.asm`).

| Константа | Значение | Где |
|---|---|---|
| `FWDL_STATE_PROG_ENTER` | **1** | `mov edx,1` перед `call [FwdlProg]` @0x400208AE |
| `FWDL_STATE_PROG_EXIT` | **0** | `xor ecx,ecx` перед `call [FwdlProg]` @0x40020C09 |
| `FWDL_MAGIC` (SysReset / SysFirmwareDisable) | **0x0BADC0DE** | `mov ecx,0BADCODEh` @0x40020711/0x4002074B/0x40020C3F |
| `max_write` | **0x800** (2048 B) | `mov edx,0x800` — размер блока `FwdlWrite` |

Обе «state»-константы уходят в один и тот же FID **0x77**
(`FwdlProg(1)` = вход, `FwdlProg(0)` = выход).

## 3. Официальная последовательность (реконструкция рабочей функции FwdlApp)

Сообщения — по строкам `.rdata` 0x4002D5xx..0x4002D9xx:

```
RfcOpen(device)
"Restarting %s"
SysFirmwareDisable(0x0BADC0DE)        # FID 5
SysReset(0x0BADC0DE)                  # FID 2
RfcClose(); Sleep(2000)               # ждём перечисления
RfcQuery()/RfcOpen()
RfcVersion()                          # FID 0, проверка 0x63,2,2
"max_write = 2048"
"Entering prog-mode"
FwdlProg(1)                           # FID 0x77, PROG_ENTER
for a in (0xFA0000,0xFB0000,0xFC0000,0xFD0000,0xFE0000,0xFF0000):
    FwdlErase(a)                      # FID 0x79, таблица @0x40037B60
for off in range(0, total, 0x800):
    FwdlWrite(0xFA0000+off, words, image+off)   # FID 0x7C
"Verifying checksum"
host_cs = 0x6969 + Σ_{word i in 0xFA0008..} (word_i + 1)     # LE-слова
FwdlCS(0xFA0008, (total-8)/2, &cs)    # FID 0x7D
if host_cs != cs -> "Checksum error!"; FwdlProg(0); error
"Finalizing"
FwdlWrite(0xFA0006, 1, &key)          # key = host_cs (16 бит) — ключ образа!
"Exiting prog-mode"
FwdlProg(0)                           # FID 0x77, PROG_EXIT
SysReset(0x0BADC0DE)                  # FID 2
"%s update OK!"
```

Следствия:

* **Стирание — по 64-КБ банкам** (таблица `0xFA0000,0xFB0000,0xFC0000,
  0xFD0000,0xFE0000,0xFF0000`, ровно 6 вызовов `FwdlErase`), т.е. в штатном
  обновлении FwdlApp трогает и boot-банк `0xFF0000`. Поэтому прошивать
  «полным» .mot без данных boot-банка нельзя: erase банка `FF` уничтожит
  загрузчик (в `dice_5_6_3_ch05_full_115200.mot` из банка `FF` есть только
  векторы `0xFFFFDC..0xFFFFFF`, 36 байт).
* Ключ образа лежит в **0xFA0006** (1 слово) и равен контрольной сумме MCU;
  в .mot там `FF FF` (не запрограммировано) — его пишет апдейтер в конце.
  Похоже, именно этот ключ и есть «enable» образа: без валидного ключа
  загрузчик не запускает приложение.
* Диапазон образа `dice_5_6_3_ch05_full_115200.mot`: 0xFA0000..0xFC751C
  (непрерывно, 45 однобайтных дырок — заполнять 0xFF), плюс
  0xFD0000..0xFD0231 (562 B) и 0xFFFFDC..0xFFFFFF (36 B, векторы).

## 4. Что было сделано с устройством (только чтение/сброс, без стираний)

Скрипты: `tmp/rfc_diag.py` (по одной команде на процесс), `tmp/rfc_restart.py`
(повтор официальной последовательности), `tmp/rfc_poll.py`, `tmp/rfc_close_control.py`.

| Вызов | Результат |
|---|---|
| `RfcQuery(0)` | 0, `dice-206751@000000000000` (индекс игнорируется — то же имя для 0..7) |
| `RfcOpen(name)` | 0 (OK) |
| `RfcMaxSize` (FID 1) | **0xFF** (30.0 с) |
| `RfcDeviceVersion` (FID 0) | **0xFF** |
| `SysBootloaderVersion` (FID 6) | **0xFF** |
| `SysHardwareVersion` (FID 3) | **0xFF** |
| `SysFirmwareVersion` (FID 4) | **0xFF** |
| `SysUsbProductId` (FID 8) | **0xFF** |
| `FwdlRead(0xFA0000, 8 слов)` (FID 0x7B) | **0xFF** |
| `FwdlCS(0xFA0000, …)` (FID 0x7D) | **0xFF** |
| **`FwdlProg(1)` (FID 0x77, PROG_ENTER)** | **0xFF** |
| `SysFirmwareDisable(0x0BADC0DE)` (FID 5) | **0xFF** |
| `SysReset(0x0BADC0DE)` (FID 2) | **0xFF** |

Итого 3 «будящих» команды (`FwdlProg(1)`, `SysFirmwareDisable`, `SysReset`) —
ни одна не отвечает. Стираний/записей не было.

## 5. Ловушка DLL (важно для будущих скриптов)

`RfcQuery()` после `RfcClose()` в том же процессе возвращает **247** и пустое
имя, хотя устройство на месте (`RfcOpen(name)` сразу после этого снова даёт 0).
Проверено `tmp/rfc_close_control.py` без единой команды MCU. Т.е. «устройство
пропало из перечисления после SysReset» — **артефакт**, а не признак сброса MCU.

## 6. Вывод

MCU не обслуживает RFC ни на одном FID; USB-устройство при этом перечисляется
и pipe-ы открываются, т.е. USB-периферия жива, а командный цикл/RFC-сервис —
нет. Поскольку ни `FwdlProg(1)` (вход в prog-mode), ни магические
`SysFirmwareDisable/SysReset` не отвечают, программный путь через
`RfcFWDL32.dll` исчерпан: загрузчик не находится в состоянии «жду
prog-enter» — он не отвечает вообще.

Гипотеза, согласующаяся со всеми наблюдениями: `SysFirmwareDisable` (FID 5)
перевёл устройство в персистентное состояние «firmware disabled» (флаг/ключ
образа), в котором RFC-сервис не запускается; питание не помогает, потому что
флаг во флеше/конфиге, а не в RAM. Тогда нужен путь, который этот флаг минует.

Возможные дальнейшие шаги (все — вне «только DLL»):

1. **Калибровка диапазона контрольной суммы на живом адаптере**: вычитать
   ключ `0xFA0006` (2 байта) и подобрать диапазон `0xFA0008..X`, при котором
   `0x6969 + Σ(слово_i + 1)` (LE-слова) совпадает с прочитанным ключом. Это
   снимет последнюю неопределённость перед прошивкой (`tmp/rfc_flash.py
   --cs-end`, по умолчанию 0xFC751D).
2. Аппаратно: Renesas-программатор в boot-mode M32C/85 (UART + CE) — полная
   перезапись флеша, включая область конфига/ключа. Для полного образа нужен
   дамп boot-банка `0xFF0000..0xFFFFFF` (в .mot его нет).
3. Донор: на **живом** DiCE войти в prog-mode и вычитать
   `0xFF0000..0xFFFFFF` (`FwdlRead`, len в словах!) — это закрывает
   «недостающий boot-банк» из `docs/rfc_bootloader_read.md` и даёт образ для
   аппаратного восстановления кирпича.
4. Сравнить USB-дескрипторы (PID/строка) кирпича и живого адаптера: если
   строки совпадают с app-режимом, значит работает именно приложение (а не
   загрузчик).
5. «Слепая» прошивка без ответов (`FwdlProg(1)` → erase → write → key →
   `FwdlProg(0)`) технически возможна (кадры уходят успешно), но
   непроверяема, и при неотвечающем MCU смысла не имеет; решение — за
   человеком, это отдельный риск. `tmp/rfc_flash.py --flash` намеренно
   требует живого отклика (FwdlRead/FwdlCS) и без него ничего не делает.

## 7. Артефакты

* `tmp/rfc_diag.py` — read-only диагностика (одна команда на процесс, rc+время).
* `tmp/rfc_restart.py` — официальная последовательность «Restarting» + проба.
* `tmp/rfc_close_control.py` — контроль артефакта RfcQuery после RfcClose.
* `tmp/rfc_poll.py` — перечисление устройства в цикле.
* `tmp/fwdlapp_scan.py`, `tmp/fwdlapp_xref.py` — строки/rip-xrefs FwdlApp.exe.
* `tmp/fwdlapp_imports.py` — импорты, строки (→ `tmp/fwdlapp_strings.txt`),
  таблица адресов стирания (0x40037B60).
* `tmp/fwdlapp.asm` / `tmp/fwdlapp_fn.txt` — линейный дизасм `.text`
  (ndisasm, base 0x40001000) и разобранная функция обновления.
