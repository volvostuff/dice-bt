# Имена функций и переменных (применено к IDB)

Имена, вынесенные из проведённого анализа в базы IDA. Основной разбор —
M32C-прошивка `dice_5_6_2.mot` (порт **13345**).

## M32C — `dice_5_6_2.mot.i64` (нанесено, проверено через MCP)

### RFC-протоковый движок (загрузка/чтение прошивки)

| Адрес | Имя | Роль |
|---|---|---|
| `0xFA2AE2` | `rfc_cmd_dispatch` | диспетчер FID → обработчик (в приложении); FID 0..8 и `0x77..0x7F`; вызов `JSRI.A`, таблица `dword_6C8` |
| `0xFA2C8E` | `rfc_rx_fsm` | конечный автомат приёма RFC-кадра; состояние в `rfc_fsm_state` (0..5); `0xB5` SOF, проверка `hdr_cs`, `msg_cs`, приём payload |
| `0xFA2E7E` | `rfc_frame_build` | сборка исходящего RFC-кадра в кольце: `0xB5`, len, `hdr_cs=len+0x1E`, `msg_cs=0x69+FID+Σpayload` |
| `0xFA2F40` | `rfc_frame_send` | обёртка: кладёт FID в `101068h`, вызывает `rfc_frame_build` |
| `0xFA2F56` | `rfc_rx_avail` | `JSR.A unk_FFA2AE` — сколько байт доступно (boot-банк) |
| `0xFA2F5C` | `rfc_tx_byte` | `JSR.A unk_FFA24E` — отправить 1 байт (boot-банк) |
| `0xFA2F6A` | `rfc_rx_avail2` | `JSR.A unk_FFA35A` — доступность/число байтов (boot-банк) |
| `0xFA2F70` | `rfc_rx_byte` | `JSR.A unk_FFA2F2` — прочитать 1 байт (boot-банк) |
| `0xFA2F9C` | `rfc_rx_reset_tail` | сброс хвоста RX при `0xBADC0DE` |

### Обработчики RFC-команд (bootloader, **отсутствующий банк `0xFF9xxx`**)

| Адрес | Имя | Роль |
|---|---|---|
| `0xFF9A0E` | `boot_rfc_verify_wordsum` | 16-битная word-sum (FID 0x7D `FwdlCS`) |
| `0xFFA24E` | `boot_rfc_tx_byte` | физический TX-байт RFC |
| `0xFFA2F2` | `boot_rfc_rx_byte` | физический RX-байт RFC |
| `0xFFA35A` | `boot_rfc_rx_avail` | физическая доступность RX |
| `0xFFA2AE` | `boot_rfc_cmd_stub` | физическая доступность RX (обёртка) |

### Маршрутизация / транспорт / каналы

| Адрес | Имя | Роль |
|---|---|---|
| `0xFBDE88` | `transport_present_detect` | детект присутствия линии по GPIO: `P1.7/P3.5/P1.1` → `tp_prev_*`, маска `tp_en_reg*` |
| `0xFBDE2C` | `vchan_create_entry` | вход в создание виртуального канала |
| `0xFC1B92` | `chan_rx_append` | **выгрузка TX** (имя обманчиво, не приём): байт из TX-кольца канала (`dword_2673`+`word_2679`) → регистр данных UART |
| `0xFC1CE6` | `chan_rx_isr` | наполнение RX-кольца канала из ISR (общий блок 0xFC1E0C..0xFC1E4F для ch2/3; для BT — `sub_FC1E7E`) |
| `0xFC154C` | `chan_tx_write` | **единственный продюсер TX-кольца** любого канала: `chan_tx_write(chan=R0L, &len, data)` |
| `0xFC15F2` | `chan_rx_read` | выборка байтов из RX-кольца канала: `chan_rx_read(chan=R0L, &len, buf)` |
| `0xFC1E7E` | `bt_rx_isr_body` | наполнение RX-кольца канала 0 (BT), абсолютная адресация; вектор 0xFAA1B0 |
| `0xFC1E50` | `bt_tx_empty_isr` | TX-empty ISR канала BT; вектор 0xFAA1AC |

### Переменные (RAM)

| Адрес | Имя | Роль |
|---|---|---|
| `0x0408` | `rfc_rx_head` | текущая позиция в RX-кольце RFC |
| `0x0410` | `rfc_rx_base` | база RX-кольца RFC |
| `0x0AC6` | `rfc_rx_payload_off` | смещение принятого payload |
| `0x0AC8` | `rfc_rx_payload_len` | длина payload |
| `0x0BE5` | `rfc_fsm_state` | состояние RFC-машины (0..5) |
| `0x0BFB` | `rfc_rx_hdr_crc` | ожидаемый `hdr_cs` |
| `0x0BFC` | `rfc_rx_msg_crc` | ожидаемый `msg_cs` |
| `0x2428` | `vchan_table` | таблица виртуальных каналов (J2534) |
| `0x23CD` | `tp_prev_p17` | сохранённое состояние P1.7 |
| `0x263B` | `tp_prev_p11` | сохранённое состояние P1.1 |
| `0x263C` | `tp_prev_p35` | сохранённое состояние P3.5 |
| `0x203`  | `tp_en_reg0` | маска «канал включён» (бит 4) |
| `0x283`  | `tp_en_reg1` | маска «канал включён» (бит 4) |
| `0x2677` | `ser_chan_table` | таблица каналов (шаг `0x63`) |
| `0xFA0006` | `version_patch_reserved` | зарезерв. байт версии (0xFF) |
| `0x100000` | `rfc_rx_ring` | RX-кольцо RFC (RAM, вне IDB — имя не вешается) |

> `rfc_rx_ring` (0x100000) лежит в RAM вне загруженных сегментов, поэтому
> `set_name` не принимается IDA; адрес зафиксирован здесь.

## DLL — `RfcFWDL32.dll` (порт **13346**) — **TODO: база сейчас не поднята**

Имена к нанесению, когда IDB снова доступна (адреса = imagebase 0x180000000):

| Адрес | Имя | Роль |
|---|---|---|
| `0x180001620` | `rfc_build_frame` | сборка RFC-кадра (0xB5/len/hdr_cs/FID/payload/msg_cs) |
| `0x180001C60` | `rfc_send_wait` | отправка + ожидание ответа (event, 30 с); 0=OK, 0xFD=FID, 0xFF=timeout, 0xF8=not open |
| `0x1800025A0` | `rfc_enum_devices` | перечисление устройств SETUPAPI |
| `0x180013410` | `rfc_req_buf` | буфер запроса: `+0=FID`, `+4=arg` |
| `0x180013418` | `rfc_resp_buf` | буфер ответа: `+0=статус`, `+1..=данные` |
| `0x1800133B8` | `rfc_inited` | флаг инициализации (0xF6 при 0) |
| `0x1800133B9` | `rfc_opened` | флаг открытого устройства |
| `0x1800133B0` | `rfc_vtable` | vtable контекста (open `+8`, close `+10h`) |
| `0x180013430` | `rfc_dev_table` | таблица устройств (массив ptr, шаг 8 B) |
| `0x180013420` | `rfc_dev_idx` | индекс перебора устройств |
| `0x180013424` | `rfc_dev_count` | число найденных устройств |

## Экспорты DLL (сигнатуры — см. `rfc_bootloader_read.md`)

`RfcOpen`, `RfcClose`, `RfcQuery`, `RfcMaxSize`, `RfcVersion`,
`RfcDeviceVersion`, `SysBootloaderVersion`, `SysFirmwareVersion`,
`SysHardwareVersion`, `SysDeviceName`, `SysFirmwareDisable`, `SysReset`,
`SysUsbProductId`, `FwdlErase`, `FwdlLock`, `FwdlProg`, `FwdlCS`,
`FwdlRead`, `FwdlWrite`, `FwdlReadE2`, `FwdlWriteE2` — имена экспортов
уже осмысленны; дополнительно именованы только внутренние субфункции
из таблицы выше.
