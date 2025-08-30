# LanProbe (refactored)

Рабочая версия после рефакторинга. Сохранена логика детекции, упрощён пример (CLI), вся операционная логика вынесена в ядро. Логи приведены к единому формату.

## Быстрый старт

1. Подготовьте OUI-базы в `data/oui/` (можно положить одновременно несколько источников):
   - `oui.csv` / `oui.txt` (IEEE)
   - `manuf` (Wireshark)
   - `nmap-mac-prefixes` (Nmap)

2. Сборка и запуск:
   ```bash
   dotnet run --project src/LanProbe.Example -- 192.168.31.0/24 --mode debug
   ```

## Режимы запуска

- **debug** — максимально подробные логи, баннеры/сканы протоколируются, сырьё может писаться в `data/raw/`.
- **log** (по умолчанию) — основные артефакты (`out/*`, `logs/*`), без тяжёлых raw.
- **quiet** — минимум артефактов: JSON-итоги и краткая консоль.

Пример:
```bash
dotnet run --project src/LanProbe.Example -- 192.168.31.0/24 --mode log --out out --logs logs --oui data/oui
```

## Что делает сканер

Полный цикл:
1) **Discovery** — поиск «живых» хостов по CIDR (ICMP + ARP, с параллелизмом).
2) **Scan + Banners** — проверка наборов портов и попытка чтения баннеров.
3) **Analyze** — классификация устройства (роутер/ПК/телефон/сервер), эвристики по портам, TTL, заголовкам, OUI.
4) **Export** — выгрузки в JSON/CSV/Markdown.

## Логи

При каждом запуске создаётся папка:
```
logs/
  <timestamp>/
    _common.log            ← общий лог запуска, шагов, итогов
    alive/                 ← логи «живых» IP
      192.168.31.1.log
      192.168.31.40.log
    unreachable/           ← логи «молчаливых» IP (если логируются)
      192.168.31.123.log
```

Правила:
- Всё, что **без IP** (или явно `_common`) — пишется в `logs/<timestamp>/_common.log`.
- Файлы по **конкретным IP** — автоматически отправляются в `alive/` или `unreachable/` через `DebugFileLog.MarkAlive(ip)` / `MarkUnreachable(ip)`.
- Запись строк по IP: `DebugFileLog.WriteLine(ip, "...")` — всегда в соответствующий файл IP.

## Структура директорий проекта

- `src/LanProbe.Core/` — ядро: discovery/scan/banners/analyze/export + общий фасад `LanProbeApp`.
- `src/LanProbe.Example/` — тонкий CLI-пример: только парсер аргументов и `LanProbeApp.RunAsync(cfg)`.
- `out/` — итоги сканирования:
  - `analysis.json`, `analysis.csv`, `analysis.md` (в quiet — минимум, обычно JSON).
  - при необходимости — `facts.json`, `facts.csv`.
- `logs/<timestamp>/` — логи запуска (см. выше).
- `data/oui/` — базы производителей MAC (IEEE/Wireshark/Nmap).
- `data/raw/` — сырьё/дампы в debug-режиме (если включено).

## Совместимость и гарантии

- Сохранена логика детекции роутеров (по web-сигнатурам: CN/Issuer/Server/Title/Redirect) и `router.brand:*`.
- Детекция телефонов: randomized MAC + 0 портов → Phone/Tablet (перебивает простую эвристику TTL=64→Linux).
- TTL понижен в весе (не доминирует).
- OUI-резолвер нормализует префиксы (`88:c3:97` ↔ `88C397`); можно смешивать базы.

## Параметры запуска (CLI)

```
LanProbe.Example <CIDR>
  [--mode debug|log|quiet]
  [--out <dir>]    (по умолчанию: out)
  [--logs <dir>]   (по умолчанию: logs)
  [--oui <dir>]    (по умолчанию: data/oui)
  [--raw <dir>]    (по умолчанию: data/raw; используется в debug)
```

Если нужно — в `RunConfig` доступны таймауты и лимиты конкуренции (см. API.md).
