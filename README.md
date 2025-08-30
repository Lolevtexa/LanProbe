# LanProbe (refactored)

Рабочая версия после рефакторинга. Сохранена логика детекции и повышена однородность логов.

## Быстрый старт

1. Подготовьте OUI-базы в `data/oui/` (можно одновременно положить):
   - `oui.csv` / `oui.txt` (IEEE)
   - `manuf` (Wireshark)
   - `nmap-mac-prefixes` (Nmap)
2. Сборка и запуск:
   ```bash
   dotnet run --project src/LanProbe.Example -- 192.168.31.0/24 --mode debug
   ```

## Режимы запуска

- **debug** — подробные логи и «сырьё» (`facts/*`), баннеры и сканы протоколируются.
- **log** (по умолчанию) — основные артефакты (`out/*`, `logs/*`) без тяжёлых raw.
- **quiet** — минимум артефактов: JSON итога и краткая консоль.

Пример:
```bash
dotnet run --project src/LanProbe.Example -- 192.168.31.0/24 --mode log --out out --logs logs --oui data/oui
```

## Структура директорий

- `out/` — итоги: `analysis.json`, `analysis.csv`, `analysis.md` (в quiet — только JSON).
- `logs/step3/<timestamp>/` — детальные логи анализа (и теперь discovery/scan).
- `data/oui/` — файлы OUI-баз (IEEE/Wireshark/Nmap).
- `data/raw/` — место для «сырых» артефактов (используется в только в debug).

## Что сохранено

- Определение маршрутизаторов по веб-сигнатурам (CN/Issuer/Server/Title/Redirect) и `router.brand:*`.
- Детекция телефонов: randomized MAC + 0 портов → Phone/Tablet (перебивает TTL=64→Linux).
- TTL уменьшен в весе (не доминирует).
- OUI-резолвер объединяет IEEE/Wireshark/Nmap, нормализация префиксов (`88:c3:97` ↔ `88C397`).

## Что изменилось

- Единый логгер `DebugFileLog` для детальных событий (ICMP/ARP/SCAN/BANNER/ANALYZE).
- Режимы запуска: `--mode debug|log|quiet` + параметры путей (`--out`, `--logs`, `--oui`, `--raw`).
- Точка входа упрощена на 3 функции: `DiscoverAliveHosts`, `ScanPortsAndGrabBanners`, `AnalyzeDevices`.

Подробности смотрите в `docs/`.
