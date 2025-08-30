# API Brief

## Фасад

### `LanProbeApp.RunAsync(RunConfig cfg, CancellationToken ct = default) : Task<int>`
Запускает полный пайплайн:
1) `DiscoverAliveHosts`  
2) `ScanPortsAndGrabBanners`  
3) `AnalyzeDevices`  
4) `ExportAll`  

В процессе инициализируется логгер `DebugFileLog` и загружаются OUI-базы.

---

## Конфигурация

### `RunConfig`
Конфигурация CLI и пайплайна.

Ключевые поля:
- `Cidr : string` — CIDR сети для сканирования (обязателен).
- `Mode : RunMode` — `Debug | Log | Quiet`.
- Пути:
  - `OutDir : string` — каталог итогов.
  - `LogsDir : string` — корень логов (внутри создаётся `logs/<timestamp>`).
  - `OuiDir : string` — каталог с OUI-базами.
  - `RawDir : string` — каталог «сырья» (debug).
- Таймауты / настройки:
  - `PingTimeoutMs : int` — таймаут ICMP (одной попытки).
  - `PingAttempts : int` — число ICMP-попыток на IP.
  - `PingConcurrency : int` — **лимит параллельных ICMP-пингов** (ограничение через `SemaphoreSlim`).
  - `ConnectTimeoutMs : int` — таймаут TCP connect при скане портов.
  - `PortScanConcurrency : int` — конкуренция сканера портов на хост.
  - `BannerTimeoutMs : int` — таймаут чтения баннеров.
  - `HighRttMs : int` — порог «высокой задержки» для анализа.

Инициализация:
- `RunConfig.Default(string cidr)` — заполняет дефолтные значения под указанный CIDR, пути (`out`, `logs`, `data/oui`, `data/raw`) и режим `Log`.

---

## Модели

### `DeviceFact`
Факт о хосте:  
- Сырые признаки: `Ip`, `InterfaceIp`, `IcmpOk`, `RttMs`, `Ttl`, `ArpOk`, `Mac`, `Vendor`, источники (`AliveSource`, `SilentHost`, `ProxyArp`, `RouteMismatch`).  
- После обогащения: `OpenPorts : int[]`, `Banners : PortBanner[]`.

### `DeviceAnalysisResult`
Результат анализа IP:
- `Vendor`, `OpenPorts`, `Services`, `Anomalies`
- `Classification`: `Kind`, `OsGuess`, `Confidence`, `Scores`, `Reasons`, `Alternatives`
- `Summary` — краткая сводка для пользователя.

---

## Основные компоненты

### Discovery
- ICMP-пинг с параллелизмом (ограничение `PingConcurrency`).
- ARP-снимок по интерфейсу.
- Присвоение статуса лога:
  - `DebugFileLog.MarkAlive(ip)` — флаг, что хост «жив» → логи IP идут в `logs/<ts>/alive/`.
  - `DebugFileLog.MarkUnreachable(ip)` — иначе → `logs/<ts>/unreachable/`.

### Scan & Banners
- Скан портов (список по умолчанию покрывает распространённые сервисы: 21, 22, 23, 25, 53, 80, 443, 445, 8080, 8443 и др.).
- Захват баннеров с таймаутом; запись краткой сводки в лог IP:
  - `DebugFileLog.WriteLine(ip, $"[SCAN] open=[...] banners={N}")`.

### Analyze
- Аггрегация фактов → детерминация вида устройства/ПО.
- Использование OUI, TTL (с пониженным весом), портов, HTTP-заголовков/редиректов.
- Поддержка маркировки роутеров по web-сигнатурам и брендам.

### Export
- `JsonExporter.Save(path, IEnumerable<DeviceFact>)`
- `CsvExporter.Save(path, IEnumerable<DeviceFact>)`
- `AnalysisExport.SaveJson/SaveCsv/SaveMarkdown(path, IEnumerable<DeviceAnalysisResult>)`

---

## Логгер

### `DebugFileLog`
- `Init(baseLogsDir)` — создаёт каталог запуска `baseLogsDir/<timestamp>` и готовит `_common.log` в **корне** этой папки.
- `WriteLine(ipOrCommon, line)`:
  - если `ipOrCommon` пустой или `"_common"` → запись в `logs/<timestamp>/_common.log`;
  - иначе запись в файл IP, который уже помечен как `alive`/`unreachable`.
- `MarkAlive(ip)` / `MarkUnreachable(ip)` — переводит файл IP в соответствующую категорию (подкаталог) внутри `logs/<timestamp>/`.

**Гарантия:** все файлы **без IP** сохраняются в корне папки запуска (`logs/<timestamp>`), а IP-специфичные — строго по своим подпапкам.

---

## Использование из CLI (пример)

```bash
dotnet run --project src/LanProbe.Example -- 192.168.31.0/24   --mode debug   --out out   --logs logs   --oui data/oui
```

В процессе:
- `logs/<timestamp>/_common.log` — старт, шаги, итоги.
- `logs/<timestamp>/alive/<ip>.log` — детальные строки по живым IP (порты/баннеры и т.д.).
- `out/analysis.json|csv|md` — результаты анализа.
