# API Brief

## Core Models

### `DeviceFact`
Базовый факт об устройстве: IP, RTT/TTL, ARP, MAC/Vendor, источники активности. После обогащения содержит `OpenPorts` и `Banners`.

### `DeviceAnalysisResult`
Итоги анализа одного IP: Vendor, OpenPorts, Services, Anomalies, Classification(Kind/OsGuess/Confidence/Scores/Reasons/Alternatives), Summary.

### `RunConfig`
Конфигурация запуска CLI (пути, таймауты, конкуренции, режим).

## Основные методы

- `DeviceAnalyzer.AnalyzeAll(IEnumerable<DeviceFact>, IOuiVendorLookup, AnalysisOptions)` → List<DeviceAnalysisResult>
- `JsonExporter.Save(path, IEnumerable<DeviceFact>)`
- `CsvExporter.Save(path, IEnumerable<DeviceFact>)`
- `AnalysisExport.SaveJson/SaveCsv/SaveMarkdown(path, IEnumerable<DeviceAnalysisResult>)`

## Логгер

- `DebugFileLog.Init(baseLogsDir)` — создаёт `logs/step3/<timestamp>`.
- `DebugFileLog.WriteLine(ip, line)` — пишет строку в файл `<ip>.log`.
