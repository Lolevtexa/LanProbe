using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

using LanProbe.Core.Util;

namespace LanProbe.Core.Net
{
    public static class OuiVendorLookup
    {
        // Префикс -> (Vendor, Source)
        private static readonly Dictionary<string, (string vendor, string src)> _map =
            new(StringComparer.OrdinalIgnoreCase);

        private static bool _loaded = false;
        private static readonly object _lock = new();

        // Инициализация (можно дергать один раз в Program.cs)
        public static void LoadAll(string baseDir = "data/oui")
        {
            if (_loaded) return;
            lock (_lock)
            {
                if (_loaded) return;

                TryLoadIeeeCsv(Path.Combine(baseDir, "oui.csv"));
                TryLoadIeeeTxt(Path.Combine(baseDir, "oui.txt"));
                TryLoadWiresharkManuf(Path.Combine(baseDir, "manuf"));
                TryLoadNmap(Path.Combine(baseDir, "nmap-mac-prefixes"));

                _loaded = true;
            }
        }

        // Главный API
        public static bool TryResolve(string mac, out string vendor, out string source, out bool isRandomized, out string usedPrefix)
        {
            vendor = "";
            source = "";
            usedPrefix = "";

            var norm = NormalizeMac(mac);
            isRandomized = IsLocallyAdministered(norm);

            // Ищем по разным длинам префикса (36/28/24 бит)
            foreach (var p in EnumeratePrefixes(norm))
            {
                if (_map.TryGetValue(p, out var v))
                {
                    vendor = v.vendor;
                    source = v.src;
                    usedPrefix = p;
                    DebugFileLog.WriteLine("", $"[OUI][DEBUG] mac={mac} norm={norm} prefix={p} vendor='{vendor}' src={source} randomized={isRandomized}");
                    return true;
                }
            }

            DebugFileLog.WriteLine("", $"[OUI][DEBUG] mac={mac} norm={norm} prefix=NONE vendor='<none>' randomized={isRandomized}");
            return false;
        }

        // ===== helpers =====

        private static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return "";
            var s = mac.Trim().ToUpperInvariant()
                .Replace("-", "")
                .Replace(":", "")
                .Replace(".", "");
            if (s.Length >= 12) s = s.Substring(0, 12);
            return s;
        }

        private static IEnumerable<string> EnumeratePrefixes(string norm12)
        {
            if (string.IsNullOrEmpty(norm12) || norm12.Length < 6) yield break;
            // 24-bit OUI
            if (norm12.Length >= 6)
                yield return $"{norm12.Substring(0, 6)}";
            // 28/36-bit (Wireshark manuf поддерживает 28/36)
            if (norm12.Length >= 7)
                yield return $"{norm12.Substring(0, 7)}";
            if (norm12.Length >= 9)
                yield return $"{norm12.Substring(0, 9)}";
        }

        private static bool IsLocallyAdministered(string norm12)
        {
            if (norm12.Length < 2) return false;
            // второй младший бит первого октета — локально администрируемый
            byte b = byte.Parse(norm12.Substring(0, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return (b & 0x02) != 0;
        }

        private static void Add(string prefix, string vendor, string src)
        {
            if (string.IsNullOrWhiteSpace(prefix) || string.IsNullOrWhiteSpace(vendor)) return;
            // нормализуем префикс: без разделителей, верхний регистр
            var p = prefix.Trim().ToUpperInvariant().Replace(":", "").Replace("-", "");
            if (p.Length < 6) return;
            var key = p.Substring(0, 6).ToUpperInvariant();
            _map[key] = (vendor.Trim(), src);
        }

        // ==== Loaders ====

        private static void TryLoadIeeeCsv(string path)
        {
            if (!File.Exists(path))
            {
                DebugFileLog.WriteLine("", $"[OUI][LOAD] ieee.csv not found: {path}");
                return;
            }

            int added = 0, skipped = 0, lineNo = 0;
            int idxAssignment = -1, idxOrg = -1, idxRegistry = -1;

            foreach (var raw in File.ReadLines(path))
            {
                lineNo++;
                // Парсим CSV
                var parts = SplitCsv(raw);
                if (parts.Length == 0) { skipped++; continue; }

                // --- Определяем индексы по заголовку (первая непустая строка) ---
                if (lineNo == 1 || (idxAssignment < 0 && parts.Any(p => p.IndexOf("Assignment", StringComparison.OrdinalIgnoreCase) >= 0)))
                {
                    // Попытка определить заголовки (разные варианты имен колонок)
                    idxAssignment = Array.FindIndex(parts, p => p.Equals("Assignment", StringComparison.OrdinalIgnoreCase));
                    if (idxAssignment < 0)
                        idxAssignment = Array.FindIndex(parts, p => p.Replace(" ", "").Equals("Assignment", StringComparison.OrdinalIgnoreCase));

                    idxOrg = Array.FindIndex(parts, p =>
                        p.Equals("OrganizationName", StringComparison.OrdinalIgnoreCase) ||
                        p.Equals("Organization Name", StringComparison.OrdinalIgnoreCase) ||
                        p.Replace(" ", "").Equals("OrganizationName", StringComparison.OrdinalIgnoreCase));

                    idxRegistry = Array.FindIndex(parts, p => p.Equals("Registry", StringComparison.OrdinalIgnoreCase));

                    // Если это точно заголовок — перейти к следующей строке
                    if (idxAssignment >= 0 || idxOrg >= 0 || idxRegistry >= 0)
                        continue;
                }

                // --- Если заголовки не нашли — пробуем «старый» формат: 0=Assignment, 1=OrganizationName ---
                if (idxAssignment < 0) idxAssignment = 0;
                if (idxOrg < 0) idxOrg = Math.Min(1, parts.Length - 1);

                // Без столбца Assignment и Org — пропускаем
                if (idxAssignment >= parts.Length || idxOrg >= parts.Length)
                {
                    skipped++; continue;
                }

                var assignment = (parts[idxAssignment] ?? "").Trim();
                var orgRaw = (parts[idxOrg] ?? "").Trim();

                if (string.IsNullOrWhiteSpace(assignment) || string.IsNullOrWhiteSpace(orgRaw))
                {
                    skipped++; continue;
                }

                // Тип префикса (если есть колонка Registry: "MA-L", "MA-M", "MA-S")
                string registry = "";
                if (idxRegistry >= 0 && idxRegistry < parts.Length)
                    registry = (parts[idxRegistry] ?? "").Trim().ToUpperInvariant();

                // Нормализация префикса: убираем разделители, в верхний регистр
                var p = assignment.Replace("-", "").Replace(":", "").Replace(".", "").ToUpperInvariant();

                // Длина ключа в зависимости от реестра (fallback: 6)
                int needLen = registry switch
                {
                    "MA-S" => 9, // 36-bit
                    "MA-M" => 7, // 28-bit
                    _ => 6  // MA-L или неизвестно — 24-bit
                };

                if (p.Length < 6) { skipped++; continue; }
                if (p.Length < needLen) needLen = 6; // на всякий случай

                var key = p.Substring(0, needLen);
                var vendor = orgRaw;

                Add(key, vendor, "ieee.csv");
                added++;
            }

            DebugFileLog.WriteLine("", $"[OUI][LOAD] ieee.csv loaded: added={added}, skipped={skipped}, file={path}");
        }


        private static void TryLoadIeeeTxt(string path)
        {
            if (!File.Exists(path)) return;
            // строки вида: "FC-BE-75   (hex)        Xiaomi Communications Co Ltd"
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length < 10 || line.StartsWith("#")) continue;
                var idx = line.IndexOf("(hex)", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;
                var asg = line.Substring(0, idx).Trim().Replace("-", "").Replace(":", "");
                var org = line.Substring(idx + 5).Trim();
                if (asg.Length >= 6) Add(asg.Substring(0, 6), org, "ieee.txt");
            }
            DebugFileLog.WriteLine("", $"[OUI][LOAD] ieee.txt loaded");
        }

        private static void TryLoadWiresharkManuf(string path)
        {
            if (!File.Exists(path)) return;
            // Формат:
            // 00:00:00\tXEROX CORPORATION
            // 08:00:2B\tXEROX CORPORATION\tXerox Network Systems
            // 70:B3:D5:12:34:00/28\tSome Vendor
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                var key = parts[0]; // может содержать /28 или /36
                var org = string.Join(" ", parts, 1, parts.Length - 1);

                // уберём маску и разделители
                var slash = key.IndexOf('/');
                if (slash > 0) key = key.Substring(0, slash);
                var p = key.Replace(":", "").Replace("-", "").ToUpperInvariant();
                if (p.Length >= 6) Add(p, org, "manuf");
            }
            DebugFileLog.WriteLine("", $"[OUI][LOAD] wireshark manuf loaded");
        }

        private static void TryLoadNmap(string path)
        {
            if (!File.Exists(path)) return;
            // Формат: FC-BE-75 Xiaomi Communications Co Ltd
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length < 8 || line.StartsWith("#")) continue;
                var sp = line.IndexOf(' ');
                if (sp <= 0) continue;
                var asg = line.Substring(0, sp).Replace("-", "").Replace(":", "");
                var org = line.Substring(sp + 1).Trim();
                if (asg.Length >= 6) Add(asg.Substring(0, 6), org, "nmap");
            }
            DebugFileLog.WriteLine("", $"[OUI][LOAD] nmap-mac-prefixes loaded");
        }

        private static string[] SplitCsv(string line)
        {
            // простой CSV-сплиттер (хватает для IEEE)
            var list = new List<string>();
            bool inQ = false;
            var cur = "";
            foreach (var ch in line)
            {
                if (ch == '\"') { inQ = !inQ; continue; }
                if (ch == ',' && !inQ) { list.Add(cur); cur = ""; continue; }
                cur += ch;
            }
            list.Add(cur);
            return list.ToArray();
        }
    }
}
