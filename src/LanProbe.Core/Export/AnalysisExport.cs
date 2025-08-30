using System.Text;
using System.Text.Json;
using LanProbe.Core.Analysis;

namespace LanProbe.Core.Export
{
    /// <summary>
    /// Класс AnalysisExport.
    /// </summary>
    public static class AnalysisExport
    {
        /// <summary>
        /// Метод SaveJson.
        /// </summary>
        /// <param name="path">Параметр path.</param>
        /// <param name="results">Параметр results.</param>
        /// <summary>
        /// Документация для SaveJson.
        /// </summary>
        public static void SaveJson(string path, IEnumerable<DeviceAnalysisResult> results)
        {
            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path, JsonSerializer.Serialize(results, opts));
        }

        /// <summary>
        /// Метод SaveCsv.
        /// </summary>
        /// <param name="path">Параметр path.</param>
        /// <param name="results">Параметр results.</param>
        public static void SaveCsv(string path, IEnumerable<DeviceAnalysisResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("ip,kind,os,confidence,vendor,open_ports,reasons");
            foreach (var r in results)
            {
                var ports = string.Join(";", (r.OpenPorts ?? Array.Empty<int>()).OrderBy(p => p));
                var reasons = string.Join(";", r.Classification.Reasons ?? new List<string>());
                sb.AppendLine($"{r.Ip},{Escape(r.Classification.Kind)},{Escape(r.Classification.OsGuess)},{r.Classification.Confidence:F2},{Escape(r.Vendor)},{ports},{Escape(reasons)}");
            }
            File.WriteAllText(path, sb.ToString());
        }

        /// <summary>
        /// Метод SaveMarkdown.
        /// </summary>
        /// <param name="path">Параметр path.</param>
        /// <param name="results">Параметр results.</param>
        public static void SaveMarkdown(string path, IEnumerable<DeviceAnalysisResult> results)
        {
            var list = results.OrderBy(r => r.Ip, StringComparer.OrdinalIgnoreCase).ToList();
            var sb = new StringBuilder();
            sb.AppendLine("# LanProbe — Итоги анализа");
            sb.AppendLine();
            sb.AppendLine($"Всего устройств: **{list.Count}**");
            sb.AppendLine();

            foreach (var r in list)
            {
                // Вендор: OUI vendor либо fallback на router.brand:* из reasons
                var vendor = r.Vendor;
                if (string.IsNullOrWhiteSpace(vendor))
                {
                    var brand = r.Classification.Reasons?.FirstOrDefault(x => x.StartsWith("router.brand:", StringComparison.OrdinalIgnoreCase));
                    if (!string.IsNullOrWhiteSpace(brand)) vendor = brand.Split(':', 2).Last();
                }

                var ports = (r.OpenPorts ?? Array.Empty<int>()).OrderBy(p => p).ToArray();
                sb.AppendLine($"## {r.Ip} — {r.Classification.Kind} ({r.Classification.OsGuess}){(string.IsNullOrWhiteSpace(vendor) ? "" : $" — {vendor}")}");
                sb.AppendLine();
                if (ports.Length > 0)
                    sb.AppendLine($"Открытые порты: `{string.Join(", ", ports)}`");
                if (r.Classification.Reasons?.Count > 0)
                    sb.AppendLine($"Причины: {string.Join(", ", r.Classification.Reasons)}");
                if (!string.IsNullOrWhiteSpace(r.Summary))
                    sb.AppendLine($"> {r.Summary}");
                sb.AppendLine();
            }

            File.WriteAllText(path, sb.ToString());
        }

        private static string Escape(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("|", "\\|").Replace("\n", " ").Replace("\r", " ");
        }
    }
}
