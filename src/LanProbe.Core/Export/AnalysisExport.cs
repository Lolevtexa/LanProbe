using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using LanProbe.Core.Analysis;

namespace LanProbe.Core.Export
{
    public static class AnalysisExport
    {
        public static void SaveJson(string path, IEnumerable<DeviceAnalysisResult> results)
        {
            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path, JsonSerializer.Serialize(results, opts));
        }

        public static void SaveCsv(string path, IEnumerable<DeviceAnalysisResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("ip,mac,vendor,ttl,rtt_ms,alive_source,open_ports,kind,os_guess,confidence,risks,anomalies");
            foreach (var r in results)
            {
                var open = string.Join(";", r.OpenPorts);
                var risks = string.Join("|", r.Risks);
                var an = string.Join("|", r.Anomalies);
                sb.AppendLine($"{r.Ip},{r.Mac},{Escape(r.Vendor)},{r.Ttl},{r.RttMs},{r.AliveSource},\"{open}\",{r.Classification.Kind},{r.Classification.OsGuess},{r.Classification.Confidence},{risks},{an}");
            }
            File.WriteAllText(path, sb.ToString());
        }

        public static void SaveMarkdown(string path, IEnumerable<DeviceAnalysisResult> results)
        {
            var list = results.ToList();
            var sb = new StringBuilder();

            sb.AppendLine("# TL;DR\n");
            foreach (var line in BuildTldrLines(list).Take(10)) sb.AppendLine($"- {line}");
            sb.AppendLine();

            sb.AppendLine("## Сервисы по хостам\n");
            foreach (var r in list)
            {
                string vendorOut = r.Vendor ?? "";
                var brand = r.Classification.Reasons
                    .FirstOrDefault(x => x.StartsWith("router.brand:", StringComparison.OrdinalIgnoreCase));
                if (string.IsNullOrWhiteSpace(vendorOut) && brand != null)
                    vendorOut = brand.Substring("router.brand:".Length).Trim();

                sb.AppendLine($"**{r.Ip}** — {r.Classification.Kind} ({r.Classification.OsGuess}), vendor: {vendorOut}\n");

                if (r.Services.Count == 0) { sb.AppendLine(); continue; }
                sb.AppendLine("| Порт | Сервис | Статус | Сервер | Заголовок/Title | Редирект | TLS |");
                sb.AppendLine("|---:|---|---|---|---|---|---|");
                foreach (var s in r.Services)
                {
                    var tls = s.Tls is null ? "" : $"{s.Tls.Version} {(s.Tls.SelfSigned == true ? "self-signed" : "")} {s.Tls.Cn}";
                    sb.AppendLine($"| {s.Port} | {s.Service} | {s.Status} | {Escape(s.Server)} | {Escape(s.Title)} | {Escape(s.RedirectTo)} | {Escape(tls)} |");
                }
                sb.AppendLine();
            }

            sb.AppendLine("## Сигналы безопасности\n");
            sb.AppendLine("| IP | Риски | Аномалии |");
            sb.AppendLine("|---|---|---|");
            foreach (var r in list)
                sb.AppendLine($"| {r.Ip} | {string.Join(", ", r.Risks)} | {string.Join(", ", r.Anomalies)} |");
            sb.AppendLine();

            sb.AppendLine("## Дубликаты контента\n");
            sb.AppendLine("| IP | Порт | Дубликат порта | Хэш |");
            sb.AppendLine("|---|---:|---:|---|");
            foreach (var r in list)
                foreach (var s in r.Services.Where(x => x.DuplicateOfPort is not null && !string.IsNullOrWhiteSpace(x.ContentHash)))
                    sb.AppendLine($"| {r.Ip} | {s.Port} | {s.DuplicateOfPort} | {s.ContentHash} |");
            sb.AppendLine();

            sb.AppendLine("## Карточки устройств\n");
            foreach (var r in list)
            {
                sb.AppendLine($"### {r.Ip} — {r.Classification.Kind} ({r.Classification.OsGuess})\n");
                sb.AppendLine(r.Summary);
                sb.AppendLine();
            }

            File.WriteAllText(path, sb.ToString());
        }

        private static IEnumerable<string> BuildTldrLines(List<DeviceAnalysisResult> list)
        {
            yield return $"Всего узлов: {list.Count}. Рискованных: {list.Count(r => r.Risks.Count > 0)}.";
            var httpExposed = list.Where(r => r.Risks.Contains("http_exposed")).Select(r => r.Ip);
            if (httpExposed.Any()) yield return $"HTTP без HTTPS: {string.Join(", ", httpExposed.Take(5))}{(httpExposed.Count() > 5 ? "…" : "")}";
            var rdp = list.Where(r => r.Risks.Contains("rdp_exposed")).Select(r => r.Ip);
            if (rdp.Any()) yield return $"Открыт RDP: {string.Join(", ", rdp.Take(5))}{(rdp.Count() > 5 ? "…" : "")}";
            var smb = list.Where(r => r.Risks.Contains("smb_exposed")).Select(r => r.Ip);
            if (smb.Any()) yield return $"Открыт SMB: {string.Join(", ", smb.Take(5))}{(smb.Count() > 5 ? "…" : "")}";
            var tlsSelf = list.Where(r => r.Risks.Contains("tls_self_signed")).Select(r => r.Ip);
            if (tlsSelf.Any()) yield return $"Self-signed TLS: {string.Join(", ", tlsSelf.Take(5))}{(tlsSelf.Count() > 5 ? "…" : "")}";
            var soon = list.Where(r => r.Risks.Contains("tls_expiring_soon")).Select(r => r.Ip);
            if (soon.Any()) yield return $"Срок действия TLS скоро истечёт: {string.Join(", ", soon.Take(5))}{(soon.Count() > 5 ? "…" : "")}";
            var highRtt = list.Where(r => r.Anomalies.Contains("high_rtt")).Select(r => r.Ip);
            if (highRtt.Any()) yield return $"Высокий RTT: {string.Join(", ", highRtt.Take(5))}{(highRtt.Count() > 5 ? "…" : "")}";
        }

        private static string Escape(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("|", "\\|").Replace("\n", " ").Replace("\r", " ");
        }
    }
}
