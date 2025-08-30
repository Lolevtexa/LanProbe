using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Text.Json.Serialization;
using LanProbe.Core.Models;

namespace LanProbe.Core.Analysis
{
    public sealed class AnalysisOptions
    {
        public int HighRttMs { get; init; } = 30;
        public DateTime NowUtc { get; init; } = DateTime.UtcNow;
        public bool IncludeRawLinks { get; init; } = false;
    }

    public interface IOuiVendorLookup
    {
        string? Find(string? mac);
        bool IsLocallyAdministered(string? mac);
    }

    public sealed record TlsEntry(
        string? Version,
        string? CipherSuite,
        string? Cn,
        string[]? San,
        string? Issuer,
        bool? SelfSigned,
        DateTimeOffset? NotBefore,
        DateTimeOffset? NotAfter
    );

    public sealed record ServiceEntry(
        int Port,
        string Service,
        string? Status,
        string? Server,
        string? Title,
        string? Generator,
        string? Charset,
        bool? IsCompressed,
        string? RedirectTo,
        string? ContentHash,
        int? DuplicateOfPort,
        TlsEntry? Tls
    );

    public sealed record DeviceClassification(
        string Kind,
        string OsGuess,
        double Confidence,
        Dictionary<string, double> Scores,
        List<string> Reasons,
        List<(string Kind, double Score)> Alternatives
    );

    public sealed record DeviceAnalysisResult(
        [property: JsonPropertyName("ip")] string Ip,
        [property: JsonPropertyName("mac")] string? Mac,
        [property: JsonPropertyName("vendor")] string? Vendor,
        [property: JsonPropertyName("ttl")] int Ttl,
        [property: JsonPropertyName("rtt_ms")] long RttMs,
        [property: JsonPropertyName("alive_source")] string AliveSource,
        [property: JsonPropertyName("open_ports")] int[] OpenPorts,
        [property: JsonPropertyName("services")] List<ServiceEntry> Services,
        [property: JsonPropertyName("risks")] List<string> Risks,
        [property: JsonPropertyName("anomalies")] List<string> Anomalies,
        [property: JsonPropertyName("classification")] DeviceClassification Classification,
        [property: JsonPropertyName("summary")] string Summary
    );

    public static class DeviceAnalyzer
    {
        static readonly Regex HttpStatusRx = new(@"^\s*HTTP/\d\.\d\s+(\d{3})", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static List<DeviceAnalysisResult> AnalyzeAll(IEnumerable<DeviceFact> facts, IOuiVendorLookup? oui, AnalysisOptions? options = null)
        {
            options ??= new AnalysisOptions();
            return facts.Select(f => AnalyzeDevice(f, oui, options)).ToList();
        }

        public static DeviceAnalysisResult AnalyzeDevice(DeviceFact f, IOuiVendorLookup? oui, AnalysisOptions options)
        {
            // Vendor (берём из facts, либо из локальной OUI-базы; randomized → помечаем)
            string? vendor = f.Vendor;
            if (string.IsNullOrWhiteSpace(vendor)) vendor = oui?.Find(f.Mac);
            if (string.IsNullOrWhiteSpace(vendor) && (oui?.IsLocallyAdministered(f.Mac) == true)) vendor = "(randomized)";

            // Services
            var services = BuildServices(f);

            // Risks & anomalies
            var risks = EvaluateRisks(f, services, options);
            var anomalies = EvaluateAnomalies(f, options);

            // Classification (c объяснениями)
            var (kind, osGuess, conf, scores, reasons, alt) = Classify(f, services, vendor);

            // Summary
            string summary = BuildSummary(f, vendor, kind, osGuess, services, risks, anomalies, reasons);

            return new DeviceAnalysisResult(
                Ip: f.Ip,
                Mac: f.Mac,
                Vendor: vendor,
                Ttl: f.Ttl,
                RttMs: f.RttMs,
                AliveSource: f.AliveSource ?? (f.IcmpOk ? "icmp" : (f.ArpOk ? "arp" : "none")),
                OpenPorts: f.OpenPorts ?? Array.Empty<int>(),
                Services: services,
                Risks: risks,
                Anomalies: anomalies,
                Classification: new DeviceClassification(kind, osGuess, conf, scores, reasons, alt),
                Summary: summary
            );
        }

        private static List<ServiceEntry> BuildServices(DeviceFact f)
        {
            var list = new List<ServiceEntry>();

            // Группы дубликатов по ContentHashSha1
            var hashGroups = (f.Banners ?? Array.Empty<PortBanner>())
                .Where(b => !string.IsNullOrWhiteSpace(b.ContentHashSha1))
                .GroupBy(b => b.ContentHashSha1!)
                .Where(g => g.Count() > 1)
                .ToDictionary(g => g.Key, g => g.Select(b => b.Port).OrderBy(p => p).ToArray());

            foreach (var b in f.Banners ?? Array.Empty<PortBanner>())
            {
                string? status = null, server = null, title = null, generator = null, charset = null;
                bool? isCompressed = null;

                if (b.Http is not null)
                {
                    var h = b.Http;
                    if (!string.IsNullOrWhiteSpace(h.StatusLine))
                    {
                        var m = HttpStatusRx.Match(h.StatusLine!);
                        if (m.Success) status = m.Groups[1].Value;
                    }
                    if (h.Headers is not null && h.Headers.TryGetValue("Server", out var srv)) server = srv;
                    title = h.Title; generator = h.Generator; charset = h.Charset; isCompressed = h.IsCompressed;
                }

                TlsEntry? tls = null;
                if (b.Tls is not null)
                {
                    tls = new TlsEntry(
                        Version: b.Tls.Version,
                        CipherSuite: b.Tls.CipherSuite,
                        Cn: b.Tls.SubjectCN,
                        San: b.Tls.SubjectAltNames,
                        Issuer: b.Tls.Issuer,
                        SelfSigned: b.Tls.SelfSigned,
                        NotBefore: b.Tls.NotBefore,
                        NotAfter: b.Tls.NotAfter
                    );
                }

                int? dupOf = b.DuplicateOfPort;
                if (dupOf is null && !string.IsNullOrWhiteSpace(b.ContentHashSha1) &&
                    hashGroups.TryGetValue(b.ContentHashSha1!, out var ports) && ports.Length > 1)
                {
                    var first = ports.First();
                    dupOf = first == b.Port && ports.Length > 1 ? ports[1] : first;
                }

                list.Add(new ServiceEntry(
                    Port: b.Port,
                    Service: b.Service,
                    Status: status,
                    Server: server,
                    Title: title,
                    Generator: generator,
                    Charset: charset,
                    IsCompressed: isCompressed,
                    RedirectTo: b.RedirectTo,
                    ContentHash: b.ContentHashSha1,
                    DuplicateOfPort: dupOf,
                    Tls: tls
                ));
            }

            // Порты без баннеров
            var withBanner = new HashSet<int>(list.Select(s => s.Port));
            foreach (var p in (f.OpenPorts ?? Array.Empty<int>()))
                if (!withBanner.Contains(p))
                    list.Add(new ServiceEntry(p, "tcp", null, null, null, null, null, null, null, null, null, null));

            return list.OrderBy(s => s.Port).ToList();
        }

        private static List<string> EvaluateRisks(DeviceFact f, List<ServiceEntry> svc, AnalysisOptions options)
        {
            var risks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var open = new HashSet<int>(f.OpenPorts ?? Array.Empty<int>());

            if (open.Contains(445)) risks.Add("smb_exposed");
            if (open.Contains(3389)) risks.Add("rdp_exposed");
            if (open.Contains(5900)) risks.Add("vnc_exposed");
            if (open.Contains(554)) risks.Add("rtsp_exposed");
            if (open.Contains(23)) risks.Add("telnet_exposed");

            // HTTP без редиректа на HTTPS
            bool httpOpen = svc.Any(s => s.Service == "http");
            bool httpsOpen = svc.Any(s => s.Service == "https");
            bool httpRedirects = svc.Where(s => s.Service == "http")
                                    .Any(s => !string.IsNullOrWhiteSpace(s.RedirectTo) &&
                                              s.RedirectTo!.StartsWith("https", StringComparison.OrdinalIgnoreCase));
            if (httpOpen && (!httpsOpen || !httpRedirects)) risks.Add("http_exposed");

            // TLS
            foreach (var s in svc)
            {
                if (s.Tls is null) continue;
                if (s.Tls.SelfSigned == true) risks.Add("tls_self_signed");

                if (s.Tls.NotAfter is DateTimeOffset na)
                {
                    var days = (na - options.NowUtc).TotalDays;
                    if (days < 0) risks.Add("tls_expired");
                    else if (days < 90) risks.Add("tls_expiring_soon");
                }

                var ver = (s.Tls.Version ?? "").ToLowerInvariant();
                if (ver.Contains("1.0") || ver.Contains("1.1")) risks.Add("tls_legacy_version");

                var cs = s.Tls.CipherSuite ?? "";
                if (cs.Contains("RC4", StringComparison.OrdinalIgnoreCase) ||
                    cs.Contains("3DES", StringComparison.OrdinalIgnoreCase) ||
                    cs.Contains("_SHA_", StringComparison.OrdinalIgnoreCase))
                    risks.Add("tls_weak_cipher");
            }

            // Устаревшие web-стеки (очень грубо)
            foreach (var s in svc.Where(x => x.Service is "http" or "https"))
            {
                var server = s.Server ?? "";
                if (server.Contains("Apache/2.2") || server.Contains("nginx/0.") || server.Contains("IIS/6") || server.Contains("IIS/7.0"))
                    risks.Add("web_stack_outdated");
            }

            return risks.OrderBy(x => x).ToList();
        }

        private static List<string> EvaluateAnomalies(DeviceFact f, AnalysisOptions options)
        {
            var anomalies = new List<string>();
            if (f.RttMs > options.HighRttMs) anomalies.Add("high_rtt");
            if (f.SilentHost) anomalies.Add("silent_host");
            if (f.RouteMismatch) anomalies.Add("route_mismatch");
            if (f.ProxyArp) anomalies.Add("proxy_arp");
            return anomalies;
        }

        private static (string kind, string osGuess, double conf,
                       Dictionary<string, double> scores, List<string> reasons, List<(string, double)> alt)
        Classify(DeviceFact f, List<ServiceEntry> svc, string? vendor)
        {
            var reasons = new List<string>();

            double scorePrinter = 0, scoreCamera = 0, scoreRouter = 0, scoreNas = 0,
                   scorePcWin = 0, scorePcUnix = 0, scorePhone = 0, scoreIot = 0;

            var open = new HashSet<int>(f.OpenPorts ?? Array.Empty<int>());

            string bannersText = string.Join(" ",
                svc.Select(s => $"{s.Server} {s.Title} {s.Generator} {s.Tls?.Cn} {s.Tls?.Issuer} {s.RedirectTo}"))
                .ToLowerInvariant();

            string v = vendor?.ToLowerInvariant() ?? "";

            bool HasAny(params int[] ports) => open.Overlaps(ports);
            static bool ContainsAny(string s, params string[] kws) =>
                kws.Any(k => s.Contains(k, StringComparison.OrdinalIgnoreCase));

            // ===== ПОРТЫ =====
            if (HasAny(9100, 515, 631)) { scorePrinter += 1.5; reasons.Add("ports:print(9100/515/631)"); }
            if (HasAny(554) || HasAny(37777) || HasAny(8765)) { scoreCamera += 2.0; reasons.Add("ports:camera(554/37777/8765)"); }
            if (HasAny(53, 23, 8291)) { scoreRouter += 1.2; reasons.Add("ports:router(53/23/8291)"); }
            if (HasAny(5000, 5001, 9000, 32400)) { scoreNas += 2.0; reasons.Add("ports:nas(5000/5001/9000/32400)"); }
            if (HasAny(445, 3389, 5985, 5986)) { scorePcWin += 1.7; reasons.Add("ports:windows(445/3389/5985/5986)"); }
            if (HasAny(22)) { scorePcUnix += 1.0; reasons.Add("port:ssh(22)"); }
            if (HasAny(1883, 5683)) { scoreIot += 1.0; reasons.Add("ports:iot(1883/5683)"); }

            // ===== БАННЕРЫ =====
            if (ContainsAny(bannersText, "jetdirect") || ContainsAny(bannersText, "ipp")) scorePrinter += 1.0;
            if (ContainsAny(bannersText, "hikvision", "dahua", "goahead")) scoreCamera += 1.5;
            if (ContainsAny(bannersText, "routeros", "openwrt", "airmax")) { scoreRouter += 1.5; reasons.Add("banner:routeros/openwrt/airmax"); }
            if (ContainsAny(bannersText, "synology", "qnap")) { scoreNas += 2.0; reasons.Add("banner:synology/qnap"); }

            // ===== VENDOR (OUI) =====
            if (ContainsAny(v, "hp", "hewlett", "brother", "canon", "epson")) scorePrinter += 1.8;
            if (ContainsAny(v, "hikvision", "dahua", "axis")) scoreCamera += 1.5;
            if (ContainsAny(v, "tplink", "tp-link", "mikrotik", "ubiquiti", "uap", "d-link", "zyxel", "xiaomi"))
            { scoreRouter += 2.0; reasons.Add($"vendor:{vendor}"); }
            if (ContainsAny(v, "synology", "qnap", "asustor", "wdc", "western digital")) scoreNas += 1.8;
            if (ContainsAny(v, "microsoft")) scorePcWin += 0.6;

            bool phoneBrand = ContainsAny(v, "apple", "samsung", "xiaomi", "huawei", "honor", "oneplus", "google", "motorola", "oppo", "vivo");

            // ===== TTL → OS =====
            string osGuess = f.Ttl >= 200 ? "Network/Router"
                          : (f.Ttl >= 120 ? "Windows"
                          : (f.Ttl >= 60 ? "Linux/Unix" : "Unknown"));
            reasons.Add($"ttl:{f.Ttl}→{osGuess}");

            if (osGuess == "Windows") scorePcWin += 0.4;
            if (osGuess == "Linux/Unix") scorePcUnix += 0.3;
            if (osGuess == "Network/Router") scoreRouter += 0.8;

            // ===== СИЛЬНЫЕ СИГНАЛЫ РОУТЕРА =====
            bool hasWeb = HasAny(80, 443, 8080);
            bool routerCn = ContainsAny(bannersText, "router.", " router", "miwifi", "routerlogin", "fritz.box");
            bool routerIssuer = ContainsAny(bannersText, "xiaomi", "mikrotik", "ubiquiti", "tplink", "tp-link", "netgear", "zyxel", "asustek", "keenetic");
            bool gwIp = f.Ip.EndsWith(".1", StringComparison.Ordinal) || f.Ip.EndsWith(".254", StringComparison.Ordinal);

            string detectedRouterBrand = "";
            if (hasWeb && RouterBrandCatalog.TryDetect(bannersText, out var rb))
            {
                detectedRouterBrand = rb;
                scoreRouter += 1.8;
                reasons.Add($"router.brand:{rb}");
            }

            if (hasWeb && (routerCn || routerIssuer || gwIp))
            {
                scoreRouter += 3.0;
                if (routerCn) reasons.Add("tls.cn:contains(router|miwifi|routerlogin|fritz.box)");
                if (routerIssuer) reasons.Add("tls.issuer:router-brand");
                if (gwIp) reasons.Add("ip:suspected-gateway(.1/.254)");
            }

            if (!string.IsNullOrEmpty(detectedRouterBrand))
            {
                scorePcUnix -= 0.2;
                scorePcWin -= 0.2;
            }

            // ===== ТЕЛЕФОНЫ =====
            bool randomized = string.Equals(vendor, "(randomized)", StringComparison.OrdinalIgnoreCase);
            bool hasServerish = HasAny(22, 445, 3389, 5432, 3306);

            if ((randomized || phoneBrand) && hasWeb && !hasServerish)
            {
                scorePhone += 1.8;
                reasons.Add(randomized ? "mac:randomized" : "vendor:phone-brand");
            }

            if (randomized && open.Count == 0)
            {
                scorePhone += 3.5;
                scorePcUnix = Math.Max(0, scorePcUnix - 0.3);
                reasons.Add("mac:randomized; no-open-ports");
            }

            if (hasServerish) scorePhone -= 0.6;

            // ===== СВОДКА =====
            var table = new (string kind, double s)[] {
        ("Printer",scorePrinter),("Camera",scoreCamera),("Router",scoreRouter),("NAS",scoreNas),
        ("PC/Windows",scorePcWin),("PC/Unix",scorePcUnix),("Phone/Tablet",scorePhone),("IoT",scoreIot)
    };

            var best = table.OrderByDescending(x => x.s).First();
            double total = table.Sum(x => Math.Max(0, x.s));
            double conf = total > 0 ? Math.Round(Math.Max(0, best.s) / total, 2) : 0.0;

            if (hasWeb && (routerCn || routerIssuer || gwIp || !string.IsNullOrEmpty(detectedRouterBrand)) &&
                scoreRouter >= best.s * 0.9)
            {
                best = ("Router", scoreRouter);
            }

            var alternatives = table.OrderByDescending(x => x.s).Take(3).ToList();

            // ===== ДЕБАГ ВЫВОД =====
            try
            {
                Console.WriteLine($"[STEP3][DEBUG] ip={f.Ip} ttl={f.Ttl} vendor='{vendor}' " +
                                  $"rand={randomized} phoneBrand={phoneBrand} hasWeb={hasWeb} " +
                                  $"routerCn={routerCn} routerIssuer={routerIssuer} gwIp={gwIp} " +
                                  $"detectedBrand='{detectedRouterBrand}' open=[{string.Join(",", open.OrderBy(x => x))}]");

                var scoresStr = string.Join(", ", table.Select(t => $"{t.kind}={Math.Max(0, t.s):0.00}"));
                Console.WriteLine($"[STEP3][DEBUG] ip={f.Ip} scores: {scoresStr}");
                Console.WriteLine($"[STEP3][DEBUG] ip={f.Ip} reasons: {string.Join("; ", reasons)}");
                Console.WriteLine($"[STEP3][DEBUG] ip={f.Ip} => best={best.kind} conf={conf:0.00} " +
                                  $"alt=[{string.Join(", ", alternatives.Select(a => $"{a.kind}:{Math.Max(0, a.s):0.00}"))}]");
            }
            catch { }

            return (best.kind, osGuess, conf,
                    table.ToDictionary(x => x.kind, x => Math.Max(0, x.s)),
                    reasons,
                    alternatives);
        }

        private static string BuildSummary(DeviceFact f, string? vendor, string kind, string osGuess,
                                           List<ServiceEntry> services, List<string> risks,
                                           List<string> anomalies, List<string> reasons)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"{f.Ip} — {kind} ({osGuess})");
            if (!string.IsNullOrWhiteSpace(vendor)) sb.Append($", {vendor}");
            if (services.Count > 0)
            {
                var tops = string.Join(",", services.Select(s => s.Service == "tcp" ? s.Port.ToString() : $"{s.Service}:{s.Port}").Take(4));
                sb.Append($"; ports: {tops}");
            }
            if (risks.Count > 0) sb.Append($"; risks: {string.Join(",", risks)}");
            if (anomalies.Count > 0) sb.Append($"; anomalies: {string.Join(",", anomalies)}");
            if (reasons.Count > 0) sb.Append($"; why: {reasons[0]}");
            return sb.ToString();
        }
    }

    internal static class HashSetExt
    {
        public static bool Overlaps(this HashSet<int> set, IEnumerable<int> other)
        {
            foreach (var x in other) if (set.Contains(x)) return true;
            return false;
        }
    }
}
