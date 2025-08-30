using System.Net;
using LanProbe.Core.Analysis;
using LanProbe.Core.Discovery;
using LanProbe.Core.Export;
using LanProbe.Core.Models;
using LanProbe.Core.Scanning;
using LanProbe.Core.Util;
using LanProbe.Core.Net;

namespace LanProbe.Core;

/// <summary>
/// Высокоуровневый фасад: полный цикл сканирования и анализа.
/// </summary>
public static class LanProbeApp
{
    /// <summary>
    /// Запуск полного пайплайна.
    /// </summary>
    public static async Task<int> RunAsync(RunConfig cfg, CancellationToken ct = default)
    {
        DebugFileLog.Init(cfg.LogsDir);
        OuiVendorLookup.LoadAll(cfg.OuiDir);

        Console.WriteLine($"[START] iface=auto cidr={cfg.Cidr} mode={cfg.Mode}");
        DebugFileLog.WriteLine("_common", $"[START] cidr={cfg.Cidr} mode={cfg.Mode}");

        var facts = await DiscoverAliveHosts(cfg, ct);
        Console.WriteLine($"[STEP1] alive={facts.Count}");
        DebugFileLog.WriteLine("_common", $"[STEP1] alive={facts.Count}");

        var enr = await ScanPortsAndGrabBanners(cfg, facts, ct);
        Console.WriteLine($"[STEP2] enriched={enr.Count} (ports+banners)");
        DebugFileLog.WriteLine("_common", $"[STEP2] enriched={enr.Count}");

        var results = AnalyzeDevices(cfg, enr);
        Console.WriteLine($"[STEP3] analyzed={results.Count}");
        DebugFileLog.WriteLine("_common", $"[STEP3] analyzed={results.Count}");

        await ExportAll(cfg, facts, results);
        Console.WriteLine($"[DONE] out={cfg.OutDir}");
        DebugFileLog.WriteLine("_common", $"[DONE] out={cfg.OutDir}");

        return 0;
    }

    /// <summary>
    /// Поиск «живых» хостов по CIDR (ICMP + ARP).
    /// </summary>
    public static async Task<List<DeviceFact>> DiscoverAliveHosts(RunConfig cfg, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var (netIp, prefix) = ParseCidr(cfg.Cidr);
        var ifaceIp = PickInterfaceInSubnet(netIp, prefix) ?? "0.0.0.0";

        var arpEntries = ArpReader.Snapshot(ifaceIp);
        var arpByIp = arpEntries
            .GroupBy(a => a.Ip)
            .ToDictionary(g => g.Key, g => g.First());

        var tasks = new List<Task<DeviceFact>>();
        foreach (var ip in EnumerateSubnet(netIp, prefix))
        {
            tasks.Add(Task.Run(async () =>
            {
                var (ok, bestRtt, ttl, succ) =
                    await Pinger.TryPingMultiAsync(ip, ifaceIp, cfg.PingTimeoutMs, cfg.PingAttempts);

                var arpOk = arpByIp.TryGetValue(ip, out var a);
                var mac = arpOk ? a!.Mac : null;
                string? vendor = null;
                if (mac is not null)
                {
                    if (OuiVendorLookup.TryResolve(mac, out var v, out _, out _, out _))
                        vendor = v;
                }

                if (ok || arpOk) DebugFileLog.MarkAlive(ip);
                else DebugFileLog.MarkUnreachable(ip);

                return new DeviceFact(
                    Timestamp: now,
                    InterfaceIp: ifaceIp,
                    Ip: ip,
                    IcmpOk: ok,
                    RttMs: bestRtt,
                    Ttl: ttl,
                    ArpOk: arpOk,
                    Mac: mac,
                    Vendor: vendor,
                    AliveSource: ok ? "icmp" : (arpOk ? "arp" : "none"),
                    SilentHost: !ok && arpOk,
                    ProxyArp: false,
                    RouteMismatch: false
                );
            }, ct));
        }

        // дождаться всех
        var all = await Task.WhenAll(tasks);
        return all.Where(f => f.IcmpOk || f.ArpOk)
                  .OrderBy(f => IPToUint(f.Ip))
                  .ToList();
    }

    /// <summary>
    /// Скан портов и баннеры для живых хостов.
    /// </summary>
    public static async Task<List<DeviceFact>> ScanPortsAndGrabBanners(
        RunConfig cfg, List<DeviceFact> alive, CancellationToken ct = default)
    {
        Directory.CreateDirectory(cfg.LogsDir);
        if (cfg.Mode == RunMode.Debug) Directory.CreateDirectory(cfg.RawDir);

        var targetPorts = DefaultPorts();
        var enr = new List<DeviceFact>(alive.Count);

        var scanner = new PortScanner(
            ports: targetPorts,
            connectTimeoutMs: cfg.ConnectTimeoutMs,
            perHostConcurrency: cfg.PortScanConcurrency
        );

        var grabber = new BannerGrabber(
            timeoutMs: cfg.BannerTimeoutMs,
            maxBytes: 4096,
            saveRaw: cfg.Mode == RunMode.Debug,
            rawDir: cfg.RawDir
        );

        foreach (var f in alive)
        {
            ct.ThrowIfCancellationRequested();

            var ip = IPAddress.Parse(f.Ip);
            var iface = string.IsNullOrWhiteSpace(f.InterfaceIp) ? null : IPAddress.Parse(f.InterfaceIp);

            var probes = await scanner.ScanAsync(ip, iface, serviceMap: null, ct);
            var openProbes = probes.Where(p => p.Open).ToArray();
            var openPorts = openProbes.Select(p => p.Port).OrderBy(x => x).ToArray();

            PortBanner[] banners = Array.Empty<PortBanner>();
            if (openProbes.Length > 0)
            {
                var grabbed = await grabber.GrabAsync(ip, openProbes, iface, ct);
                banners = grabbed?.ToArray() ?? Array.Empty<PortBanner>();
            }

            // Расширяем fact (портами/баннерами) внутри DeviceFact через «копию с изменениями»
            enr.Add(f with
            {
                OpenPorts = openPorts,
                Banners = banners
            });

            DebugFileLog.WriteLine(f.Ip, $"[SCAN] open=[{string.Join(",", openPorts)}] banners={banners.Length}");
        }

        return enr;
    }

    /// <summary>Финальный анализ устройств.</summary>
    public static List<DeviceAnalysisResult> AnalyzeDevices(RunConfig cfg, List<DeviceFact> facts)
    {
        var opts = new AnalysisOptions
        {
            HighRttMs = cfg.HighRttMs,
            NowUtc = DateTime.UtcNow,
            IncludeRawLinks = (cfg.Mode != RunMode.Quiet)
        };
        var results = DeviceAnalyzer.AnalyzeAll(facts, oui: null, options: opts);
        return results;
    }

    /// <summary>Экспорт итогов (JSON/CSV, Markdown для анализа).</summary>
    private static Task ExportAll(RunConfig cfg, List<DeviceFact> facts, List<DeviceAnalysisResult> results)
    {
        Directory.CreateDirectory(cfg.OutDir);

        var jsonFacts = Path.Combine(cfg.OutDir, "facts.json");
        var csvFacts = Path.Combine(cfg.OutDir, "facts.csv");
        JsonExporter.Save(jsonFacts, facts);
        CsvExporter.Save(csvFacts, facts);

        var jsonAnalysis = Path.Combine(cfg.OutDir, "analysis.json");
        var csvAnalysis = Path.Combine(cfg.OutDir, "analysis.csv");
        var mdAnalysis = Path.Combine(cfg.OutDir, "analysis.md");
        AnalysisExport.SaveJson(jsonAnalysis, results);
        AnalysisExport.SaveCsv(csvAnalysis, results);
        AnalysisExport.SaveMarkdown(mdAnalysis, results);

        return Task.CompletedTask;
    }

    // --- Вспомогательные утилиты (минимум зависимостей в примере) ---

    private static (string netIp, int prefix) ParseCidr(string cidr)
    {
        var parts = cidr.Split('/');
        return (parts[0], int.Parse(parts[1]));
    }

    private static IEnumerable<string> EnumerateSubnet(string netIp, int prefix)
    {
        var baseBytes = IPAddress.Parse(netIp).GetAddressBytes();
        uint baseUint = ToUint(baseBytes);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint start = (baseUint & mask);
        uint end = start | ~mask;
        for (uint a = start; a <= end; a++) yield return FromUint(a);
    }

    private static bool InSubnet(string ip, string netIp, int prefix)
    {
        uint a = ToUint(IPAddress.Parse(ip).GetAddressBytes());
        uint b = ToUint(IPAddress.Parse(netIp).GetAddressBytes());
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (a & mask) == (b & mask);
    }

    private static string? PickInterfaceInSubnet(string netIp, int prefix)
    {
        var n = IPAddress.Parse(netIp);
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            var ipProps = ni.GetIPProperties();
            foreach (var ua in ipProps.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                var ifaceIp = ua.Address;
                if (InSubnet(ifaceIp.ToString(), netIp, prefix)) return ifaceIp.ToString();
            }
        }
        return null;
    }

    private static uint IPToUint(string ip) => ToUint(IPAddress.Parse(ip).GetAddressBytes());
    private static uint ToUint(byte[] x) => BitConverter.ToUInt32(x.Reverse().ToArray(), 0);
    private static string FromUint(uint x) => new IPAddress(BitConverter.GetBytes(x).Reverse().ToArray()).ToString();

    private static int[] DefaultPorts() => new[]
    {
        // широкий, но разумный набор по умолчанию
        21,22,23,25,53,80,81,110,135,139,143,161,389,443,445,465,587,631,2222,8000,8008,8080,8081,8123,8181,8443,8888,9000,9090,32400
    };
}
