using LanProbe.Core.Discovery;
using LanProbe.Core.Enrichment;
using LanProbe.Core.Export;
using LanProbe.Core.Models;
using LanProbe.Core.Scanning;
using LanProbe.Core.Analysis;
using LanProbe.Core.Util;
using LanProbe.Core.Net;
using System.Net;
using System.Text;
using System.Linq;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        // === Глобальные параметры: кодировки и UTF-8 консоль ===
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length < 1)
        {
            Console.WriteLine("usage: LanProbe.Example <CIDR> [--mode debug|log|quiet] [--out out] [--logs logs] [--raw data/raw] [--oui data/oui]");
            return 2;
        }

        // === Конфигурация ===
        var cfg = ParseArgs(args);

        // Инициализация каталога логов (внутри будет logs/step3/<timestamp>/...)
        DebugFileLog.Init(cfg.LogsDir);

        // === Стадии ===
        Console.WriteLine($"[START] iface=auto cidr={cfg.Cidr} mode={cfg.Mode}");
        var facts = await DiscoverAliveHosts(cfg);
        Console.WriteLine($"[ALIVE] hosts={facts.Count()}");

        var enriched = await ScanPortsAndGrabBanners(cfg, facts);
        Console.WriteLine($"[ENRICH] enriched={enriched.Count()}");

        var results = AnalyzeDevices(cfg, enriched);
        Console.WriteLine($"[ANALYZE] analyzed={results.Count}");

        // Экспорты (уважают RunMode, но точки выхода централизованы здесь)
        Directory.CreateDirectory(cfg.OutDir);
        AnalysisExport.SaveJson(Path.Combine(cfg.OutDir, "analysis.json"), results);
        if (cfg.Mode != RunMode.Quiet)
        {
            AnalysisExport.SaveCsv(Path.Combine(cfg.OutDir, "analysis.csv"), results);
            AnalysisExport.SaveMarkdown(Path.Combine(cfg.OutDir, "analysis.md"), results);
        }

        Console.WriteLine("[DONE]");
        return 0;
    }

    // === Discover ===
    private static async Task<List<DeviceFact>> DiscoverAliveHosts(RunConfig cfg)
    {
        var ifaceIp = GetLocalInterfaceIpInCidr(cfg.Cidr)
            ?? throw new InvalidOperationException($"Не найден локальный интерфейс в сети {cfg.Cidr}");
        var ips = CidrList(cfg.Cidr).ToList();

        DebugFileLog.WriteLine("", "[ARP] cache not cleared (continue)");
        var arpBefore = ArpReader.Snapshot(ifaceIp);
        DebugFileLog.WriteLine("", $"[ARP0][DEBUG] entries={arpBefore.Count}");

        var pingTasks = new List<Task<(string ip, (bool ok, long bestRttMs, int ttl, int successCount) pr)>>();
        foreach (var ip in ips)
        {
            // Любые строчки до классификации сразу попадут в logs/<ip>/unreachable/<TS>.log
            DebugFileLog.WriteLine(ip, "[DISCOVER] probing...");
            pingTasks.Add(Task.Run(async () =>
            {
                var pr = await Pinger.TryPingMultiAsync(ip, ifaceIp, cfg.PingTimeoutMs, cfg.PingAttempts);
                DebugFileLog.WriteLine(ip, $"[ICMP][DEBUG] attempts={cfg.PingAttempts} timeout={cfg.PingTimeoutMs} ok={pr.ok} rtt={pr.bestRttMs} ttl={pr.ttl}");
                return (ip, pr);
            }));
        }
        await Task.WhenAll(pingTasks);

        var arpAfter = ArpReader.Snapshot(ifaceIp);
        DebugFileLog.WriteLine("", $"[ARP1][DEBUG] entries={arpAfter.Count}");

        var arpMap = arpAfter.ToDictionary(a => a.Ip, a => a.Mac);
        var macLookup = new MacVendorLookup(Path.Combine(cfg.OuiDir, "ouicache.csv"));

        var facts = new List<DeviceFact>();

        foreach (var t in pingTasks)
        {
            var (ip, pr) = t.Result;
            var arpOk = arpMap.TryGetValue(ip, out var mac);

            if (!pr.ok && !arpOk)
            {
                // Так и остаётся в unreachable: не добавляем в facts => не пойдёт в обогащение/анализ
                DebugFileLog.WriteLine(ip, "[DISCOVER] still unreachable (no ICMP & no ARP)");
                continue;
            }

            // С этого момента IP — живой: переносим лог в alive/ и дальше пишем туда
            DebugFileLog.MarkAlive(ip);
            DebugFileLog.WriteLine(ip, $"[DISCOVER] alive via {(pr.ok ? "ICMP" : "ARP")}");

            var vendor = macLookup.Find(mac);
            facts.Add(new DeviceFact(
                Timestamp: DateTime.UtcNow,
                InterfaceIp: ifaceIp,
                Ip: ip,
                IcmpOk: pr.ok,
                RttMs: pr.bestRttMs,
                Ttl: pr.ttl,
                ArpOk: arpOk,
                Mac: mac ?? "",
                Vendor: vendor ?? "",
                AliveSource: pr.ok ? "icmp" : "arp",
                SilentHost: false,
                ProxyArp: false,
                RouteMismatch: false
            ));
        }

        if (cfg.Mode != RunMode.Quiet)
        {
            Directory.CreateDirectory(Path.Combine(cfg.OutDir, "facts"));
            JsonExporter.Save(Path.Combine(cfg.OutDir, "facts", "facts.json"), facts);
            CsvExporter.Save(Path.Combine(cfg.OutDir, "facts", "facts.csv"), facts);
        }

        return facts;
    }

    // === Enrich ===
    private static async Task<List<DeviceFact>> ScanPortsAndGrabBanners(RunConfig cfg, IEnumerable<DeviceFact> facts)
    {
        var alive = facts.Where(f => f.IcmpOk || f.ArpOk).ToList();
        var ports = new[] { 22, 23, 53, 80, 81, 82, 88, 139, 143, 389, 443, 445, 554, 555, 631, 8008, 8080, 8443, 9000, 9090, 49152 };
        var scanner = new PortScanner(ports, cfg.ConnectTimeoutMs, cfg.PortScanConcurrency);
        var grabber = new BannerGrabber(cfg.BannerTimeoutMs);

        var enriched = new List<DeviceFact>();
        foreach (var f in alive)
        {
            var probes = await scanner.ScanAsync(
                System.Net.IPAddress.Parse(f.Ip),
                string.IsNullOrWhiteSpace(f.InterfaceIp) ? null : System.Net.IPAddress.Parse(f.InterfaceIp),
                null,
                CancellationToken.None
            );
            var open = probes.Where(p => p.Open).Select(p => p.Port).ToArray();
            if (open.Length > 0)
                DebugFileLog.WriteLine(f.Ip, $"[SCAN][DEBUG] open={string.Join(',', open)}");

            var bannersList = await grabber.GrabAsync(
                System.Net.IPAddress.Parse(f.Ip),
                probes.Where(p => p.Open),
                string.IsNullOrWhiteSpace(f.InterfaceIp) ? null : System.Net.IPAddress.Parse(f.InterfaceIp),
                CancellationToken.None
            );
            DebugFileLog.WriteLine(f.Ip, $"[BANNER][DEBUG] grabbed={bannersList.Count}");

            var banners = bannersList.ToArray();
            enriched.Add(f with { OpenPorts = open, Banners = banners });
        }

        return enriched;
    }

    // === Analyze ===
    private static List<DeviceAnalysisResult> AnalyzeDevices(RunConfig cfg, IEnumerable<DeviceFact> enriched)
    {
        // Подготовим OUI комбинированный резолвер
        OuiVendorLookup.LoadAll(cfg.OuiDir);

        var opts = new AnalysisOptions
        {
            HighRttMs = cfg.HighRttMs,
            NowUtc = DateTime.UtcNow,
            IncludeRawLinks = (cfg.Mode != RunMode.Quiet)
        };

        var results = DeviceAnalyzer.AnalyzeAll(enriched, new OuiVendorLookupAdapter(), opts);

        return results;
    }

    // === Arg parsing & helpers ===
    private static RunConfig ParseArgs(string[] args)
    {
        var cfg = RunConfig.Default(args[0]);
        string? mode = null;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--mode" && i + 1 < args.Length) mode = args[++i];
            else if (args[i] == "--out" && i + 1 < args.Length) cfg = cfg with { OutDir = args[++i] };
            else if (args[i] == "--logs" && i + 1 < args.Length) cfg = cfg with { LogsDir = args[++i] };
            else if (args[i] == "--raw" && i + 1 < args.Length) cfg = cfg with { RawDir = args[++i] };
            else if (args[i] == "--oui" && i + 1 < args.Length) cfg = cfg with { OuiDir = args[++i] };
        }
        if (!string.IsNullOrWhiteSpace(mode))
        {
            cfg = cfg with
            {
                Mode = mode!.ToLowerInvariant() switch
                {
                    "debug" => RunMode.Debug,
                    "quiet" => RunMode.Quiet,
                    _ => RunMode.Log
                }
            };
        }
        return cfg;
    }

    private static IEnumerable<string> CidrList(string cidr)
    {
        var (net, prefix) = (IPAddress.Parse(cidr.Split('/')[0]), int.Parse(cidr.Split('/')[1]));
        uint ip = BitConverter.ToUInt32(net.GetAddressBytes().Reverse().ToArray(), 0);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint netw = ip & mask;
        uint hostCount = (uint)(1u << (32 - prefix));
        for (uint i = 1; i < hostCount - 1; i++)
            yield return new IPAddress(BitConverter.GetBytes(netw + i).Reverse().ToArray()).ToString();
    }

    private static string? GetLocalInterfaceIpInCidr(string cidr)
    {
        // Простая заглушка: вернуть первый локальный IPv4, совпадающий по сети.
        foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
        {
            if (InCidr(ip.ToString(), cidr)) return ip.ToString();
        }
        return null;
    }

    private static bool InCidr(string ip, string cidr)
    {
        var parts = cidr.Split('/');
        var baseIp = IPAddress.Parse(parts[0]).GetAddressBytes();
        int prefix = int.Parse(parts[1]);
        var ipb = IPAddress.Parse(ip).GetAddressBytes();
        uint a = ToUint(ipb), b = ToUint(baseIp);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (a & mask) == (b & mask);
        static uint ToUint(byte[] x) => BitConverter.ToUInt32(x.Reverse().ToArray(), 0);
    }
}
