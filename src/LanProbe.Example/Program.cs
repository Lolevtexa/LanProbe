using LanProbe.Core.Discovery;
using LanProbe.Core.Enrichment;
using LanProbe.Core.Export;
using LanProbe.Core.Models;
using LanProbe.Core.Scanning;
using System.Net;
using System.Text;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length != 1) { Console.WriteLine("usage: LanProbe.Example <CIDR>"); return; }
        string cidr = args[0];

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        Directory.CreateDirectory("data/exports");
        Directory.CreateDirectory("data/logs");

        // ====== Выбор интерфейса в подсети ======
        var localIf = Dns.GetHostEntry(Dns.GetHostName()).AddressList
            .First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && InCidr(a.ToString(), cidr))
            .ToString();
        Console.WriteLine($"[START] iface={localIf} cidr={cidr}");

        // ====== ARP до очистки, очистка, ARP0 снимок ======
        File.WriteAllText("data/logs/arp_before_clear.txt", ArpReader.RawOutput(localIf));
        if (ArpReader.ClearAllAndVerify(localIf))
            Console.WriteLine("[ARP] cache cleared");
        else
            Console.WriteLine("[ARP] cache not cleared (continue)");

        var arp0raw = ArpReader.RawOutput(localIf);
        File.WriteAllText("data/logs/arp0.txt", arp0raw);
        var arp0 = ArpReader.Snapshot(localIf);
        Console.WriteLine($"[ARP0] entries={arp0.Count}");

        // ====== Подготовка IP-адресов ======
        // var ips = CidrList(cidr).Where(ip => ip != localIf).ToList();
        var ips = CidrList(cidr).ToList();

        // ====== Пинги (асинхронная волна) ======
        var results = new Dictionary<string, (bool ok, long bestRttMs, int ttl, int successCount)>();
        var throttler = new SemaphoreSlim(64);
        var tasks = new List<Task>();
        var logStep1 = new StringBuilder();

        foreach (var ip in ips)
        {
            await throttler.WaitAsync();
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var res = await Pinger.TryPingMultiAsync(ip, localIf, timeoutMsPerTry: 1200, attempts: 3, delayBetweenMs: 150);
                    lock (results) results[ip] = res;
                    lock (logStep1) logStep1.AppendLine($"{DateTime.UtcNow:o},{localIf},{ip},{res.ok},{res.bestRttMs},{res.ttl},{res.successCount}");
                }
                finally { throttler.Release(); }
            }));
        }
        await Task.WhenAll(tasks);
        File.WriteAllText("data/logs/step1_ping.csv", "ts,iface,ip,ok,best_rtt_ms,ttl,success_count\n" + logStep1.ToString());

        // ====== ARP1 снимок ======
        await Task.Delay(400);
        var arp1raw = ArpReader.RawOutput(localIf);
        File.WriteAllText("data/logs/arp1.txt", arp1raw);
        var arp1 = ArpReader.Snapshot(localIf);
        Console.WriteLine($"[ARP1] entries={arp1.Count}");

        // ====== Построение DeviceFact только для реально живых ======
        var vendorDb = new MacVendorLookup("data/vendors.csv");

        var facts = new List<DeviceFact>();
        foreach (var ip in ips)
        {
            results.TryGetValue(ip, out var pr);
            var mac = arp1.FirstOrDefault(e => e.Ip == ip)?.Mac;
            bool arpOk = mac != null;
            if (!pr.ok && !arpOk) continue;

            string alive = pr.ok ? "icmp" : (arpOk ? "arp" : "none");
            facts.Add(new DeviceFact(
                Timestamp: DateTime.UtcNow,
                InterfaceIp: localIf,
                Ip: ip,
                IcmpOk: pr.ok,
                RttMs: pr.bestRttMs,
                Ttl: pr.ttl,
                ArpOk: arpOk,
                Mac: mac,
                Vendor: vendorDb.Find(mac),
                AliveSource: alive,
                SilentHost: (!pr.ok && arpOk),
                ProxyArp: false,
                RouteMismatch: (pr.ok && !arpOk)
            ));
        }

        // Базовый экспорт Шага 1 (как было)
        CsvExporter.Save("data/exports/devices.csv", facts);
        JsonExporter.Save("data/exports/devices.json", facts);
        Console.WriteLine($"[STEP1] alive={facts.Count}");

        // ====== ШАГ 2: TCP-порты и баннеры ======
        int[] portsToScan =
        {
            21,22,23,25,53,80,81,82,110,123,135,139,143,161,389,443,445,465,515,554,631,873,
            990,993,995,1433,1723,1883,2049,2181,2376,2377,3000,3128,3306,3389,3478,37777,
            5000,5001,5050,5060,5353,5357,5432,5672,5683,5900,5985,5986,6379,6443,7001,8000,
            8008,8080,8081,8123,8181,8291,8443,8765,8888,9000,9042,9090,9092,9100,9200,9300,
            9443,10000,10443,18080,27017,32400,32443
        };

        var portScanner   = new PortScanner(portsToScan, connectTimeoutMs: 1100, perHostConcurrency: 64);
        var bannerGrabber = new BannerGrabber(timeoutMs: 1800, maxBytes: 24_000);

        IPAddress? bindOnInterface = IPAddress.Parse(localIf);
        var ct = new CancellationTokenSource(TimeSpan.FromMinutes(5)).Token;

        string? ServiceName(int port) => port switch
        {
            22 => "ssh", 80 => "http", 443 => "https", 445 => "smb", 3389 => "rdp",
            8291 => "mikrotik", 9100 => "jetdirect", 631 => "ipp", 554 => "rtsp",
            8080 => "http-alt", 6379 => "redis", 3306 => "mysql", 5432 => "postgres",
            _ => null
        };

        var logStep2 = new StringBuilder();
        logStep2.AppendLine("ts,ip,port,open,connect_ms,service,probe,summary");

        var step2Tasks = facts.Select(async d =>
        {
            var ip = IPAddress.Parse(d.Ip);

            var probes = await portScanner.ScanAsync(ip, bindOnInterface, ServiceName, ct);
            var banners = await bannerGrabber.GrabAsync(ip, probes, bindOnInterface, ct);

            foreach (var pp in probes.Where(x => x.Open))
            {
                var b = banners.FirstOrDefault(x => x.Port == pp.Port);
                var probeName = b?.Probe ?? "fact/open";
                var summary = b?.Summary?.Replace(',', ' ') ?? "open";
                lock (logStep2)
                    logStep2.AppendLine($"{DateTime.UtcNow:o},{d.Ip},{pp.Port},true,{pp.ConnectMs},{pp.ServiceGuess ?? ""},{probeName},{summary}");
            }

            return d with
            {
                OpenPorts = probes.Where(p => p.Open).Select(p => p.Port).OrderBy(p => p).ToArray(),
                Banners   = banners.ToArray()
            };
        });

        var enriched = await Task.WhenAll(step2Tasks);

        await File.WriteAllTextAsync("data/exports/devices.step2.json",
            System.Text.Json.JsonSerializer.Serialize(enriched, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }), ct);

        File.WriteAllText("data/logs/step2_ports.csv", logStep2.ToString());
        Console.WriteLine($"[STEP2] enriched={enriched.Length} (ports+banners)");
        Console.WriteLine("[DONE]");
    }

    // ==== helpers ====
    static IEnumerable<string> CidrList(string cidr)
    {
        var (net, prefix) = (IPAddress.Parse(cidr.Split('/')[0]), int.Parse(cidr.Split('/')[1]));
        uint ip = BitConverter.ToUInt32(net.GetAddressBytes().Reverse().ToArray(), 0);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint netw = ip & mask;
        uint hostCount = (uint)(1u << (32 - prefix));
        for (uint i = 1; i < hostCount - 1; i++)
            yield return new IPAddress(BitConverter.GetBytes(netw + i).Reverse().ToArray()).ToString();
    }

    static bool InCidr(string ip, string cidr)
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
