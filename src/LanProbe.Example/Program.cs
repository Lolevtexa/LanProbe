using LanProbe.Core.Discovery;
using LanProbe.Core.Enrichment;
using LanProbe.Core.Export;
using LanProbe.Core.Models;
using System.Net;
using System.Threading;
using System.Text;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length != 1) { Console.WriteLine("usage: LanProbe.Example <CIDR>"); return; }
        string cidr = args[0];

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        // выбрать локальный интерфейс в подсети
        var localIf = Dns.GetHostEntry(Dns.GetHostName()).AddressList
            .First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                     && InCidr(a.ToString(), cidr)).ToString();

        Directory.CreateDirectory("data/exports");
        Directory.CreateDirectory("data/logs");
        Console.WriteLine($"[IFACE] using local interface: {localIf}");
        Console.WriteLine($"[ARP] exe: {ArpReader.ResolveArpPath()}");

        // Лог до очистки (по нужному интерфейсу)
        File.WriteAllText("data/logs/arp_before_clear.txt", ArpReader.RawOutput(localIf));

        // попытка очистить ARP
        if (ArpReader.ClearAllAndVerify(localIf))
            Console.WriteLine("[OK] ARP cache cleared (verified)");
        else
            Console.WriteLine("[WARN] ARP cache not cleared (entries still present or no rights)");

        // ARP₀ сразу после очистки
        var arp0raw = ArpReader.RawOutput(localIf);
        File.WriteAllText("data/logs/arp0.txt", arp0raw);
        var arp0 = ArpReader.Snapshot(localIf);
        Console.WriteLine($"[ARP0] entries on {localIf}: {arp0.Count}");

        // подготовка набора IP
        var ips = CidrList(cidr).Where(ip => ip != localIf).ToList();

        // асинхронная волна пингов (throttle)
        var results = new Dictionary<string, (bool ok, long rtt, int ttl, int succ)>();
        var throttler = new SemaphoreSlim(64); // параллелизм (под сеть/машину подстрой)
        var tasks = new List<Task>();

        foreach (var ip in ips)
        {
            await throttler.WaitAsync();
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var res = await Pinger.TryPingMultiAsync(ip, localIf, timeoutMsPerTry: 1200, attempts: 3, delayBetweenMs: 150);
                    lock (results) results[ip] = res;
                }
                finally
                {
                    throttler.Release();
                }
            }));
        }
        await Task.WhenAll(tasks);

        // ARP₁ — главный снимок после всех запросов
        await Task.Delay(400);
        var arp1raw = ArpReader.RawOutput(localIf);
        File.WriteAllText("data/logs/arp1.txt", arp1raw);
        var arp1 = ArpReader.Snapshot(localIf);
        Console.WriteLine($"[ARP1] entries on {localIf}: {arp1.Count}");

        // вендор (можно оставить пустой vendors.csv)
        var vendorDb = new MacVendorLookup("data/vendors.csv");

        // сбор фактов
        var facts = new List<DeviceFact>();
        foreach (var ip in ips)
        {
            results.TryGetValue(ip, out var pr);
            var mac = arp1.FirstOrDefault(e => e.Ip == ip)?.Mac;
            bool arpOk = mac != null;

            if (!pr.ok && !arpOk) continue;

            string alive = pr.ok ? "icmp" : (arpOk ? "arp" : "none");

            Console.WriteLine($"[IP] {ip} icmp_ok={pr.ok} rtt={pr.rtt}ms ttl={pr.ttl} arp_ok={arpOk} mac={mac ?? "-"}");

            facts.Add(new DeviceFact(
                Timestamp: DateTime.UtcNow,
                InterfaceIp: localIf,
                Ip: ip,
                IcmpOk: pr.ok,
                RttMs: pr.rtt,
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

        CsvExporter.Save("data/exports/devices.csv", facts);
        JsonExporter.Save("data/exports/devices.json", facts);
        Console.WriteLine("Scan finished (async wave).");
    }

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
