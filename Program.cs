using LanProbe.Discovery;
using LanProbe.Models;
using LanProbe.Net;
using LanProbe.Probes;
using LanProbe.Utils;
using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Text;

// .NET 8/9
Console.OutputEncoding = Encoding.UTF8;

// 1) Определяем основную подсеть (IPv4)
IPAddress? overrideNet = null, overrideMask = null;
if (args.Length == 1 && args[0].Contains('/'))
{
    var parts = args[0].Split('/');
    if (IPAddress.TryParse(parts[0], out var netIp) && int.TryParse(parts[1], out var cidr) && cidr is >=0 and <=32)
    {
        // Построим маску из CIDR
        uint m = cidr == 0 ? 0u : 0xFFFFFFFFu << (32 - cidr);
        var maskBytes = BitConverter.GetBytes(m);
        if (BitConverter.IsLittleEndian) Array.Reverse(maskBytes);
        overrideNet = netIp;
        overrideMask = new IPAddress(maskBytes);
    }
}

var (localIp, mask) = overrideNet is not null && overrideMask is not null
    ? (overrideNet, overrideMask)
    : NetworkInfo.GetPrimaryIPv4();
if (localIp is null || mask is null)
{
    Console.WriteLine("Не удалось определить локальный IPv4 и маску.");
    return;
}
var (network, broadcast) = NetworkInfo.GetSubnet(localIp, mask);
Console.WriteLine($"Скан: {network}/{NetworkInfo.MaskToCidr(mask)} (локальный {localIp})");

// 2) Параллельно запускаем локальные обнаружения: SSDP, NBNS, mDNS
var ssdpFound = new ConcurrentDictionary<string, Dictionary<string, string>>();
var nbnsFound = new ConcurrentDictionary<string, string>(); // IP -> NetBIOS имя
var mdnsFound = new ConcurrentDictionary<string, string>(); // service/type -> details
using var cts = new CancellationTokenSource();

var discoveryTasks = new[]
{
    SsdpDiscovery.QueryAll(ssdpFound, TimeSpan.FromSeconds(3), cts.Token),
    NbnsDiscovery.BroadcastNodeStatus(nbnsFound, TimeSpan.FromSeconds(3), cts.Token),
    MdnsDiscovery.QueryServices(mdnsFound, TimeSpan.FromSeconds(3), cts.Token)
};

// 3) По хостам подсети: ARP + TCP-скан + пробы сервисов
var devices = new ConcurrentDictionary<string, Device>();
var ips = NetworkInfo.EnumerateHosts(network, broadcast).ToArray();
var keyPorts = new[] { 22, 80, 443, 445, 3389, 9100, 23, 21 };
ProgressBar.Start(ips.Length);

using var sem = new SemaphoreSlim(256);
var perHostTasks = ips.Select(async ip =>
{
    await sem.WaitAsync();
    try
    {
        var dev = new Device { Ip = ip.ToString() };

        // TCP-скан «ключевых портов»
        var openPorts = await PortScanner.Scan(ip, keyPorts, TimeSpan.FromMilliseconds(700));
        foreach (var p in openPorts) dev.OpenPorts.Add(p);

        // ARP для MAC
        dev.Mac = Arp.TryGetMac(ip);

        // сервисные пробы
        var probes = new List<Task>();
        if (dev.OpenPorts.Contains(22)) probes.Add(SshProbe.Run(ip, dev));
        if (dev.OpenPorts.Contains(80)) probes.Add(HttpProbe.Run(ip, 80, useTls: false, dev));
        if (dev.OpenPorts.Contains(443)) probes.Add(HttpProbe.Run(ip, 443, useTls: true, dev));
        if (dev.OpenPorts.Contains(3389)) probes.Add(RdpProbe.Run(ip, dev));
        if (dev.OpenPorts.Contains(9100)) probes.Add(PjlProbe.Run(ip, dev));
        await Task.WhenAll(probes);

        // имя из NBNS (если есть)
        if (nbnsFound.TryGetValue(dev.Ip, out var nbName) && string.IsNullOrWhiteSpace(dev.Hostname))
            dev.Hostname = nbName;

        // простые эвристики
        Device.Infer(dev);

        if (dev.HasAnyData)
            devices[dev.Ip] = dev;
    }
    finally
    {
        sem.Release();
        ProgressBar.Tick();
    }
}).ToArray();

await Task.WhenAll(perHostTasks);
await Task.WhenAll(discoveryTasks);
cts.Cancel();

ProgressBar.Finish();

// 4) Вывод
Console.WriteLine("\n=== SSDP найдено ===");
foreach (var (key, headers) in ssdpFound.OrderBy(k => k.Key))
{
    Console.WriteLine($"[{key}]");
    foreach (var h in headers) Console.WriteLine($"  {h.Key}: {h.Value}");
}

Console.WriteLine("\n=== mDNS найдено (типы сервисов) ===");
foreach (var kv in mdnsFound.OrderBy(k => k.Key))
    Console.WriteLine($"{kv.Key} => {kv.Value}");

Console.WriteLine("\n=== Хосты ===");
foreach (var d in devices.Values.OrderBy(d =>
{
    var bytes = IPAddress.Parse(d.Ip).GetAddressBytes();
    return BitConverter.ToInt32(bytes.Reverse().ToArray(), 0);
}))
{
    Console.WriteLine(new string('-', 60));
    Console.WriteLine(d);
}

Console.WriteLine("\nГотово.");
