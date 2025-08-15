using LanProbe.Discovery;
using LanProbe.Models;
using LanProbe.Net;
using LanProbe.Probes;
using LanProbe.Utils;
using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Net.NetworkInformation;


// .NET 8/9
Console.OutputEncoding = Encoding.UTF8;
var swTotal = Stopwatch.StartNew();

// 1) Определяем основную подсеть (IPv4)
IPAddress? overrideNet = null, overrideMask = null;
if (args.Length == 1 && args[0].Contains('/'))
{
    var parts = args[0].Split('/');
    if (IPAddress.TryParse(parts[0], out var netIp) && int.TryParse(parts[1], out var cidr) && cidr is >= 0 and <= 32)
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
var (ifaceIp, gatewayIp) = NetworkInfo.GetIfaceAndGatewayFor(network, mask);
string? routerMac = gatewayIp != null ? Arp.TryGetMac(gatewayIp) : null;
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
        bool pingOk = false;
        try
        {
            using var p = new Ping();
            var r = await p.SendPingAsync(ip, 500);
            pingOk = (r.Status == IPStatus.Success);
        }
        catch { /* ignore */ }

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

        bool hasMeanAttr = dev.Attr.Any(); // после SSH-фикса сюда не попадут пустяки
        bool hasMacNotRouter = !string.IsNullOrWhiteSpace(dev.Mac) && (routerMac == null || dev.Mac != routerMac);
        bool isGateway = (gatewayIp != null && ip.Equals(gatewayIp));

        bool isRealish = pingOk || hasMacNotRouter || hasMeanAttr || isGateway;

        if (isRealish)
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
swTotal.Stop();

// 4) Вывод
var deviceList = devices.Values.OrderBy(d =>
{
    var bytes = IPAddress.Parse(d.Ip).GetAddressBytes();
    return BitConverter.ToInt32(bytes.Reverse().ToArray(), 0);
}).ToList();

// Имя базы для файлов
string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
string baseName = $"tmp/LanProbe_{NetworkInfo.MaskToCidr(mask)}_{network}_{stamp}"
                    .Replace(":", "-"); // на всякий случай

// Файлы с отчётами
string jsonPath = ReportWriter.WriteJson(deviceList, baseName);
string csvPath = ReportWriter.WriteCsv(deviceList, baseName);
// по желанию: отдельные файлы по SSDP/mDNS (коммент можно убрать)
string ssdpPath = ReportWriter.WriteText(ssdpFound, baseName);
string mdnsPath = ReportWriter.WriteText(mdnsFound, baseName, "mdns");

// ===== КОНСОЛЬ: ТОЛЬКО ОБЩАЯ ИНФОРМАЦИЯ =====
Console.WriteLine();
Console.WriteLine("====== Сводка сканирования ======");
Console.WriteLine($"Подсеть:        {network}/{NetworkInfo.MaskToCidr(mask)}");
Console.WriteLine($"Адресов всего:  {ips.Length}");
Console.WriteLine($"Устройств:      {deviceList.Count}");
Console.WriteLine($"SSDP записей:   {ssdpFound.Count}");
Console.WriteLine($"mDNS записей:   {mdnsFound.Count}");
Console.WriteLine($"Время:          {swTotal.Elapsed:mm\\:ss}");
Console.WriteLine();
Console.WriteLine("Файлы отчёта:");
Console.WriteLine($"  JSON: {jsonPath}");
Console.WriteLine($"  CSV : {csvPath}");
Console.WriteLine($"  SSDP: {ssdpPath}");
Console.WriteLine($"  mDNS: {mdnsPath}");
Console.WriteLine();
Console.WriteLine("Готово.");
