// File: LanProbe/Scanning/LanScanner.cs
//
// Назначение: высокоуровневый сканер подсети. Перебирает адреса в сети,
// проверяет «живость» (ICMP), сканирует TCP-порты, выполняет пробы (SSH/RDP/HTTP/PJL),
// делает reverse DNS и пытается извлечь как можно больше сведений об устройстве.
//
// Использование в примере:
//   var devices = await LanScanner.ScanSubnetAsync();                       // активная подсеть
//   var devices = await LanScanner.ScanSubnetAsync("192.168.1.0/24");       // по CIDR
//   var devices = await LanScanner.ScanSubnetAsync(ip, mask, options, ct);  // ip+mask напрямую
//
// Требует существующие классы/методы библиотеки:
//   - LanProbe.Net.NetworkInfo (GetPrimaryIPv4, GetSubnet, EnumerateHosts)
//   - LanProbe.Net.PortScanner.Scan(IPAddress, IEnumerable<int>, TimeSpan)
//   - LanProbe.Net.Arp.TryGetMac(IPAddress)
//   - LanProbe.Probes.SshProbe.Run(IPAddress, Device)
//   - LanProbe.Probes.RdpProbe.Run(IPAddress, Device)
//   - LanProbe.Probes.HttpProbe.Run(IPAddress, int port, bool useTls, Device)
//   - LanProbe.Probes.PjlProbe.Run(IPAddress, Device)
//   - LanProbe.Models.Device (+ Device.Infer)
//
// Примечания по безопасности/правам:
//   - ICMP Ping обычно работает без повышенных прав в Windows.
//   - ARP работает для L2 соседей в вашей локальной сети (Windows).
//   - Для больших подсетей стоит аккуратно настраивать MaxConcurrency и таймауты.

using LanProbe.Models;
using LanProbe.Net;
using LanProbe.Probes;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace LanProbe.Scanning;

/// <summary>
/// Настройки сканирования подсети.
/// </summary>
public sealed class ScanOptions
{
    /// <summary>Список TCP-портов для проверки.</summary>
    public int[] Ports { get; init; } = new[] { 22, 80, 443, 3389, 515, 9100 };

    /// <summary>Таймаут TCP-подключения для проверки порта.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromMilliseconds(900);

    /// <summary>Максимальное число параллельных проверок хостов.</summary>
    public int MaxConcurrency { get; init; } = 256;

    /// <summary>Выполнять ли reverse DNS (PTR-запрос)?</summary>
    public bool DoReverseDns { get; init; } = true;

    /// <summary>Пытаться ли получить MAC через ARP (Windows, соседи L2)?</summary>
    public bool TryArpMac { get; init; } = true;

    /// <summary>Выполнять ли ICMP-пинг перед/во время проверки?</summary>
    public bool DoIcmpPing { get; init; } = true;

    /// <summary>Таймаут ICMP-пинга.</summary>
    public TimeSpan PingTimeout { get; init; } = TimeSpan.FromMilliseconds(400);

    /// <summary>Пробовать ли HTTPS на 443 в дополнение к HTTP на 80.</summary>
    public bool ProbeHttpTlsOn443 { get; init; } = true;

    /// <summary>
    /// Считать ли reverse DNS достаточным основанием, чтобы «включить»
    /// устройство в отчёт? По умолчанию — нет (иначе возможен «шум» из синтетических PTR).
    /// </summary>
    public bool IncludeHostsWithOnlyReverseDns { get; init; } = false;
}

/// <summary>
/// Высокоуровневый сканер подсети: определяет «живые» хосты и собирает о них сведения.
/// </summary>
public static class LanScanner
{
    /// <summary>
    /// Сканирует активную локальную подсеть (определяется по первичному IPv4 интерфейсу ОС).
    /// </summary>
    public static Task<List<Device>> ScanSubnetAsync(ScanOptions? opts = null, CancellationToken ct = default)
    {
        var (ip, mask) = NetworkInfo.GetPrimaryIPv4();
        if (ip is null || mask is null)
            throw new InvalidOperationException("Не удалось определить активный IPv4 интерфейс и/или маску.");
        return ScanSubnetAsync(ip, mask, opts, ct);
    }

    /// <summary>
    /// Сканирует подсеть, заданную строкой CIDR (например, "192.168.1.0/24").
    /// </summary>
    public static Task<List<Device>> ScanSubnetAsync(string cidr, ScanOptions? opts = null, CancellationToken ct = default)
    {
        var (ip, mask) = ParseCidr(cidr);
        return ScanSubnetAsync(ip, mask, opts, ct);
    }

    /// <summary>
    /// Сканирует подсеть, заданную IP-адресом и маской.
    /// </summary>
    public static async Task<List<Device>> ScanSubnetAsync(IPAddress ip, IPAddress mask, ScanOptions? opts = null, CancellationToken ct = default)
    {
        opts ??= new ScanOptions();

        // Подсеть и список хостов
        var (network, broadcast) = NetworkInfo.GetSubnet(ip, mask);
        var hosts = NetworkInfo.EnumerateHosts(network, broadcast).ToArray();

        var devices = new ConcurrentDictionary<string, Device>();
        using var sem = new SemaphoreSlim(opts.MaxConcurrency);
        var tasks = new List<Task>(hosts.Length);

        foreach (var host in hosts)
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var dev = new Device { Ip = host.ToString() };

                    // 1) ICMP-пинг (быстрый индикатор «живости»)
                    bool aliveByPing = false;
                    if (opts.DoIcmpPing)
                    {
                        try
                        {
                            using var ping = new Ping();
                            var reply = await ping.SendPingAsync(host, (int)opts.PingTimeout.TotalMilliseconds);
                            aliveByPing = reply.Status == IPStatus.Success;
                            if (aliveByPing)
                                dev.Attr["Alive"] = "ICMP";
                        }
                        catch
                        {
                            // Игнорируем ICMP-ошибки (не все хосты разрешают/прокидывают ICMP).
                        }
                    }

                    // 2) ARP-MAC (Windows, соседи L2)
                    if (opts.TryArpMac)
                    {
                        try
                        {
                            dev.Mac = Arp.TryGetMac(host);
                        }
                        catch
                        {
                            // Игнорируем ошибки ARP
                        }
                    }

                    // 3) reverse DNS (PTR)
                    if (opts.DoReverseDns)
                    {
                        try
                        {
                            var he = await Dns.GetHostEntryAsync(host);
                            if (!string.IsNullOrWhiteSpace(he.HostName))
                                dev.Hostname = he.HostName;
                        }
                        catch
                        {
                            // Нет PTR или недоступен DNS — не критично
                        }
                    }

                    // 4) TCP-порты
                    var openPorts = await PortScanner.Scan(host, opts.Ports, opts.ConnectTimeout);
                    foreach (var p in openPorts) dev.OpenPorts.Add(p);

                    // 5) Пробы по доступным службам (SSH/RDP/HTTP/PJL)
                    if (dev.OpenPorts.Contains(22))
                    {
                        try { await SshProbe.Run(host, dev); } catch { /* ignore */ }
                    }

                    if (dev.OpenPorts.Contains(3389))
                    {
                        try { await RdpProbe.Run(host, dev); } catch { /* ignore */ }
                    }

                    if (dev.OpenPorts.Contains(80))
                    {
                        try { await HttpProbe.Run(host, 80, useTls: false, dev); } catch { /* ignore */ }
                    }

                    if (opts.ProbeHttpTlsOn443 && dev.OpenPorts.Contains(443))
                    {
                        try { await HttpProbe.Run(host, 443, useTls: true, dev); } catch { /* ignore */ }
                    }

                    if (dev.OpenPorts.Contains(9100) || dev.OpenPorts.Contains(515))
                    {
                        try { await PjlProbe.Run(host, dev); } catch { /* ignore */ }
                    }

                    // 6) Выводы об ОС/типе
                    Device.Infer(dev);

                    // 7) Критерий включения устройства в результаты:
                    //    - открыт хотя бы один порт ИЛИ
                    //    - есть MAC (сосед L2) ИЛИ
                    //    - помечен Alive (ICMP) ИЛИ
                    //    - есть диагностические атрибуты от проб.
                    //    reverse DNS сам по себе, как правило, НЕ включаем, чтобы не шуметь.
                    bool include =
                        dev.OpenPorts.Count > 0 ||
                        !string.IsNullOrWhiteSpace(dev.Mac) ||
                        dev.Attr.Count > 0 ||
                        (opts.IncludeHostsWithOnlyReverseDns && !string.IsNullOrWhiteSpace(dev.Hostname));

                    if (include)
                        devices[dev.Ip] = dev;
                }
                catch
                {
                    // Игнорируем ошибки одного хоста, продолжаем скан
                }
                finally
                {
                    sem.Release();
                }
            }, ct));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return devices.Values.OrderBy(d => d.Ip).ToList();
    }

    /// <summary>
    /// Разбирает CIDR вида "A.B.C.D/nn" и возвращает (ip, mask).
    /// </summary>
    public static (IPAddress ip, IPAddress mask) ParseCidr(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2)
            throw new FormatException("Ожидался формат CIDR: A.B.C.D/nn");

        if (!IPAddress.TryParse(parts[0], out var ip))
            throw new FormatException("Некорректный IP-адрес.");

        if (!int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32)
            throw new FormatException("Некорректный префикс маски.");

        var maskBytes = new byte[4];
        for (int i = 0; i < prefix; i++)
            maskBytes[i / 8] |= (byte)(0x80 >> (i % 8));

        return (ip, new IPAddress(maskBytes));
    }
}
