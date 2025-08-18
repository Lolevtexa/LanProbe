using LanProbe.Models;
using LanProbe.Net;
using LanProbe.Scanning;
using LanProbe.Utils;
using System.Net;

Console.WriteLine("LanProbe Subnet Scanner");

// Варианты запуска:
// 1) без параметров — скан активной локальной подсети;
// 2) CIDR: 192.168.1.0/24 — скан указанной подсети;
// 3) IP + MASK: 192.168.1.0 255.255.255.0 — скан указанной подсети.

IPAddress? ip = null, mask = null;

if (args.Length == 1 && args[0].Contains('/'))
{
    var (ipCidr, mCidr) = LanScanner.ParseCidr(args[0]);
    ip = ipCidr; mask = mCidr;
}
else if (args.Length == 2)
{
    if (!IPAddress.TryParse(args[0], out var ipArg) ||
        !IPAddress.TryParse(args[1], out var maskArg))
    {
        Console.WriteLine("Некорректные аргументы. Примеры:\n" +
            "  dotnet run -- 192.168.1.0/24\n" +
            "  dotnet run -- 192.168.1.0 255.255.255.0");
        return;
    }
    ip = ipArg; mask = maskArg;
}
else if (args.Length == 0)
{
    // ip/mask будут выбраны автоматически по активному интерфейсу
}
else
{
    Console.WriteLine("Использование:\n" +
        "  dotnet run --                (скан активной подсети)\n" +
        "  dotnet run -- 192.168.1.0/24 (скан указанной подсети)\n" +
        "  dotnet run -- 192.168.1.0 255.255.255.0");
    return;
}

// Опции сканирования (можете под себя подкрутить порты/тайм-аут/конкурентность)
var opts = new ScanOptions
{
    Ports = new[] { 22, 80, 443, 3389, 515, 9100 },
    ConnectTimeout = TimeSpan.FromMilliseconds(900),
    MaxConcurrency = 256,
    DoReverseDns = true,
    TryArpMac = true,
    DoIcmpPing = true,
    PingTimeout = TimeSpan.FromMilliseconds(400),
};

var devices = await LanScanner.ScanSubnetAsync(ip, mask, opts);

Console.WriteLine($"Найдено устройств: {devices.Count}");
foreach (var d in devices)
{
    Console.WriteLine(new string('-', 60));
    Console.WriteLine(d);
}

// Сохраняем отчёты рядом с исполняемым файлом
await ReportWriter.WriteJson("devices.json", devices);
await ReportWriter.WriteCsv("devices.csv", devices);
await ReportWriter.WriteText("devices.txt", devices);

Console.WriteLine("Сохранены отчёты: devices.json, devices.csv, devices.txt");
