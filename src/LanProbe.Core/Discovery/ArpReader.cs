// src/LanProbe.Core/Discovery/ArpReader.cs
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace LanProbe.Core.Discovery;

public record ArpEntry(string InterfaceIp, string Ip, string Mac, string Type);

public static class ArpReader {
    // IP   +   MAC                + тип (одно "слово"): динамический/static и т.п.
    static readonly Regex Line = new(@"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\S+)", RegexOptions.Compiled);

    public static string ResolveArpPath() {
        var sys32 = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\arp.exe");
        return File.Exists(sys32) ? sys32 : "arp";
    }

    // Сырой вывод arp -a -N <ifaceIp> для логов
    public static string RawOutput(string interfaceIp) {
        var p = new Process {
            StartInfo = new ProcessStartInfo {
                FileName = ResolveArpPath(),
                Arguments = $"-a -N {interfaceIp}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                // Кодировка не принципиальна: IP/MAC ASCII; берём UTF8 для стабильности
                StandardOutputEncoding = Encoding.UTF8
            }
        };
        p.Start();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return output;
    }

    // Снимок только для указанного интерфейса — не парсим заголовки вообще
    public static List<ArpEntry> Snapshot(string interfaceIp) {
        var p = new Process {
            StartInfo = new ProcessStartInfo {
                FileName = ResolveArpPath(),
                Arguments = $"-a -N {interfaceIp}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };
        p.Start();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();

        var result = new List<ArpEntry>();
        foreach (var raw in output.Split('\n')) {
            var line = raw.TrimEnd();
            var m = Line.Match(line);
            if (!m.Success) continue;

            var ip  = m.Groups[1].Value;
            var mac = m.Groups[2].Value.ToLowerInvariant();

            // отсеиваем multicast/broadcast
            if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "255.255.255.255") continue;

            result.Add(new ArpEntry(interfaceIp, ip, mac, m.Groups[3].Value.ToLowerInvariant()));
        }
        return result;
    }

    // Очистка + реальная проверка
    public static bool ClearAllAndVerify(string interfaceIp) {
        try {
            var p = new Process {
                StartInfo = new ProcessStartInfo {
                    FileName = ResolveArpPath(),
                    Arguments = "-d *",
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            p.WaitForExit();
        } catch { /* ignore */ }

        // Проверим фактом, а не ExitCode: смотрим снимок на нашем интерфейсе
        var after = Snapshot(interfaceIp);
        // в кэше могут остаться статические (мультикаст), но динамических по нашим хостам быть не должно
        // упростим: если вообще есть строки с обычными IP — считаем, что не очистилось
        return after.Count == 0;
    }
}
