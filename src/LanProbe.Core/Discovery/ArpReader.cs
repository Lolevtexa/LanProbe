using System.Diagnostics;
using System.Text.RegularExpressions;

namespace LanProbe.Core.Discovery;

public record ArpEntry(string InterfaceIp, string Ip, string Mac, string Type);

public static class ArpReader
{
    static readonly Regex Line = new(@"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]+)\s+(\S+)", RegexOptions.IgnoreCase);

    public static bool ClearAll() {
        try {
            var p = new Process {
                StartInfo = new ProcessStartInfo {
                    FileName = "arp",
                    Arguments = "-d *",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            string outp = p.StandardOutput.ReadToEnd();
            string errp = p.StandardError.ReadToEnd();
            p.WaitForExit();

            // ExitCode==0 обычно значит "успех"
            return p.ExitCode == 0;
        }
        catch {
            return false;
        }
    }

    public static List<ArpEntry> Snapshot()
    {
        var p = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "arp",
                Arguments = "-a",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };
        p.Start();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();

        var result = new List<ArpEntry>();
        string? currentIf = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.StartsWith("Интерфейс:") || line.StartsWith("Interface:"))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                currentIf = parts.Length > 1 ? parts[1] : null;
                continue;
            }
            var m = Line.Match(line);
            if (m.Success && currentIf != null)
            {
                var ip = m.Groups[1].Value;
                var mac = m.Groups[2].Value.ToLowerInvariant();
                if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "255.255.255.255") continue;
                result.Add(new ArpEntry(currentIf, ip, mac, m.Groups[3].Value.ToLowerInvariant()));
            }
        }
        return result;
    }

    public static string? FindMac(List<ArpEntry> table, string ip, string iface)
        => table.FirstOrDefault(e => e.Ip == ip && e.InterfaceIp == iface)?.Mac;
}
