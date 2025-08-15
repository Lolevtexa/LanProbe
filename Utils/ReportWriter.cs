using LanProbe.Models;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LanProbe.Utils;

public static class ReportWriter
{
    public static string WriteJson(IEnumerable<Device> devices, string baseName)
    {
        var path = $"{baseName}.json";
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true
        };
        // Подготовим «плоскую» модель для удобства чтения
        var data = devices.Select(d => new
        {
            d.Ip,
            d.Mac,
            d.Hostname,
            d.OsHint,
            d.TypeHint,
            OpenPorts = d.OpenPorts.OrderBy(p => p).ToArray(),
            Attributes = d.Attr
        });
        File.WriteAllText(path, JsonSerializer.Serialize(data, opts), Encoding.UTF8);
        return Path.GetFullPath(path);
    }

    public static string WriteCsv(IEnumerable<Device> devices, string baseName)
    {
        var path = $"{baseName}.csv";
        var sb = new StringBuilder();
        sb.AppendLine("IP,MAC,Hostname,OS,Type,Ports,Attributes");

        foreach (var d in devices)
        {
            string ports = string.Join(";", d.OpenPorts.OrderBy(p => p));
            // key=value;key2=value2
            string attrs = string.Join(";", d.Attr.OrderBy(k => k.Key)
                .Select(kv => $"{kv.Key}={Sanitize(kv.Value)}"));

            sb.AppendLine(string.Join(",",
                Csv(d.Ip),
                Csv(d.Mac),
                Csv(d.Hostname),
                Csv(d.OsHint),
                Csv(d.TypeHint),
                Csv(ports),
                Csv(attrs)
            ));
        }

        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        return Path.GetFullPath(path);
    }

    public static string WriteText(IDictionary<string, Dictionary<string,string>> ssdp, string baseName)
    {
        var path = $"{baseName}-ssdp.txt";
        var sb = new StringBuilder();
        foreach (var kv in ssdp.OrderBy(k => k.Key))
        {
            sb.AppendLine($"[{kv.Key}]");
            foreach (var h in kv.Value) sb.AppendLine($"  {h.Key}: {h.Value}");
            sb.AppendLine();
        }
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        return Path.GetFullPath(path);
    }

    public static string WriteText(IDictionary<string,string> mdns, string baseName, string suffix = "mdns")
    {
        var path = $"{baseName}-{suffix}.txt";
        var sb = new StringBuilder();
        foreach (var kv in mdns.OrderBy(k => k.Key))
            sb.AppendLine($"{kv.Key} => {kv.Value}");
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        return Path.GetFullPath(path);
    }

    private static string Csv(string? s)
        => $"\"{(s ?? "").Replace("\"", "\"\"")}\"";

    private static string Sanitize(string s)
        => s.Replace("\r", " ").Replace("\n", " ").Trim();
}
