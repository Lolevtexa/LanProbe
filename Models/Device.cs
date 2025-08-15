using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace LanProbe.Models;

public class Device
{
    public string Ip { get; set; } = "";
    public string? Mac { get; set; }
    public string? Hostname { get; set; }
    public string? OsHint { get; set; }
    public string? TypeHint { get; set; }
    public HashSet<int> OpenPorts { get; } = new();
    public Dictionary<string, string> Attr { get; } = new();

    public bool HasAnyData =>
        OpenPorts.Count > 0 || !string.IsNullOrWhiteSpace(Mac) ||
        !string.IsNullOrWhiteSpace(Hostname) || Attr.Count > 0;

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"IP: {Ip}");
        if (!string.IsNullOrWhiteSpace(Mac)) sb.AppendLine($"MAC: {Mac}");
        if (!string.IsNullOrWhiteSpace(Hostname)) sb.AppendLine($"Host: {Hostname}");
        if (!string.IsNullOrWhiteSpace(OsHint)) sb.AppendLine($"OS: {OsHint}");
        if (!string.IsNullOrWhiteSpace(TypeHint)) sb.AppendLine($"Type: {TypeHint}");
        if (OpenPorts.Count > 0) sb.AppendLine("Ports: " + string.Join(",", OpenPorts.OrderBy(p => p)));
        foreach (var kv in Attr) sb.AppendLine($"{kv.Key}: {kv.Value}");
        return sb.ToString();
    }

    public static void Infer(Device d)
    {
        if (d.Attr.ContainsKey("RDP_CN"))
            d.OsHint ??= "Windows (RDP)";

        if (d.Attr.TryGetValue("SSH_Banner", out var ssh))
        {
            if (ssh.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Linux (Ubuntu)";
            else if (ssh.Contains("Debian", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Linux (Debian)";
            else if (ssh.Contains("OpenWrt", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Linux (OpenWrt)";
            else if (ssh.Contains("Dropbear", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Embedded Linux (Dropbear)";
        }

        if (d.Attr.TryGetValue("PJL_ID", out _))
            d.TypeHint ??= "Printer/MFP";

        // По HTTP Server — примеры
        var httpVals = d.Attr.Where(k => k.Key.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase)).Select(k => k.Value);
        if (httpVals.Any(v => v.Contains("Synology", StringComparison.OrdinalIgnoreCase)))
            d.TypeHint ??= "NAS (Synology)";
        if (httpVals.Any(v => v.Contains("MikroTik", StringComparison.OrdinalIgnoreCase)))
            d.TypeHint ??= "Router (MikroTik)";
        if (httpVals.Any(v => v.Contains("Ubiquiti", StringComparison.OrdinalIgnoreCase)))
            d.TypeHint ??= "Ubiquiti device";
    }
}
