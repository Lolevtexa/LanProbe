using LanProbe.Core.Models;
using System.Text;

namespace LanProbe.Core.Export;

/// <summary>
/// Класс CsvExporter.
/// </summary>
public static class CsvExporter {
    /// <summary>
    /// Документация для Save.
    /// </summary>
    public static void Save(string path, IEnumerable<DeviceFact> facts) {
        var sb = new StringBuilder();
        sb.AppendLine("ts,iface,ip,icmp_ok,rtt_ms,ttl,arp_ok,mac,vendor,alive_source,silent_host,proxy_arp,route_mismatch");
        foreach (var f in facts) {
            sb.AppendLine($"{f.Timestamp:o},{f.InterfaceIp},{f.Ip},{f.IcmpOk},{f.RttMs},{f.Ttl},{f.ArpOk},{f.Mac},{f.Vendor},{f.AliveSource},{f.SilentHost},{f.ProxyArp},{f.RouteMismatch}");
        }
        File.WriteAllText(path, sb.ToString());
    }
}
