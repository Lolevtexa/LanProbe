using System.Text.Json.Serialization;

namespace LanProbe.Core.Models;

/// <summary>
/// Запись DeviceFact.
/// </summary>
public sealed record DeviceFact(
    [property: JsonPropertyName("ts")]            DateTime Timestamp,
    [property: JsonPropertyName("iface")]         string InterfaceIp,
    [property: JsonPropertyName("ip")]            string Ip,
    [property: JsonPropertyName("icmp_ok")]       bool IcmpOk,
    [property: JsonPropertyName("rtt_ms")]        long RttMs,
    [property: JsonPropertyName("ttl")]           int Ttl,
    [property: JsonPropertyName("arp_ok")]        bool ArpOk,
    [property: JsonPropertyName("mac")]           string? Mac,
    [property: JsonPropertyName("vendor")]        string? Vendor,
    [property: JsonPropertyName("alive_source")]  string? AliveSource,  // "icmp" | "arp"
    [property: JsonPropertyName("silent_host")]   bool SilentHost,      // true если есть ARP, но нет ICMP
    [property: JsonPropertyName("proxy_arp")]     bool ProxyArp,
    [property: JsonPropertyName("route_mismatch")]bool RouteMismatch
)
{
    // ==== Новые поля Шага 2 ====

    /// Открытые TCP-порты (отсортированы).
    /// <summary>
    /// Свойство OpenPorts.
    /// </summary>
    [JsonPropertyName("open_ports")]
    public int[] OpenPorts { get; init; } = Array.Empty<int>();

    /// Баннеры/метаданные по портам (HTTP/HTTPS/SSH/Generic и т.д.).
    /// <summary>
    /// Свойство Banners.
    /// </summary>
    [JsonPropertyName("banners")]
    public PortBanner[] Banners { get; init; } = Array.Empty<PortBanner>();
}
