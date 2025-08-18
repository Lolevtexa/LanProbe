using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace LanProbe.Models;

/// <summary>
/// Представляет сетевое устройство и содержит собранную о нём информацию.
///
/// В экземпляре <see cref="Device"/> хранится IP‑адрес, MAC‑адрес, имя
/// хоста, предполагаемая операционная система и тип устройства, а также
/// набор открытых портов и произвольные атрибуты, полученные с помощью
/// различных проб и методик обнаружения.
/// </summary>
public class Device
{
    /// <summary>
    /// IP‑адрес устройства (в виде строки). Поле заполняется пользователем.
    /// </summary>
    public string Ip { get; set; } = "";

    /// <summary>
    /// MAC‑адрес устройства, если удалось определить.
    /// </summary>
    public string? Mac { get; set; }

    /// <summary>
    /// Имя хоста (DNS или RDP CN), если известно.
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// Предполагаемая операционная система, определённая эвристически.
    /// </summary>
    public string? OsHint { get; set; }

    /// <summary>
    /// Предполагаемый тип устройства (например, принтер, NAS и т.д.).
    /// </summary>
    public string? TypeHint { get; set; }

    /// <summary>
    /// Набор открытых TCP‑портов.
    /// </summary>
    public HashSet<int> OpenPorts { get; } = new();

    /// <summary>
    /// Произвольные атрибуты, собранные в ходе опросов. Ключи могут
    /// содержать имена протоколов или портов, а значения — строки.
    /// </summary>
    public Dictionary<string, string> Attr { get; } = new();

    /// <summary>
    /// Истина, если по устройству есть хоть какие‑то данные (открытые
    /// порты, MAC, имя хоста или атрибуты).
    /// </summary>
    public bool HasAnyData =>
        OpenPorts.Count > 0 || !string.IsNullOrWhiteSpace(Mac) ||
        !string.IsNullOrWhiteSpace(Hostname) || Attr.Count > 0;

    /// <summary>
    /// Формирует человекочитаемое представление устройства для отчётов.
    /// </summary>
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

    /// <summary>
    /// Пытается на основе собранных атрибутов сделать выводы об операционной системе
    /// или типе устройства. Метод изменяет свойства <see cref="OsHint"/> и
    /// <see cref="TypeHint"/>, если соответствующие подсказки ещё не заполнены.
    /// </summary>
    /// <param name="d">Устройство, для которого нужно сделать вывод.</param>
    public static void Infer(Device d)
    {
        // Подсказки на основе RDP Common Name
        if (d.Attr.ContainsKey("RDP_CN"))
            d.OsHint ??= "Windows (RDP)";

        // Подсказки на основе SSH баннера
        if (d.Attr.TryGetValue("SSH_Banner", out var ssh))
        {
            if (ssh.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Linux (Ubuntu)";
            else if (ssh.Contains("Debian", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Linux (Debian)";
            else if (ssh.Contains("OpenWrt", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Linux (OpenWrt)";
            else if (ssh.Contains("Dropbear", StringComparison.OrdinalIgnoreCase)) d.OsHint ??= "Embedded Linux (Dropbear)";
        }

        // Устройства с PJL отвечают принтеры/MFP
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