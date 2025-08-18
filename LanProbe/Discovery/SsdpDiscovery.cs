using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Discovery;

/// <summary>
/// Обнаружение устройств UPnP/SSDP путём отправки M‑SEARCH запроса и
/// чтения ответов. Собирает заголовки из ответов и помещает их в
/// concurrent‑словарь.
/// </summary>
public static class SsdpDiscovery
{
    /// <summary>
    /// Выполняет SSDP‑обнаружение в течение указанного времени.
    /// </summary>
    /// <param name="sink">Словарь, в который будут помещены ответы. Ключ — значение поля USN или LOCATION, значение — словарь всех заголовков.</param>
    /// <param name="duration">Продолжительность опроса.</param>
    /// <param name="ct">Токен отмены.</param>
    public static async Task QueryAll(ConcurrentDictionary<string, Dictionary<string, string>> sink,
                                       TimeSpan duration, CancellationToken ct)
    {
        string req = string.Join("\r\n", new[]
        {
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            "MAN: \"ssdp:discover\"",
            "MX: 2",
            "ST: ssdp:all",
            "", ""
        });

        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = 1500;
        udp.MulticastLoopback = false;

        var payload = Encoding.ASCII.GetBytes(req);
        var ep = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);

        // Несколько отправок для надёжности
        for (int i = 0; i < 3; i++)
        {
            await udp.SendAsync(payload, payload.Length, ep);
            await Task.Delay(200, ct);
        }

        var stopAt = DateTime.UtcNow + duration;
        while (DateTime.UtcNow < stopAt && !ct.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromMilliseconds(600), ct);
                var text = Encoding.UTF8.GetString(result.Buffer);
                var headers = ParseHttpHeaders(text);
                var key = headers.TryGetValue("USN", out var usn) ? usn :
                          headers.TryGetValue("LOCATION", out var loc) ? loc :
                          result.RemoteEndPoint.ToString();
                sink[key] = headers;
            }
            catch
            {
                // timeout
            }
        }
    }

    private static Dictionary<string, string> ParseHttpHeaders(string raw)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in raw.Split("\r\n"))
        {
            var idx = line.IndexOf(':');
            if (idx > 0)
            {
                var k = line.Substring(0, idx).Trim();
                var v = line[(idx + 1)..].Trim();
                if (!string.IsNullOrEmpty(k)) dict[k] = v;
            }
        }
        return dict;
    }
}