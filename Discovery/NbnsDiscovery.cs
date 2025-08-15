using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Discovery;

public static class NbnsDiscovery
{
    public static async Task BroadcastNodeStatus(ConcurrentDictionary<string,string> sink,
                                                 TimeSpan duration, CancellationToken ct)
    {
        using var udp = new UdpClient();
        udp.EnableBroadcast = true;
        udp.Client.ReceiveTimeout = 1200;

        // NBNS Node Status запрос (0x00 0x21) к имени "*"
        var packet = BuildNodeStatusPacket();

        // Широковещательные посылки
        var bcast = new IPEndPoint(IPAddress.Broadcast, 137);
        for (int i = 0; i < 2; i++)
        {
            await udp.SendAsync(packet, packet.Length, bcast);
            await Task.Delay(150, ct);
        }

        var stopAt = DateTime.UtcNow + duration;
        while (DateTime.UtcNow < stopAt && !ct.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromMilliseconds(600), ct);
                var name = TryParseFirstName(result.Buffer) ?? "NBNS-Name";
                sink[result.RemoteEndPoint.Address.ToString()] = name;
            }
            catch { /* timeout */ }
        }
    }

    static byte[] BuildNodeStatusPacket()
    {
        // Простейший NBNS запрос NODE STATUS для имени "*"
        // Транзакционный ID произвольный (0x1234)
        var ms = new MemoryStream();
        void W16(ushort v){ ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)(v & 0xFF)); }

        W16(0x1234); // ID
        W16(0x0000); // Flags: Query
        W16(0x0001); // QDCOUNT
        W16(0x0000); // ANCOUNT
        W16(0x0000); // NSCOUNT
        W16(0x0000); // ARCOUNT

        // NBNS name encoding для "*" (звёздочка)
        // Спец-имя: 0x2A -> кодируем как label длиной 0x20 (RFC 1002 «compressed NB name»), но проще: «*               » (15 пробелов) и 0x00 тип
        // Чтобы не увязнуть, используем готовое "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (код NBNS для "*"):
        var starName = Encoding.ASCII.GetBytes("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        ms.WriteByte(32); // длина лейбла
        ms.Write(starName, 0, starName.Length);
        ms.WriteByte(0x00); // конец имени

        W16(0x0021); // QTYPE: NBSTAT (0x21)
        W16(0x0001); // QCLASS: IN

        return ms.ToArray();
    }

    static string? TryParseFirstName(byte[] buf)
    {
        // Очень упрощённо: в ответе NBSTAT после заголовков есть список имён.
        // Найдём ASCII-последовательности и вернём первую «вменяемую».
        try
        {
            var ascii = Encoding.ASCII.GetString(buf);
            // Поищем сегмент с читаемыми именами
            var lines = ascii.Split('\0', '\r', '\n');
            foreach (var s in lines)
            {
                var t = new string(s.Where(ch => ch >= 32 && ch < 127).ToArray()).Trim();
                if (t.Length >= 1 && t.Length <= 32 && t.Any(char.IsLetterOrDigit))
                    return t;
            }
        }
        catch { }
        return null;
    }
}
