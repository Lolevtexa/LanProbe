using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Discovery;

public static class MdnsDiscovery
{
    public static async Task QueryServices(ConcurrentDictionary<string,string> sink,
                                           TimeSpan duration, CancellationToken ct)
    {
        using var udp = new UdpClient();
        udp.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));
        udp.Client.ReceiveTimeout = 1200;

        var pkt = BuildDnsQuery("_services._dns-sd._udp.local");
        var ep = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
        await udp.SendAsync(pkt, pkt.Length, ep);

        var stopAt = DateTime.UtcNow + duration;
        while (DateTime.UtcNow < stopAt && !ct.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromMilliseconds(600), ct);
                var txt = Encoding.UTF8.GetString(result.Buffer);
                // Достанем встречающиеся «_xxx._udp.local» / «_xxx._tcp.local»
                foreach (var s in ExtractServiceTypes(txt))
                    sink.TryAdd(s, result.RemoteEndPoint.ToString());
            }
            catch { /* timeout */ }
        }
    }

    static byte[] BuildDnsQuery(string name)
    {
        var ms = new MemoryStream();
        void W16(ushort v){ ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)(v & 0xFF)); }

        W16(0x0000); // ID=0 (mDNS)
        W16(0x0000); // Flags=0 (query)
        W16(0x0001); // QDCOUNT=1
        W16(0x0000); // ANCOUNT
        W16(0x0000); // NSCOUNT
        W16(0x0000); // ARCOUNT

        foreach (var label in (name + ".").Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var b = Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)b.Length);
            ms.Write(b, 0, b.Length);
        }
        ms.WriteByte(0x00); // end name

        W16(0x000C); // QTYPE=PTR(12)
        W16(0x0001); // QCLASS=IN

        return ms.ToArray();
    }

    static IEnumerable<string> ExtractServiceTypes(string raw)
    {
        // Находим подстроки вида _xxx._udp.local / _xxx._tcp.local
        var tokens = raw.Split('\0', '\r', '\n', ' ', '"', '\'');
        foreach (var t in tokens)
        {
            if (t.StartsWith("_", StringComparison.Ordinal) &&
               (t.Contains("._udp.local") || t.Contains("._tcp.local")))
            {
                // Нормализуем
                var s = t.Trim().TrimEnd('.', ';');
                if (s.Length <= 64) yield return s;
            }
        }
    }
}
