using LanProbe.Models;
using LanProbe.Utils;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Probes;

public static class SshProbe
{
    public static async Task Run(IPAddress ip, Device dev)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, 22);
            client.ReceiveTimeout = 800;
            var stream = client.GetStream();
            var buf = new byte[256];
            int n = await stream.ReadAsync(buf, 0, buf.Length);
            if (n > 0)
            {
                var banner = Encoding.ASCII.GetString(buf, 0, n).Trim();
                // Засчитываем только настоящий SSH-баннер
                if (banner.StartsWith("SSH-", StringComparison.Ordinal))
                    dev.Attr["SSH_Banner"] = banner;
            }
        }
        catch { }
    }
}
