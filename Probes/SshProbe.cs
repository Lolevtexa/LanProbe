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
            client.ReceiveTimeout = 1000;
            var stream = client.GetStream();
            var buf = new byte[256];
            int n = await stream.ReadAsync(buf, 0, buf.Length);
            var banner = Encoding.ASCII.GetString(buf, 0, n).Trim();
            dev.Attr["SSH_Banner"] = banner;
        }
        catch { }
    }
}
