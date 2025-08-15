using LanProbe.Models;
using LanProbe.Utils;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Probes;

public static class PjlProbe
{
    public static async Task Run(IPAddress ip, Device dev)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, 9100);
            using var stream = client.GetStream();
            var cmd = "\x1B%-12345X@PJL INFO ID\r\n";
            var data = Encoding.ASCII.GetBytes(cmd);
            await stream.WriteAsync(data);
            await stream.FlushAsync();
            await Task.Delay(150);
            var resp = await StreamHelpers.ReadAllAsync(stream);
            if (!string.IsNullOrWhiteSpace(resp))
                dev.Attr["PJL_ID"] = resp.Trim();
        }
        catch { }
    }
}
