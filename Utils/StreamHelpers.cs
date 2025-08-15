using System.Net.Sockets;
using System.Text;

namespace LanProbe.Utils;

public static class StreamHelpers
{
    public static async Task<string> ReadAllAsync(Stream s)
    {
        var sb = new StringBuilder();
        var buf = new byte[4096];

        // Небольшая пауза, чтобы накопить ответ
        await Task.Delay(120);

        if (s is NetworkStream ns)
        {
            while (ns.DataAvailable)
            {
                int n = await s.ReadAsync(buf, 0, buf.Length);
                if (n <= 0) break;
                sb.Append(Encoding.UTF8.GetString(buf, 0, n));
            }
        }
        else
        {
            int n;
            while ((n = await s.ReadAsync(buf, 0, buf.Length)) > 0)
                sb.Append(Encoding.UTF8.GetString(buf, 0, n));
        }

        return sb.ToString();
    }
}
