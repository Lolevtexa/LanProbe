using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace LanProbe.Net;

public static class PortScanner
{
    public static async Task<List<int>> Scan(IPAddress ip, int[] ports, TimeSpan timeout)
    {
        var open = new ConcurrentBag<int>();
        var tasks = ports.Select(async p =>
        {
            using var cts = new CancellationTokenSource(timeout);
            try
            {
                using var client = new TcpClient();
                var task = client.ConnectAsync(ip, p);
                var completed = await Task.WhenAny(task, Task.Delay(timeout, cts.Token));
                if (completed == task && client.Connected) open.Add(p);
            }
            catch { }
        });
        await Task.WhenAll(tasks);
        return open.ToList();
    }
}
