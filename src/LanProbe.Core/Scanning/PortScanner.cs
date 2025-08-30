using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using LanProbe.Core.Models;

namespace LanProbe.Core.Scanning;

/// <summary>
/// Класс PortScanner.
/// </summary>
public sealed class PortScanner
{
    private readonly int[] _ports;
    private readonly int _connectTimeoutMs;
    private readonly int _perHostConcurrency;

    /// <summary>
    /// Конструктор PortScanner.
    /// </summary>
    /// <param name="ports">Параметр ports.</param>
    /// <param name="connectTimeoutMs">Параметр connectTimeoutMs.</param>
    /// <param name="perHostConcurrency">Параметр perHostConcurrency.</param>
    public PortScanner(IEnumerable<int> ports, int connectTimeoutMs = 1200, int perHostConcurrency = 64)
    {
        _ports = ports.Distinct().OrderBy(p => p).ToArray();
        _connectTimeoutMs = connectTimeoutMs;
        _perHostConcurrency = Math.Max(1, perHostConcurrency);
    }

    /// <summary>
    /// Документация для ScanAsync.
    /// </summary>
    public async Task<IReadOnlyList<PortProbe>> ScanAsync(
        IPAddress target,
        IPAddress? bindOnInterface,
        Func<int,string?>? serviceMap,
        CancellationToken ct)
    {
        var bag = new ConcurrentBag<PortProbe>();
        using var sem = new SemaphoreSlim(_perHostConcurrency);

        var tasks = _ports.Select(async port =>
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                bool open = await IsOpenAsync(target, port, bindOnInterface, _connectTimeoutMs, ct).ConfigureAwait(false);
                sw.Stop();

                bag.Add(new PortProbe(
                    Port: port,
                    Open: open,
                    ConnectMs: (int)Math.Min(int.MaxValue, sw.ElapsedMilliseconds),
                    ServiceGuess: serviceMap?.Invoke(port)
                ));
            }
            finally { sem.Release(); }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return bag.OrderBy(p => p.Port).ToArray();
    }

    private static async Task<bool> IsOpenAsync(IPAddress target, int port, IPAddress? bind, int timeoutMs, CancellationToken ct)
    {
        using var sock = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        if (bind is not null && bind.AddressFamily == target.AddressFamily)
        {
            try { sock.Bind(new IPEndPoint(bind, 0)); } catch { /* не критично */ }
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeoutMs);

        try
        {
            await sock.ConnectAsync(new IPEndPoint(target, port), linked.Token).ConfigureAwait(false);
            return sock.Connected;
        }
        catch { return false; }
    }
}