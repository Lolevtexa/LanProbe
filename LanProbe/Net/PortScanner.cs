using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace LanProbe.Net;

/// <summary>
/// Предоставляет методы для асинхронного сканирования TCP‑портов на удалённом хосте.
/// </summary>
public static class PortScanner
{
    /// <summary>
    /// Сканирует указанный набор портов и возвращает список открытых портов.
    /// </summary>
    /// <param name="ip">IP‑адрес хоста, который необходимо проверить.</param>
    /// <param name="ports">Массив портов для проверки.</param>
    /// <param name="timeout">
    /// Максимальная длительность попытки подключения к каждому порту. По
    /// истечении тайм‑аута порт считается закрытым.
    /// </param>
    /// <returns>
    /// Коллекция номеров портов, для которых удалось установить соединение.
    /// </returns>
    public static async Task<List<int>> Scan(IPAddress ip, int[] ports, TimeSpan timeout)
    {
        var open = new ConcurrentBag<int>();
        // Для каждого порта создаём отдельный таск. Используется ConcurrentBag,
        // чтобы избежать гонок при добавлении найденных портов.
        var tasks = ports.Select(async p =>
        {
            using var cts = new CancellationTokenSource(timeout);
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, p);
                // Ожидаем или подключения, или истечения тайм‑аута.
                var completed = await Task.WhenAny(connectTask, Task.Delay(timeout, cts.Token));
                if (completed == connectTask && client.Connected)
                    open.Add(p);
            }
            catch
            {
                // игнорируем исключения: порт считается закрытым
            }
        });
        await Task.WhenAll(tasks);
        return open.ToList();
    }
}