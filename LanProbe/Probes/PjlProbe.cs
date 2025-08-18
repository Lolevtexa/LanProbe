using LanProbe.Models;
using LanProbe.Utils;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Probes;

/// <summary>
/// Проба PJL (Printer Job Language): подключается к порту 9100, отправляет
/// команду <c>\x1B%-12345X@PJL INFO ID</c> и читает ответ, содержащий
/// идентификатор принтера или МФУ. Результат сохраняется в атрибут
/// <c>PJL_ID</c>.
/// </summary>
public static class PjlProbe
{
    /// <summary>
    /// Выполняет PJL‑пробу для указанного хоста.
    /// </summary>
    /// <param name="ip">IP‑адрес устройства.</param>
    /// <param name="dev">Устройство для обновления атрибутов.</param>
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
        catch
        {
            // игнорируем ошибки
        }
    }
}