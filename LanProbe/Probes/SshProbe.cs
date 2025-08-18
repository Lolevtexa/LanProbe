using LanProbe.Models;
using LanProbe.Utils;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanProbe.Probes;

/// <summary>
/// Проба SSH: подключается к порту 22 и считывает баннер SSH сервера.
/// Если баннер выглядит как стандартный (<c>SSH-...</c>), он
/// сохраняется в атрибут <c>SSH_Banner</c> устройства.
/// </summary>
public static class SshProbe
{
    /// <summary>
    /// Выполняет SSH‑пробу.
    /// </summary>
    /// <param name="ip">IP‑адрес удалённого хоста.</param>
    /// <param name="dev">Устройство, в которое будут сохранены результаты.</param>
    public static async Task Run(IPAddress ip, Device dev)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, 22);
            client.ReceiveTimeout = 800;
            using var stream = client.GetStream();
            var buf = new byte[256];
            int n = await stream.ReadAsync(buf, 0, buf.Length);
            if (n > 0)
            {
                var banner = Encoding.ASCII.GetString(buf, 0, n).Trim();
                // Засчитываем только настоящий SSH‑баннер
                if (banner.StartsWith("SSH-", StringComparison.Ordinal))
                    dev.Attr["SSH_Banner"] = banner;
            }
        }
        catch
        {
            // игнорируем ошибки
        }
    }
}