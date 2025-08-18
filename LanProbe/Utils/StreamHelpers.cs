using System.Net.Sockets;
using System.Text;

namespace LanProbe.Utils;

/// <summary>
/// Предоставляет вспомогательные методы для чтения всего содержимого из
/// потоков сетевых соединений. Позволяет прочитать ответ от TCP
/// сервера до конца, учитывая наличие данных в буфере.
/// </summary>
public static class StreamHelpers
{
    /// <summary>
    /// Асинхронно считывает все данные из потока, возвращая строку.
    /// Метод делает небольшую паузу, чтобы дождаться прихода
    /// ответа, затем читает все доступные байты. Для сетевых
    /// потоков используется свойство <see cref="NetworkStream.DataAvailable"/>,
    /// чтобы избежать блокировки чтения.
    /// </summary>
    /// <param name="s">Поток для чтения.</param>
    /// <returns>Прочитанная строка в кодировке UTF‑8.</returns>
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