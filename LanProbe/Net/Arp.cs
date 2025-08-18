using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace LanProbe.Net;

/// <summary>
/// Предоставляет метод для получения MAC‑адреса для заданного IPv4‑адреса.
///
/// Для получения MAC‑адреса вызывается Win32‑функция SendARP из
/// библиотеки iphlpapi.dll. Метод работает только на Windows. На
/// других платформах метод всегда возвращает <c>null</c>.
/// </summary>
public static class Arp
{
    // Импортируем функцию из iphlpapi.dll для отправки ARP‑запроса.
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

    /// <summary>
    /// Пытается получить MAC‑адрес указанного IP‑адреса.
    /// </summary>
    /// <param name="ip">IPv4‑адрес удалённого хоста.</param>
    /// <returns>
    /// Строка с MAC‑адресом в формате «AA:BB:CC:DD:EE:FF» или <c>null</c>,
    /// если адрес не удалось получить.
    /// </returns>
    public static string? TryGetMac(IPAddress ip)
    {
        try
        {
            // Получаем байты IP‑адреса в сетевом порядке (big endian).
            byte[] dst = ip.GetAddressBytes();
            // Для правильной передачи в API байты должны быть в обратном порядке
            // на little endian системах.
            if (BitConverter.IsLittleEndian) Array.Reverse(dst);
            uint dest = BitConverter.ToUInt32(dst, 0);
            uint len = 6;
            byte[] mac = new byte[6];
            int r = SendARP(dest, 0, mac, ref len);
            // При успехе возвращаем первые 6 байт в виде строки.
            if (r == 0 && len >= 6)
                return string.Join(":", mac.Take(6).Select(b => b.ToString("X2")));
        }
        catch
        {
            // Игнорируем любые исключения и возвращаем null при ошибке.
        }
        return null;
    }
}