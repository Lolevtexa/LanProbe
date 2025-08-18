using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace LanProbe.Net;

/// <summary>
/// Предоставляет методы для получения информации о сетевых интерфейсах и
/// вычисления параметров подсети.
/// </summary>
public static class NetworkInfo
{
    /// <summary>
    /// Возвращает IP‑адрес и маску первичного (активного) сетевого интерфейса.
    /// </summary>
    /// <returns>
    /// Кортеж, содержащий IP‑адрес и маску. Если активный IPv4
    /// интерфейс не найден, оба значения равны <c>null</c>.
    /// </returns>
    public static (IPAddress? ip, IPAddress? mask) GetPrimaryIPv4()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                 .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                             n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var unicast = ni.GetIPProperties().UnicastAddresses
                .FirstOrDefault(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (unicast != null)
                return (unicast.Address, unicast.IPv4Mask);
        }
        return (null, null);
    }

    /// <summary>
    /// Вычисляет адрес сети и широковещательный адрес по IP и маске.
    /// </summary>
    /// <param name="ip">IP‑адрес узла.</param>
    /// <param name="mask">Маска подсети.</param>
    /// <returns>
    /// Кортеж с адресом сети и широковещательным адресом.
    /// </returns>
    public static (IPAddress network, IPAddress broadcast) GetSubnet(IPAddress ip, IPAddress mask)
    {
        var ipBytes = ip.GetAddressBytes();
        var maskBytes = mask.GetAddressBytes();
        var net = new byte[4];
        var bcast = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            net[i] = (byte)(ipBytes[i] & maskBytes[i]);
            bcast[i] = (byte)(net[i] | (~maskBytes[i]));
        }
        return (new IPAddress(net), new IPAddress(bcast));
    }

    /// <summary>
    /// Преобразует маску подсети в CIDR‑префикс (количество единичных битов).
    /// </summary>
    /// <param name="mask">Маска подсети.</param>
    /// <returns>Длина префикса в битах (от 0 до 32).</returns>
    public static int MaskToCidr(IPAddress mask)
    {
        var b = mask.GetAddressBytes();
        int cidr = 0;
        foreach (var x in b) for (int i = 7; i >= 0; i--) cidr += ((x >> i) & 1);
        return cidr;
    }

    /// <summary>
    /// Перечисляет все допустимые хосты в подсети (исключая адрес сети и broadcast).
    /// </summary>
    /// <param name="network">Адрес сети.</param>
    /// <param name="broadcast">Широковещательный адрес.</param>
    /// <returns>
    /// Последовательность IP‑адресов всех хостов в подсети.
    /// </returns>
    public static IEnumerable<IPAddress> EnumerateHosts(IPAddress network, IPAddress broadcast)
    {
        uint net = BinaryPrimitives.ReadUInt32BigEndian(network.GetAddressBytes());
        uint bcast = BinaryPrimitives.ReadUInt32BigEndian(broadcast.GetAddressBytes());
        for (uint u = net + 1; u < bcast; u++)
        {
            var bytes = BitConverter.GetBytes(u);
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            yield return new IPAddress(bytes);
        }
    }

    /// <summary>
    /// Находит IP‑адрес интерфейса и шлюз, принадлежащие указанной сети.
    /// </summary>
    /// <param name="network">Адрес сети.</param>
    /// <param name="mask">Маска подсети.</param>
    /// <returns>
    /// Кортеж с IP‑адресом интерфейса и адресом шлюза. Если подходящий
    /// интерфейс не найден, оба значения равны <c>null</c>.
    /// </returns>
    public static (IPAddress? ifaceIp, IPAddress? gateway) GetIfaceAndGatewayFor(IPAddress network, IPAddress mask)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                 .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                             n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var ipProps = ni.GetIPProperties();
            var ua = ipProps.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (ua is null || ua.IPv4Mask is null) continue;

            // Проверяем, принадлежит ли интерфейс указанной подсети
            var (net2, _) = GetSubnet(ua.Address, mask);
            if (net2.Equals(network))
            {
                var gw = ipProps.GatewayAddresses
                    .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address;
                return (ua.Address, gw);
            }
        }
        return (null, null);
    }
}