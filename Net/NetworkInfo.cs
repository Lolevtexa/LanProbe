using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;

namespace LanProbe.Net;

public static class NetworkInfo
{
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

    public static int MaskToCidr(IPAddress mask)
    {
        var b = mask.GetAddressBytes();
        int cidr = 0;
        foreach (var x in b) for (int i = 7; i >= 0; i--) cidr += ((x >> i) & 1);
        return cidr;
    }

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

            // принадлежит ли интерфейс этой подсети
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
