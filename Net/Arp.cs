using System.Net;
using System.Runtime.InteropServices;

namespace LanProbe.Net;

public static class Arp
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

    public static string? TryGetMac(IPAddress ip)
    {
        try
        {
            byte[] dst = ip.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(dst);
            uint dest = BitConverter.ToUInt32(dst, 0);
            uint len = 6;
            byte[] mac = new byte[6];
            int r = SendARP(dest, 0, mac, ref len);
            if (r == 0 && len >= 6)
                return string.Join(":", mac.Take(6).Select(b => b.ToString("X2")));
        }
        catch { }
        return null;
    }
}
