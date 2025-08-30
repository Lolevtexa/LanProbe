using System.Net;

namespace LanProbe.Core.Discovery;

public static class CidrEnumerator {
    public static IEnumerable<string> Enumerate(string cidr) {
        var parts = cidr.Split('/');
        var baseIp = IPAddress.Parse(parts[0]);
        int prefix = int.Parse(parts[1]);
        uint ip = BitConverter.ToUInt32(baseIp.GetAddressBytes().Reverse().ToArray(), 0);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint net = ip & mask;
        uint hostCount = (uint)(1u << (32 - prefix));
        for (uint i = 1; i < hostCount - 1; i++) {
            yield return new IPAddress(BitConverter.GetBytes((net + i)).Reverse().ToArray()).ToString();
        }
    }
}
