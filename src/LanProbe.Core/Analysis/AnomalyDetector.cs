using LanProbe.Core.Models;

namespace LanProbe.Core.Analysis;

public static class AnomalyDetector
{
    public static (string aliveSource, bool silent, bool proxy, bool routeMismatch)
        Analyze(bool icmpOk, bool arpOk, string? mac, string gatewayMac)
    {
        if (icmpOk && arpOk && mac != gatewayMac)
            return ("icmp", false, false, false);
        if (!icmpOk && arpOk && mac != gatewayMac)
            return ("arp", true, false, false);
        if (icmpOk && !arpOk)
            return ("icmp", false, false, true);
        if (arpOk && mac == gatewayMac)
            return ("arp", false, true, false);
        return ("none", false, false, false);
    }
}
