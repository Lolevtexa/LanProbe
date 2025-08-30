using System;

namespace LanProbe.Core.Models;

public record DeviceFact(
    DateTime Timestamp,
    string InterfaceIp,
    string Ip,
    bool IcmpOk,
    long RttMs,
    int Ttl,
    bool ArpOk,
    string? Mac,
    string? Vendor,
    string AliveSource,
    bool SilentHost,
    bool ProxyArp,
    bool RouteMismatch
);
