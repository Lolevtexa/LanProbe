using LanProbe.Models;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace LanProbe.Probes;

public static class RdpProbe
{
    public static async Task Run(IPAddress ip, Device dev)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, 3389);
            using var stream = client.GetStream();
            using var ssl = new SslStream(stream, false, (s, cert, chain, errors) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ip.ToString() });
            if (ssl.RemoteCertificate is not null)
            {
                var cert = new X509Certificate2(ssl.RemoteCertificate);
                var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                dev.Attr["RDP_CN"] = cn;
                if (cn.StartsWith("TERMSRV/", StringComparison.OrdinalIgnoreCase))
                    dev.Hostname ??= cn["TERMSRV/".Length..];
            }
        }
        catch { }
    }
}
