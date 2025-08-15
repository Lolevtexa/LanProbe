using LanProbe.Models;
using LanProbe.Utils;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace LanProbe.Probes;

public static class HttpProbe
{
    public static async Task Run(IPAddress ip, int port, bool useTls, Device dev)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, port);
            using var stream = client.GetStream();

            if (useTls)
            {
                using var ssl = new SslStream(stream, false, (s, cert, chain, errors) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = ip.ToString() });

                if (ssl.RemoteCertificate is not null)
                {
                    var cert = new X509Certificate2(ssl.RemoteCertificate);
                    dev.Attr[$"TLS_CN_{port}"] = cert.GetNameInfo(X509NameType.SimpleName, false);
                    var subject = cert.Subject;
                    var match = Regex.Match(subject, @"O=([^,]+)");
                    if (match.Success)
                        dev.Attr[$"TLS_O_{port}"] = match.Groups[1].Value.Trim();
                }

                await SendHeadAndExtract(ssl, ip, port, dev, true);
            }
            else
            {
                var req = $"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n";
                var data = Encoding.ASCII.GetBytes(req);
                await stream.WriteAsync(data);
                await stream.FlushAsync();
                var resp = await StreamHelpers.ReadAllAsync(stream);
                Extract(resp, port, dev, false);
            }
        }
        catch { }
    }

    static async Task SendHeadAndExtract(SslStream ssl, IPAddress ip, int port, Device dev, bool https)
    {
        var req = $"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n";
        var data = Encoding.ASCII.GetBytes(req);
        await ssl.WriteAsync(data);
        await ssl.FlushAsync();
        var resp = await StreamHelpers.ReadAllAsync(ssl);
        Extract(resp, port, dev, https);
    }

    static void Extract(string raw, int port, Device dev, bool https)
    {
        var mServer = Regex.Match(raw, @"(?im)^Server:\s*(.+)$");
        if (mServer.Success) dev.Attr[$"{(https ? "HTTPS" : "HTTP")}_Server_{port}"] = mServer.Groups[1].Value.Trim();

        var mTitle = Regex.Match(raw, @"(?is)<title>\s*(.+?)\s*</title>");
        if (mTitle.Success) dev.Attr[$"HTML_Title_{port}"] = mTitle.Groups[1].Value.Trim();
    }
}
