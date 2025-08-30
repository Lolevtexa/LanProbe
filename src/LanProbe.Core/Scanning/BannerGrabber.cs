using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using LanProbe.Core.Models;

namespace LanProbe.Core.Scanning;

/// Сбор баннеров для открытых портов: HTTP/HTTPS/SSH/Generic, факт open для SMB/RDP/VNC/принтеров и пр.
public sealed class BannerGrabber
{
    private readonly int _timeoutMs;
    private readonly int _maxBytes;

    private static readonly HashSet<int> HttpPorts = new([80,81,82,3000,5000,8000,8001,8008,8080,8081,8123,8181,8888,9000,9090,32400]);
    private static readonly HashSet<int> HttpsPorts = new([443,4443,5001,6443,8443,9443,10000,10443,32443]);
    private static readonly HashSet<int> SshPorts = new([22]);

    private static readonly HashSet<int> PeekTextPorts = new([21,25,110,143,6379,11211]);
    private static readonly HashSet<int> FactOnly = new([445,3389,5357,9100,515,631,37777,8291,5900,161,1433,3306,5432,27017,9200,6379]);

    public BannerGrabber(int timeoutMs = 1800, int maxBytes = 24_000)
    {
        _timeoutMs = timeoutMs;
        _maxBytes = maxBytes;
    }

    public async Task<IReadOnlyList<PortBanner>> GrabAsync(
        IPAddress target,
        IEnumerable<PortProbe> openProbes,
        IPAddress? bindOnInterface,
        CancellationToken ct)
    {
        var result = new List<PortBanner>();

        foreach (var p in openProbes.Where(p => p.Open))
        {
            int port = p.Port;

            if (SshPorts.Contains(port))
            {
                var b = await GrabSshAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }

            if (HttpPorts.Contains(port))
            {
                var b = await GrabHttpAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }

            if (HttpsPorts.Contains(port))
            {
                var b = await GrabHttpsTlsAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }

            if (PeekTextPorts.Contains(port))
            {
                var b = await GenericPeekAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }

            if (FactOnly.Contains(port))
            {
                result.Add(new PortBanner(port, "fact/open", ServiceOf(port), "open"));
                continue;
            }

            var generic = await GenericPeekAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
            result.Add(generic ?? new PortBanner(port, "fact/open", "tcp", "open"));
        }

        return result;
    }

    // --- HTTP ---
    private async Task<PortBanner?> GrabHttpAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);

        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            var req = $"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: LanProbe/1.0\r\nConnection: close\r\n\r\n";
            var head = Encoding.ASCII.GetBytes(req);
            await stream.WriteAsync(head, 0, head.Length, linked.Token).ConfigureAwait(false);

            var raw = await ReadToLimitAsync(stream, _maxBytes, linked.Token).ConfigureAwait(false);
            string text = Encoding.ASCII.GetString(raw);

            var http = ParseHttp(text);
            string summary = http.Headers?.TryGetValue("Server", out var server) == true
                ? $"HTTP {http.StatusLine ?? ""}, {server}"
                : http.StatusLine ?? "http";

            // лёгкий GET для title (если не нашли)
            if ((http.Headers is null || !http.Headers.ContainsKey("Server")) && http.Title is null)
            {
                using var client2 = new TcpClient(host.AddressFamily);
                if (bind is not null && bind.AddressFamily == host.AddressFamily) client2.Client.Bind(new IPEndPoint(bind, 0));
                await client2.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
                using var s2 = client2.GetStream();

                var get = $"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: LanProbe/1.0\r\nConnection: close\r\n\r\n";
                var getBytes = Encoding.ASCII.GetBytes(get);
                await s2.WriteAsync(getBytes, 0, getBytes.Length, linked.Token).ConfigureAwait(false);

                var raw2 = await ReadToLimitAsync(s2, _maxBytes, linked.Token).ConfigureAwait(false);
                var http2 = ParseHttp(Encoding.ASCII.GetString(raw2));
                if (http2.Title is not null) http = http with { Title = http2.Title };
            }

            return new PortBanner(
                Port: port,
                Probe: "http/head",
                Service: "http",
                Summary: summary.Length > 180 ? summary[..180] : summary,
                Http: http
            );
        }
        catch
        {
            return new PortBanner(port, "fact/open", "http", "open");
        }
    }

    private static HttpInfo ParseHttp(string text)
    {
        var lines = text.Split("\r\n");
        string? status = lines.Length > 0 && lines[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ? lines[0] : null;

        var headers = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        int i = 1;
        for (; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrEmpty(line)) { i++; break; }
            var p = line.IndexOf(':');
            if (p > 0)
            {
                var key = line[..p].Trim();
                var val = line[(p+1)..].Trim();
                if (!headers.ContainsKey(key)) headers[key] = val;
            }
        }

        string? title = null;
        if (i < lines.Length)
        {
            var body = string.Join("\n", lines.Skip(i));
            var m = Regex.Match(body, @"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (m.Success)
            {
                title = Regex.Replace(m.Groups[1].Value, @"\s+", " ").Trim();
                if (title.Length > 180) title = title[..180];
            }
        }

        return new HttpInfo(status, headers.Count > 0 ? headers : null, title);
    }

    // --- HTTPS / TLS ---
    private async Task<PortBanner?> GrabHttpsTlsAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);

        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var ns = client.GetStream();
            using var ssl = new SslStream(ns, false, static (_, _, _, _) => true);

            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = host.ToString(),
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck }
            };
            await ssl.AuthenticateAsClientAsync(opts, linked.Token).ConfigureAwait(false);

            var cert = ssl.RemoteCertificate is null ? null : new X509Certificate2(ssl.RemoteCertificate);
            var ti = new TlsInfo(
                Version: ssl.SslProtocol.ToString(),
                CipherSuite: TryCipherSuite(ssl),
                SubjectCN: cert?.GetNameInfo(X509NameType.DnsName, false),
                SubjectAltNames: TryGetSans(cert),
                Issuer: cert?.Issuer,
                NotBefore: cert?.NotBefore,
                NotAfter: cert?.NotAfter,
                SigAlg: cert?.SignatureAlgorithm?.FriendlyName
            );

            string summary = $"TLS {ti.Version}, CN={ti.SubjectCN ?? "-"}, Issuer={(ti.Issuer ?? "-")}";
            return new PortBanner(port, "tls/cert", "https", summary.Length > 180 ? summary[..180] : summary, Tls: ti);
        }
        catch
        {
            return new PortBanner(port, "fact/open", "https", "open");
        }
    }

    private static string? TryCipherSuite(SslStream ssl)
    {
#if NET9_0_OR_GREATER
        try { return ssl.NegotiatedCipherSuite.ToString(); } catch { return null; }
#else
        return null;
#endif
    }

    private static string[]? TryGetSans(X509Certificate2? cert)
    {
        if (cert is null) return null;
        try
        {
            var ext = cert.Extensions["2.5.29.17"]; // SubjectAltName
            if (ext is null) return null;
            var s = ext.Format(false); // "DNS Name=..., DNS Name=..."
            var names = new List<string>();
            foreach (var part in s.Split(','))
            {
                var p = part.Trim();
                var eq = p.IndexOf('=');
                if (eq > 0)
                {
                    var key = p[..eq].Trim().ToLowerInvariant();
                    var val = p[(eq+1)..].Trim();
                    if (key.Contains("dns")) names.Add(val);
                }
            }
            return names.Count > 0 ? names.ToArray() : null;
        }
        catch { return null; }
    }

    // --- SSH ---
    private async Task<PortBanner?> GrabSshAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);

        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            var line = await ReadLineAsync(stream, 1024, linked.Token).ConfigureAwait(false);
            var first = (line ?? "").Trim();
            if (string.IsNullOrEmpty(first))
                return new PortBanner(port, "fact/open", "ssh", "open");

            return new PortBanner(port, "ssh/banner", "ssh", first.Length > 180 ? first[..180] : first, RawFirstLine: first);
        }
        catch
        {
            return new PortBanner(port, "fact/open", "ssh", "open");
        }
    }

    // --- Generic Peek ---
    private async Task<PortBanner?> GenericPeekAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);

        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            var bytes = await ReadToLimitAsync(stream, 512, linked.Token).ConfigureAwait(false);
            var text = Encoding.ASCII.GetString(bytes).Trim();

            if (!string.IsNullOrEmpty(text))
            {
                var service = GuessByTextBanner(text) ?? "tcp";
                var summary = text.Length > 180 ? text[..180] : text;
                return new PortBanner(port, "generic/peek", service, summary, RawFirstLine: text);
            }
            return new PortBanner(port, "fact/open", "tcp", "open");
        }
        catch
        {
            return new PortBanner(port, "fact/open", "tcp", "open");
        }
    }

    private static string? GuessByTextBanner(string s)
    {
        var t = s.ToLowerInvariant();
        if (t.StartsWith("+ok") || t.Contains("pop")) return "pop3";
        if (t.Contains("imap")) return "imap";
        if (t.StartsWith("220") && t.Contains("smtp")) return "smtp";
        if (t.StartsWith("220") && t.Contains("ftp")) return "ftp";
        if (t.Contains("redis")) return "redis";
        if (t.Contains("memcached")) return "memcached";
        return null;
    }

    private static async Task<string?> ReadLineAsync(NetworkStream stream, int maxBytes, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new byte[1];
        while (sb.Length < maxBytes)
        {
            var n = await stream.ReadAsync(buf, 0, 1, ct).ConfigureAwait(false);
            if (n <= 0) break;
            char ch = (char)buf[0];
            if (ch == '\n') break;
            sb.Append(ch);
        }
        return sb.ToString();
    }

    private static async Task<byte[]> ReadToLimitAsync(NetworkStream stream, int maxBytes, CancellationToken ct)
    {
        var rented = ArrayPool<byte>.Shared.Rent(maxBytes);
        int total = 0;
        try
        {
            while (total < maxBytes)
            {
                var n = await stream.ReadAsync(rented.AsMemory(total, maxBytes - total), ct).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;

                if (total >= 4 &&
                    rented[total - 4] == '\r' && rented[total - 3] == '\n' &&
                    rented[total - 2] == '\r' && rented[total - 1] == '\n')
                    break;
            }
            return rented.AsSpan(0, total).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static string ServiceOf(int port) => port switch
    {
        80 or 81 or 82 or 3000 or 5000 or 8000 or 8001 or 8008 or 8080 or 8081 or 8123 or 8181 or 8888 or 9000 or 9090 or 32400 => "http",
        443 or 4443 or 5001 or 6443 or 8443 or 9443 or 10000 or 10443 or 32443 => "https",
        22 => "ssh",
        445 => "smb",
        3389 => "rdp",
        5357 => "wsd",
        9100 or 515 or 631 => "printer",
        37777 => "dahua",
        8291 => "mikrotik",
        5900 => "vnc",
        161 => "snmp",
        1433 => "mssql",
        3306 => "mysql",
        5432 => "postgres",
        27017 => "mongodb",
        9200 => "elasticsearch",
        6379 => "redis",
        _ => "tcp"
    };
}
