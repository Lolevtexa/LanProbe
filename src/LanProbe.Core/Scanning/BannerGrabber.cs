using System.Buffers;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using LanProbe.Core.Models;

namespace LanProbe.Core.Scanning;

/// Богатые баннеры для открытых портов: HTTP/HTTPS(+GET+gzip+title+generator), SSH, RDP, SMB2, VNC, RTSP.
/// Плюс: self-signed, redirect URL, SHA1 контента, дубли между 80 и 8080.
/// Можно включить сохранение «сырого» ответа в data/raw.
public sealed class BannerGrabber
{
    private readonly int _timeoutMs;
    private readonly int _maxBytes;
    private readonly bool _saveRaw;
    private readonly string _rawDir;

    private static readonly HashSet<int> HttpPorts = new([80,81,82,3000,5000,8000,8001,8008,8080,8081,8123,8181,8888,9000,9090,32400]);
    private static readonly HashSet<int> HttpsPorts = new([443,4443,5001,6443,8443,9443,10000,10443,32443]);
    private static readonly HashSet<int> SshPorts = new([22]);

    private static readonly HashSet<int> PeekTextPorts = new([21,25,110,143,6379,11211]);
    private static readonly HashSet<int> FactOnly = new([5357,]); // WSD и прочие «молчуны», где делаем лишь факт open

    public BannerGrabber(int timeoutMs = 2000, int maxBytes = 64_000, bool saveRaw = false, string rawDir = "data/raw")
    {
        _timeoutMs = timeoutMs;
        _maxBytes = maxBytes;
        _saveRaw = saveRaw;
        _rawDir = rawDir;
        if (_saveRaw) Directory.CreateDirectory(_rawDir);
    }

    public async Task<IReadOnlyList<PortBanner>> GrabAsync(
        IPAddress target,
        IEnumerable<PortProbe> openProbes,
        IPAddress? bindOnInterface,
        CancellationToken ct)
    {
        var result = new List<PortBanner>();
        var httpContentByPort = new Dictionary<int,(string? hash, string? title)>(); // для поиска дублей 80/8080

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
                if (b is not null) { result.Add(b); httpContentByPort[port] = (b.ContentHashSha1, b.Http?.Title); continue; }
            }

            if (HttpsPorts.Contains(port))
            {
                var b = await GrabHttpsAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); httpContentByPort[port] = (b.ContentHashSha1, b.Http?.Title); continue; }
            }

            // Доп. зонды:
            if (port == 3389)
            {
                var b = await ProbeRdpAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }
            if (port == 445)
            {
                var b = await ProbeSmb2Async(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }
            if (port == 5900)
            {
                var b = await ProbeVncAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
                if (b is not null) { result.Add(b); continue; }
            }
            if (port == 554)
            {
                var b = await ProbeRtspAsync(target, port, bindOnInterface, ct).ConfigureAwait(false);
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
            result.Add(generic ?? new PortBanner(port, "fact/open", ServiceOf(port), "open"));
        }

        // Отметка дублей контента (например, 80 и 8080 одинаковые)
        var groups = httpContentByPort
            .Where(kv => !string.IsNullOrEmpty(kv.Value.hash))
            .GroupBy(kv => kv.Value.hash)
            .Where(g => g.Count() > 1);

        foreach (var g in groups)
        {
            var ports = g.Select(x => x.Key).OrderBy(x => x).ToArray();
            foreach (var pb in result.Where(b => ports.Contains(b.Port) && (b.Service == "http" || b.Service == "https")).ToList())
            {
                var newPb = pb with { DuplicateOfPort = ports.First() };
                // заменить в списке
                var idx = result.IndexOf(pb);
                if (idx >= 0) result[idx] = newPb;
            }
        }

        return result;
    }

    // ---------- HTTP ----------
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

            // HEAD
            var headReq = BuildHttpRequest("HEAD", host.ToString());
            await stream.WriteAsync(headReq, 0, headReq.Length, linked.Token).ConfigureAwait(false);
            var headRaw = await ReadToLimitAsync(stream, _maxBytes, linked.Token).ConfigureAwait(false);

            // Если редирект — зафиксируем Location
            var headTxt = Encoding.ASCII.GetString(headRaw);
            var httpHead = ParseHttp(headTxt, bodyAllowed:false, out _, out _);
            string? redirectTo = TryGetHeader(httpHead.Headers, "Location");

            // GET (для title/generator/charset/хэш и чтобы получить Server при некоторых бэкэндах)
            using var client2 = new TcpClient(host.AddressFamily);
            if (bind is not null && bind.AddressFamily == host.AddressFamily) client2.Client.Bind(new IPEndPoint(bind, 0));
            await client2.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var s2 = client2.GetStream();
            var getReq = BuildHttpRequest("GET", host.ToString(), acceptEncoding:true);
            await s2.WriteAsync(getReq, 0, getReq.Length, linked.Token).ConfigureAwait(false);

            var raw = await ReadToLimitAsync(s2, _maxBytes, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, raw);

            var txt = Encoding.ASCII.GetString(raw);
            var httpGet = ParseHttp(txt, bodyAllowed:true, out var bodyBytes, out var isCompressed);

            // Если было gzip — распакуем и повторно распарсим title/generator
            string? title = httpGet.Title;
            string? generator = httpGet.Generator;
            string? charset = httpGet.Charset;
            byte[]? bodyForHash = bodyBytes;

            if (isCompressed && bodyBytes is not null)
            {
                var (dec, decTxt) = TryDecompressAndDecode(bodyBytes, httpGet.Headers);
                if (dec is not null)
                {
                    bodyForHash = dec;
                    // вытащим title/generator/charset из декодированного текста
                    title ??= ExtractTitle(decTxt);
                    generator ??= ExtractMetaGenerator(decTxt);
                    charset ??= ExtractCharsetFromMeta(decTxt) ?? charset;
                }
            }
            else
            {
                // если не сжато — попробуем корректно декодировать по charset
                var decoded = DecodeBody(bodyBytes, httpGet.Headers);
                if (decoded.txt is not null)
                {
                    title ??= ExtractTitle(decoded.txt);
                    generator ??= ExtractMetaGenerator(decoded.txt);
                    charset ??= decoded.charset ?? charset;
                }
            }

            var hash = bodyForHash is not null && bodyForHash.Length > 0 ? Sha1(bodyForHash) : null;

            // Сводка
            var server = TryGetHeader(httpGet.Headers, "Server");
            var status = httpGet.StatusLine ?? httpHead.StatusLine ?? "HTTP";
            var summary = server is not null ? $"HTTP {status}, {server}" : status;

            var httpInfo = new HttpInfo(
                StatusLine: status,
                Headers: MergeHeaders(httpHead.Headers, httpGet.Headers),
                Title: title,
                Generator: generator,
                Charset: charset,
                IsCompressed: isCompressed
            );

            return new PortBanner(
                Port: port,
                Probe: "http/get",
                Service: "http",
                Summary: Trim180(summary),
                Http: httpInfo,
                Tls: null,
                RawFirstLine: null,
                ContentHashSha1: hash,
                RedirectTo: redirectTo
            );
        }
        catch
        {
            return new PortBanner(port, "fact/open", "http", "open");
        }
    }

    // ---------- HTTPS (TLS + GET) ----------
    private async Task<PortBanner?> GrabHttpsAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
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
                SigAlg: cert?.SignatureAlgorithm?.FriendlyName,
                SelfSigned: cert is not null && string.Equals(cert.Issuer, cert.Subject, StringComparison.OrdinalIgnoreCase)
            );

            // HTTPS GET
            var getReq = BuildHttpRequest("GET", host.ToString(), acceptEncoding:true);
            await ssl.WriteAsync(getReq, 0, getReq.Length, linked.Token).ConfigureAwait(false);
            await ssl.FlushAsync(linked.Token).ConfigureAwait(false);

            var raw = await ReadToLimitAsync(ssl, _maxBytes, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, raw);

            var txt = Encoding.ASCII.GetString(raw);
            var httpGet = ParseHttp(txt, bodyAllowed:true, out var bodyBytes, out var isCompressed);
            string? redirectTo = TryGetHeader(httpGet.Headers, "Location");

            string? title = httpGet.Title;
            string? generator = httpGet.Generator;
            string? charset = httpGet.Charset;
            byte[]? bodyForHash = bodyBytes;

            if (isCompressed && bodyBytes is not null)
            {
                var (dec, decTxt) = TryDecompressAndDecode(bodyBytes, httpGet.Headers);
                if (dec is not null)
                {
                    bodyForHash = dec;
                    title ??= ExtractTitle(decTxt);
                    generator ??= ExtractMetaGenerator(decTxt);
                    charset ??= ExtractCharsetFromMeta(decTxt) ?? charset;
                }
            }
            else
            {
                var decoded = DecodeBody(bodyBytes, httpGet.Headers);
                if (decoded.txt is not null)
                {
                    title ??= ExtractTitle(decoded.txt);
                    generator ??= ExtractMetaGenerator(decoded.txt);
                    charset ??= decoded.charset ?? charset;
                }
            }

            var hash = bodyForHash is not null && bodyForHash.Length > 0 ? Sha1(bodyForHash) : null;

            var server = TryGetHeader(httpGet.Headers, "Server");
            var status = httpGet.StatusLine ?? "HTTP";
            var summary = server is not null ? $"HTTPS {status}, {server}" : $"HTTPS {status}";

            var httpInfo = new HttpInfo(
                StatusLine: status,
                Headers: httpGet.Headers,
                Title: title,
                Generator: generator,
                Charset: charset,
                IsCompressed: isCompressed
            );

            return new PortBanner(
                Port: port,
                Probe: "http/get",
                Service: "https",
                Summary: Trim180(summary),
                Http: httpInfo,
                Tls: ti,
                RawFirstLine: null,
                ContentHashSha1: hash,
                RedirectTo: redirectTo
            );
        }
        catch
        {
            return new PortBanner(port, "tls/cert", "https", "open (tls)");
        }
    }

    // ---------- SSH ----------
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
            return new PortBanner(port, "ssh/banner", "ssh", Trim180(string.IsNullOrEmpty(first) ? "open" : first), RawFirstLine: first);
        }
        catch { return new PortBanner(port, "fact/open", "ssh", "open"); }
    }

    // ---------- RDP 3389 ----------
    private async Task<PortBanner?> ProbeRdpAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);
        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var s = client.GetStream();

            // Минимальный TPKT + X.224 Connection Request + RDP Negotiation Request (type 1 - TLS)
            byte[] req = new byte[] {
                0x03,0x00,0x00,0x2a, // TPKT (len=42)
                0x26,0xe0,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x43,0x00,0x6f,0x00,0x6f,0x00,0x6b,0x00,0x69,0x00,0x65,0x00, // "Cookie"
                0x20,0x00,
                0x6d,0x00,0x73,0x00,0x74,0x00,0x73,0x00,0x68,0x00,0x61,0x00,0x73,0x00,0x68,0x00, // " mstshash"
                0x0d,0x0a,
                0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00
            };
            await s.WriteAsync(req, 0, req.Length, linked.Token).ConfigureAwait(false);

            var buf = await ReadToLimitAsync(s, 256, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, buf);

            // Простейшая интерпретация: ответ есть -> RDP Negotiation Response
            return new PortBanner(port, "rdp/neg", "rdp", $"RDP: {buf.Length} bytes reply");
        }
        catch { return new PortBanner(port, "fact/open", "rdp", "open"); }
    }

    // ---------- SMB2 445 ----------
    private async Task<PortBanner?> ProbeSmb2Async(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);
        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var s = client.GetStream();

            // Минимальный SMB2 NEGOTIATE (без NTLM/сессии)
            byte[] smb2Neg = Convert.FromHexString(
                "000000A4" + // NetBIOS len
                "FE534D4240000100000000000000000000000000000000000000000000000000" + // SMB2 header
                "00000000000000000100000000000000" +
                "24000000020000000000000000000000" + // NEGOTIATE
                "0200" + "0200" + // StructureSize, DialectCount=2
                "0000" + "00000000" + "00000000" + // SecurityMode, Reserved, Capabilities
                "0000000000000000" + // ClientGuid
                "00000000" + "00000000" + // NegotiateContextOffset/Count
                "0000" + "0000" + // Reserved2
                "0200" + "0302"    // Dialects: 0x0202(SMB2.0.2), 0x0302(SMB3.0.2)
            );
            await s.WriteAsync(smb2Neg, 0, smb2Neg.Length, linked.Token).ConfigureAwait(false);

            var buf = await ReadToLimitAsync(s, 512, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, buf);
            // Упрощённо: если начинается с 0xFE 'S' 'M' 'B' — получили SMB2/3 ответ
            var isSmb2 = buf.Length >= 4 && buf[0] == 0xFE && buf[1] == 0x53 && buf[2] == 0x4D && buf[3] == 0x42;
            return new PortBanner(port, "smb2/neg", "smb", isSmb2 ? "SMB2/3 negotiate reply" : $"SMB reply {buf.Length} bytes");
        }
        catch { return new PortBanner(port, "fact/open", "smb", "open"); }
    }

    // ---------- VNC 5900 ----------
    private async Task<PortBanner?> ProbeVncAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);
        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var s = client.GetStream();
            var bytes = await ReadToLimitAsync(s, 64, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, bytes);
            var text = Encoding.ASCII.GetString(bytes).Trim();
            return new PortBanner(port, "vnc/banner", "vnc", Trim180(string.IsNullOrEmpty(text) ? "open" : text), RawFirstLine: text);
        }
        catch { return new PortBanner(port, "fact/open", "vnc", "open"); }
    }

    // ---------- RTSP 554 ----------
    private async Task<PortBanner?> ProbeRtspAsync(IPAddress host, int port, IPAddress? bind, CancellationToken ct)
    {
        using var client = new TcpClient(host.AddressFamily);
        if (bind is not null && bind.AddressFamily == host.AddressFamily) client.Client.Bind(new IPEndPoint(bind, 0));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(_timeoutMs);
        try
        {
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var s = client.GetStream();
            var req = $"OPTIONS rtsp://{host}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LanProbe/1.0\r\n\r\n";
            var data = Encoding.ASCII.GetBytes(req);
            await s.WriteAsync(data, 0, data.Length, linked.Token).ConfigureAwait(false);

            var bytes = await ReadToLimitAsync(s, 2048, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, bytes);
            var txt = Encoding.ASCII.GetString(bytes);
            // вытащим Public:
            var publicHdr = Regex.Match(txt, @"(?im)^Public:\s*(.+)$");
            var summary = publicHdr.Success ? $"RTSP Public: {publicHdr.Groups[1].Value.Trim()}" : "RTSP reply";
            return new PortBanner(port, "rtsp/options", "rtsp", Trim180(summary));
        }
        catch { return new PortBanner(port, "fact/open", "rtsp", "open"); }
    }

    // ---------- Generic Peek ----------
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
            var bytes = await ReadToLimitAsync(stream, 1024, linked.Token).ConfigureAwait(false);
            SaveRaw(host, port, bytes);
            var text = Encoding.ASCII.GetString(bytes).Trim();

            if (!string.IsNullOrEmpty(text))
            {
                var service = GuessByTextBanner(text) ?? ServiceOf(port);
                var summary = Trim180(text);
                var hash = bytes.Length > 0 ? Sha1(bytes) : null;
                return new PortBanner(port, "generic/peek", service, summary, RawFirstLine: text, ContentHashSha1: hash);
            }
            return new PortBanner(port, "fact/open", ServiceOf(port), "open");
        }
        catch { return new PortBanner(port, "fact/open", ServiceOf(port), "open"); }
    }

    // ---------- Вспомогательные ----------
    private static string ServiceOf(int port) => port switch
    {
        80 or 81 or 82 or 3000 or 5000 or 8000 or 8001 or 8008 or 8080 or 8081 or 8123 or 8181 or 8888 or 9000 or 9090 or 32400 => "http",
        443 or 4443 or 5001 or 6443 or 8443 or 9443 or 10000 or 10443 or 32443 => "https",
        22 => "ssh", 445 => "smb", 3389 => "rdp", 5900 => "vnc", 554 => "rtsp", 5357 => "wsd",
        9100 or 515 or 631 => "printer", 37777 => "dahua", 8291 => "mikrotik",
        1433 => "mssql", 3306 => "mysql", 5432 => "postgres", 27017 => "mongodb", 9200 => "elasticsearch", 6379 => "redis",
        _ => "tcp"
    };

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

    private static string? TryGetHeader(Dictionary<string,string>? headers, string name)
        => headers is null ? null : (headers.TryGetValue(name, out var v) ? v : headers.TryGetValue(name.ToLower(), out var v2) ? v2 : null);

    private static Dictionary<string,string>? MergeHeaders(Dictionary<string,string>? a, Dictionary<string,string>? b)
    {
        if (a is null) return b;
        if (b is null) return a;
        var res = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in a) if (!res.ContainsKey(kv.Key)) res[kv.Key] = kv.Value;
        foreach (var kv in b) if (!res.ContainsKey(kv.Key)) res[kv.Key] = kv.Value;
        return res;
    }

    private static HttpInfo ParseHttp(string text, bool bodyAllowed, out byte[]? bodyBytes, out bool isCompressed)
    {
        isCompressed = false;
        bodyBytes = null;

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
        string? generator = null;
        string? charset = null;

        if (bodyAllowed && i < lines.Length)
        {
            var bodyStr = string.Join("\n", lines.Skip(i));
            // Content-Encoding
            var enc = TryGetHeader(headers, "Content-Encoding");
            isCompressed = enc is not null && (enc.Contains("gzip", StringComparison.OrdinalIgnoreCase) || enc.Contains("deflate", StringComparison.OrdinalIgnoreCase));

            if (!isCompressed)
            {
                title = ExtractTitle(bodyStr);
                generator = ExtractMetaGenerator(bodyStr);
                charset = ExtractCharsetFromMeta(bodyStr) ?? ExtractCharsetFromHeader(headers);
                bodyBytes = Encoding.ASCII.GetBytes(bodyStr);
            }
            else
            {
                // тело сжато — оставим обработку наверху
                bodyBytes = Encoding.ASCII.GetBytes(bodyStr);
                charset = ExtractCharsetFromHeader(headers);
            }
        }
        else
        {
            charset = ExtractCharsetFromHeader(headers);
        }

        return new HttpInfo(status, headers.Count > 0 ? headers : null, title, generator, charset, isCompressed);
    }

    private static (byte[]? bin, string txt) TryDecompressAndDecode(byte[] body, Dictionary<string,string>? headers)
    {
        try
        {
            using var src = new MemoryStream(body);
            Stream? z = null;
            var enc = ExtractContentEncoding(headers);
            if (enc == "gzip") z = new GZipStream(src, CompressionMode.Decompress, leaveOpen:false);
            else if (enc == "deflate") z = new DeflateStream(src, CompressionMode.Decompress, leaveOpen:false);
            else return (null, "");

            using var ms = new MemoryStream();
            z.CopyTo(ms);
            var buf = ms.ToArray();

            var dec = DecodeBody(buf, headers);
            return (buf, dec.txt ?? Encoding.UTF8.GetString(buf));
        }
        catch { return (null, ""); }
    }

    private static (string? txt, string? charset) DecodeBody(byte[]? body, Dictionary<string,string>? headers)
    {
        if (body is null || body.Length == 0) return (null, null);
        var charset = ExtractCharsetFromHeader(headers);
        try
        {
            if (!string.IsNullOrEmpty(charset))
            {
                var enc = Encoding.GetEncoding(charset, EncoderFallback.ReplacementFallback, DecoderFallback.ReplacementFallback);
                return (enc.GetString(body), charset);
            }
        }
        catch { /* fallback */ }
        // try UTF-8, then win-1251 (часто на локальных устройствах)
        try { return (Encoding.UTF8.GetString(body), "utf-8"); } catch { }
        try { return (Encoding.GetEncoding(1251).GetString(body), "windows-1251"); } catch { }
        return (Encoding.ASCII.GetString(body), "ascii");
    }

    private static string? ExtractCharsetFromHeader(Dictionary<string,string>? headers)
    {
        var ct = headers is null ? null : TryGetHeader(headers, "Content-Type");
        if (ct is null) return null;
        var m = Regex.Match(ct, @"charset=([A-Za-z0-9_\-]+)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static string ExtractTitle(string html)
    {
        var m = Regex.Match(html, @"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (!m.Success) return null!;
        var t = Regex.Replace(m.Groups[1].Value, @"\s+", " ").Trim();
        return string.IsNullOrEmpty(t) ? null! : t.Length > 180 ? t[..180] : t;
    }

    private static string ExtractMetaGenerator(string html)
    {
        var m = Regex.Match(html, @"<meta[^>]*name\s*=\s*[""']generator[""'][^>]*content\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (!m.Success) return null!;
        var t = Regex.Replace(m.Groups[1].Value, @"\s+", " ").Trim();
        return string.IsNullOrEmpty(t) ? null! : t.Length > 180 ? t[..180] : t;
    }

    private static string ExtractCharsetFromMeta(string html)
    {
        var m = Regex.Match(html, @"<meta\s+charset\s*=\s*[""']?([A-Za-z0-9_\-]+)[""']?", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null!;
    }

    private static string ExtractContentEncoding(Dictionary<string,string>? headers)
    {
        var ce = headers is null ? null : TryGetHeader(headers, "Content-Encoding");
        if (ce is null) return "";
        if (ce.Contains("gzip", StringComparison.OrdinalIgnoreCase)) return "gzip";
        if (ce.Contains("deflate", StringComparison.OrdinalIgnoreCase)) return "deflate";
        return "";
    }

    private static string Sha1(byte[] data)
    {
        using var sha = SHA1.Create();
        return Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
    }

    private static string Trim180(string s) => s.Length > 180 ? s[..180] : s;

#if NET9_0_OR_GREATER
    private static string? TryCipherSuite(SslStream ssl)
    {
        try { return ssl.NegotiatedCipherSuite.ToString(); } catch { return null; }
    }
#else
    private static string? TryCipherSuite(SslStream _) => null;
#endif

    private static string[]? TryGetSans(X509Certificate2? cert)
    {
        if (cert is null) return null;
        try
        {
            var ext = cert.Extensions["2.5.29.17"]; // SAN
            if (ext is null) return null;
            var s = ext.Format(false);
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

    private static byte[] BuildHttpRequest(string method, string host, bool acceptEncoding=false)
    {
        var sb = new StringBuilder();
        sb.Append($"{method} / HTTP/1.1\r\n");
        sb.Append($"Host: {host}\r\n");
        sb.Append("User-Agent: LanProbe/1.0\r\n");
        if (acceptEncoding) sb.Append("Accept-Encoding: gzip, deflate\r\n");
        sb.Append("Connection: close\r\n\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private void SaveRaw(IPAddress host, int port, byte[] buf)
    {
        if (!_saveRaw || buf is null || buf.Length == 0) return;
        try
        {
            var path = Path.Combine(_rawDir, $"{host}_{port}.bin");
            File.WriteAllBytes(path, buf);
        }
        catch { /* ignore */ }
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

    private static async Task<byte[]> ReadToLimitAsync(Stream stream, int maxBytes, CancellationToken ct)
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

                // HTTP: остановимся на конце заголовков, если тела много
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
}
