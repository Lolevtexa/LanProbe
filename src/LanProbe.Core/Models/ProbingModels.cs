namespace LanProbe.Core.Models;

/// <summary>
/// Запись PortProbe.
/// </summary>
public sealed record PortProbe(
    int Port,
    bool Open,
    int ConnectMs,
    string? ServiceGuess
);

/// <summary>
/// Запись HttpInfo.
/// </summary>
public sealed record HttpInfo(
    string? StatusLine,
    Dictionary<string,string>? Headers,
    string? Title,
    string? Generator,     // из <meta name="generator">
    string? Charset,       // детект из Content-Type / <meta charset>
    bool   IsCompressed    // gzip/deflate
);

/// <summary>
/// Запись TlsInfo.
/// </summary>
public sealed record TlsInfo(
    string? Version,
    string? CipherSuite,
    string? SubjectCN,
    string[]? SubjectAltNames,
    string? Issuer,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    string? SigAlg,
    bool?  SelfSigned      // Issuer == Subject?
);

/// <summary>
/// Запись PortBanner.
/// </summary>
public sealed record PortBanner(
    int Port,
    string Probe,          // "http/head","http/get","tls/cert","ssh/banner","generic/peek","rdp/neg","smb2/neg","vnc/banner","rtsp/options","fact/open"
    string Service,        // "http","https","ssh","rdp","smb","vnc","rtsp","tcp"...
    string Summary,        // краткая выжимка
    HttpInfo? Http = null,
    TlsInfo? Tls = null,
    string? RawFirstLine = null,    // первая строка текстового баннера
    string? ContentHashSha1 = null, // хэш первых N байт тела/ответа
    string? RedirectTo = null,      // URL редиректа (если был)
    int?    DuplicateOfPort = null  // если контент совпал с другим портом (напр., 80 == 8080)
);
