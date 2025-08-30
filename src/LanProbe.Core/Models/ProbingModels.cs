using System.Text.Json.Serialization;

namespace LanProbe.Core.Models;

/// Результат проверки конкретного TCP-порта
public sealed record PortProbe(
    int Port,
    bool Open,
    int ConnectMs,
    string? ServiceGuess // "http","https","ssh","smb","rdp",...
);

/// Ключевые HTTP-поля
public sealed record HttpInfo(
    string? StatusLine,
    Dictionary<string,string>? Headers,
    string? Title
);

/// TLS-метаданные
public sealed record TlsInfo(
    string? Version,
    string? CipherSuite,
    string? SubjectCN,
    string[]? SubjectAltNames,
    string? Issuer,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    string? SigAlg
);

/// Обобщённый баннер/метаданные порта
public sealed record PortBanner(
    int Port,
    string Probe,     // "http/head","http/get","tls/cert","ssh/banner","generic/peek","fact/open"
    string Service,   // "http","https","ssh","tcp","smb","rdp",...
    string Summary,   // краткая выжимка
    HttpInfo? Http = null,
    TlsInfo? Tls = null,
    string? RawFirstLine = null
);
