using LanProbe.Models;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace LanProbe.Probes;

/// <summary>
/// Проба RDP: устанавливает TLS‑соединение с портом 3389 и извлекает
/// общие сведения из сертификата сервера (Common Name). Полученный CN
/// сохраняется в словаре атрибутов устройства с ключом <c>RDP_CN</c>.
/// </summary>
public static class RdpProbe
{
    /// <summary>
    /// Выполняет подключение к службе RDP на указанном IP и обновляет
    /// данные устройства.
    /// </summary>
    /// <param name="ip">IP‑адрес удалённого хоста.</param>
    /// <param name="dev">Объект устройства, в который будут записаны атрибуты.</param>
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
        catch
        {
            // игнорируем ошибки
        }
    }
}