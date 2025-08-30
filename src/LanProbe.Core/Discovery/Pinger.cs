// src/LanProbe.Core/Discovery/Pinger.cs
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace LanProbe.Core.Discovery;

public static class Pinger {
    // Успех по наличию "TTL="
    static readonly Regex TtlRx = new(@"TTL\s*=\s*(\d+)", RegexOptions.IgnoreCase);
    // RTT: число перед "ms"/"мс"
    static readonly Regex RttRx = new(@"(?<!\d)(\d+)\s*(?:ms|мс)", RegexOptions.IgnoreCase);

    /// <summary>
    /// Пингуем через ping.exe c заданного исходного IP несколько раз.
    /// Успех = была хотя бы одна строка с TTL=.
    /// Возвращаем: ok, bestRttMs, lastTtl, successesCount.
    /// </summary>
    public static async Task<(bool ok, long bestRttMs, int ttl, int successCount)>
        TryPingMultiAsync(string ip, string sourceIp, int timeoutMsPerTry = 1200, int attempts = 3, int delayBetweenMs = 150)
    {
        bool anyOk = false;
        long bestRtt = long.MaxValue;
        int lastTtl = -1;
        int succ = 0;

        for (int i = 0; i < attempts; i++) {
            var psi = new ProcessStartInfo {
                FileName = "ping",
                Arguments = $"-4 -S {sourceIp} -n 1 -w {timeoutMsPerTry} {ip}",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi)!;
            string output = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();

            var ttlMatch = TtlRx.Match(output);
            if (ttlMatch.Success) {
                anyOk = true; succ++;
                if (int.TryParse(ttlMatch.Groups[1].Value, out var ttlVal)) lastTtl = ttlVal;

                // возьмём минимальный RTT среди найденных чисел в ответе
                var rttMatches = RttRx.Matches(output);
                foreach (Match m in rttMatches)
                    if (long.TryParse(m.Groups[1].Value, out var rttVal) && rttVal >= 0 && rttVal < bestRtt)
                        bestRtt = rttVal;
            }

            if (i + 1 < attempts) await Task.Delay(delayBetweenMs);
        }

        if (!anyOk) bestRtt = -1;
        return (anyOk, bestRtt, lastTtl, succ);
    }
}
