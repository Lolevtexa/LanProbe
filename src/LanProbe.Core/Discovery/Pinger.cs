using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using LanProbe.Core.Util;

namespace LanProbe.Core.Discovery;

/// <summary>
/// Класс Pinger.
/// </summary>
public static class Pinger {
    // TTL: "TTL=64" / "ttl = 128"
    static readonly Regex TtlRx = new(@"TTL\s*=\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // RTT (EN): "time=3ms" или "time<1ms"
    static readonly Regex RttEnEq = new(@"time\s*=\s*(\d+)\s*ms", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex RttEnLt = new(@"time\s*<\s*1\s*ms",       RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // RTT (RU): "время=3мс" или "время<1мс"
    static readonly Regex RttRuEq = new(@"время\s*=\s*(\d+)\s*мс", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex RttRuLt = new(@"время\s*<\s*1\s*мс",     RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// Пингуем несколько раз. Успех = есть хоть одна строка с TTL=.
    /// Возвращаем: ok, bestRttMs (минимум), lastTtl, successCount.
    public static async Task<(bool ok, long bestRttMs, int ttl, int successCount)>
        TryPingMultiAsync(string ip, string sourceIp, int timeoutMsPerTry = 1200, int attempts = 3, int delayBetweenMs = 150)
    {
        bool anyOk = false;
        long bestRtt = long.MaxValue;
        int lastTtl = -1;
        int succ = 0;

        // правильная OEM кодировка консольного ping.exe (cp866 на RU, cp437/850 на EN и т.д.)
        Encoding oem;
        try {
            oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        } catch {
            oem = Encoding.UTF8; // fallback
        }

        for (int i = 0; i < attempts; i++) {
            var psi = new ProcessStartInfo {
                FileName = "ping",
                Arguments = $"-4 -S {sourceIp} -n 1 -w {timeoutMsPerTry} {ip}",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = oem
            };

            using var p = Process.Start(psi)!;
            string output = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();

            var ttlMatch = TtlRx.Match(output);
            if (ttlMatch.Success) {
                anyOk = true; succ++;
                if (int.TryParse(ttlMatch.Groups[1].Value, out var ttlVal)) lastTtl = ttlVal;

                // сначала ищем точное "=", затем "<1"
                var rttCandidates = new List<long>();
                foreach (Match m in RttEnEq.Matches(output)) if (long.TryParse(m.Groups[1].Value, out var v)) rttCandidates.Add(v);
                foreach (Match m in RttRuEq.Matches(output)) if (long.TryParse(m.Groups[1].Value, out var v)) rttCandidates.Add(v);
                if (RttEnLt.IsMatch(output) || RttRuLt.IsMatch(output)) rttCandidates.Add(0);

                if (rttCandidates.Count > 0) {
                    var min = rttCandidates.Min();
                    if (min >= 0 && min < bestRtt) bestRtt = min;
                }
            }

            if (i + 1 < attempts) await Task.Delay(delayBetweenMs);
        }

        DebugFileLog.WriteLine(ip, $"[ICMP][DEBUG] final ok={anyOk} rtt={bestRtt} ttl={lastTtl}; succ=[{string.Join(",", succ)}]");
        if (!anyOk || bestRtt == long.MaxValue) bestRtt = -1;
        return (anyOk, bestRtt, lastTtl, succ);
    }
}