using LanProbe.Core;
using LanProbe.Core.Models;
using System.Text;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length == 0 || args[0].StartsWith("-") || args[0].StartsWith("/"))
        {
            Console.WriteLine("usage: LanProbe.Example <CIDR> [--mode debug|log|quiet] [--out out] [--logs logs] [--raw data/raw] [--oui data/oui]");
            return 2;
        }

        var cfg = ParseArgs(args);
        return await LanProbeApp.RunAsync(cfg);
    }

    // Оставляем только выбор аргументов в примере — всё остальное в ядре
    private static RunConfig ParseArgs(string[] args)
    {
        string cidr = args[0];
        var map = ArgsToMap(args.Skip(1).ToArray());

        RunMode mode = map.GetOrDefault("--mode", "log")!.ToLower() switch
        {
            "debug" => RunMode.Debug,
            "quiet" => RunMode.Quiet,
            _ => RunMode.Log
        };

        // ВАЖНО: у Default есть обязательный параметр cidr
        var baseCfg = RunConfig.Default(cidr);

        // Переопределяем только то, что передали ключами
        var cfg = baseCfg with
        {
            Mode   = mode,
            OutDir = map.GetOrDefault("--out",  baseCfg.OutDir)!,
            LogsDir= map.GetOrDefault("--logs", baseCfg.LogsDir)!,
            RawDir = map.GetOrDefault("--raw",  baseCfg.RawDir)!,
            OuiDir = map.GetOrDefault("--oui",  baseCfg.OuiDir)!
        };

        return cfg;
    }

    private static Dictionary<string, string?> ArgsToMap(string[] rest)
    {
        var d = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < rest.Length; i++)
        {
            var a = rest[i];
            if (!a.StartsWith("--")) continue;
            var val = (i + 1 < rest.Length && !rest[i + 1].StartsWith("--")) ? rest[++i] : null;
            d[a] = val;
        }
        return d;
    }

    private static string? GetOrDefault(this Dictionary<string, string?> d, string key, string def)
        => d.TryGetValue(key, out var v) ? (v ?? def) : def;
}
