using System;
using System.Text.Json.Serialization;

namespace LanProbe.Core.Models
{
    /// <summary>
    /// Режимы запуска CLI.
    /// </summary>
    public enum RunMode { Debug, Log, Quiet }

    /// <summary>
    /// Централизованная конфигурация запуска.
    /// Все пути/таймауты/конкурентность хранятся здесь и передаются между стадиями.
    /// </summary>
    public sealed record RunConfig(
        [property: JsonPropertyName("cidr")]            string Cidr,
        [property: JsonPropertyName("out_dir")]         string OutDir,
        [property: JsonPropertyName("logs_dir")]        string LogsDir,
        [property: JsonPropertyName("raw_dir")]         string RawDir,
        [property: JsonPropertyName("oui_dir")]         string OuiDir,
        [property: JsonPropertyName("mode")]            RunMode Mode,
        [property: JsonPropertyName("ping_attempts")]   int PingAttempts,
        [property: JsonPropertyName("ping_timeout_ms")] int PingTimeoutMs,
        [property: JsonPropertyName("ping_concurrency")]int PingConcurrency,
        [property: JsonPropertyName("connect_timeout_ms")] int ConnectTimeoutMs,
        [property: JsonPropertyName("banner_timeout_ms")]  int BannerTimeoutMs,
        [property: JsonPropertyName("port_scan_concurrency")] int PortScanConcurrency,
        [property: JsonPropertyName("high_rtt_ms")]     int HighRttMs
    )
    {
        /// <summary>Фабрика по умолчанию.</summary>
        public static RunConfig Default(string cidr) => new(
            Cidr: cidr,
            OutDir: "out",
            LogsDir: "logs",
            RawDir: "data/raw",
            OuiDir: "data/oui",
            Mode: RunMode.Log,
            PingAttempts: 3,
            PingTimeoutMs: 1200,
            PingConcurrency: 64,
            ConnectTimeoutMs: 1100,
            BannerTimeoutMs: 2000,
            PortScanConcurrency: 64,
            HighRttMs: 30
        );
    }
}
