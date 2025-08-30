using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace LanProbe.Core.Analysis
{
    /// Improved OUI lookup with MA-L (24-bit) and MA-S (36-bit) support and randomized MAC detection.
    public sealed class OuiVendorLookup : IOuiVendorLookup
    {
        private readonly Dictionary<string, string> _maL = new(StringComparer.OrdinalIgnoreCase); // "AA-BB-CC"
        private readonly Dictionary<string, string> _maS = new(StringComparer.OrdinalIgnoreCase); // "AA-BB-CC-DD-EE"

        public OuiVendorLookup(string? dataDir)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(dataDir) && Directory.Exists(dataDir))
                {
                    var ouiCsv = Path.Combine(dataDir, "oui.csv");
                    if (File.Exists(ouiCsv))
                        foreach (var line in File.ReadLines(ouiCsv).Skip(1))
                        {
                            var parts = SplitCsv(line);
                            if (parts.Length >= 3)
                            {
                                var assignment = parts[1].Trim().ToUpperInvariant().Replace(":", "-");
                                if (assignment.Length == 8) _maL[assignment] = parts[2].Trim();
                            }
                        }

                    var oui36Csv = Path.Combine(dataDir, "oui36.csv");
                    if (File.Exists(oui36Csv))
                        foreach (var line in File.ReadLines(oui36Csv).Skip(1))
                        {
                            var parts = SplitCsv(line);
                            if (parts.Length >= 3)
                            {
                                var assignment = parts[1].Trim().ToUpperInvariant().Replace(":", "-");
                                if (assignment.Length == 14) _maS[assignment] = parts[2].Trim();
                            }
                        }

                    var nmap = Path.Combine(dataDir, "nmap-mac-prefixes");
                    if (File.Exists(nmap))
                        foreach (var line in File.ReadLines(nmap))
                        {
                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;
                            var parts = line.Split(new[] { '\t', ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length == 2 && parts[0].Length >= 8)
                            {
                                var key = parts[0].Trim().ToUpperInvariant().Replace(":", "-");
                                if (key.Length == 8 && !_maL.ContainsKey(key)) _maL[key] = parts[1].Trim();
                            }
                        }

                    var manuf = Path.Combine(dataDir, "manuf");
                    if (File.Exists(manuf))
                        foreach (var line in File.ReadLines(manuf))
                        {
                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;
                            var parts = line.Split(new[] { '\t', ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length == 2)
                            {
                                var k = parts[0].Trim().ToUpperInvariant().Replace(":", "-");
                                if (k.Length == 8 && !_maL.ContainsKey(k)) _maL[k] = parts[1].Trim();
                                if (k.Length == 14 && !_maS.ContainsKey(k)) _maS[k] = parts[1].Trim();
                            }
                        }
                }
            }
            catch { /* lookup опционален */ }
        }

        public string? Find(string? mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return null;
            var parts = Normalize(mac);
            if (parts is null) return null;

            var key36 = string.Join("-", parts.Take(5));
            if (_maS.TryGetValue(key36, out var v36)) return v36;

            var key24 = string.Join("-", parts.Take(3));
            if (_maL.TryGetValue(key24, out var v24)) return v24;

            return null;
        }

        public bool IsLocallyAdministered(string? mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return false;
            var parts = Normalize(mac);
            if (parts is null) return false;
            if (byte.TryParse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b0))
                return (b0 & 0x02) != 0;
            return false;
        }

        private static string[]? Normalize(string mac)
        {
            var s = mac.Trim().ToUpperInvariant().Replace(":", "-");
            var p = s.Split('-');
            if (p.Length < 3) return null;
            for (int i = 0; i < p.Length; i++) if (p[i].Length == 1) p[i] = "0" + p[i];
            return p;
        }

        private static string[] SplitCsv(string line)
        {
            var list = new List<string>(); bool inQ = false;
            var cur = new System.Text.StringBuilder();
            foreach (var ch in line)
            {
                if (ch == '\"') { inQ = !inQ; continue; }
                if (ch == ',' && !inQ) { list.Add(cur.ToString()); cur.Clear(); }
                else cur.Append(ch);
            }
            list.Add(cur.ToString());
            return list.ToArray();
        }
    }
}
