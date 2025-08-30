namespace LanProbe.Core.Enrichment;

public class MacVendorLookup {
    private readonly Dictionary<string,string> _db = new();

    public MacVendorLookup(string filePath) {
        if (File.Exists(filePath)) {
            foreach (var line in File.ReadLines(filePath)) {
                var parts = line.Split(',', 2);
                if (parts.Length == 2) _db[parts[0].ToLower()] = parts[1];
            }
        }
    }

    public string? Find(string? mac) {
        if (mac == null) return null;
        var prefix = string.Join("-", mac.Split('-').Take(3));
        return _db.TryGetValue(prefix, out var vendor) ? vendor : null;
    }
}
