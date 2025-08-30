using System.Text.Json;
using LanProbe.Core.Models;

namespace LanProbe.Core.Export;

public static class JsonExporter {
    public static void Save(string path, IEnumerable<DeviceFact> facts) {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(facts, opts));
    }
}
