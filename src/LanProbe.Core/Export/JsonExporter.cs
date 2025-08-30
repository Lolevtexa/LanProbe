using System.Text.Json;
using LanProbe.Core.Models;

namespace LanProbe.Core.Export;

/// <summary>
/// Класс JsonExporter.
/// </summary>
public static class JsonExporter {
    /// <summary>
    /// Документация для Save.
    /// </summary>
    public static void Save(string path, IEnumerable<DeviceFact> facts) {
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(facts, opts));
    }
}
