using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using LanProbe.Models;

namespace LanProbe.Utils;

/// <summary>
/// Утилита для записи отчётов о найденных устройствах в различные
/// форматы. <see cref="ReportWriter"/> позволяет сохранить список
/// устройств в виде JSON, CSV или текстового файла. Благодаря этому
/// результаты сканирования могут быть легко проанализированы вручную
/// или обработаны другими инструментами.
/// </summary>
public static class ReportWriter
{
    /// <summary>
    /// Сериализует коллекцию устройств в JSON‑файл. Для
    /// сериализации используется <see cref="System.Text.Json"/> с
    /// включённым форматированием для удобства чтения.
    /// </summary>
    /// <param name="path">Путь к файлу, в который будет записан JSON.</param>
    /// <param name="devices">Коллекция устройств для сериализации.</param>
    public static async Task WriteJson(string path, IEnumerable<Device> devices)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        string json = JsonSerializer.Serialize(devices, options);
        await File.WriteAllTextAsync(path, json).ConfigureAwait(false);
    }

    /// <summary>
    /// Записывает коллекцию устройств в CSV‑файл. Каждая строка
    /// содержит поля IP, MAC, имя хоста, подсказки по ОС и типу,
    /// список открытых портов и атрибуты. Значения, содержащие
    /// запятые, кавычки или переводы строки, корректно экранируются
    /// согласно спецификации CSV.
    /// </summary>
    /// <param name="path">Путь к CSV‑файлу.</param>
    /// <param name="devices">Коллекция устройств для записи.</param>
    public static async Task WriteCsv(string path, IEnumerable<Device> devices)
    {
        var sb = new StringBuilder();
        // Заголовок
        sb.AppendLine("IP,MAC,Hostname,OS,Type,OpenPorts,Attributes");
        foreach (var d in devices)
        {
            var ports = string.Join(";", d.OpenPorts.OrderBy(p => p));
            // Атрибуты в виде key=value;key=value
            var attrs = string.Join(";", d.Attr.Select(kv => kv.Key + "=" + kv.Value));
            // Формируем массив строк для безопасного экранирования
            string[] cols = new string[]
            {
                Escape(d.Ip),
                Escape(d.Mac ?? string.Empty),
                Escape(d.Hostname ?? string.Empty),
                Escape(d.OsHint ?? string.Empty),
                Escape(d.TypeHint ?? string.Empty),
                Escape(ports),
                Escape(attrs)
            };
            sb.AppendLine(string.Join(",", cols));
        }
        await File.WriteAllTextAsync(path, sb.ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// Записывает коллекцию устройств в простой текстовый файл. Для
    /// каждого устройства вызывается метод <see cref="Device.ToString"/>,
    /// и результат отделяется пустой строкой. Такой формат пригоден
    /// для быстрого ознакомления с результатами сканирования.
    /// </summary>
    /// <param name="path">Путь к файлу.</param>
    /// <param name="devices">Список устройств для сохранения.</param>
    public static async Task WriteText(string path, IEnumerable<Device> devices)
    {
        var sb = new StringBuilder();
        foreach (var d in devices)
        {
            sb.AppendLine(d.ToString().Trim());
            sb.AppendLine();
        }
        await File.WriteAllTextAsync(path, sb.ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// Экранирует строку для использования в CSV. Если строка
    /// содержит запятую, кавычку или перевод строки, она
    /// заключается в двойные кавычки, а кавычки внутри неё
    /// удваиваются.
    /// </summary>
    /// <param name="value">Строка для экранирования.</param>
    /// <returns>Экранированная строка, пригодная для записи в CSV.</returns>
    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
        {
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}