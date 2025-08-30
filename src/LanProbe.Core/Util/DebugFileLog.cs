using System.Collections.Concurrent;
using System.Globalization;

namespace LanProbe.Core.Util
{
    /// <summary>
    /// Класс DebugFileLog.
    /// </summary>
    public static class DebugFileLog
    {
        private static readonly object _initLock = new();
        private static volatile bool _inited = false;

        private static string _rootDir = "logs";
        private static string _ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);

        // Категория для IP: "unreachable" (по умолчанию) или "alive"
        private static readonly ConcurrentDictionary<string, string> _categoryByIp = new();

        private static readonly ConcurrentQueue<string> _queue = new();
        private static int _flushing = 0;

        /// <summary>
        /// Метод Init.
        /// </summary>
        /// <param name="rootDir">Параметр rootDir.</param>
        public static void Init(string? rootDir)
        {
            if (_inited) return;
            lock (_initLock)
            {
                if (_inited) return;
                _rootDir = string.IsNullOrWhiteSpace(rootDir) ? "logs" : rootDir!;
                _ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);

                Directory.CreateDirectory(Path.Combine(_rootDir, _ts, "unreachable"));
                Directory.CreateDirectory(Path.Combine(_rootDir, _ts, "alive"));

                _inited = true;
            }
        }

        /// <summary>
        /// Метод MarkAlive.
        /// </summary>
        /// <param name="ip">Параметр ip.</param>
        public static void MarkAlive(string ip) => SetCategory(ip, "alive");
        /// <summary>
        /// Метод MarkUnreachable.
        /// </summary>
        /// <param name="ip">Параметр ip.</param>
        public static void MarkUnreachable(string ip) => SetCategory(ip, "unreachable");

        private static void SetCategory(string ip, string category)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;
            if (!_inited) Init(_rootDir);

            var newCat = string.IsNullOrWhiteSpace(category) ? "unreachable" : category;
            var oldCat = _categoryByIp.AddOrUpdate(ip, newCat, (_, __) => newCat);

            if (oldCat != newCat)
                TryMoveExisting(ip, oldCat, newCat);
        }

        /// <summary>
        /// Метод WriteLine.
        /// </summary>
        /// <param name="ip">Параметр ip.</param>
        /// <param name="message">Параметр message.</param>
        public static void WriteLine(string ip, string message)
        {
            if (!_inited) Init(_rootDir);
            var cat = _categoryByIp.GetOrAdd(ip ?? "_common", "unreachable");
            var path = PathFor(ip ?? "_common", cat);
            _queue.Enqueue($"{DateTime.UtcNow:O} [{ip}] {message} >>{path}");
            TryFlush();
        }

        private static string PathFor(string ip, string category)
        {
            var cat = string.IsNullOrWhiteSpace(category) ? "unreachable" : category;
            var dir = Path.Combine(_rootDir, _ts, cat);
            Directory.CreateDirectory(dir);
            var safe = string.IsNullOrWhiteSpace(ip) ? "_common" : ip;
            return Path.Combine(dir, $"{safe}.log");
        }

        private static void TryMoveExisting(string ip, string oldCat, string newCat)
        {
            try
            {
                var oldFile = PathFor(ip, oldCat);
                var newFile = PathFor(ip, newCat);

                if (File.Exists(oldFile))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(newFile)!);
                    if (File.Exists(newFile))
                    {
                        File.AppendAllText(newFile, File.ReadAllText(oldFile));
                        File.Delete(oldFile);
                    }
                    else
                    {
                        File.Move(oldFile, newFile);
                    }
                }
            }
            catch { /* best-effort */ }
        }

        private static void TryFlush()
        {
            if (Interlocked.CompareExchange(ref _flushing, 1, 0) != 0) return;
            try
            {
                while (_queue.TryDequeue(out var item))
                {
                    var idx = item.LastIndexOf(" >>", StringComparison.Ordinal);
                    var text = idx >= 0 ? item[..idx] : item;
                    var path = idx >= 0 ? item[(idx + 3)..] : PathFor("_common", "unreachable");

                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    File.AppendAllText(path, text + Environment.NewLine);
                }
            }
            finally
            {
                Interlocked.Exchange(ref _flushing, 0);
            }
        }
    }
}
