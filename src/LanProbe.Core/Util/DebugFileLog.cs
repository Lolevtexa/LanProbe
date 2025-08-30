using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Threading;

namespace LanProbe.Core.Util
{
    public static class DebugFileLog
    {
        private static readonly object _initLock = new();
        private static volatile bool _inited = false;
        private static string _runDir = "";
        private static readonly ConcurrentQueue<string> _queue = new();
        private static int _flushing = 0;

        public static void Init(string? baseDir = null)
        {
            if (_inited) return;
            lock (_initLock)
            {
                if (_inited) return;
                var ts = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss", CultureInfo.InvariantCulture);
                var root = string.IsNullOrWhiteSpace(baseDir) ? "logs" : baseDir;
                _runDir = Path.Combine(root, "step3", ts);
                Directory.CreateDirectory(_runDir);
                _inited = true;
            }
        }

        public static void WriteLine(string ip, string line)
        {
            if (!_inited) Init();
            var safeIp = string.IsNullOrWhiteSpace(ip) ? "misc" : ip.Replace(':','_').Replace('/', '_');
            var path = Path.Combine(_runDir, $"{safeIp}.log");
            _queue.Enqueue($"{DateTime.Now:HH:mm:ss.fff} {line} >>{path}");
            FlushQueued(path);
        }

        // простая (без таймера) синхронная «очередь в файл»
        private static void FlushQueued(string path)
        {
            if (Interlocked.Exchange(ref _flushing, 1) != 0) return;
            try
            {
                using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                using var sw = new StreamWriter(fs);
                while (_queue.TryDequeue(out var item))
                {
                    // в item в конце есть " >>path"; отделим полезный текст
                    var idx = item.LastIndexOf(" >>", StringComparison.Ordinal);
                    var text = idx >= 0 ? item.Substring(0, idx) : item;
                    sw.WriteLine(text);
                }
            }
            finally { Interlocked.Exchange(ref _flushing, 0); }
        }
    }
}
