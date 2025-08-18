using System.Diagnostics;
using System.Text;
using System.Threading;

namespace LanProbe.Utils;

/// <summary>
/// Реализует простую текстовую прогресс‑бар для консольных приложений.
/// Показывает количество обработанных элементов, процент выполнения и
/// приблизительное время до завершения. Не предназначен для
/// многократного параллельного использования: отображает один
/// прогресс‑бар в процессе.
/// </summary>
public static class ProgressBar
{
    private static readonly object _lock = new();
    private static int _total;
    private static int _done;
    private static readonly Stopwatch _sw = new();
    private static CancellationTokenSource? _cts;
    private static Task? _pumpTask;
    private static bool _finished;

    /// <summary>
    /// Запускает прогресс‑бар для указанного количества элементов.
    /// </summary>
    /// <param name="total">Общее количество элементов, которое будет обработано.</param>
    public static void Start(int total)
    {
        lock (_lock)
        {
            // Стартуем только если ещё не запущено
            if (_pumpTask is not null && !_pumpTask.IsCompleted) return;

            _total = Math.Max(1, total);
            _done = 0;
            _finished = false;
            _sw.Restart();

            _cts?.Dispose();
            _cts = new CancellationTokenSource();

            // Один фоновый таск, который перерисовывает строку раз в секунду
            _pumpTask = Task.Run(async () =>
            {
                try
                {
                    while (!_cts!.IsCancellationRequested)
                    {
                        Render(force: true);
                        await Task.Delay(1000, _cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    // normal termination
                }
            });

            Render(force: true);
        }
    }

    /// <summary>
    /// Увеличивает счётчик выполненных элементов и обновляет отображение.
    /// </summary>
    /// <param name="step">Количество элементов, завершённых с момента последнего вызова.</param>
    public static void Tick(int step = 1)
    {
        // Лёгкий инкремент без гонок
        Interlocked.Add(ref _done, step);
        // Позволим чаще обновить строку, но без спама: рендер внутри сам дешёво работает
        Render(force: true);
    }

    /// <summary>
    /// Завершает прогресс‑бар и выводит итоговое время.
    /// </summary>
    public static void Finish()
    {
        lock (_lock)
        {
            _done = _total;
            _finished = true;

            Render(force: true);
            Console.WriteLine();

            _sw.Stop();
            _cts?.Cancel();
        }
        try { _pumpTask?.Wait(); } catch { /* ignore */ }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            _pumpTask = null;
        }
    }

    // Рисует прогресс‑бар. Может быть вызвано часто.
    private static void Render(bool force = false)
    {
        lock (_lock)
        {
            double p = Math.Clamp((double)_done / Math.Max(1, _total), 0, 1);
            int width = Math.Clamp(Console.WindowWidth - 30, 10, 80);
            int filled = (int)Math.Round(p * width);

            var bar = new StringBuilder(width + 32);
            bar.Append('[');
            bar.Append(new string('#', filled));
            bar.Append(new string('-', width - filled));
            bar.Append(']');

            string timeText;
            if (_finished)
            {
                var ts = _sw.Elapsed;
                timeText = $"Время {ts:mm\\:ss}";
            }
            else
            {
                string eta = "ETA --:--";
                if (_done > 0)
                {
                    double rate = _done / Math.Max(0.001, _sw.Elapsed.TotalSeconds); // items/sec
                    double remain = (_total - _done) / Math.Max(0.001, rate);
                    var ts = TimeSpan.FromSeconds(remain);
                    eta = $"ETA {ts:mm\\:ss}";
                }
                timeText = eta;
            }

            var line = $"{bar}  {_done,4}/{_total,-4}  {(p * 100),6:0.0}%  {timeText}";
            Console.Write("\r" + line.PadRight(Math.Max(0, Console.WindowWidth - 1)));
        }
    }
}