using System.Runtime.InteropServices;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Tests;

// Suspends a live thread and reads it back from the system process list - depends on OS thread scheduling that a
// headless CI runner does not reliably reproduce. Runs on a real machine; excluded from CI (Category=Integration).
[Trait("Category", "Integration")]
public class ThreadListTests
{
    [DllImport("kernel32.dll")] static extern int GetCurrentThreadId();
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, int tid);
    [DllImport("kernel32.dll")] static extern int SuspendThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern int ResumeThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [Fact]
    public void The_system_process_list_shows_our_own_threads_and_which_are_suspended()
    {
        // Thread suspend/read-back depends on OS scheduling a headless CI runner does not reproduce; run on a real machine.
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        int tid = 0;
        using var ready = new ManualResetEventSlim();
        using var stop = new ManualResetEventSlim();
        var thread = new Thread(() => { tid = GetCurrentThreadId(); ready.Set(); stop.Wait(); }) { IsBackground = true };
        thread.Start();
        ready.Wait();

        IntPtr h = OpenThread(0x0002 /* THREAD_SUSPEND_RESUME */, false, tid);
        Assert.NotEqual(IntPtr.Zero, h);
        try
        {
            Assert.True(SuspendThread(h) >= 0);
            var threads = WinApi.Threads(Environment.ProcessId);
            var mine = Assert.Single(threads, t => t.Tid == tid);
            Assert.True(mine.Suspended);
            Assert.NotNull(mine.CreatedUtc);
            Assert.True((DateTime.UtcNow - mine.CreatedUtc!.Value).Duration() < TimeSpan.FromMinutes(5));
            Assert.Contains(threads, t => t.Tid != tid && !t.Suspended); // the rest are not

            ResumeThread(h);
            Assert.False(Assert.Single(WinApi.Threads(Environment.ProcessId), t => t.Tid == tid).Suspended);
        }
        finally
        {
            ResumeThread(h);
            CloseHandle(h);
            stop.Set();
        }
    }
}
