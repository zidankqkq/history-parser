using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Reads (never writes) the private memory of a few Windows processes that keep paths of recently
/// run programs: Explorer, the Diagnostic Policy Service (DPS), the Program Compatibility Assistant
/// (PcaSvc), Connected User Experiences (DiagTrack), Application Information (Appinfo, which starts elevated
/// programs) and the DCOM launcher (DcomLaunch), plus any running Java process (whose
/// command line also lists the jars on its classpath).
/// CSRSS is a protected process and cannot be read from user mode; that is reported, not bypassed.
/// </summary>
public sealed class ProcessMemoryCollector : ICollector
{
    public string Name => "Process memory strings";

    const long MaxBytesPerProcess = 1L << 30;
    /// <summary>The Java heap is one huge region of game objects; paths live in the smaller native heaps.</summary>
    const long MaxJavaRegion = 256L << 20;
    const int MinStringLength = 8;

    static readonly Regex PathPattern = new(
        @"(?:[a-zA-Z]:\\|\\Device\\HarddiskVolume\d+\\)[^<>:""|?*\r\n\t\0]{1,260}?\.(?:exe|dll|jar)(?![a-zA-Z0-9])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Options.ScanProcessMemory) return 0;
        bool debug = WinApi.TryEnableDebugPrivilege();

        var targets = new List<(string Label, int Pid, bool Java)>();
        // Appinfo starts every "Run as administrator" program; DcomLaunch starts COM servers and brokered apps.
        foreach (var svc in new[] { "DPS", "PcaSvc", "DiagTrack", "Appinfo", "DcomLaunch" })
        {
            var s = WinApi.QueryService(svc);
            if (s.Pid > 0 && targets.All(t => t.Pid != s.Pid)) targets.Add(($"{svc} (svchost)", s.Pid, false));
        }
        foreach (var name in new[] { "explorer", "javaw", "java" })
            foreach (var p in Process.GetProcessesByName(name))
                using (p) targets.Add(($"{name}.exe", p.Id, name != "explorer"));

        int items = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var failures = new List<string>();
        foreach (var (label, pid, java) in targets)
        {
            ct.ThrowIfCancellationRequested();
            if (java && WinApi.GetCommandLine(pid) is { } cmd)
                items += OnString(ctx, $"{label} command line", pid, cmd, seen);
            try
            {
                var sw = Stopwatch.StartNew();
                long scanned = ScanProcess(pid, java ? MaxJavaRegion : long.MaxValue, ct,
                    s => items += OnString(ctx, label, pid, s, seen));
                ctx.Check("Memory", $"{label} pid {pid}", CheckState.Ok,
                    $"Scanned {scanned / (1024 * 1024):N0} MB of private memory in {sw.Elapsed.TotalSeconds:0.0}s.");
            }
            catch (UnauthorizedAccessException e)
            {
                failures.Add($"{label}: {e.Message}");
            }
        }

        ctx.Check("Memory", "csrss.exe", CheckState.Unknown,
            "Protected process (PPL): its memory cannot be read without a kernel driver. Not scanned by design.");
        if (!debug)
            failures.Add("SeDebugPrivilege could not be enabled (not running as administrator?)");
        if (failures.Count > 0)
            ctx.Check("Memory", "Process access", CheckState.Warning, string.Join("; ", failures));
        return items;
    }

    int OnString(ScanContext ctx, string label, int pid, string s, HashSet<string> seen)
    {
        int added = 0;
        if (DpsStringParser.Match(s) is { } dps)
        {
            if (seen.Add($"{pid}|dps|{dps.Name}|{dps.Time}"))
            {
                ctx.MemoryHits.Add(new MemoryHit { Process = label, Pid = pid, Path = dps.Name, RecordedTime = dps.Time, Raw = Clip(s) });
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.ProcessMemory, Kind = EvidenceKind.Presence, Path = "?\\" + dps.Name,
                    Origin = label, Detail = $"DPS string, recorded time {dps.Time} (timezone not verified — shown as written)",
                });
                added++;
            }
        }

        foreach (Match m in PathPattern.Matches(s))
        {
            var path = ctx.Paths.Normalize(CleanPath(m.Value));
            // Partly overwritten heap strings produce paths with stray non-ASCII characters. Keep a
            // non-ASCII path only when it resolves to a real file (e.g. a user name in another script).
            if (path.Any(c => c > 0x7F) && !File.Exists(path)) continue;
            if (!seen.Add($"{pid}|{path}")) continue;
            ctx.MemoryHits.Add(new MemoryHit { Process = label, Pid = pid, Path = path, Raw = Clip(s) });
            ctx.Add(new Evidence
            {
                Source = EvidenceSource.ProcessMemory, Kind = EvidenceKind.Presence, Path = path, Origin = label,
                Detail = $"Found in {label}",
            });
            added++;
        }
        return added;
    }

    /// <summary>Paths inside JSON blobs are escaped ("C:\\Program Files\\x.exe").</summary>
    internal static string CleanPath(string p)
    {
        while (p.Contains(@"\\", StringComparison.Ordinal)) p = p.Replace(@"\\", @"\");
        return p;
    }

    static string Clip(string s) => s.Length > 300 ? s[..300] + "…" : s;

    /// <summary>Reads committed private regions and hands every candidate string to <paramref name="onString"/>.</summary>
    public static long ScanProcess(int pid, long maxRegion, CancellationToken ct, Action<string> onString,
        byte[][]? asciiNeedles = null, byte[][]? wideNeedles = null, bool multiLine = false)
    {
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) throw new UnauthorizedAccessException($"OpenProcess failed (error {Marshal.GetLastWin32Error()})");

        long scanned = 0;
        IntPtr address = IntPtr.Zero;
        var buffer = new byte[4 << 20];
        var mbiSize = (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        while (scanned < MaxBytesPerProcess && VirtualQueryEx(h, address, out var mbi, mbiSize) != UIntPtr.Zero)
        {
            ct.ThrowIfCancellationRequested();
            long regionSize = (long)(ulong)mbi.RegionSize;
            bool readable = mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 && mbi.Protect != 0 &&
                            regionSize <= maxRegion;
            if (readable)
            {
                for (long offset = 0; offset < regionSize && scanned < MaxBytesPerProcess; offset += buffer.Length)
                {
                    int chunk = (int)Math.Min(buffer.Length, regionSize - offset);
                    if (!ReadProcessMemory(h, mbi.BaseAddress + (nint)offset, buffer, (UIntPtr)chunk, out var read)) break;
                    int n = (int)(ulong)read;
                    scanned += n;
                    StringExtractor.Extract(buffer.AsSpan(0, n), MinStringLength, onString,
                        asciiNeedles ?? StringExtractor.FileNeedlesAscii, wideNeedles ?? StringExtractor.FileNeedlesWide, multiLine);
                }
            }
            long next = (long)mbi.BaseAddress + regionSize;
            if (next <= (long)address) break;
            address = (IntPtr)next;
        }
        return scanned;
    }
}

public static class StringExtractor
{
    public static readonly byte[][] FileNeedlesAscii = Needles(Encoding.ASCII);
    public static readonly byte[][] FileNeedlesWide = Needles(Encoding.Unicode);
    /// <summary>Console prompts: every prompt contains a drive path ("C:\").</summary>
    public static readonly byte[][] PromptNeedlesAscii = [Encoding.ASCII.GetBytes(":\\")];
    public static readonly byte[][] PromptNeedlesWide = [Encoding.Unicode.GetBytes(":\\")];

    static byte[][] Needles(Encoding e) =>
        new[] { ".exe", ".EXE", ".dll", ".DLL", ".jar", ".JAR", ".Exe", ".Dll", ".Jar", "!!" }.Select(e.GetBytes).ToArray();

    /// <summary>Windows input calls a script needs to fake clicks or key presses (for reading whole scripts out of PowerShell).</summary>
    public static readonly byte[][] InputNeedlesAscii = InputNeedles(Encoding.ASCII);
    public static readonly byte[][] InputNeedlesWide = InputNeedles(Encoding.Unicode);

    static byte[][] InputNeedles(Encoding e) =>
        new[] { "mouse_event", "SendInput", "keybd_event", "MOUSEEVENTF_", "SendKeys", "PostMessage", "SendMessage" }.Select(e.GetBytes).ToArray();

    /// <summary>The longest run grown around one hit: scripts are long, but a run has to end somewhere.</summary>
    const int MaxRun = 256 * 1024;

    static bool AsciiPrintable(byte b) => b is >= 0x20 and < 0x7F;
    static bool AsciiText(byte b) => AsciiPrintable(b) || b is (byte)'\r' or (byte)'\n' or (byte)'\t';

    static bool WidePrintable(ReadOnlySpan<byte> d, int i)
    {
        if (i < 0 || i + 1 >= d.Length) return false;
        char c = (char)(d[i] | (d[i + 1] << 8));
        return c is >= ' ' and < (char)0x7F || (c >= 0xA0 && c < 0xD800 && char.IsLetterOrDigit(c));
    }

    static bool WideText(ReadOnlySpan<byte> d, int i) =>
        WidePrintable(d, i) || (i >= 0 && i + 1 < d.Length && d[i + 1] == 0 && d[i] is (byte)'\r' or (byte)'\n' or (byte)'\t');

    /// <summary>
    /// Finds every occurrence of a file extension ('.exe' / '.dll' / '.jar') or DPS '!!' marker in
    /// ASCII or UTF-16LE, grows it to the surrounding run of printable characters, and emits that
    /// run once. Searching for the needles first (vectorized) is far faster than walking every byte.
    /// </summary>
    public static void Extract(ReadOnlySpan<byte> data, int minLength, Action<string> onString) =>
        Extract(data, minLength, onString, FileNeedlesAscii, FileNeedlesWide);

    /// <param name="multiLine">Keep line breaks and tabs inside a run, so a whole script comes out as one string.</param>
    public static void Extract(ReadOnlySpan<byte> data, int minLength, Action<string> onString,
        byte[][] asciiNeedles, byte[][] wideNeedles, bool multiLine = false)
    {
        var hits = new List<int>();
        int max = multiLine ? MaxRun : int.MaxValue / 4;

        Collect(data, asciiNeedles, hits);
        int lastEnd = -1;
        foreach (var pos in hits)
        {
            if (pos < lastEnd) continue;
            int s = pos, e = pos;
            while (s > 0 && pos - s < max && (multiLine ? AsciiText(data[s - 1]) : AsciiPrintable(data[s - 1]))) s--;
            while (e < data.Length && e - pos < max && (multiLine ? AsciiText(data[e]) : AsciiPrintable(data[e]))) e++;
            if (e - s >= minLength) onString(Encoding.ASCII.GetString(data[s..e]));
            lastEnd = e;
        }

        hits.Clear();
        Collect(data, wideNeedles, hits);
        lastEnd = -1;
        foreach (var pos in hits)
        {
            if (pos < lastEnd) continue;
            int s = pos, e = pos;
            while (pos - s < max * 2 && (multiLine ? WideText(data, s - 2) : WidePrintable(data, s - 2))) s -= 2;
            while (e - pos < max * 2 && (multiLine ? WideText(data, e) : WidePrintable(data, e))) e += 2;
            if ((e - s) / 2 >= minLength) onString(Encoding.Unicode.GetString(data[s..e]));
            lastEnd = e;
        }
    }

    static void Collect(ReadOnlySpan<byte> data, byte[][] needles, List<int> hits)
    {
        foreach (var needle in needles)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int i = data[offset..].IndexOf(needle);
                if (i < 0) break;
                hits.Add(offset + i);
                offset += i + needle.Length;
            }
        }
        hits.Sort();
    }
}
