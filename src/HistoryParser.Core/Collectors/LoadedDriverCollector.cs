using HistoryParser.Core.Models;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Every driver and kernel module loaded right now, from the kernel's own list. A driver never shows up in Prefetch, BAM or
/// the other program records, so without this the only trace of one is its install event - which can be cleared, and which
/// a driver loaded without a service never writes. Windows does not record when a driver was loaded, so each is dated at
/// the scan: "it was loaded then" is the one thing that is certain.
/// </summary>
public sealed class LoadedDriverCollector : ICollector
{
    public string Name => "Loaded drivers";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        var bases = new IntPtr[4096];
        if (!EnumDeviceDrivers(bases, bases.Length * IntPtr.Size, out int needed))
            throw new UnauthorizedAccessException("The list of loaded drivers could not be read.");

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        string drive = Path.GetPathRoot(windows)!.TrimEnd('\\');
        var name = new char[1024];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int count = Math.Min(bases.Length, needed / IntPtr.Size), items = 0;
        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (bases[i] == IntPtr.Zero) continue; // without administrator rights Windows hides kernel addresses
            int length = GetDeviceDriverFileName(bases[i], name, name.Length);
            if (length <= 0) continue;
            string path = ToPath(new string(name, 0, length), windows, drive, ctx.Paths.Normalize);
            if (!seen.Add(path)) continue;
            ctx.Add(new Evidence
            {
                Source = EvidenceSource.LoadedDriver, Kind = EvidenceKind.LoadedModule, Path = path, TimeUtc = ctx.NowUtc, Origin = "the Windows kernel",
                Detail = "Loaded in the kernel when the scan ran (Windows does not record when a driver was loaded)",
            });
            items++;
        }
        ctx.Check("Drivers", "Loaded drivers", items > 0 ? CheckState.Ok : CheckState.Unknown,
            items > 0 ? $"{items} drivers and kernel modules are loaded now."
                      : "Could not be listed: Windows hides kernel addresses without administrator rights.");
        return items;
    }

    /// <summary>The kernel names its modules "\SystemRoot\System32\drivers\x.sys", "\??\C:\folder\x.sys" or "\Windows\system32\ntoskrnl.exe".</summary>
    internal static string ToPath(string kernelName, string windows, string drive, Func<string, string> normalize)
    {
        if (kernelName.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) return windows + kernelName[11..];
        if (kernelName.StartsWith(@"\??\", StringComparison.Ordinal)) return kernelName[4..];
        if (kernelName.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return normalize(kernelName);
        return kernelName.StartsWith('\\') ? drive + kernelName : normalize(kernelName);
    }
}
