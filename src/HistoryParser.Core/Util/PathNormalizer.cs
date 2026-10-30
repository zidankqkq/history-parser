using System.Globalization;
using System.Runtime.InteropServices;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Util;

/// <summary>
/// Turns the many path spellings Windows artifacts use into one drive-letter form, so the
/// same file from Prefetch, BAM, PCA ... lands in the same record:
/// <c>\Device\HarddiskVolume3\x</c>, <c>\VOLUME{01d..-a1b2c3d4}\x</c>, <c>{KnownFolderGuid}\x</c>,
/// <c>\\?\C:\x</c>, <c>%ProgramFiles%\x</c>.
/// </summary>
public sealed class PathNormalizer
{
    readonly List<(string Prefix, string Drive)> _devices;
    readonly Dictionary<uint, string> _serials;
    readonly Dictionary<Guid, string> _knownFolders;

    public PathNormalizer(IEnumerable<KeyValuePair<string, string>> deviceToDrive,
        IDictionary<uint, string> serialToDrive, IDictionary<Guid, string> knownFolders)
    {
        _devices = deviceToDrive
            .Select(kv => (kv.Key.TrimEnd('\\'), kv.Value.TrimEnd('\\')))
            .OrderByDescending(d => d.Item1.Length)
            .ToList();
        _serials = new Dictionary<uint, string>(serialToDrive);
        _knownFolders = new Dictionary<Guid, string>(knownFolders);
    }

    public IReadOnlyList<(string Prefix, string Drive)> Devices => _devices;

    public static string Key(string path) => path.ToUpperInvariant();

    public string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        string p = raw.Trim().TrimEnd('\0').Replace('/', '\\');

        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal))
            p = p[4..];

        if (p.StartsWith(@"\DEVICE\", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (prefix, drive) in _devices)
            {
                if (p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                    (p.Length == prefix.Length || p[prefix.Length] == '\\'))
                    return Collapse(drive + p[prefix.Length..]);
            }
            return p;
        }

        if (p.StartsWith(@"\VOLUME{", StringComparison.OrdinalIgnoreCase))
        {
            int close = p.IndexOf('}');
            if (close > 8)
            {
                string inner = p[8..close];
                int dash = inner.LastIndexOf('-');
                if (dash >= 0 &&
                    uint.TryParse(inner[(dash + 1)..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint serial) &&
                    _serials.TryGetValue(serial, out var drive))
                    return Collapse(drive + p[(close + 1)..]);
            }
            return p;
        }

        if (p.Length > 38 && p[0] == '{' && p[37] == '}' && Guid.TryParse(p.AsSpan(0, 38), out var g) &&
            _knownFolders.TryGetValue(g, out var folder))
            return Collapse(folder.TrimEnd('\\') + p[38..]);

        if (p.Contains('%')) p = Environment.ExpandEnvironmentVariables(p);
        return Collapse(p);
    }

    /// <summary>"C:\Git\bin\..\usr\bash.exe" → "C:\Git\usr\bash.exe", so one file is never listed twice. Pure string work, no disk access.</summary>
    static string Collapse(string p)
    {
        if (p.Length < 3 || p[1] != ':' || (!p.Contains(@"\..\") && !p.Contains(@"\.\"))) return p;
        try { return Path.GetFullPath(p); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return p; }
    }

    static readonly Guid[] KnownFolderIds =
    [
        new("6D809377-6AF0-444B-8957-A3773F02200E"), // ProgramFilesX64
        new("7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E"), // ProgramFilesX86
        new("905e63b6-c1bf-494e-b29c-65b732d3d21a"), // ProgramFiles
        new("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7"), // System
        new("D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27"), // SystemX86
        new("F38BF404-1D43-42F2-9305-67DE0B28FC23"), // Windows
        new("B4BFCC3A-DB2C-424C-B029-7FE99A87C641"), // Desktop
        new("374DE290-123F-4565-9164-39C4925E467B"), // Downloads
        new("FDD39AD0-238F-46AF-ADB4-6C85480369C7"), // Documents
        new("F1B32785-6FBA-4FCF-9D55-7B8E7F157091"), // LocalAppData
        new("3EB685DB-65F9-4CF6-A03A-E3EF65729F3D"), // RoamingAppData
        new("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97"), // ProgramData
        new("5E6C858F-0E22-4760-9AFE-EA3317B67173"), // Profile
        new("0762D272-C50A-4BB0-A382-697DCD729B80"), // UserProfiles
        new("A77F5D77-2E2B-44C3-A6A2-ABA601054A51"), // Programs (start menu)
        new("0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8"), // CommonPrograms
    ];

    public static PathNormalizer ForThisMachine()
    {
        var devices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var serials = new Dictionary<uint, string>();
        foreach (var d in DriveInfo.GetDrives())
        {
            string letter = d.Name[..2];
            var buf = new char[1024];
            uint n = NativeMethods.QueryDosDevice(letter, buf, (uint)buf.Length);
            if (n > 0)
            {
                string target = new string(buf, 0, (int)n).Split('\0')[0];
                if (target.Length > 0) devices[target] = letter;
            }
            if (NativeMethods.GetVolumeInformation(d.Name, null, 0, out uint serial, out _, out _, null, 0))
                serials[serial] = letter;
        }

        var known = new Dictionary<Guid, string>();
        foreach (var id in KnownFolderIds)
        {
            if (NativeMethods.SHGetKnownFolderPath(id, 0, IntPtr.Zero, out IntPtr ptr) == 0)
            {
                try
                {
                    var path = Marshal.PtrToStringUni(ptr);
                    if (!string.IsNullOrEmpty(path)) known[id] = path;
                }
                finally { Marshal.FreeCoTaskMem(ptr); }
            }
        }
        return new PathNormalizer(devices, serials, known);
    }
}
