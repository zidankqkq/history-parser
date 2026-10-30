using System.Globalization;
using System.Text.RegularExpressions;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Parsers;

public sealed record ShimCacheEntry(int Position, string Path, DateTime? LastModifiedUtc);

/// <summary>AppCompatCache value, Windows 10/11 layout ("10ts" entries).</summary>
public static class ShimCacheParser
{
    const uint EntrySignature = 0x73743031; // "10ts"

    public static List<ShimCacheEntry> Parse(ReadOnlySpan<byte> d)
    {
        int headerSize = (int)Bin.U32(d, 0);
        if (headerSize is not (0x30 or 0x34))
            throw new FormatException($"Unsupported AppCompatCache header size 0x{headerSize:X}.");
        var list = new List<ShimCacheEntry>();
        int pos = headerSize;
        while (pos + 12 <= d.Length && Bin.U32(d, pos) == EntrySignature)
        {
            int entrySize = (int)Bin.U32(d, pos + 8);
            int start = pos + 12;
            if (entrySize < 2 || start + entrySize > d.Length) break;
            int pathLen = Bin.U16(d, start);
            string path = Bin.Utf16(d, start + 2, pathLen);
            long ft = Bin.I64(d, start + 2 + pathLen);
            list.Add(new ShimCacheEntry(list.Count, path, FileTime.ToUtc(ft)));
            pos = start + entrySize;
        }
        return list;
    }
}

public sealed record RecycleBinEntry(string OriginalPath, long Size, DateTime? DeletedUtc);

/// <summary>Recycle Bin <c>$I</c> metadata files (version 1 = Vista-8, version 2 = Windows 10+).</summary>
public static class RecycleBinParser
{
    public static RecycleBinEntry Parse(ReadOnlySpan<byte> d)
    {
        long version = Bin.I64(d, 0);
        long size = Bin.I64(d, 8);
        var deleted = FileTime.ToUtc(Bin.I64(d, 16));
        string path = version switch
        {
            1 => Bin.Utf16(d, 24, Math.Min(520, d.Length - 24)),
            2 => Bin.Utf16(d, 28, checked(Bin.I32(d, 24) * 2)),
            _ => throw new FormatException($"Unknown $I version {version}."),
        };
        return new RecycleBinEntry(path, size, deleted);
    }
}

public sealed record UserAssistEntry(string Path, int RunCount, int FocusCount, DateTime? LastRunUtc);

public static class UserAssistParser
{
    /// <summary>Windows 7+ 72-byte value. <paramref name="encodedName"/> is ROT13.</summary>
    public static UserAssistEntry? Parse(string encodedName, ReadOnlySpan<byte> d)
    {
        if (d.Length < 68) return null;
        return new UserAssistEntry(Rot13.Decode(encodedName), (int)Bin.U32(d, 4), (int)Bin.U32(d, 8),
            FileTime.ToUtc(Bin.I64(d, 60)));
    }
}

public static class BamParser
{
    /// <summary>BAM/DAM values start with a FILETIME of the last execution.</summary>
    public static DateTime? Parse(ReadOnlySpan<byte> d) => d.Length >= 8 ? FileTime.ToUtc(Bin.I64(d, 0)) : null;
}

public sealed record PcaEntry(string Path, DateTime TimeUtc, string Extra);

/// <summary>Windows 11 Program Compatibility Assistant text databases.</summary>
public static class PcaParser
{
    static readonly string[] Formats = ["yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss"];

    static bool TryTime(string s, out DateTime utc) =>
        DateTime.TryParseExact(s.Trim(), Formats, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out utc);

    /// <summary><c>PcaAppLaunchDic.txt</c>: one <c>path|yyyy-MM-dd HH:mm:ss.fff</c> per line (UTC).</summary>
    public static List<PcaEntry> ParseLaunchDic(string text)
    {
        var list = new List<PcaEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim('\r', '\0', ' ');
            int bar = line.LastIndexOf('|');
            if (bar <= 0) continue;
            if (TryTime(line[(bar + 1)..], out var t)) list.Add(new PcaEntry(line[..bar], t, ""));
        }
        return list;
    }

    /// <summary>
    /// <c>PcaGeneralDb0/1.txt</c>: pipe-separated; the column order has changed between builds,
    /// so we pick the first column that parses as a time and the first that looks like a path.
    /// </summary>
    public static List<PcaEntry> ParseGeneralDb(string text)
    {
        var list = new List<PcaEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var fields = raw.Trim('\r', '\0', ' ').Split('|');
            if (fields.Length < 3) continue;
            DateTime? time = null;
            string? path = null;
            foreach (var f in fields)
            {
                if (time == null && TryTime(f, out var t)) time = t;
                else if (path == null && (f.Contains(":\\") || f.StartsWith('%')) &&
                         Regex.IsMatch(f, @"\.(exe|dll|jar)\s*$", RegexOptions.IgnoreCase)) path = f.Trim();
            }
            if (time != null && path != null)
                list.Add(new PcaEntry(path, time.Value,
                    string.Join(" | ", fields.Where(f => f.Length > 0 && f != path).Take(6))));
        }
        return list;
    }
}

public static class DpsStringParser
{
    // e.g. !!javaw.exe!2024/05/12:18:22:13!1a2b!
    static readonly Regex Pattern = new(@"!!(?<name>[^!\r\n]{1,260}?\.(?:exe|dll|jar))!(?<time>\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static (string Name, string Time)? Match(string s)
    {
        var m = Pattern.Match(s);
        return m.Success ? (m.Groups["name"].Value, m.Groups["time"].Value) : null;
    }
}
