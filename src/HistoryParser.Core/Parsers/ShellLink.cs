using System.Text;

namespace HistoryParser.Core.Parsers;

/// <summary>A .lnk shortcut: the target's full path and the target's own times when the link was last written.</summary>
public sealed record ShellLinkInfo(string TargetPath, DateTime? TargetCreatedUtc, DateTime? TargetModifiedUtc, long TargetSize);

/// <summary>Reads the target path out of a Shell Link (.lnk) file (MS-SHLLINK), from its LinkInfo block.</summary>
public static class ShellLink
{
    const int HeaderSize = 0x4C;
    const uint HasLinkTargetIdList = 0x1, HasLinkInfo = 0x2;

    public static ShellLinkInfo? Parse(byte[] b)
    {
        if (b.Length < HeaderSize || BitConverter.ToUInt32(b, 0) != HeaderSize) return null;
        uint flags = BitConverter.ToUInt32(b, 0x14);
        var created = Util.FileTime.ToUtc(BitConverter.ToInt64(b, 0x1C));
        var modified = Util.FileTime.ToUtc(BitConverter.ToInt64(b, 0x2C));
        long size = BitConverter.ToUInt32(b, 0x34);

        int p = HeaderSize;
        if ((flags & HasLinkTargetIdList) != 0)
        {
            if (p + 2 > b.Length) return null;
            p += 2 + BitConverter.ToUInt16(b, p);
        }
        if ((flags & HasLinkInfo) == 0 || p + 0x1C > b.Length) return null;

        int infoSize = BitConverter.ToInt32(b, p);
        int infoHeader = BitConverter.ToInt32(b, p + 4);
        uint infoFlags = BitConverter.ToUInt32(b, p + 8);
        if (infoSize < 0x1C || p + infoSize > b.Length || (infoFlags & 1) == 0) return null; // no local path (network target)

        string? basePath = null, suffix = null;
        if (infoHeader >= 0x24)
        {
            basePath = Utf16(b, At(b, p, 0x1C), p + infoSize);
            suffix = Utf16(b, At(b, p, 0x20), p + infoSize);
        }
        basePath ??= Ansi(b, At(b, p, 0x10), p + infoSize);
        suffix ??= Ansi(b, At(b, p, 0x18), p + infoSize);
        if (string.IsNullOrEmpty(basePath)) return null;

        string path = string.IsNullOrEmpty(suffix) ? basePath : basePath.TrimEnd('\\') + "\\" + suffix;
        return new ShellLinkInfo(path, created, modified, size);
    }

    /// <summary>Absolute position of a LinkInfo field that holds an offset; -1 when the offset is 0 (field absent).</summary>
    static int At(byte[] b, int info, int field) => BitConverter.ToInt32(b, info + field) is > 0 and var off ? info + off : -1;

    static string? Ansi(byte[] b, int start, int end)
    {
        if (start <= 0 || start >= end) return null;
        int z = Array.IndexOf(b, (byte)0, start, end - start);
        return Encoding.Latin1.GetString(b, start, (z < 0 ? end : z) - start);
    }

    static string? Utf16(byte[] b, int start, int end)
    {
        if (start <= 0 || start >= end) return null;
        int i = start;
        while (i + 1 < end && (b[i] != 0 || b[i + 1] != 0)) i += 2;
        return Encoding.Unicode.GetString(b, start, i - start);
    }
}
