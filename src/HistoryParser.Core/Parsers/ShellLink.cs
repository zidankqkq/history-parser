using System.Text;

namespace HistoryParser.Core.Parsers;

/// <summary>
/// A .lnk shortcut: what it points at and the target's own times when the link was last written. The target can be a file or folder, a network path, or a web
/// or app address. <paramref name="EnvironmentTarget"/> is kept as written, because it is what Windows follows when a link holds one, and it can differ from the rest.
/// </summary>
public sealed record ShellLinkInfo(string TargetPath, DateTime? TargetCreatedUtc, DateTime? TargetModifiedUtc, long TargetSize, string? Arguments = null, string? EnvironmentTarget = null);

/// <summary>
/// Reads a Shell Link (MS-SHLLINK). The target comes from the first of these that gives one: the LinkInfo block's local or network path, the ID list,
/// the environment block, then the relative path. Many links have no LinkInfo at all, such as those Windows makes for an opened address.
/// </summary>
public static class ShellLink
{
    const int HeaderSize = 0x4C, EnvironmentBlockSize = 0x314;
    const uint HasLinkTargetIdList = 0x1, HasLinkInfo = 0x2, HasName = 0x4, HasRelativePath = 0x8, HasWorkingDir = 0x10, HasArguments = 0x20, HasIconLocation = 0x40, IsUnicode = 0x80;
    const uint VolumeIdAndLocalBasePath = 0x1, CommonNetworkRelativeLink = 0x2, EnvironmentBlock = 0xA0000001;
    const byte UriItem = 0x61;
    static readonly Guid MyComputer = new("20D04FE0-3AEA-1069-A2D8-08002B30309D");

    /// <summary>Whether this is a shell link at all. A link can be sound and still point at no file, such as a Control Panel item or a saved search.</summary>
    public static bool IsLink(byte[] b) => b.Length >= HeaderSize && BitConverter.ToUInt32(b, 0) == HeaderSize;

    /// <summary>Null when it isn't a link, or points at nothing with a path or address.</summary>
    public static ShellLinkInfo? Parse(byte[] b)
    {
        if (!IsLink(b)) return null;
        uint flags = BitConverter.ToUInt32(b, 0x14);
        var created = Util.FileTime.ToUtc(BitConverter.ToInt64(b, 0x1C));
        var modified = Util.FileTime.ToUtc(BitConverter.ToInt64(b, 0x2C));
        long size = BitConverter.ToUInt32(b, 0x34);

        int p = HeaderSize;
        string? fromIds = null, fromInfo = null;
        if ((flags & HasLinkTargetIdList) != 0)
        {
            if (p + 2 > b.Length) return null;
            int length = BitConverter.ToUInt16(b, p);
            fromIds = FromIdList(b, p + 2, Math.Min(p + 2 + length, b.Length));
            p += 2 + length;
        }
        if ((flags & HasLinkInfo) != 0)
        {
            int infoSize = p + 4 <= b.Length ? BitConverter.ToInt32(b, p) : 0;
            if (infoSize >= 4 && infoSize <= b.Length - p)
            {
                fromInfo = FromLinkInfo(b, p, infoSize);
                p += infoSize;
            }
            else p = b.Length; // what follows can't be found
        }

        string? Next(uint flag)
        {
            if ((flags & flag) == 0 || p + 2 > b.Length) return null;
            int count = BitConverter.ToUInt16(b, p) * ((flags & IsUnicode) != 0 ? 2 : 1);
            p += 2;
            if (count > b.Length - p) { p = b.Length; return null; }
            string text = ((flags & IsUnicode) != 0 ? Encoding.Unicode : Encoding.Latin1).GetString(b, p, count);
            p += count;
            return text;
        }
        Next(HasName);
        string? relative = Next(HasRelativePath), workingDir = Next(HasWorkingDir), arguments = Next(HasArguments);
        Next(HasIconLocation);
        string? environment = FromExtraData(b, p);

        // A path written with variables is read with this reader's own values, so one that names a folder outright is the better target.
        string? target = NotEmpty(fromInfo) ?? NotEmpty(fromIds) ?? NotEmpty(environment) ?? FromRelative(relative, workingDir);
        return target == null ? null : new ShellLinkInfo(target, created, modified, size, NotEmpty(arguments), NotEmpty(environment));
    }

    static string? NotEmpty(string? text) => string.IsNullOrEmpty(text) ? null : text;

    static string? FromLinkInfo(byte[] b, int info, int infoSize)
    {
        if (infoSize < 0x1C) return null;
        int end = info + infoSize;
        bool wide = infoSize >= 0x24 && BitConverter.ToInt32(b, info + 4) >= 0x24;
        uint flags = BitConverter.ToUInt32(b, info + 8);
        string? root = null;
        if ((flags & VolumeIdAndLocalBasePath) != 0)
            root = NotEmpty(wide ? Utf16(b, At(b, info, 0x1C), end) : null) ?? Ansi(b, At(b, info, 0x10), end);
        if (string.IsNullOrEmpty(root) && (flags & CommonNetworkRelativeLink) != 0)
            root = NetworkName(b, At(b, info, 0x14), end);
        if (string.IsNullOrEmpty(root)) return null;
        string? suffix = NotEmpty(wide ? Utf16(b, At(b, info, 0x20), end) : null) ?? Ansi(b, At(b, info, 0x18), end);
        return string.IsNullOrEmpty(suffix) ? root : root.TrimEnd('\\') + "\\" + suffix;
    }

    /// <summary>\\server\share from a CommonNetworkRelativeLink. The Unicode offset exists only when the ANSI one points past it.</summary>
    static string? NetworkName(byte[] b, int at, int end)
    {
        if (at <= 0 || at > end - 0x14) return null;
        int ansi = BitConverter.ToInt32(b, at + 8);
        if (ansi > 0x14 && at <= end - 0x18 && Utf16(b, At(b, at, 0x14), end) is { Length: > 0 } wide) return wide;
        return Ansi(b, ansi > 0 ? at + ansi : -1, end);
    }

    /// <summary>The target as Explorer stored it. Null when a step of it isn't part of a path: Control Panel items, searches and the like.</summary>
    static string? FromIdList(byte[] b, int start, int end)
    {
        var parts = new List<string>();
        bool named = false;
        for (int q = start; q <= end - 4;)
        {
            int size = BitConverter.ToUInt16(b, q);
            if (size < 4 || size > end - q) break;
            if (b[q + 2] == UriItem) return Address(b.AsSpan(q, size));
            var item = ShellItems.Parse(b[q..(q + size)]);
            switch (item.Kind)
            {
                case ShellItemKind.Special: return null;
                case ShellItemKind.Root when item.KnownFolder == MyComputer: break;
                case ShellItemKind.Root: parts.Add("{" + item.KnownFolder + "}"); break;
                default: parts.Add(item.Name.TrimEnd('\\')); named = true; break;
            }
            q += size;
        }
        if (!named) return null;
        string path = string.Join('\\', parts);
        return path.EndsWith(':') ? path + "\\" : path;
    }

    /// <summary>The address in a URI item: the first run of text there that starts with a scheme. Bit 0x80 of the item's flags says it is UTF-16.</summary>
    static string? Address(ReadOnlySpan<byte> item)
    {
        bool wide = (item[3] & 0x80) != 0;
        int step = wide ? 2 : 1;
        for (int i = 6; i <= item.Length - step;)
        {
            int end = i;
            while (end <= item.Length - step && Unit(item, end, wide) >= 0x20) end += step;
            if (end > i)
            {
                string text = (wide ? Encoding.Unicode : Encoding.Latin1).GetString(item[i..end]);
                if (Util.PathNormalizer.HasScheme(text)) return text;
            }
            i = end + step;
        }
        return null;
    }

    static int Unit(ReadOnlySpan<byte> b, int at, bool wide) => wide ? BitConverter.ToUInt16(b[at..]) : b[at];

    static string? FromExtraData(byte[] b, int p)
    {
        while (p >= 0 && p <= b.Length - 8)
        {
            int size = BitConverter.ToInt32(b, p);
            if (size < 8 || size > b.Length - p) return null;
            if (BitConverter.ToUInt32(b, p + 4) == EnvironmentBlock && size >= EnvironmentBlockSize)
                return NotEmpty(Utf16(b, p + 268, p + 788)) ?? Ansi(b, p + 8, p + 268);
            p += size;
        }
        return null;
    }

    static string? FromRelative(string? relative, string? workingDir)
    {
        if (string.IsNullOrEmpty(relative)) return null;
        if (Path.IsPathFullyQualified(relative) || string.IsNullOrEmpty(workingDir) || !Path.IsPathFullyQualified(workingDir)) return relative;
        try { return Path.GetFullPath(relative, workingDir); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return relative; }
    }

    /// <summary>Absolute position of a field that holds an offset; -1 when the offset is 0 (field absent).</summary>
    static int At(byte[] b, int start, int field) => BitConverter.ToInt32(b, start + field) is > 0 and var off ? start + off : -1;

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
