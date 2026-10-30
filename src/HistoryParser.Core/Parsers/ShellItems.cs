using System.Text;

namespace HistoryParser.Core.Parsers;

public enum ShellItemKind { Root, Drive, Folder, File, ArchiveEntry, Special }

/// <summary>
/// One shell item (one step of an Explorer path) as stored in ShellBags. Times are the folder's own dates as they
/// were when Explorer recorded it, in the 2-second FAT resolution shell items use.
/// </summary>
public sealed record ShellItem(ShellItemKind Kind, string Name, Guid? KnownFolder = null,
    DateTime? Modified = null, DateTime? Created = null, DateTime? Accessed = null);

/// <summary>
/// Reads the shell items Explorer keeps in its ShellBags (BagMRU). Layouts handled, each checked against real
/// BagMRU data: root folders (0x1F + known-folder GUID), drives (0x2F "C:\"), folder and file entries
/// (0x30-0x3F family, long name in the 0xBEEF0004 extension block), delegate items (0x74 "CFSF", a folder entry
/// inside), and entries browsed inside archives (zip / modpack contents: name and in-archive path with lengths).
/// Anything else (control panel, devices, property-store items) is <see cref="ShellItemKind.Special"/>.
/// </summary>
public static class ShellItems
{
    public static ShellItem Parse(byte[] data)
    {
        if (data.Length < 4) return new(ShellItemKind.Special, "");
        int size = Math.Min(BitConverter.ToUInt16(data, 0), data.Length);
        if (size < 4) return new(ShellItemKind.Special, "");
        var b = data.AsSpan(0, size);
        byte type = b[2];

        if (type == 0x1F && size >= 20) return new(ShellItemKind.Root, "", new Guid(b.Slice(4, 16)));
        if (type == 0x2F && size >= 6 && char.IsAsciiLetter((char)b[3]) && b[4] == ':')
            return new(ShellItemKind.Drive, $"{char.ToUpperInvariant((char)b[3])}:\\");
        if ((type & 0x70) == 0x30 && FileEntry(b, 0) is { } entry) return entry;
        if (type == 0x74 && size > 34 && Encoding.ASCII.GetString(b.Slice(6, 4)) == "CFSF" && FileEntry(b, 10) is { } inner)
            return inner;
        if (ArchiveEntry(b) is { } archived) return archived;
        return new(ShellItemKind.Special, "");
    }

    /// <summary>A folder or file entry starting at <paramref name="at"/>: FAT modified time, attributes, 8.3 name, then extension blocks.</summary>
    static ShellItem? FileEntry(ReadOnlySpan<byte> b, int at)
    {
        if (at + 16 > b.Length) return null;
        var modified = Fat(BitConverter.ToUInt16(b[(at + 8)..]), BitConverter.ToUInt16(b[(at + 10)..]));
        ushort attributes = BitConverter.ToUInt16(b[(at + 12)..]);
        int nameStart = at + 14, nameEnd = nameStart;
        while (nameEnd < b.Length && b[nameEnd] != 0) nameEnd++;
        if (nameEnd == nameStart || nameEnd >= b.Length) return null;
        var shortName = Encoding.Latin1.GetString(b[nameStart..nameEnd]);
        if (shortName.Any(c => c < 0x20)) return null;

        string name = shortName;
        DateTime? created = null, accessed = null;
        // The long name lives in the 0xBEEF0004 block; its field at +16 is the offset of that name in the block.
        int sig = b[nameEnd..].IndexOf([(byte)0x04, (byte)0x00, (byte)0xEF, (byte)0xBE]);
        if (sig >= 0)
        {
            int block = nameEnd + sig - 4;
            int blockSize = BitConverter.ToUInt16(b[block..]);
            if (block >= nameEnd && blockSize >= 0x14 && block + blockSize <= b.Length)
            {
                created = Fat(BitConverter.ToUInt16(b[(block + 8)..]), BitConverter.ToUInt16(b[(block + 10)..]));
                accessed = Fat(BitConverter.ToUInt16(b[(block + 12)..]), BitConverter.ToUInt16(b[(block + 14)..]));
                int nameOffset = BitConverter.ToUInt16(b[(block + 16)..]);
                if (nameOffset >= 0x14 && nameOffset < blockSize && Utf16(b[(block + nameOffset)..(block + blockSize)]) is { Length: > 0 } longName)
                    name = longName;
            }
        }
        return new((attributes & 0x10) != 0 ? ShellItemKind.Folder : ShellItemKind.File, name, null, modified, created, accessed);
    }

    /// <summary>
    /// An entry browsed inside an archive: near the end, [name length][path length] (UTF-16 characters) then the
    /// name and its folder inside the archive, each zero-terminated. The lengths and terminators must all agree.
    /// </summary>
    static ShellItem? ArchiveEntry(ReadOnlySpan<byte> b)
    {
        for (int i = 0x24; i + 10 <= b.Length; i += 2)
        {
            uint nameLength = BitConverter.ToUInt32(b[i..]), pathLength = BitConverter.ToUInt32(b[(i + 4)..]);
            if (nameLength is 0 or > 260 || pathLength > 2048) continue;
            int name = i + 8, nameEnd = name + 2 * (int)nameLength, path = nameEnd + 2, pathEnd = path + 2 * (int)pathLength;
            if (pathEnd + (pathLength > 0 ? 2 : 0) > b.Length) continue;
            if (BitConverter.ToUInt16(b[nameEnd..]) != 0 || !Printable(b[name..nameEnd])) continue;
            if (pathLength > 0 && (BitConverter.ToUInt16(b[pathEnd..]) != 0 || !Printable(b[path..pathEnd]))) continue;
            return new(ShellItemKind.ArchiveEntry, Encoding.Unicode.GetString(b[name..nameEnd]));
        }
        return null;
    }

    static bool Printable(ReadOnlySpan<byte> utf16)
    {
        for (int i = 0; i + 1 < utf16.Length; i += 2)
            if (BitConverter.ToUInt16(utf16[i..]) is < 0x20 or 0xFFFF) return false;
        return true;
    }

    static string? Utf16(ReadOnlySpan<byte> b)
    {
        int end = 0;
        while (end + 1 < b.Length && (b[end] != 0 || b[end + 1] != 0)) end += 2;
        if (end + 1 >= b.Length) return null; // no terminator inside the block
        var s = Encoding.Unicode.GetString(b[..end]);
        return s.Any(c => c < 0x20) ? null : s;
    }

    /// <summary>A FAT date and time; null when either is zero or invalid.</summary>
    internal static DateTime? Fat(ushort date, ushort time)
    {
        if (date == 0) return null;
        int day = date & 0x1F, month = (date >> 5) & 0x0F, year = 1980 + (date >> 9);
        int seconds = (time & 0x1F) * 2, minutes = (time >> 5) & 0x3F, hours = time >> 11;
        if (day is < 1 or > 31 || month is < 1 or > 12 || hours > 23 || minutes > 59 || seconds > 59) return null;
        if (day > DateTime.DaysInMonth(year, month)) return null;
        return new DateTime(year, month, day, hours, minutes, seconds, DateTimeKind.Unspecified);
    }
}
