using System.Buffers.Binary;
using System.Text;

namespace HistoryParser.Core.Util;

/// <summary>Bounds-checked little-endian reads. Every artifact we parse is untrusted input.</summary>
internal static class Bin
{
    static void Need(ReadOnlySpan<byte> d, int offset, int length)
    {
        if (offset < 0 || length < 0 || (long)offset + length > d.Length)
            throw new FormatException($"Read of {length} bytes at offset {offset} is outside the {d.Length}-byte buffer.");
    }

    public static ushort U16(ReadOnlySpan<byte> d, int o) { Need(d, o, 2); return BinaryPrimitives.ReadUInt16LittleEndian(d[o..]); }
    public static uint U32(ReadOnlySpan<byte> d, int o) { Need(d, o, 4); return BinaryPrimitives.ReadUInt32LittleEndian(d[o..]); }
    public static int I32(ReadOnlySpan<byte> d, int o) { Need(d, o, 4); return BinaryPrimitives.ReadInt32LittleEndian(d[o..]); }
    public static long I64(ReadOnlySpan<byte> d, int o) { Need(d, o, 8); return BinaryPrimitives.ReadInt64LittleEndian(d[o..]); }
    public static ulong U64(ReadOnlySpan<byte> d, int o) { Need(d, o, 8); return BinaryPrimitives.ReadUInt64LittleEndian(d[o..]); }

    /// <summary>UTF-16LE string of <paramref name="byteLength"/> bytes, cut at the first NUL.</summary>
    public static string Utf16(ReadOnlySpan<byte> d, int o, int byteLength)
    {
        Need(d, o, byteLength);
        var s = Encoding.Unicode.GetString(d.Slice(o, byteLength & ~1));
        int nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }

    /// <summary>UTF-16LE block that may contain several NUL-separated strings.</summary>
    public static string Utf16Raw(ReadOnlySpan<byte> d, int o, int byteLength)
    {
        Need(d, o, byteLength);
        return Encoding.Unicode.GetString(d.Slice(o, byteLength & ~1));
    }
}
