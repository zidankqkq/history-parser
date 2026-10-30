using HistoryParser.Core.Native;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Parsers;

public sealed record PrefetchVolume(string DevicePath, uint Serial, DateTime? CreatedUtc);

public sealed record PrefetchInfo(
    int Version,
    string ExecutableName,
    uint Hash,
    int RunCount,
    IReadOnlyList<DateTime> RunTimesUtc,   // newest first
    IReadOnlyList<string> FileNames,
    IReadOnlyList<PrefetchVolume> Volumes);

/// <summary>
/// Windows Prefetch (.pf) parser for formats 17 (XP) through 31 (Windows 11).
/// Windows 10+ files are MAM-compressed with Xpress Huffman; we use ntdll's own decompressor.
/// </summary>
public static class PrefetchParser
{
    const uint Scca = 0x41434353; // "SCCA"
    const int MaxUncompressed = 64 * 1024 * 1024;

    public static PrefetchInfo Parse(byte[] raw) => ParseUncompressed(IsMam(raw) ? Decompress(raw) : raw);

    public static bool IsMam(ReadOnlySpan<byte> raw) =>
        raw.Length >= 8 && raw[0] == (byte)'M' && raw[1] == (byte)'A' && raw[2] == (byte)'M';

    public static byte[] Decompress(byte[] raw)
    {
        if (!IsMam(raw)) throw new FormatException("Not a MAM-compressed prefetch file.");
        byte flags = raw[3];
        ushort format = (ushort)(flags & 0x0F);
        bool hasChecksum = (flags & 0xF0) != 0;
        uint size = Bin.U32(raw, 4);
        if (size == 0 || size > MaxUncompressed) throw new FormatException($"Implausible uncompressed size {size}.");
        int offset = hasChecksum ? 12 : 8;
        if (raw.Length <= offset) throw new FormatException("Truncated MAM header.");

        var compressed = raw.AsSpan(offset).ToArray();
        if (NativeMethods.RtlGetCompressionWorkSpaceSize(format, out uint workspaceSize, out _) != 0)
            throw new FormatException($"Unsupported compression format {format}.");
        var workspace = new byte[workspaceSize];
        var output = new byte[size];
        uint status = NativeMethods.RtlDecompressBufferEx(format, output, size, compressed, (uint)compressed.Length,
            out uint finalSize, workspace);
        if (status != 0) throw new FormatException($"Decompression failed (NTSTATUS 0x{status:X8}).");
        return finalSize == size ? output : output.AsSpan(0, (int)finalSize).ToArray();
    }

    /// <summary>Builds a MAM file from an uncompressed one (tests only).</summary>
    internal static byte[] Compress(byte[] data)
    {
        const ushort format = NativeMethods.COMPRESSION_FORMAT_XPRESS_HUFF;
        NativeMethods.RtlGetCompressionWorkSpaceSize(format, out uint workspaceSize, out _);
        var workspace = new byte[workspaceSize];
        var buffer = new byte[data.Length + 4096];
        uint status = NativeMethods.RtlCompressBuffer(format, data, (uint)data.Length, buffer, (uint)buffer.Length,
            4096, out uint compressedSize, workspace);
        if (status != 0) throw new InvalidOperationException($"RtlCompressBuffer failed 0x{status:X8}");
        var result = new byte[8 + compressedSize];
        result[0] = (byte)'M'; result[1] = (byte)'A'; result[2] = (byte)'M'; result[3] = 0x04;
        BitConverter.GetBytes((uint)data.Length).CopyTo(result, 4);
        Array.Copy(buffer, 0, result, 8, compressedSize);
        return result;
    }

    public static PrefetchInfo ParseUncompressed(ReadOnlySpan<byte> d)
    {
        int version = (int)Bin.U32(d, 0);
        if (Bin.U32(d, 4) != Scca) throw new FormatException("Missing SCCA signature.");

        string exe = Bin.Utf16(d, 16, 60);
        uint hash = Bin.U32(d, 76);
        int filenameOffset = (int)Bin.U32(d, 100);
        int filenameSize = (int)Bin.U32(d, 104);
        int volumeOffset = (int)Bin.U32(d, 108);
        int volumeCount = (int)Bin.U32(d, 112);

        var times = new List<long>();
        int runCount;
        int volumeEntrySize;
        switch (version)
        {
            case 17:
                times.Add(Bin.I64(d, 120));
                runCount = (int)Bin.U32(d, 144);
                volumeEntrySize = 40;
                break;
            case 23:
                times.Add(Bin.I64(d, 128));
                runCount = (int)Bin.U32(d, 152);
                volumeEntrySize = 104;
                break;
            case 26:
                for (int i = 0; i < 8; i++) times.Add(Bin.I64(d, 128 + i * 8));
                runCount = (int)Bin.U32(d, 208);
                volumeEntrySize = 104;
                break;
            case 30:
            case 31:
                for (int i = 0; i < 8; i++) times.Add(Bin.I64(d, 128 + i * 8));
                // Two layouts exist; the file-metrics offset tells them apart.
                runCount = Bin.U32(d, 84) == 0x128 ? (int)Bin.U32(d, 200) : (int)Bin.U32(d, 208);
                volumeEntrySize = 96;
                break;
            default:
                throw new FormatException($"Unsupported prefetch version {version}.");
        }

        var runTimes = times.Select(FileTime.ToUtc).Where(t => t.HasValue).Select(t => t!.Value)
            .OrderByDescending(t => t).ToList();

        var names = new List<string>();
        if (filenameSize > 0)
        {
            var block = Bin.Utf16Raw(d, filenameOffset, filenameSize);
            names.AddRange(block.Split('\0', StringSplitOptions.RemoveEmptyEntries));
        }

        var volumes = new List<PrefetchVolume>();
        if (volumeCount is > 0 and < 64)
        {
            for (int i = 0; i < volumeCount; i++)
            {
                int e = volumeOffset + i * volumeEntrySize;
                int pathOffset = (int)Bin.U32(d, e);
                int pathChars = (int)Bin.U32(d, e + 4);
                long created = Bin.I64(d, e + 8);
                uint serial = Bin.U32(d, e + 16);
                string device = pathChars is > 0 and < 1024 ? Bin.Utf16(d, volumeOffset + pathOffset, pathChars * 2) : "";
                volumes.Add(new PrefetchVolume(device, serial, FileTime.ToUtc(created)));
            }
        }

        return new PrefetchInfo(version, exe, hash, runCount, runTimes, names, volumes);
    }
}
