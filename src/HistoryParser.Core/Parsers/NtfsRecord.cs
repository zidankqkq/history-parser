using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using HistoryParser.Core.Util;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Parsers;

/// <summary>
/// The two timestamp sets NTFS keeps for every file. <c>$STANDARD_INFORMATION</c> is what Explorer
/// shows and what any program can rewrite with one API call; <c>$FILE_NAME</c> is maintained by the
/// file system itself. Timestamp-faking tools almost always change only the first.
/// </summary>
public sealed record NtfsTimes(
    DateTime? SiCreated, DateTime? SiModified, DateTime? SiChanged, DateTime? SiAccessed,
    DateTime? FnCreated, DateTime? FnModified, DateTime? FnChanged, DateTime? FnAccessed);

public static class NtfsRecord
{
    /// <summary>Parses an MFT file record (fix-ups applied here) and returns both timestamp sets.</summary>
    public static NtfsTimes? Parse(byte[] record)
    {
        if (record.Length < 64 || record[0] != (byte)'F' || record[1] != (byte)'I' || record[2] != (byte)'L' || record[3] != (byte)'E')
            return null;
        ApplyFixups(record);

        int attr = Bin.U16(record, 0x14);
        long?[] si = new long?[4];
        long?[]? fn = null;
        while (attr + 16 <= record.Length)
        {
            uint type = Bin.U32(record, attr);
            if (type == 0xFFFFFFFF) break;
            int length = (int)Bin.U32(record, attr + 4);
            if (length < 16 || attr + length > record.Length) break;
            bool resident = record[attr + 8] == 0;
            if (resident)
            {
                int content = attr + Bin.U16(record, attr + 0x14);
                if (type == 0x10 && content + 32 <= record.Length)
                {
                    for (int i = 0; i < 4; i++) si[i] = Bin.I64(record, content + i * 8);
                }
                else if (type == 0x30 && content + 0x42 <= record.Length)
                {
                    byte nameSpace = record[content + 0x41];
                    // Prefer the long (Win32 / POSIX) name over the 8.3 DOS alias.
                    if (fn == null || nameSpace != 2)
                    {
                        fn = new long?[4];
                        for (int i = 0; i < 4; i++) fn[i] = Bin.I64(record, content + 8 + i * 8);
                    }
                }
            }
            attr += length;
        }
        DateTime? T(long? v) => v is { } x ? FileTime.ToUtc(x) : null;
        return new NtfsTimes(T(si[0]), T(si[1]), T(si[2]), T(si[3]),
            T(fn?[0]), T(fn?[1]), T(fn?[2]), T(fn?[3]));
    }

    /// <summary>The last two bytes of every 512-byte sector are stored in the update sequence array.</summary>
    internal static void ApplyFixups(byte[] record)
    {
        int usaOffset = Bin.U16(record, 4);
        int usaCount = Bin.U16(record, 6);
        for (int i = 1; i < usaCount; i++)
        {
            int sectorEnd = i * 512 - 2;
            int usa = usaOffset + i * 2;
            if (sectorEnd + 2 > record.Length || usa + 2 > record.Length) break;
            record[sectorEnd] = record[usa];
            record[sectorEnd + 1] = record[usa + 1];
        }
    }

    /// <summary>Reads both timestamp sets of a file on a local NTFS volume (administrator only).</summary>
    public sealed class Reader : IDisposable
    {
        readonly Dictionary<string, SafeFileHandle?> _volumes = new(StringComparer.OrdinalIgnoreCase);

        public NtfsTimes? Read(string path)
        {
            if (path.Length < 3 || path[1] != ':') return null;
            ulong frn;
            using (var file = CreateFile(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
            {
                if (file.IsInvalid || !GetFileInformationByHandle(file, out var info)) return null;
                frn = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            }

            string letter = path[..2];
            if (!_volumes.TryGetValue(letter, out var volume))
            {
                volume = CreateFile($@"\\.\{letter}", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (volume.IsInvalid) { volume.Dispose(); volume = null; }
                _volumes[letter] = volume;
            }
            if (volume == null) return null;

            var input = BitConverter.GetBytes((long)(frn & 0x0000FFFFFFFFFFFF));
            var output = new byte[4096 + 12];
            if (!DeviceIoControl(volume, FSCTL_GET_NTFS_FILE_RECORD, input, input.Length, output, output.Length, out int returned, IntPtr.Zero) ||
                returned < 12)
                return null;
            // The call returns the nearest in-use record at or below the number asked for; make sure it is ours.
            if ((BitConverter.ToUInt64(output, 0) & 0x0000FFFFFFFFFFFF) != (frn & 0x0000FFFFFFFFFFFF)) return null;
            int length = BitConverter.ToInt32(output, 8);
            if (length <= 0 || length > returned - 12) return null;
            return Parse(output.AsSpan(12, length).ToArray());
        }

        public void Dispose()
        {
            foreach (var v in _volumes.Values) v?.Dispose();
            _volumes.Clear();
        }
    }
}
