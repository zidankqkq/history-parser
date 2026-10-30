using System.Runtime.InteropServices;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Parsers;

[Flags]
public enum UsnReason : uint
{
    DataOverwrite = 0x1,
    DataExtend = 0x2,
    DataTruncation = 0x4,
    FileCreate = 0x100,
    FileDelete = 0x200,
    RenameOldName = 0x1000,
    RenameNewName = 0x2000,
    SecurityChange = 0x800,
    HardLinkChange = 0x10000,
    BasicInfoChange = 0x8000,
    Close = 0x80000000,
}

/// <summary>One USN_RECORD (V2 or V3). The name is a view into the read buffer; copy it if you keep it.</summary>
public readonly ref struct UsnRecord
{
    public readonly ulong FileRef;
    public readonly ulong ParentRef;
    public readonly long Usn;
    public readonly long TimeStamp;
    public readonly UsnReason Reason;
    public readonly uint Attributes;
    public readonly ReadOnlySpan<char> Name;

    public UsnRecord(ulong fileRef, ulong parentRef, long usn, long timeStamp, UsnReason reason, uint attributes,
        ReadOnlySpan<char> name)
    {
        FileRef = fileRef; ParentRef = parentRef; Usn = usn; TimeStamp = timeStamp;
        Reason = reason; Attributes = attributes; Name = name;
    }

    public bool IsDirectory => (Attributes & 0x10) != 0;
}

public delegate void UsnRecordHandler(in UsnRecord record);

public static class UsnParser
{
    /// <summary>
    /// Walks the records in a buffer returned by FSCTL_READ_USN_JOURNAL / FSCTL_ENUM_USN_DATA,
    /// starting after the 8-byte "next USN/FRN" header.
    /// </summary>
    public static int ParseBuffer(ReadOnlySpan<byte> buffer, UsnRecordHandler handler)
    {
        int count = 0, pos = 8;
        while (pos + 8 <= buffer.Length)
        {
            int length = (int)Bin.U32(buffer, pos);
            if (length < 60 || pos + length > buffer.Length) break;
            var rec = buffer.Slice(pos, length);
            ushort major = Bin.U16(rec, 4);
            if (major == 2)
            {
                int nameLength = Bin.U16(rec, 56), nameOffset = Bin.U16(rec, 58);
                if (nameOffset + nameLength <= length)
                {
                    handler(new UsnRecord(Bin.U64(rec, 8), Bin.U64(rec, 16), Bin.I64(rec, 24), Bin.I64(rec, 32),
                        (UsnReason)Bin.U32(rec, 40), Bin.U32(rec, 52),
                        MemoryMarshal.Cast<byte, char>(rec.Slice(nameOffset, nameLength & ~1))));
                    count++;
                }
            }
            else if (major == 3 && length >= 76)
            {
                // 128-bit file IDs: NTFS keeps the classic 64-bit reference in the low half.
                int nameLength = Bin.U16(rec, 72), nameOffset = Bin.U16(rec, 74);
                if (nameOffset + nameLength <= length)
                {
                    handler(new UsnRecord(Bin.U64(rec, 8), Bin.U64(rec, 24), Bin.I64(rec, 40), Bin.I64(rec, 48),
                        (UsnReason)Bin.U32(rec, 56), Bin.U32(rec, 68),
                        MemoryMarshal.Cast<byte, char>(rec.Slice(nameOffset, nameLength & ~1))));
                    count++;
                }
            }
            pos += (length + 7) & ~7;
        }
        return count;
    }
}

/// <summary>
/// Detects the system clock being moved backwards from records that are stored in a strict order
/// (USN numbers, event record IDs) but carry wall-clock timestamps. If a later record has a clearly
/// earlier time than the one before it, the clock went back between them.
/// </summary>
public sealed class ClockOrderTracker
{
    readonly TimeSpan _tolerance;
    long _previous;
    public List<(DateTime Before, DateTime After)> Rollbacks { get; } = new();
    public DateTime? Earliest { get; private set; }
    public DateTime? Latest { get; private set; }

    public ClockOrderTracker(TimeSpan tolerance) => _tolerance = tolerance;

    public void Observe(long fileTime)
    {
        if (FileTime.ToUtc(fileTime) is not { } t) return;
        if (Earliest == null || t < Earliest) Earliest = t;
        if (Latest == null || t > Latest) Latest = t;
        if (_previous != 0 && fileTime < _previous - _tolerance.Ticks && Rollbacks.Count < 100)
            Rollbacks.Add((DateTime.FromFileTimeUtc(_previous), t));
        _previous = fileTime;
    }

    public void Observe(DateTime utc) => Observe(utc.ToFileTimeUtc());
}
