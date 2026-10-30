using System.Text;
using HistoryParser.Core.Collectors;

namespace HistoryParser.Core.Tests;

/// <summary>
/// Recycle Bin info files ($I…) keep the deleted item's extension, so a deleted jar leaves "$IAB12CD.jar". Every program that
/// lists the Recycle Bin reads them, and Prefetch records that - History Parser once showed dozens as jars that had "run".
/// </summary>
public class RecycleRecordTests
{
    static byte[] Record(string originalPath)
    {
        // Version 2: version, original size, deletion time, name length in characters (with the NUL), UTF-16 name.
        var name = Encoding.Unicode.GetBytes(originalPath + "\0");
        var bytes = new byte[28 + name.Length];
        BitConverter.GetBytes(2L).CopyTo(bytes, 0);
        BitConverter.GetBytes(12345L).CopyTo(bytes, 8);
        BitConverter.GetBytes(new DateTime(2026, 10, 27, 20, 0, 0, DateTimeKind.Utc).ToFileTimeUtc()).CopyTo(bytes, 16);
        BitConverter.GetBytes(originalPath.Length + 1).CopyTo(bytes, 24);
        name.CopyTo(bytes, 28);
        return bytes;
    }

    const string Bin = @"$Recycle.Bin\S-1-5-21-1-2-3-1001";

    [Fact]
    public void A_real_info_record_named_like_a_jar_is_not_a_program()
    {
        var path = Scratch.File(Bin, "$IAB12CD.jar", Record(@"C:\Users\x\.minecraft\mods\sodium.jar"));
        Assert.True(PrefetchCollector.IsRecycleBinRecord(path));
    }

    [Fact]
    public void A_jar_hidden_under_an_info_record_name_is_still_a_jar()
    {
        var jar = Scratch.File(Bin, "$IZZ99ZZ.jar", "PK\u0003\u0004 a real jar"u8.ToArray());
        Assert.False(PrefetchCollector.IsRecycleBinRecord(jar));
        // A record whose own item had another extension is not the bookkeeping for this name either.
        var mismatch = Scratch.File(Bin, "$IXY34XY.jar", Record(@"C:\Users\x\Desktop\notes.txt"));
        Assert.False(PrefetchCollector.IsRecycleBinRecord(mismatch));
    }

    [Fact]
    public void Only_info_records_in_a_recycle_bin_count()
    {
        // $R… is the deleted item itself: a recycled jar that ran is evidence.
        Assert.False(PrefetchCollector.IsRecycleBinRecord(Scratch.File(Bin, "$RAB12CD.jar", "PK\u0003\u0004"u8.ToArray())));
        Assert.False(PrefetchCollector.IsRecycleBinRecord(Scratch.File("not-a-bin", "$IAB12CD.jar", Record(@"C:\a\b.jar"))));
    }
}
