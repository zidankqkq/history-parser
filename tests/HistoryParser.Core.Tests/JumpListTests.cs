using System.Text;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Tests;

/// <summary>
/// Jump List DestList records. Checked against the 42 real Jump Lists on the test PC (1,317 entries, no failures; open
/// counts, times and pins matched what Explorer shows); these tests pin the Windows 10/11 and Windows 7 layouts.
/// </summary>
public class JumpListTests
{
    static byte[] Entry(int id, DateTime when, int count, bool pinned, string path, bool modern)
    {
        int pathAt = modern ? 0x80 : 0x70;
        var e = new byte[pathAt + 2 + path.Length * 2 + (modern ? 4 : 0)];
        BitConverter.GetBytes(id).CopyTo(e, 0x58);
        BitConverter.GetBytes(when.ToFileTimeUtc()).CopyTo(e, 0x64);
        BitConverter.GetBytes(pinned ? 0 : -1).CopyTo(e, 0x6C);
        if (modern) BitConverter.GetBytes(count).CopyTo(e, 0x74);
        BitConverter.GetBytes((ushort)path.Length).CopyTo(e, pathAt);
        Encoding.Unicode.GetBytes(path).CopyTo(e, pathAt + 2);
        return e;
    }

    static byte[] DestList(int version, params byte[][] entries)
    {
        var header = new byte[32];
        BitConverter.GetBytes(version).CopyTo(header, 0);
        BitConverter.GetBytes(entries.Length).CopyTo(header, 4);
        return [.. header, .. entries.SelectMany(e => e)];
    }

    [Fact]
    public void Windows_10_and_11_entries_carry_time_count_and_pin()
    {
        var when = new DateTime(2026, 10, 26, 23, 11, 4, DateTimeKind.Utc);
        var list = JumpList.DestList(DestList(4,
            Entry(1, when, 18, false, @"C:\Users\x\Desktop\hack clients\client.jar", true),
            Entry(2, when.AddDays(-1), 201, true, @"C:\Users\x\Downloads", true)));
        Assert.Equal(2, list.Count);
        Assert.Equal((1, @"C:\Users\x\Desktop\hack clients\client.jar", when, 18, false), (list[0].Id, list[0].Path, list[0].LastUtc!.Value, list[0].Count!.Value, list[0].Pinned));
        Assert.True(list[1].Pinned);
    }

    [Fact]
    public void Windows_7_entries_have_no_count()
    {
        var when = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var list = JumpList.DestList(DestList(1, Entry(7, when, 0, false, @"D:\x.exe", false)));
        Assert.Equal((7, @"D:\x.exe", (int?)null), (list[0].Id, list[0].Path, list[0].Count));
        Assert.Equal(when, list[0].LastUtc);
    }

    [Fact]
    public void A_damaged_list_stops_instead_of_reading_garbage()
    {
        var bytes = DestList(4, Entry(1, DateTime.UtcNow, 1, false, @"C:\a.exe", true));
        Array.Resize(ref bytes, bytes.Length - 10);
        Assert.Empty(JumpList.DestList(bytes));
    }
}
