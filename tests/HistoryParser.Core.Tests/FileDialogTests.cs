using System.Text;
using Microsoft.Win32;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The item lists Open / Save dialogs keep. The folder, archive, drive and Downloads items are the real ones from
/// <see cref="ShellBagTests"/>; file items for other names are built to the same layout, and the last test reads this
/// PC's own lists.
/// </summary>
public class FileDialogTests
{
    static readonly Guid ThisPc = new("20D04FE0-3AEA-1069-A2D8-08002B30309D");
    static readonly Guid DownloadsId = new("088E3905-0323-4B02-9826-5D99428E115F");
    static readonly DateTime Written = new(2026, 11, 19, 21, 5, 0, DateTimeKind.Utc);

    static string? Known(Guid g) => g == ThisPc ? "" : g == DownloadsId ? @"D:\Downloads" : null;

    static byte[] B(string hex) => Convert.FromHexString(hex);

    /// <summary>The real items end with the two zero bytes that close a list; inside a longer list they must not.</summary>
    static byte[] Item(string hex)
    {
        var b = B(hex);
        return b[..BitConverter.ToUInt16(b, 0)];
    }

    static byte[] Root(Guid g) => [0x14, 0x00, 0x1F, 0x50, .. g.ToByteArray()];

    /// <summary>A file (or folder) item laid out as Windows 10 and 11 write them: the short name, then the block holding the long one.</summary>
    static byte[] Entry(string name, bool folder = false, DateTime? modified = null)
    {
        var m = modified ?? new DateTime(2026, 11, 18, 14, 30, 0);
        ushort date = (ushort)(((m.Year - 1980) << 9) | (m.Month << 5) | m.Day), time = (ushort)((m.Hour << 11) | (m.Minute << 5) | (m.Second / 2));
        var shortName = Encoding.ASCII.GetBytes("FILE~1.BIN");
        var longName = Encoding.Unicode.GetBytes(name + "\0");
        var item = new List<byte> { 0, 0, (byte)(folder ? 0x31 : 0x32), 0, 0x10, 0x27, 0, 0 };
        item.AddRange(BitConverter.GetBytes(date)); item.AddRange(BitConverter.GetBytes(time));
        item.AddRange(BitConverter.GetBytes((ushort)(folder ? 0x10 : 0x20)));
        item.AddRange(shortName); item.Add(0); item.Add(0);
        int blockStart = item.Count;
        var block = new byte[0x2E + longName.Length + 2];
        BitConverter.GetBytes((ushort)block.Length).CopyTo(block, 0);
        BitConverter.GetBytes((ushort)9).CopyTo(block, 2);
        BitConverter.GetBytes(0xBEEF0004).CopyTo(block, 4);
        BitConverter.GetBytes(date).CopyTo(block, 8); BitConverter.GetBytes(time).CopyTo(block, 10);
        BitConverter.GetBytes(date).CopyTo(block, 12); BitConverter.GetBytes(time).CopyTo(block, 14);
        BitConverter.GetBytes((ushort)0x2E).CopyTo(block, 16);
        longName.CopyTo(block, 0x2E);
        BitConverter.GetBytes((ushort)blockStart).CopyTo(block, block.Length - 2);
        item.AddRange(block);
        var bytes = item.ToArray();
        BitConverter.GetBytes((ushort)bytes.Length).CopyTo(bytes, 0);
        return bytes;
    }

    static byte[] ListOf(params byte[][] items) => [.. items.SelectMany(i => i), 0, 0];

    [Fact]
    public void A_list_is_split_into_its_items_and_ends_at_the_zero_size()
    {
        var list = ListOf(Root(DownloadsId), Entry("loader.dll"));
        var items = FileDialogHistory.Items([.. list, 0x99, 0x99, 0x99]);
        Assert.Equal(2, items.Count);
        Assert.Equal(ShellItemKind.Root, ShellItems.Parse(items[0]).Kind);
        Assert.Equal("loader.dll", ShellItems.Parse(items[1]).Name);
    }

    [Fact]
    public void A_file_in_a_known_folder_gets_that_folders_real_path()
    {
        var found = FileDialogHistory.PathOf(FileDialogHistory.Items(ListOf(Root(DownloadsId), Entry("loader.dll"))), Known);
        Assert.Equal(@"D:\Downloads\loader.dll", found!.Value.Path);
        Assert.Equal(ShellItemKind.File, found.Value.Last.Kind);
    }

    [Fact]
    public void A_file_reached_through_This_PC_gets_its_drive_and_folders()
    {
        // Real items: the drive, the folder "ACLib" and the archive, as Explorer stored them.
        var list = ListOf(Root(ThisPc), Item(ShellBagTests.Drive), Item(ShellBagTests.Folder), Item(ShellBagTests.Zip));
        var found = FileDialogHistory.PathOf(FileDialogHistory.Items(list), Known);
        Assert.Equal(@"C:\ACLib\ScreenshareSuite-test.zip", found!.Value.Path);
    }

    [Fact]
    public void A_list_that_starts_somewhere_Windows_does_not_spell_out_keeps_the_end_of_the_path()
    {
        var found = FileDialogHistory.PathOf(FileDialogHistory.Items(ListOf(Root(Guid.NewGuid()), Entry("mods", folder: true), Entry("client.jar"))), Known);
        Assert.Equal(@"…\mods\client.jar", found!.Value.Path);
        var pick = Assert.Single(FileDialogHistory.List("jar", new Dictionary<int, byte[]> { [0] = ListOf(Root(Guid.NewGuid()), Entry("client.jar")) }, [0], Written, Known));
        Assert.False(pick.Complete);
    }

    [Fact]
    public void A_file_picked_from_search_results_is_read_from_the_path_its_last_item_carries()
    {
        // The layout of two entries in a real PC's .jar list: a 645-byte root, then two items of property sets (type 0),
        // the last holding the full path as text among other strings.
        static byte[] Properties(params string[] texts)
        {
            var body = new List<byte> { 0, 0, 0x00, 0x00, 0x5F, 0x03, 0x81, 0x19, 0x14, 0x10, 0x31, 0x53, 0x50, 0x53 };
            foreach (var t in texts) { body.AddRange(new byte[] { 0x1F, 0, 0, 0, 0x0B, 0, 0, 0 }); body.AddRange(Encoding.Unicode.GetBytes(t + "\0")); body.AddRange(new byte[6]); }
            var bytes = body.ToArray();
            BitConverter.GetBytes((ushort)bytes.Length).CopyTo(bytes, 0);
            return bytes;
        }
        var list = ListOf(Root(Guid.NewGuid()), Properties("Search results in Downloads", "kind:program"),
            Properties("client.jar", ".jar", "prop:System.ItemNameDisplay", @"C:\Users\bob\Downloads\client.jar", "{0a1b2c3d-0000-0000-0000-000000000000}.jar"));
        var pick = Assert.Single(FileDialogHistory.List("jar", new Dictionary<int, byte[]> { [0] = list }, [0], Written, Known));
        Assert.Equal(@"C:\Users\bob\Downloads\client.jar", pick.Path);
        Assert.True(pick.Complete);
    }

    [Theory]
    [InlineData("prop:System.ItemNameDisplay")] // a colon that is not a drive's
    [InlineData(@"C:\Users\bob\Downloads\")]     // a folder
    [InlineData(@"C:\Users\bob\no extension")]
    [InlineData(@"abc:\x.jar")]
    public void Text_that_is_not_a_files_full_path_is_not_taken_for_one(string text)
    {
        byte[] item = [0x40, 0x00, 0x00, 0x00, .. Encoding.Unicode.GetBytes(text + "\0"), 0, 0];
        Assert.Null(FileDialogHistory.EmbeddedPath(item));
    }

    [Fact]
    public void A_list_that_leads_to_nothing_on_disk_is_not_a_path()
    {
        Assert.Null(FileDialogHistory.PathOf(FileDialogHistory.Items(ListOf(Item(ShellBagTests.ControlPanel))), Known));
        Assert.Null(FileDialogHistory.PathOf(FileDialogHistory.Items(ListOf(Root(DownloadsId))), Known));
        Assert.Null(FileDialogHistory.PathOf([], Known));
    }

    [Fact]
    public void Only_the_newest_pick_of_a_list_is_dated_and_folders_are_left_out()
    {
        var values = new Dictionary<int, byte[]>
        {
            [0] = ListOf(Root(DownloadsId), Entry("old.dll")),
            [1] = ListOf(Root(DownloadsId), Entry("newest.dll", modified: new DateTime(2026, 11, 19, 20, 0, 0))),
            [2] = ListOf(Root(DownloadsId), Entry("a folder", folder: true)),
            [3] = ListOf(Root(DownloadsId), Entry("middle.dll")),
        };
        var picks = FileDialogHistory.List("dll", values, [1, 2, 3, 0, 7], Written, Known).ToList();
        Assert.Equal([@"D:\Downloads\newest.dll", @"D:\Downloads\middle.dll", @"D:\Downloads\old.dll"], picks.Select(p => p.Path));
        Assert.Equal([0, 2, 3], picks.Select(p => p.Position));
        Assert.Equal(Written, picks[0].PickedUtc);
        Assert.All(picks.Skip(1), p => Assert.Null(p.PickedUtc));
        Assert.Equal(new DateTime(2026, 11, 19, 20, 0, 0, DateTimeKind.Utc), picks[0].FileModifiedUtc);
    }

    [Fact]
    public void A_file_in_its_own_list_and_in_the_list_of_every_type_is_one_row_with_the_better_date()
    {
        var file = ListOf(Root(DownloadsId), Entry("loader.dll"));
        var other = ListOf(Root(DownloadsId), Entry("other.dll"));
        var own = FileDialogHistory.List("dll", new Dictionary<int, byte[]> { [0] = other, [1] = file }, [0, 1], Written.AddDays(-1), Known);
        var all = FileDialogHistory.List("*", new Dictionary<int, byte[]> { [5] = file }, [5], Written, Known);
        var merged = FileDialogHistory.Merge(own.Concat(all)).ToList();
        Assert.Equal(2, merged.Count);
        var pick = Assert.Single(merged, p => p.Path.EndsWith("loader.dll"));
        Assert.Equal("dll", pick.List);
        Assert.Equal(1, pick.Position);
        Assert.Equal(Written, pick.PickedUtc);
        Assert.Equal("Picked in an Open/Save dialog by bob: #2 of 2 in the .dll list; the file was dated " + Util.When.L(new DateTime(2026, 11, 18, 14, 30, 0, DateTimeKind.Utc)) + " then",
            FileDialogHistory.Describe(pick, "bob"));
    }

    [Fact]
    public void An_undated_pick_says_why_it_has_no_time()
    {
        var pick = new FileDialogHistory.Pick(@"C:\x\a.jar", "*", 4, 20, null, null);
        Assert.Equal("Picked in an Open/Save dialog by bob: #5 of 20 in the list of all file types (only the newest pick of a list is dated)", FileDialogHistory.Describe(pick, "bob"));
    }

    [Fact]
    public void The_program_that_showed_a_dialog_and_the_folder_it_was_last_in()
    {
        byte[] Value(string program, params byte[][] items) => [.. Encoding.Unicode.GetBytes(program + "\0"), .. ListOf(items)];
        Assert.Equal(("injector.exe", @"D:\Downloads"), FileDialogHistory.LastVisited(Value("injector.exe", Root(DownloadsId)), Known));
        Assert.Equal(("launcher.exe", @"C:\ACLib"), FileDialogHistory.LastVisited(Value("launcher.exe", Root(ThisPc), Item(ShellBagTests.Drive), Item(ShellBagTests.Folder)), Known));
        Assert.Equal(("tool.exe", (string?)null), FileDialogHistory.LastVisited(Value("tool.exe", Item(ShellBagTests.ControlPanel)), Known));
        Assert.Null(FileDialogHistory.LastVisited([], Known));
        Assert.Null(FileDialogHistory.LastVisited([0x41, 0x00, 0x42], Known));
    }

    [Fact]
    public void Garbage_never_throws()
    {
        var random = new Random(11);
        for (int i = 0; i < 3000; i++)
        {
            var bytes = new byte[random.Next(0, 300)];
            random.NextBytes(bytes);
            if (bytes.Length >= 2 && i % 2 == 0) BitConverter.TryWriteBytes(bytes.AsSpan(0, 2), (ushort)random.Next(0, bytes.Length + 4));
            FileDialogHistory.PathOf(FileDialogHistory.Items(bytes), Known);
            FileDialogHistory.LastVisited(bytes, Known);
            FileDialogHistory.List("x", new Dictionary<int, byte[]> { [0] = bytes }, [0], Written, Known).ToList();
        }
    }

    [Fact]
    public void Entries_the_order_does_not_name_are_still_listed_after_the_ones_it_does()
    {
        byte[] order = [.. BitConverter.GetBytes(4), .. BitConverter.GetBytes(1), .. BitConverter.GetBytes(4), .. BitConverter.GetBytes(-1), .. BitConverter.GetBytes(9)];
        Assert.Equal([4, 1, 0, 2, 7], FileDialogCollector.Order(order, [0, 1, 2, 4, 7], out bool ordered));
        Assert.True(ordered);
    }

    [Fact]
    public void A_list_with_no_order_lists_everything_and_says_nothing_can_be_dated()
    {
        Assert.Equal([0, 3, 5], FileDialogCollector.Order(null, [5, 0, 3], out bool ordered));
        Assert.False(ordered);
        Assert.Equal([2], FileDialogCollector.Order(BitConverter.GetBytes(-1), [2], out ordered));
        Assert.False(ordered);
    }

    [Fact]
    public void This_PCs_own_lists_give_files_of_the_type_each_list_is_for()
    {
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        using var lists = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU");
        if (lists == null) return;
        int read = 0, entries = 0;
        foreach (var name in lists.GetSubKeyNames().Where(n => n != "*"))
        {
            using var list = lists.OpenSubKey(name)!;
            var values = new Dictionary<int, byte[]>();
            foreach (var v in list.GetValueNames())
                if (int.TryParse(v, out int slot) && list.GetValue(v) is byte[] data) values[slot] = data;
            entries += values.Count;
            foreach (var pick in FileDialogHistory.List(name, values, [.. values.Keys], Written, _ => @"X:\Known"))
            {
                read++;
                // The list is named after the type, so a name read correctly ends in it.
                Assert.EndsWith("." + name, pick.Path, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain('\0', pick.Path);
            }
        }
        // Not every entry is a file on disk (a few lead to search results or phones), but most are.
        if (entries >= 10) Assert.True(read >= entries * 0.8, $"only {read} of {entries} entries were read as files");
    }
}
