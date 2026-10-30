using HistoryParser.Core.Collectors;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Tests;

/// <summary>Shell items copied byte for byte from a real Windows 11 BagMRU.</summary>
public class ShellBagTests
{
    const string Folder = "5000310000000000755C404B100041434C6962003C0009000400EFBE755C404B755C404B2E000000D1550D0000001300000000000000000000000000000095D33C00410043004C0069006200000014000000";
    const string Zip = "80003200F9C095145B5D5D57200053435245454E7E312E5A49500000640009000400EFBE5B5D55575B5D5D572E000000612505000000200000000000000000000000000000006C498B00530063007200650065006E0073006800610072006500530075006900740065002D0074006500730074002E007A006900700000001C000000";
    const string Delegate = "840074001E00434653461800310000000000EB5C800A1000434C415544457E3100000000741A595E96DFD3488D671733BCEE28BAC5CDFADF9F6756418947C5C76BC0B67F400009000400EFBEEB5C800AEB5C800A2E000000A794060000000500000000000000000000000000000016CA02012E0063006C006100750064006500000044000000";
    const string Drive = "19002F433A5C000000000000000000000000000000000000000000";
    const string Downloads = "3A001F0005398E082303024B98265D99428E115F260001002600EFBE110000000F0DB93548B7DC015390079851B7DC010678069C51B7DC0114000000";
    const string InArchive = "8000760065007200000000000000000000000000000000000000000000000000100000004E002F0041000000000000000000000000000000000000000000000000000000000000002F00000000000000FFFF0000040000000A0000006D006F006400730000006F00760065007200720069006400650073002F000000000000000000";
    const string ControlPanel = "0C0001008421DE39020000000000";

    static byte[] B(string hex) => Convert.FromHexString(hex);

    [Fact]
    public void A_folder_entry_gives_its_long_name_and_dates()
    {
        var item = ShellItems.Parse(B(Folder));
        Assert.Equal(ShellItemKind.Folder, item.Kind);
        Assert.Equal("ACLib", item.Name);
        Assert.Equal(new DateTime(2026, 3, 21, 9, 26, 0), item.Modified);
    }

    [Fact]
    public void An_archive_opened_like_a_folder_is_a_file_entry_with_its_long_name()
    {
        var item = ShellItems.Parse(B(Zip));
        Assert.Equal(ShellItemKind.File, item.Kind);
        Assert.Equal("ScreenshareSuite-test.zip", item.Name); // not the 8.3 name SCREEN~1.ZIP
    }

    [Fact]
    public void A_delegate_item_holds_a_folder_entry() => Assert.Equal((ShellItemKind.Folder, ".claude"),
        (ShellItems.Parse(B(Delegate)).Kind, ShellItems.Parse(B(Delegate)).Name));

    [Fact]
    public void Drives_and_root_folders()
    {
        Assert.Equal((ShellItemKind.Drive, "C:\\"), (ShellItems.Parse(B(Drive)).Kind, ShellItems.Parse(B(Drive)).Name));
        var root = ShellItems.Parse(B(Downloads));
        Assert.Equal(ShellItemKind.Root, root.Kind);
        Assert.Equal(new Guid("088E3905-0323-4B02-9826-5D99428E115F"), root.KnownFolder);
    }

    [Fact]
    public void A_folder_inside_an_archive_gives_its_name()
    {
        var item = ShellItems.Parse(B(InArchive));
        Assert.Equal(ShellItemKind.ArchiveEntry, item.Kind);
        Assert.Equal("mods", item.Name);
    }

    [Theory]
    [InlineData(ControlPanel)]
    [InlineData("0100")]
    [InlineData("")]
    public void Anything_else_is_special(string hex) => Assert.Equal(ShellItemKind.Special, ShellItems.Parse(B(hex)).Kind);

    [Fact]
    public void Garbage_never_throws()
    {
        var random = new Random(7);
        for (int i = 0; i < 2000; i++)
        {
            var bytes = new byte[random.Next(0, 200)];
            random.NextBytes(bytes);
            if (bytes.Length >= 2) BitConverter.TryWriteBytes(bytes.AsSpan(0, 2), (ushort)bytes.Length);
            ShellItems.Parse(bytes);
        }
    }

    [Fact]
    public void Paths_are_built_from_the_Desktop_and_known_folders_down()
    {
        var t = new DateTime(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);
        static ShellBagCollector.BagChild Child(int slot, string hex, ShellBagCollector.BagNode? node = null) => new(slot, B(hex), node);
        static ShellBagCollector.BagNode Node(DateTime? written, int[] mru, params ShellBagCollector.BagChild[] children) =>
            new("BagMRU", written, mru, children);

        var zipNode = Node(t.AddHours(2), [0], Child(0, InArchive, Node(t.AddHours(3), [])));
        var downloads = Node(t.AddHours(1), [1], Child(0, Folder, Node(t, [])), Child(1, Zip, zipNode));
        var drive = Node(t, [], Child(0, Folder, Node(t, [])));
        var root = Node(t.AddHours(4), [2],
            Child(0, Downloads, downloads),
            Child(1, Drive, drive),
            Child(2, Delegate, Node(t, [])),     // a folder on the Desktop itself
            Child(3, ControlPanel, Node(t, [], Child(0, Folder))));

        var visits = ShellBagCollector.Walk(root, g => g == new Guid("088E3905-0323-4B02-9826-5D99428E115F") ? @"C:\Users\a\Downloads" : null,
            @"C:\Users\a\Desktop", "a").ToDictionary(v => v.Path);

        Assert.Equal("Folder", visits[@"C:\Users\a\Downloads\ACLib"].What);
        Assert.Equal("Archive", visits[@"C:\Users\a\Downloads\ScreenshareSuite-test.zip"].What);
        Assert.Equal(t.AddHours(1), visits[@"C:\Users\a\Downloads\ScreenshareSuite-test.zip"].OpenedUtc);   // first in its parent's MRU
        Assert.Null(visits[@"C:\Users\a\Downloads\ACLib"].OpenedUtc);                                         // not first: no exact time
        Assert.Equal(t.AddHours(2), visits[@"C:\Users\a\Downloads\ScreenshareSuite-test.zip"].RecordUpdatedUtc);
        Assert.Equal("Inside archive", visits[@"C:\Users\a\Downloads\ScreenshareSuite-test.zip\mods"].What);
        Assert.True(visits.ContainsKey(@"C:\ACLib"));
        Assert.True(visits.ContainsKey(@"C:\Users\a\Desktop\.claude"));
        Assert.True(visits.ContainsKey(@"…\ACLib"));   // under the control panel: only the end of the path is known
        Assert.Equal(new DateTime(2026, 3, 21, 9, 26, 0, DateTimeKind.Utc), visits[@"C:\ACLib"].FolderModifiedUtc);
    }

    [Fact]
    public void The_same_folder_recorded_twice_is_one_row_with_the_latest_times()
    {
        var a = new Models.FolderVisit { Path = @"C:\x", User = "u", OpenedUtc = new DateTime(2026, 1, 1), Source = "UsrClass" };
        var b = a with { Path = @"c:\X", OpenedUtc = null, RecordUpdatedUtc = new DateTime(2026, 2, 1), Source = "NTUSER" };
        var merged = Assert.Single(ShellBagCollector.Merge([a, b]));
        Assert.Equal(new DateTime(2026, 1, 1), merged.OpenedUtc);
        Assert.Equal(new DateTime(2026, 2, 1), merged.RecordUpdatedUtc);
        Assert.Equal(new DateTime(2026, 2, 1), merged.LastActivityUtc);
    }
}
