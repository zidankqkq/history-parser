using HistoryParser.Core.Collectors;

namespace HistoryParser.Core.Tests;

/// <summary>
/// Windows logs event 501 ("a process has deleted a USN journal") for every delete request, including the ones a program
/// sends only to be told when a journal is deleted. The first tests use what a real PC's log held.
/// </summary>
public class JournalDeleteTests
{
    static readonly DateTime Day = new(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>A journal's id is the time it was created.</summary>
    static ulong Id(DateTime createdUtc) => (ulong)createdUtc.ToFileTimeUtc();

    static JournalDeletes.Request Req(DateTime t, string process, ulong journal, string volume = "C:") => new(t, process, volume, journal);

    [Fact]
    public void A_real_event_is_read_as_logged()
    {
        // Copied from Microsoft-Windows-Ntfs/Operational on a Windows 11 PC.
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ProcessName"] = "SearchIndexer.", ["VolumeCorrelationId"] = "{55f2653b-3977-49fd-bf06-bc3e63728e39}",
            ["VolumeNameLength"] = "2", ["VolumeName"] = "C:", ["JournalId"] = "0x1db13d34cf0acb2", ["CurrentUsn"] = "0x0",
        };
        var r = JournalDeletes.Parse(data, Day.AddHours(22));
        Assert.NotNull(r);
        Assert.Equal("SearchIndexer.", r!.Process);
        Assert.Equal("C:", r.Volume);
        Assert.Equal(0x01db13d34cf0acb2UL, r.JournalId);
        Assert.Equal(Day.AddHours(22), r.TimeUtc);
    }

    [Theory]
    [InlineData("", "C:")]
    [InlineData("0x0", "C:")]
    [InlineData("not a number", "C:")]
    [InlineData("0x1db13d34cf0acb2", "")]
    public void An_event_without_a_journal_or_a_drive_is_not_a_request(string journal, string volume)
    {
        var data = new Dictionary<string, string> { ["ProcessName"] = "x.exe", ["VolumeName"] = volume, ["JournalId"] = journal };
        Assert.Null(JournalDeletes.Parse(data, Day));
    }

    [Fact]
    public void Requests_that_name_the_journal_still_there_are_not_deletions()
    {
        // That PC: the search indexer sent one about once a day for ten weeks, and the journal was never deleted.
        const ulong current = 0x01db13d34cf0acb2UL;
        var requests = Enumerable.Range(0, 25).Select(i => Req(Day.AddDays(-i * 3).AddHours(1), "SearchIndexer.", current)).ToList();
        Assert.Empty(JournalDeletes.Deletions(requests, "C:", current));
    }

    [Fact]
    public void A_request_for_a_journal_that_is_gone_followed_at_once_by_a_new_journal_is_the_deletion()
    {
        ulong old = Id(Day.AddDays(-400));
        var deletedAt = Day.AddHours(19).AddMinutes(30);
        ulong current = Id(deletedAt.AddSeconds(4));
        var requests = new[]
        {
            Req(Day.AddDays(-2), "SearchIndexer.", old),
            Req(Day.AddHours(1), "SearchIndexer.", old),
            Req(deletedAt, "fsutil.exe", old),
            Req(deletedAt.AddHours(3), "SearchIndexer.", current),
        };
        var d = Assert.Single(JournalDeletes.Deletions(requests, "c:", current));
        Assert.Equal("fsutil.exe", d.Request.Process);
        Assert.Equal(deletedAt, d.Request.TimeUtc);
        Assert.Equal(Day.AddDays(-400), d.DeletedCreatedUtc);
        Assert.Equal(current, d.NextJournalId);
        Assert.Equal(deletedAt.AddSeconds(4), d.NextCreatedUtc);
    }

    [Fact]
    public void A_journal_replaced_long_after_the_last_request_is_not_blamed_on_that_request()
    {
        // The drive was formatted, or chkdsk rebuilt the journal: the old journal's last request is an indexer's from hours before.
        ulong old = Id(Day.AddDays(-400));
        ulong current = Id(Day.AddHours(20));
        var requests = new[] { Req(Day.AddHours(9), "SearchIndexer.", old) };
        Assert.Empty(JournalDeletes.Deletions(requests, "C:", current));
    }

    [Fact]
    public void Two_wipes_in_a_row_are_two_deletions()
    {
        ulong a = Id(Day.AddDays(-400));
        var first = Day.AddHours(10);
        ulong b = Id(first.AddSeconds(2));
        var second = Day.AddHours(18);
        ulong c = Id(second.AddSeconds(30));
        var requests = new[] { Req(first, "fsutil.exe", a), Req(Day.AddHours(11), "SearchIndexer.", b), Req(second, "cleaner.exe", b) };
        var found = JournalDeletes.Deletions(requests, "C:", c);
        Assert.Equal(["fsutil.exe", "cleaner.exe"], found.Select(d => d.Request.Process));
        Assert.Equal([b, c], found.Select(d => d.NextJournalId!.Value));
    }

    [Fact]
    public void With_no_journal_on_the_drive_now_the_last_request_for_the_last_journal_is_returned()
    {
        ulong old = Id(Day.AddDays(-400));
        var requests = new[] { Req(Day.AddHours(1), "SearchIndexer.", old), Req(Day.AddHours(19), "fsutil.exe", old) };
        var d = Assert.Single(JournalDeletes.Deletions(requests, "C:", null));
        Assert.Equal("fsutil.exe", d.Request.Process);
        Assert.Null(d.NextJournalId);
    }

    [Fact]
    public void Another_drives_requests_are_left_out()
    {
        ulong old = Id(Day.AddDays(-400));
        var at = Day.AddHours(19);
        var requests = new[] { Req(at, "fsutil.exe", old, "D:") };
        Assert.Empty(JournalDeletes.Deletions(requests, "C:", Id(at.AddSeconds(3))));
        Assert.Single(JournalDeletes.Deletions(requests, "D:", Id(at.AddSeconds(3))));
    }

    [Fact]
    public void The_finding_names_the_process_and_both_times()
    {
        ulong old = Id(Day.AddDays(-400));
        var at = Day.AddHours(19);
        var d = Assert.Single(JournalDeletes.Deletions([Req(at, "fsutil.exe", old)], "C:", Id(at.AddSeconds(45))));
        var (title, detail) = UsnJournalCollector.DeletionFinding("C:", d, system: true);
        Assert.Equal("USN journal on C: deleted by fsutil.exe", title);
        Assert.Contains(Util.When.L(at), detail);
        Assert.Contains("45 s later", detail);
        Assert.DoesNotContain("not the Windows drive", detail);
    }

    [Fact]
    public void This_PCs_own_log_is_read_and_the_journal_its_newest_requests_name_is_never_called_deleted()
    {
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        var requests = JournalDeletes.Read(); // empty where the log is off or cannot be read
        Assert.All(requests, r => Assert.True(r.JournalId != 0 && r.Volume.Length > 0));
        foreach (var volume in requests.Select(r => r.Volume).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ulong newest = requests.Where(r => r.Volume.Equals(volume, StringComparison.OrdinalIgnoreCase)).Max(r => r.JournalId);
            Assert.DoesNotContain(JournalDeletes.Deletions(requests, volume, newest), d => d.Request.JournalId == newest);
        }
    }

    [Fact]
    public void A_request_with_no_process_name_still_reads_as_a_sentence()
    {
        Assert.Equal("an unnamed process", JournalDeletes.Who(Req(Day, "", 1)));
    }
}
