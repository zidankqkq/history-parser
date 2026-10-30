using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

public class CorrelatorTests
{
    static readonly DateTime Now = new(2026, 10, 24, 20, 0, 0, DateTimeKind.Utc);
    const string Jar = @"C:\Users\bob\Desktop\client.jar";
    const string Exe = @"C:\Users\bob\Downloads\tool.exe";

    static Correlator Make(IReadOnlyList<ClockChange>? clocks = null, bool exists = false, string[]? running = null,
        DateTime? lastWrite = null) =>
        new(Now, TimeSpan.FromMinutes(2), clocks ?? [], running ?? [],
            fileExists: _ => exists, driveExists: _ => true, lastWriteUtc: _ => lastWrite);

    static Evidence Ev(EvidenceSource s, EvidenceKind k, string path, DateTime? t, int? runs = null, string detail = "") =>
        new() { Source = s, Kind = k, Path = path, TimeUtc = t, RunCount = runs, Detail = detail };

    static FileRecord Single(IEnumerable<FileRecord> records, string path) =>
        Assert.Single(records, r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void Merges_sources_case_insensitively_and_prefers_mixed_case_display()
    {
        var records = Make().Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe.ToUpperInvariant(), Now.AddHours(-2), 5),
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-1)),
        ]);
        var r = Assert.Single(records);
        Assert.Equal(Exe, r.Path);
        Assert.Equal(5, r.RunCount);
        Assert.Equal(Now.AddHours(-1), r.LastExecutionUtc);
        Assert.Equal([EvidenceSource.Prefetch, EvidenceSource.Bam], r.Sources);
    }

    [Fact]
    public void Ran_then_deleted_is_reported_with_the_deleted_status()
    {
        var r = Single(Make().Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.LoadedModule, Jar, Now.AddMinutes(-50)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Deleted, Jar, Now.AddMinutes(-40)),
        ]), Jar);
        Assert.Equal(FileStatus.Deleted, r.Status);
        Assert.Equal(Now.AddMinutes(-40), r.DeletedUtc);
        var f = Assert.Single(r.Findings);
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal(FindingCategory.Deletion, f.Category);
    }

    [Fact]
    public void Run_after_deletion_is_impossible_and_rated_high()
    {
        var r = Single(Make().Build([
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Deleted, Exe, Now.AddHours(-3)),
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-1)),
        ]), Exe);
        Assert.Contains(r.Findings, f => f.Severity == Severity.High && f.Category == FindingCategory.ClockTampering);
    }

    [Fact]
    public void Dll_listed_by_a_later_run_of_its_loader_is_not_impossible()
    {
        // Real case: MicrosoftEdgeUpdate.exe's .pf still lists a DLL the updater deleted earlier.
        const string dll = @"C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3\psmachine.dll";
        var r = Single(Make().Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.LoadedModule, dll, Now.AddMinutes(-5)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Deleted, dll, Now.AddMinutes(-10)),
        ]), dll);
        Assert.Equal(FileStatus.Deleted, r.Status);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Pca_compatibility_events_are_not_compared_with_prefetch_runs()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-4), 3),
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-1), 3),
            Ev(EvidenceSource.Pca, EvidenceKind.Presence, Exe, Now.AddDays(-2)),
        ]), Exe);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Run_after_deletion_is_fine_when_the_file_was_recreated()
    {
        var r = Single(Make().Build([
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Deleted, Exe, Now.AddHours(-3)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Created, Exe, Now.AddHours(-2)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Deleted, Exe, Now.AddMinutes(-30)),
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-1)),
        ]), Exe);
        Assert.DoesNotContain(r.Findings, f => f.Severity == Severity.High);
    }

    [Fact]
    public void Recycle_bin_beats_missing()
    {
        var r = Single(Make().Build([
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-5)),
            Ev(EvidenceSource.RecycleBin, EvidenceKind.Recycled, Exe, Now.AddHours(-4)),
        ]), Exe);
        Assert.Equal(FileStatus.InRecycleBin, r.Status);
    }

    [Fact]
    public void Missing_without_any_deletion_record()
    {
        var r = Single(Make().Build([Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-5))]), Exe);
        Assert.Equal(FileStatus.Missing, r.Status);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Bam_older_than_prefetch_run_is_flagged_unless_still_running()
    {
        Evidence[] ev =
        [
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddHours(-1)),
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-6)),
        ];
        Assert.Contains(Single(Make(exists: true).Build(ev), Exe).Findings, f => f.Title.StartsWith("BAM time is older"));
        Assert.DoesNotContain(Single(Make(exists: true, running: ["tool.exe"]).Build(ev), Exe).Findings,
            f => f.Title.StartsWith("BAM time is older"));
    }

    [Fact]
    public void Bam_written_at_exit_after_the_prefetch_start_is_normal()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddHours(-3)),
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddHours(-1)),
        ]), Exe);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Pca_launch_newer_than_every_prefetch_run_is_flagged()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-3), 2),
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-2), 2),
            Ev(EvidenceSource.Pca, EvidenceKind.Execution, Exe, Now.AddHours(-1)),
        ]), Exe);
        Assert.Contains(r.Findings, f => f.Title == "PCA launch is newer than Prefetch" && f.Severity == Severity.Low);
    }

    [Fact]
    public void Pca_launch_matching_a_prefetch_run_is_consistent()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-2).AddSeconds(8), 1),
            Ev(EvidenceSource.Pca, EvidenceKind.Execution, Exe, Now.AddDays(-2)),
        ]), Exe);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Pca_launch_inside_the_prefetch_window_but_unmatched_is_a_low_lead()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-4), 2),
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddDays(-1), 2),
            Ev(EvidenceSource.Pca, EvidenceKind.Execution, Exe, Now.AddDays(-2)),
        ]), Exe);
        Assert.Contains(r.Findings, f => f.Title == "PCA launch missing from Prefetch" && f.Severity == Severity.Low);
    }

    [Fact]
    public void Run_inside_a_clock_rollback_window_is_high()
    {
        var rollback = new ClockChange { Source = "test", OldTimeUtc = Now.AddHours(-1), NewTimeUtc = Now.AddHours(-4) };
        var r = Single(Make([rollback], exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddHours(-3)),
        ]), Exe);
        Assert.Contains(r.Findings, f => f.Title == "Run time falls inside a clock rollback" && f.Severity == Severity.High);
    }

    [Fact]
    public void Future_timestamps_are_high()
    {
        var r = Single(Make(exists: true).Build([Ev(EvidenceSource.Bam, EvidenceKind.Execution, Exe, Now.AddDays(1))]), Exe);
        Assert.Contains(r.Findings, f => f.Title == "Timestamp in the future" && f.Severity == Severity.High);
    }

    [Fact]
    public void Attribute_change_after_the_last_run_is_a_weak_lead()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddHours(-3)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.TimestampChanged, Exe, Now.AddHours(-2)),
        ]), Exe);
        Assert.Contains(r.Findings, f => f.Title == "File attributes changed after its last run" && f.Severity == Severity.Low);
    }

    [Fact]
    public void Contents_replaced_after_the_last_run_is_medium()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddHours(-3)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Modified, Exe, Now.AddHours(-2)),
        ]), Exe);
        Assert.Contains(r.Findings, f => f.Title == "File replaced after its last run" && f.Severity == Severity.Medium);
    }

    [Fact]
    public void Launch_moments_before_the_scan_is_not_compared_with_prefetch()
    {
        var r = Single(Make(exists: true).Build([
            Ev(EvidenceSource.Prefetch, EvidenceKind.Execution, Exe, Now.AddHours(-3), 4),
            Ev(EvidenceSource.UserAssist, EvidenceKind.Execution, Exe, Now.AddMinutes(-1)),
        ]), Exe);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void ShimCache_modified_time_mismatch()
    {
        var shim = new Evidence
        {
            Source = EvidenceSource.ShimCache, Kind = EvidenceKind.Presence, Path = Exe, FileModifiedUtc = Now.AddDays(-10),
        };
        Assert.Contains(Single(Make(exists: true, lastWrite: Now.AddDays(-1)).Build([shim]), Exe).Findings,
            f => f.Title == "File differs from the one Windows cached");
        Assert.Empty(Single(Make(exists: true, lastWrite: Now.AddDays(-10)).Build([shim]), Exe).Findings);
    }

    [Fact]
    public void Name_only_evidence_joins_a_unique_record()
    {
        var records = Make().Build([
            Ev(EvidenceSource.Bam, EvidenceKind.Execution, Jar, Now.AddHours(-2)),
            Ev(EvidenceSource.UsnJournal, EvidenceKind.Deleted, @"?\client.jar", Now.AddHours(-1)),
        ]);
        var r = Assert.Single(records);
        Assert.Equal(FileStatus.Deleted, r.Status);
    }

    [Fact]
    public void Pseudo_entries_are_not_files()
    {
        Assert.Empty(Make().Build([Ev(EvidenceSource.EventLog, EvidenceKind.Presence, "[System] Windows started", Now)]));
    }
}

public class RuleTests
{
    [Theory]
    [InlineData(@"PS C:\Users\bob> Remove-Item C:\Windows\Prefetch\*      ", "PowerShell", @"Remove-Item C:\Windows\Prefetch\*")]
    [InlineData(@"C:\Users\bob>fsutil usn deletejournal /d c:", "cmd", "fsutil usn deletejournal /d c:")]
    [InlineData(@"C:\Users\bob\Desktop>cd ..", "cmd", "cd ..")]
    public void Prompt_lines_yield_the_command(string line, string shell, string command) =>
        Assert.Equal((shell, command), ShellHistoryCollector.ParsePromptLine(line));

    [Theory]
    [InlineData(@"C:\Users\bob>")]                         // empty prompt
    [InlineData(@"    Directory: C:\Users\bob")]          // command output
    [InlineData(@"<C:\Windows\x.exe>")]
    public void Non_prompt_lines_are_ignored(string line) => Assert.Null(ShellHistoryCollector.ParsePromptLine(line));

    [Fact]
    public void Old_name_sections_are_ignored_but_still_parse()
    {
        // [cheats]/[tools] from an older rules file load without error - names are no longer matched.
        var k = KeywordLists.Parse("# comment\n[cheats]\nfoo\n[tools]\nbar1\n[commands]\nbypass.bat => runs a bypass\n");
        Assert.Equal("runs a bypass", k.Classify(@"C:\> .\bypass.bat"));
        // A misspelt section is still an error rather than silently dropping the entries under it.
        Assert.Throws<FormatException>(() => KeywordLists.Parse("[cheat]\nfoo\n"));
    }

    [Fact]
    public void Default_rules_survive_a_save_and_load()
    {
        var defaults = KeywordLists.Default();
        var reloaded = KeywordLists.Parse(defaults.ToText());
        Assert.Equal(defaults.Commands.Select(c => c.Pattern), reloaded.Commands.Select(c => c.Pattern));
        Assert.Equal("deletes the USN journal", reloaded.Classify("fsutil usn deletejournal /d c:"));
    }

    [Fact]
    public void Custom_command_rules_plain_text_and_regex()
    {
        var rules = KeywordLists.Parse("[commands]\nbypass.bat => runs a known bypass\n/\\bdoomsday\\b/ => launches Doomsday\nC:\\Windows\\Temp\n");
        Assert.Equal("runs a known bypass", rules.Classify(@"C:\Users\bob> .\BYPASS.BAT -silent"));
        Assert.Equal("launches Doomsday", rules.Classify("java -jar doomsday.jar"));
        // Plain text is literal: the backslash path is not treated as a regex.
        Assert.StartsWith("matches the custom rule", rules.Classify(@"del C:\Windows\Temp\x.exe"));
        Assert.Null(rules.Classify("fsutil usn deletejournal")); // a [commands] section replaces the defaults
    }

    [Fact]
    public void Rules_file_without_commands_keeps_the_default_command_rules()
    {
        var rules = KeywordLists.Parse("# only a comment\n");
        Assert.Equal("deletes the USN journal", rules.Classify("fsutil usn deletejournal"));
    }

    [Fact]
    public void Bad_rules_report_the_line()
    {
        var (lists, errors) = KeywordLists.TryParse("[commands]\nok => fine\n/([unclosed/ => broken\n[weird]\n");
        Assert.Null(lists);
        Assert.Contains(errors, e => e.StartsWith("Line 3:"));
        Assert.Contains(errors, e => e.StartsWith("Line 4:"));
    }

    [Theory]
    [InlineData("fsutil usn deletejournal /d c:", true)]
    [InlineData("wevtutil cl System", true)]
    [InlineData("Remove-Item C:\\Windows\\Prefetch\\* -Force", true)]
    [InlineData("sc stop sysmain", true)]
    [InlineData("Set-Date -Date (Get-Date).AddHours(-3)", true)]
    [InlineData("w32tm.exe /config /update /manualpeerlist:\"$timeSource\"", false)]
    [InlineData("git status", false)]
    [InlineData("Get-Date", false)]
    public void Anti_forensic_commands(string line, bool suspicious) =>
        Assert.Equal(suspicious, ShellHistoryCollector.Classify(line) != null);

    [Fact]
    public void Resume_from_sleep_is_not_a_clock_change()
    {
        Assert.Null(EventLogCollector.ClassifyKernelGeneral("2", "", TimeSpan.FromHours(15)));
        Assert.Null(EventLogCollector.ClassifyKernelGeneral("1", "svchost.exe", TimeSpan.FromSeconds(-29)));
        Assert.Null(EventLogCollector.ClassifyKernelGeneral("3", "", TimeSpan.FromHours(-7)));
    }

    [Fact]
    public void Manual_and_hardware_clock_rollbacks_are_flagged()
    {
        Assert.Equal(Severity.High, EventLogCollector.ClassifyKernelGeneral("1", "SystemSettingsAdminFlows.exe", TimeSpan.FromHours(-3))?.Severity);
        Assert.Equal(Severity.High, EventLogCollector.ClassifyKernelGeneral("2", "", TimeSpan.FromHours(-3))?.Severity);
        Assert.Equal(Severity.Medium, EventLogCollector.ClassifyKernelGeneral("1", "svchost.exe", TimeSpan.FromHours(2))?.Severity);
    }

    [Theory]
    [InlineData("\"C:\\Users\\x\\Downloads\\drv.sys\" -arg", @"C:\Users\x\Downloads\drv.sys")]
    [InlineData(@"C:\Temp\mapper.sys", @"C:\Temp\mapper.sys")]
    public void Service_image_paths(string image, string expected) =>
        Assert.Equal(expected, EventLogCollector.StripImagePath(image));
}
