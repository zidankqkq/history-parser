using HistoryParser.Core.Bypass;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

/// <summary>Things Windows and normal apps do on their own must not read as tampering.</summary>
public class WindowsNoiseTests
{
    static Severity Grade(int count, TimeSpan age, int filesBefore, bool recreated = false, string[]? recentlyUsed = null,
        bool usageKnown = true, bool duringUpdate = false) =>
        UsnJournalCollector.GradePrefetchBurst(new UsnJournalCollector.PfBurst(count, age, filesBefore, recreated, recentlyUsed ?? [],
            usageKnown, duringUpdate)).Severity;

    [Fact]
    public void Old_single_prefetch_deletion_is_housekeeping() => Assert.Equal(Severity.Low, Grade(1, TimeSpan.FromDays(3), 300));

    [Fact]
    public void Windows_trimming_a_full_folder_is_low_even_when_the_folder_is_small_now() =>
        // 376 deleted at once, leaving ~640: before the burst the folder was at Windows' limit.
        Assert.Equal(Severity.Low, Grade(376, TimeSpan.FromHours(3), 1016));

    [Fact]
    public void Prefetch_file_that_exists_again_is_a_rewrite() => Assert.Equal(Severity.Low, Grade(1, TimeSpan.FromMinutes(5), 300, recreated: true));

    [Fact]
    public void Batch_of_stale_prefetch_files_is_housekeeping() => Assert.Equal(Severity.Low, Grade(60, TimeSpan.FromHours(2), 400));

    [Fact]
    public void Batch_that_includes_programs_used_that_day_is_high() =>
        Assert.Equal(Severity.High, Grade(12, TimeSpan.FromHours(2), 300, recentlyUsed: ["JAVAW.EXE-1A2B3C4D.pf"]));

    [Fact]
    public void Batch_during_a_windows_update_is_low() => Assert.Equal(Severity.Low, Grade(80, TimeSpan.FromHours(2), 400, duringUpdate: true));

    [Fact]
    public void Batch_the_journal_cannot_explain_is_medium() => Assert.Equal(Severity.Medium, Grade(30, TimeSpan.FromHours(2), 400, usageKnown: false));

    [Fact]
    public void Recently_used_program_deleted_just_before_the_scan_is_medium() =>
        Assert.Equal(Severity.Medium, Grade(1, TimeSpan.FromHours(2), 300, recentlyUsed: ["CHEAT.EXE-11223344.pf"]));

    [Theory]
    [InlineData("SysMain", "disabled", false, Severity.High)]
    [InlineData("SysMain", "disabled", true, Severity.Medium)]
    [InlineData("PcaSvc", "demand start", false, Severity.Medium)]
    [InlineData("PcaSvc", "demand start", true, Severity.Low)]
    [InlineData("PcaSvc", "auto start", false, Severity.Low)]
    [InlineData("WSearch", "disabled", false, Severity.Low)]
    public void Start_type_changes_are_judged_by_service_and_account(string service, string to, bool bySystem, Severity expected) =>
        Assert.Equal(expected, ServiceJudge.StartTypeChange(service, to, bySystem).Severity);

    [Theory]
    [InlineData("PcaSvc", "auto start")]
    [InlineData("WSearch", "demand start")]
    [InlineData("DiagTrack", "disabled")]
    public void Windows_changing_services_itself_is_not_a_finding(string service, string to) =>
        Assert.Null(ServiceJudge.StartTypeChange(service, to, bySystem: true).Severity);

    [Fact]
    public void Non_critical_service_stop_is_not_a_finding() =>
        Assert.Null(ServiceJudge.Stop("WSearch", DateTime.UtcNow, []).Severity);

    [Fact]
    public void Critical_stop_during_a_windows_update_is_low()
    {
        var t = new DateTime(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);
        Assert.Equal(Severity.Low, ServiceJudge.Stop("EventLog", t, [t.AddMinutes(5)]).Severity);
    }

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Discord\app-1.0.9163\Discord.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Roblox\Versions\version-0123abcd\RobloxPlayerBeta.exe")]
    [InlineData(@"C:\Program Files\Google\Chrome\Application\131.0.6778.86\chrome_pwa_launcher.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\SomeApp\packages\SomeApp-2.0-full.nupkg\setup.exe")]
    public void Updater_paths_are_recognised(string path) => Assert.True(ArtifactAudit.LooksLikeUpdate(path));

    [Theory]
    [InlineData(@"C:\Users\a\Downloads\loader.exe")]
    [InlineData(@"C:\Users\a\Desktop\clients\vape.jar")]
    [InlineData(@"C:\Users\a\AppData\Roaming\.minecraft\mods\xray-1.2.jar")]
    [InlineData(@"C:\Users\a\AppData\Roaming\.minecraft\versions\1.8.9-Client\1.8.9-Client.jar")]
    [InlineData(@"C:\Users\a\AppData\Roaming\.minecraft\versions\1.20.1\1.20.1.jar")]
    public void Ordinary_paths_are_not_updates(string path) => Assert.False(ArtifactAudit.LooksLikeUpdate(path));
}

public class TimeWindowTests
{
    static readonly DateTime Now = new(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);
    static readonly DateTime Boot = Now.AddHours(-5);

    static Finding F(DateTime? t, string? path = null) =>
        new() { Severity = Severity.Medium, Category = FindingCategory.Deletion, Title = "x", Detail = "", TimeUtc = t, Path = path };

    [Theory]
    [InlineData(TimeWindow.ThisBoot, 5)]
    [InlineData(TimeWindow.Day, 24)]
    [InlineData(TimeWindow.ThreeDays, 72)]
    [InlineData(TimeWindow.Week, 168)]
    public void Windows_start_where_expected(TimeWindow w, int hoursBack) =>
        Assert.Equal(Now.AddHours(-hoursBack), TimeWindows.Since(w, Now, Boot));

    [Fact]
    public void Everything_has_no_start() => Assert.Null(TimeWindows.Since(TimeWindow.All, Now, Boot));

    [Fact]
    public void Dated_findings_outside_the_window_are_dropped()
    {
        var since = Now.AddDays(-3);
        Assert.False(TimeWindows.Keep(F(Now.AddDays(-20)), since));
        Assert.True(TimeWindows.Keep(F(Now.AddHours(-1)), since));
    }

    [Fact]
    public void Undated_findings_about_the_pc_now_always_stay() => Assert.True(TimeWindows.Keep(F(null), Now.AddDays(-1)));

    [Fact]
    public void Undated_findings_follow_their_file()
    {
        var kept = new HashSet<string> { @"C:\a.exe" };
        Assert.True(TimeWindows.Keep(F(null, @"C:\a.exe"), Now.AddDays(-1), kept));
        Assert.False(TimeWindows.Keep(F(null, @"C:\old.exe"), Now.AddDays(-1), kept));
    }

    [Theory]
    [InlineData("boot", TimeWindow.ThisBoot)]
    [InlineData("3d", TimeWindow.ThreeDays)]
    [InlineData("ALL", TimeWindow.All)]
    public void Command_line_spellings_parse(string s, TimeWindow expected) => Assert.Equal(expected, TimeWindows.Parse(s));
}

/// <summary>"It's in Temp" or "it's named like the tool" must never be a way to slip a cheat past the screensharer.</summary>
public class EvasionTests
{
    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\is-AB12C.tmp\setup.tmp.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\nsx1234.tmp\System.dll")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\{0A1B2C3D-1111-2222-3333-444455556666}\.be\vc_redist.x64.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\lghub_setup.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\unins000.exe")]
    public void Installer_parts_in_temp_are_recognised(string path) => Assert.True(Util.FileTypes.IsInstallerTemp(path));

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\vape.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\loader.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\{0A1B2C3D-1111-2222-3333-444455556666}\client.dll")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\_MEI12345\injector.exe")]
    [InlineData(@"C:\Users\a\Downloads\setup.exe")]
    public void Anything_else_in_temp_gets_no_allowance(string path) => Assert.False(Util.FileTypes.IsInstallerTemp(path));

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\update\cheat.exe")]
    [InlineData(@"C:\Users\a\Downloads\Updates\cheat.exe")]
    [InlineData(@"C:\Users\a\Desktop\app-1.2.3\cheat.exe")]
    public void Update_folders_in_throwaway_places_are_not_updates(string path) => Assert.False(ArtifactAudit.LooksLikeUpdate(path));

    [Fact]
    public void A_cheat_named_like_the_tool_is_not_the_tool()
    {
        var fake = Scratch.File("named-like-tool", "HistoryParser.exe", "MZ pretending"u8.ToArray());
        Assert.NotEqual(Analysis.SelfTraces.Match.Yes, Analysis.SelfTraces.Classify(fake));
    }

    [Fact]
    public void A_deleted_file_named_like_the_tool_keeps_its_severity()
    {
        var r = new FileRecord { Path = @"C:\Users\a\Downloads\gone\HistoryParser.exe", Name = "HistoryParser.exe", Type = FileType.Exe, Status = FileStatus.Deleted };
        r.Findings.Add(new Finding { Severity = Severity.Medium, Category = FindingCategory.Deletion, Title = "Ran, then deleted", Detail = "", Path = r.Path });
        var general = new List<Finding>();
        Analysis.SelfTraces.Mark([r], general);
        Assert.Equal(Severity.Medium, r.Findings[0].Severity);
        Assert.False(r.IsThisTool);
    }
}

public class SafeSaveTests
{
    static readonly DateTime T0 = new(2026, 10, 25, 22, 54, 49, DateTimeKind.Utc);
    const string Jump = @"C:\Users\a\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\5d696d521de238c3.customDestinations-ms";

    static List<ArtifactChange> Run(params Evidence[] usn)
    {
        var history = new ScanResult
        {
            Machine = new MachineInfo { ComputerName = "pc", UserName = "u", OsVersion = "", BootTimeUtc = T0.AddDays(-1), TimeZone = "", ToolVersion = "" },
            StartedUtc = T0.AddHours(1), FinishedUtc = T0.AddHours(1), Files = [], Findings = [], Checks = [], Sources = [], ClockChanges = [],
            MemoryHits = [], Timeline = usn.ToList(),
        };
        var ctx = new BypassContext(history, ArgumentRules.Default(), KeywordLists.Default());
        ArtifactAudit.Run(ctx, CancellationToken.None);
        return ctx.Artifacts.Where(a => a.Path == Jump).ToList();
    }

    static Evidence Usn(EvidenceKind kind, string path, DateTime t, string detail, string? related = null) =>
        new() { Source = EvidenceSource.UsnJournal, Kind = kind, Path = path, TimeUtc = t, Detail = detail, RelatedPath = related };

    [Fact]
    public void Windows_safe_save_of_a_jump_list_is_not_suspicious()
    {
        var rows = Run(
            Usn(EvidenceKind.Renamed, Jump, T0, $"Renamed to {Jump}~RF1c4bb6a.TMP", Jump + "~RF1c4bb6a.TMP"),
            Usn(EvidenceKind.Created, Jump, T0.AddSeconds(1), "File created"));
        Assert.Contains(rows, r => r.Change.StartsWith("Saved by Windows") && !r.Suspicious);
    }

    [Fact]
    public void Renamed_to_tmp_and_never_back_stays_suspicious()
    {
        var rows = Run(Usn(EvidenceKind.Renamed, Jump, T0, $"Renamed to {Jump}~RF1c4bb6a.TMP", Jump + "~RF1c4bb6a.TMP"));
        Assert.Contains(rows, r => r.Suspicious);
    }
}

public class WindowsSaveCopyTests
{
    const string Dir = @"C:\Users\a\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\";
    const string Jump = Dir + "dc8543725dad0653.customDestinations-ms";

    [Theory]
    [InlineData(Dir + "HHWZHXDGANS078K1L5WX.temp")]                               // Explorer's jump-list save
    [InlineData(Dir + "dc8543725dad0653.customDestinations-ms~RF1c4bb6a.TMP")]   // ReplaceFile's backup copy
    public void Windows_own_save_copies_are_recognised(string copy) => Assert.True(Util.FileTypes.IsWindowsSaveCopy(copy, Jump));

    [Theory]
    [InlineData(@"C:\Users\a\Downloads\HHWZHXDGANS078K1L5WX.temp")]   // right name, wrong folder
    [InlineData(Dir + "loader.tmp")]                                    // just a .tmp name
    [InlineData(Dir + "hhwzhxdgans078k1l5wx.temp")]                     // not Windows' pattern (lowercase)
    [InlineData(Dir + "HHWZHXDGANS078K1L5.temp")]                       // wrong length
    [InlineData(Dir + "other.customDestinations-ms~RF1c4bb6a.TMP")]    // a backup of a different file
    public void Lookalikes_are_not_windows_saves(string copy) => Assert.False(Util.FileTypes.IsWindowsSaveCopy(copy, Jump));
}

public class SafeSaveSequenceTests
{
    static readonly DateTime T0 = new(2026, 10, 26, 3, 55, 4, DateTimeKind.Utc);
    const string Dir = @"C:\Users\a\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\";
    const string Jump = Dir + "dc8543725dad0653.customDestinations-ms";

    static ArtifactChange Row(Evidence e)
    {
        var history = new ScanResult
        {
            Machine = new MachineInfo { ComputerName = "pc", UserName = "u", OsVersion = "", BootTimeUtc = T0.AddDays(-1), TimeZone = "", ToolVersion = "" },
            StartedUtc = T0.AddHours(1), FinishedUtc = T0.AddHours(1), Files = [], Findings = [], Checks = [], Sources = [], ClockChanges = [],
            MemoryHits = [], Timeline = [e],
        };
        var ctx = new BypassContext(history, ArgumentRules.Default(), KeywordLists.Default());
        ArtifactAudit.Run(ctx, CancellationToken.None);
        return ctx.Artifacts.Single(a => a.Path == Jump);
    }

    [Fact]
    public void Jump_list_swapped_in_from_its_temp_copy_is_a_save() =>
        Assert.False(Row(new Evidence { Source = EvidenceSource.UsnJournal, Kind = EvidenceKind.Renamed, Path = Jump, TimeUtc = T0,
            Detail = $"Renamed from {Dir}HHWZHXDGANS078K1L5WX.temp", RelatedPath = Dir + "HHWZHXDGANS078K1L5WX.temp" }).Suspicious);

    [Fact]
    public void Jump_list_swapped_in_from_a_file_elsewhere_stays_suspicious() =>
        Assert.True(Row(new Evidence { Source = EvidenceSource.UsnJournal, Kind = EvidenceKind.Renamed, Path = Jump, TimeUtc = T0,
            Detail = @"Renamed from C:\Users\a\Downloads\HHWZHXDGANS078K1L5WX.temp", RelatedPath = @"C:\Users\a\Downloads\HHWZHXDGANS078K1L5WX.temp" }).Suspicious);
}
