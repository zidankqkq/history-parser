using HistoryParser.Core.Analysis;
using HistoryParser.Core.Bypass;
using HistoryParser.Core.Models;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Tests;

/// <summary>Programs on a volume with no drive letter, virtual disks, and the registry key that stops event logging.</summary>
public class VolumeTests
{
    static readonly DateTime Now = new(2026, 11, 20, 18, 0, 0, DateTimeKind.Utc);
    static readonly DateTime Boot = Now.AddHours(-6);
    const string Hidden = @"\\?\Volume{1a2b3c4d-0000-0000-0000-100000000000}";

    // ---- paths ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(@"\\?\Volume{1a2b3c4d-0000-0000-0000-100000000000}\tools\x.exe", true)]
    [InlineData(@"\\?\Volume{1a2b3c4d-0000-0000-0000-100000000000}", true)]
    [InlineData(@"\\?\volume{1a2b3c4d-0000-0000-0000-100000000000}\x.exe", true)]
    [InlineData(@"\\?\Volume{}\x.exe", false)]
    [InlineData(@"\\?\Volume{1a2b3c4d-0000-0000-0000-100000000000}x.exe", false)]
    [InlineData(@"\\?\C:\x.exe", false)]
    [InlineData(@"C:\x.exe", false)]
    [InlineData(@"\Device\HarddiskVolume7\x.exe", false)]
    public void A_volume_path_is_told_from_every_other_spelling(string path, bool expected) => Assert.Equal(expected, Volumes.IsVolumePath(path));

    static PathNormalizer Normalizer() => new(
        [
            new KeyValuePair<string, string>(@"\Device\HarddiskVolume3", "C:"),
            new(@"\Device\HarddiskVolume7", Hidden),            // no letter, mounted nowhere
            new(@"\Device\HarddiskVolume9", @"C:\Mount\Data"),  // no letter, mounted as a folder
        ],
        new Dictionary<uint, string> { [0xA1B2C3D4] = Hidden }, new Dictionary<Guid, string>());

    [Fact]
    public void A_program_on_a_volume_with_no_letter_gets_a_path_that_can_be_opened()
    {
        var n = Normalizer();
        Assert.Equal(Hidden + @"\tools\x.exe", n.Normalize(@"\Device\HarddiskVolume7\tools\x.exe"));
        // Prefetch names the volume by its serial number instead.
        Assert.Equal(Hidden + @"\TOOLS\X.EXE", n.Normalize(@"\VOLUME{01dc5f1e2a3b4c5d-A1B2C3D4}\TOOLS\X.EXE"));
    }

    [Fact]
    public void A_volume_mounted_as_a_folder_is_that_folder()
    {
        Assert.Equal(@"C:\Mount\Data\game\run.exe", Normalizer().Normalize(@"\Device\HarddiskVolume9\game\run.exe"));
    }

    [Fact]
    public void Normalizing_a_volume_path_again_changes_nothing()
    {
        var n = Normalizer();
        string once = n.Normalize(@"\Device\HarddiskVolume7\tools\x.exe");
        Assert.Equal(once, n.Normalize(once));
    }

    [Fact]
    public void This_PCs_volumes_are_listed_and_every_one_gets_a_path()
    {
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        var volumes = Volumes.List();
        string system = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!;
        var windows = Assert.Single(volumes, v => v.MountPaths.Contains(system, StringComparer.OrdinalIgnoreCase));
        Assert.StartsWith(@"\Device\", windows.Device);
        Assert.All(volumes, v => Assert.True(Volumes.IsVolumePath(v.GuidPath), v.GuidPath));

        var n = PathNormalizer.ForThisMachine();
        Assert.Equal(system + @"x\y.exe", n.Normalize(windows.Device + @"\x\y.exe"), ignoreCase: true);
        foreach (var v in volumes)
            Assert.False(n.Normalize(v.Device + @"\x.exe").StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase), v.Device);
    }

    // ---- what the file's row says --------------------------------------------------------------------------

    static FileRecord Build(string path, bool exists, bool driveExists = true, DateTime? ran = null, EvidenceKind kind = EvidenceKind.Execution)
    {
        var correlator = new Correlator(Now, TimeSpan.FromMinutes(2), [], [], fileExists: _ => exists, driveExists: _ => driveExists,
            lastWriteUtc: _ => null, routine: _ => null, bootUtc: Boot);
        return Assert.Single(correlator.Build([new Evidence
        {
            Source = kind == EvidenceKind.Presence ? EvidenceSource.ShimCache : EvidenceSource.Bam, Kind = kind, Path = path, TimeUtc = ran ?? Now.AddHours(-1),
        }]));
    }

    [Fact]
    public void A_program_that_ran_from_a_volume_with_no_letter_and_is_there_now_is_flagged()
    {
        var r = Build(Hidden + @"\tools\x.exe", exists: true, ran: Now.AddDays(-3));
        Assert.Equal(FileStatus.Exists, r.Status);
        Assert.Equal("File is present, on a volume that has no drive letter", r.StatusDetail);
        var f = Assert.Single(r.Findings, f => f.Title == "Ran from a volume with no drive letter");
        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains("The file is there now.", f.Detail);
        Assert.DoesNotContain("since the last boot", f.Detail);
    }

    [Fact]
    public void One_that_ran_since_the_last_boot_and_is_gone_is_flagged_too()
    {
        var r = Build(Hidden + @"\tools\x.exe", exists: false, ran: Now.AddHours(-1));
        Assert.Equal(FileStatus.Missing, r.Status);
        Assert.Equal("Not present on its volume, which has no drive letter", r.StatusDetail);
        var f = Assert.Single(r.Findings, f => f.Title == "Ran from a volume with no drive letter");
        Assert.Contains("The file is not there now.", f.Detail);
        Assert.Contains("since the last boot", f.Detail);
    }

    [Fact]
    public void An_older_record_whose_file_is_not_there_may_be_about_another_volume_and_is_not_flagged()
    {
        var r = Build(Hidden + @"\tools\x.exe", exists: false, ran: Now.AddDays(-3));
        Assert.DoesNotContain(r.Findings, f => f.Title == "Ran from a volume with no drive letter");
    }

    [Fact]
    public void A_file_that_was_only_seen_there_is_not_flagged()
    {
        var r = Build(Hidden + @"\tools\x.exe", exists: true, kind: EvidenceKind.Presence);
        Assert.Equal(FileStatus.Exists, r.Status);
        Assert.DoesNotContain(r.Findings, f => f.Title == "Ran from a volume with no drive letter");
    }

    [Fact]
    public void A_program_on_a_lettered_drive_is_never_called_hidden()
    {
        var r = Build(@"C:\tools\x.exe", exists: true);
        Assert.Equal("File is present", r.StatusDetail);
        Assert.DoesNotContain(r.Findings, f => f.Title == "Ran from a volume with no drive letter");
    }

    [Fact]
    public void A_device_no_volume_has_now_reads_as_a_drive_that_is_not_connected()
    {
        var r = Build(@"\Device\HarddiskVolume12\cheats\loader.exe", exists: false);
        Assert.Equal(FileStatus.DriveNotConnected, r.Status);
        Assert.StartsWith(@"No volume is \Device\HarddiskVolume12 now", r.StatusDetail);
    }

    [Theory]
    [InlineData(@"\Device\HarddiskVolume12\a\b.exe", @"\Device\HarddiskVolume12")]
    [InlineData(@"\DEVICE\HARDDISKVOLUME3\X.EXE", @"\DEVICE\HARDDISKVOLUME3")]
    [InlineData(@"\Device\HarddiskVolumeShadowCopy4\a.exe", null)]
    [InlineData(@"\Device\HarddiskVolume12", null)]
    [InlineData(@"\Device\Mup\server\share\a.exe", null)]
    [InlineData(@"C:\a.exe", null)]
    public void The_device_is_read_from_a_path_that_names_one(string path, string? device) => Assert.Equal(device, Correlator.DeviceVolume(path));

    // ---- virtual disks -------------------------------------------------------------------------------------

    [Fact]
    public void A_virtual_disk_event_becomes_a_row_identified_by_the_file()
    {
        var data = new Dictionary<string, string> { ["VhdFileName"] = @"\\?\C:\Users\bob\Documents\backup.vhdx", ["VhdDiskNumber"] = "2", ["VirtualDisk"] = "0xffffb00f2e4a1010" };
        var attached = UsbAudit.ParseVirtualDiskEvent(1, data)!;
        Assert.Equal("Virtual disk backup.vhdx", attached.Device);
        Assert.Equal(@"C:\Users\bob\Documents\backup.vhdx", attached.Serial);
        Assert.Equal("Attached", attached.Action);
        Assert.Equal("disk 2", attached.Detail);
        Assert.Equal("Removed", UsbAudit.ParseVirtualDiskEvent(2, data)!.Action);
    }

    [Fact]
    public void Other_events_and_ones_without_a_file_are_not_rows()
    {
        var data = new Dictionary<string, string> { ["VhdFileName"] = @"C:\a.vhd" };
        Assert.Null(UsbAudit.ParseVirtualDiskEvent(12, data));
        Assert.Null(UsbAudit.ParseVirtualDiskEvent(1, new Dictionary<string, string>()));
        Assert.Null(UsbAudit.ParseVirtualDiskEvent(1, new Dictionary<string, string> { ["VhdFileName"] = "  " }));
    }

    // ---- the setup-environment switch ----------------------------------------------------------------------

    [Fact]
    public void Without_the_key_the_switch_is_fine_and_nothing_is_raised()
    {
        var (state, detail, finding) = RecordingAudit.JudgeSetupSwitch(false, null);
        Assert.Equal(CheckState.Ok, state);
        Assert.Equal("Not set.", detail);
        Assert.Null(finding);
    }

    [Fact]
    public void With_the_key_it_is_reported_with_when_it_was_written()
    {
        var written = Now.AddMinutes(-25);
        var (state, detail, finding) = RecordingAudit.JudgeSetupSwitch(true, written);
        Assert.Equal(CheckState.Bad, state);
        Assert.Contains(When.L(written), detail);
        Assert.Equal("Windows is set to act as its setup environment (MiniNT)", finding!.Value.Title);
        Assert.Equal(written, finding.Value.TimeUtc);
    }

    [Fact]
    public void This_PC_does_not_have_the_key()
    {
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\MiniNT");
        Assert.Null(key); // an installed Windows never has it; if this fails the check's premise is wrong
    }
}
