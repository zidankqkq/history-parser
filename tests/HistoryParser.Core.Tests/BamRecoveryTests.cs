using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using RegistryHive = HistoryParser.Core.Parsers.RegistryHive;

namespace HistoryParser.Core.Tests;

/// <summary>
/// A registry file Windows itself creates, writes and deletes from. RegLoadAppKey gives any program a private registry
/// file with no special rights, and the kernel treats its keys and values exactly as it treats the SYSTEM file's, so a
/// value deleted here is freed the way a deleted BAM entry is. Nothing in these tests is a hand-made hive.
/// </summary>
static class AppHive
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegLoadAppKeyW(string file, out SafeRegistryHandle result, int samDesired, int options, int reserved);

    const int KEY_ALL_ACCESS = 0xF003F;

    /// <summary>Runs <paramref name="work"/> on a new registry file, then returns the file as Windows left it on disk.</summary>
    public static byte[] Make(string name, Action<RegistryKey> work)
    {
        string file = Scratch.PathFor("app-hive", name + ".dat");
        foreach (var old in Directory.GetFiles(Path.GetDirectoryName(file)!, name + ".dat*")) File.Delete(old);
        int rc = RegLoadAppKeyW(file, out var handle, KEY_ALL_ACCESS, 0, 0);
        if (rc != 0) throw new Win32Exception(rc);
        using (var root = RegistryKey.FromHandle(handle)) work(root);
        return File.ReadAllBytes(file);
    }
}

public class BamRecoveryTests
{
    static readonly DateTime Now = new(2026, 11, 20, 18, 0, 0, DateTimeKind.Utc);
    const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const string Users = @"ControlSet001\Services\bam\State\UserSettings\" + Sid;
    const string Kept = @"\Device\HarddiskVolume3\Program Files\Launcher\launcher.exe";
    const string Gone = @"\Device\HarddiskVolume3\Users\bob\Downloads\loader.exe";

    /// <summary>A BAM value as Windows writes it: the time, then sixteen more bytes.</summary>
    static byte[] Value(DateTime utc)
    {
        var data = new byte[24];
        BitConverter.GetBytes(utc.ToFileTimeUtc()).CopyTo(data, 0);
        data[20] = 2;
        return data;
    }

    static RegistryKey UsersKey(RegistryKey root)
    {
        using (var select = root.CreateSubKey("Select")) select.SetValue("Current", 1, RegistryValueKind.DWord);
        return root.CreateSubKey(Users);
    }

    static readonly DateTime Boot = Now.AddHours(-5);

    /// <summary><paramref name="live"/> is what the registry has now; <paramref name="onDisk"/> says whether the programs' files are there.</summary>
    static BamRecovery.Result Find(byte[] file, string[] live, bool onDisk = true) =>
        BamRecovery.Find(new RegistryHive(file), (_, _, name) => live.Contains(name, StringComparer.OrdinalIgnoreCase), Now, Boot, _ => onDisk);

    [Fact]
    public void A_deleted_entry_is_read_back_from_freed_space()
    {
        var ran = Now.AddMinutes(-40);
        var file = AppHive.Make("deleted", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(ran), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(Gone);
        });

        var found = Find(file, [Kept]);
        var entry = Assert.Single(found.Deleted);
        Assert.Equal(Gone, entry.DevicePath);
        Assert.Equal(ran, entry.TimeUtc);
        Assert.True(entry.FromFreeSpace);
        Assert.Null(entry.Sid);
        Assert.Equal(1, found.OnDisk);
        Assert.True(found.FreeCells > 0);
    }

    [Fact]
    public void An_entry_still_in_the_file_but_gone_from_the_registry_is_a_deletion_with_its_user()
    {
        var ran = Now.AddMinutes(-10);
        var file = AppHive.Make("stale", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(ran), RegistryValueKind.Binary);
        });

        // The file has both; the registry (as the scan sees it afterwards) has only one.
        var entry = Assert.Single(Find(file, [Kept]).Deleted);
        Assert.Equal(Gone, entry.DevicePath);
        Assert.Equal(ran, entry.TimeUtc);
        Assert.False(entry.FromFreeSpace);
        Assert.Equal(Sid, entry.Sid);
    }

    [Fact]
    public void Nothing_is_reported_when_the_registry_still_has_every_entry()
    {
        var file = AppHive.Make("intact", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(Now.AddHours(-1)), RegistryValueKind.Binary);
        });
        var found = Find(file, [Kept, Gone]);
        Assert.Empty(found.Deleted);
        Assert.Equal(2, found.OnDisk);
    }

    [Fact]
    public void A_program_run_again_updates_its_entry_and_leaves_nothing_that_reads_as_deleted()
    {
        // This is what every program does all day: the same value is written again with a new time.
        var file = AppHive.Make("updated", root =>
        {
            using var users = UsersKey(root);
            for (int i = 6; i >= 0; i--)
            {
                users.SetValue(Kept, Value(Now.AddHours(-i)), RegistryValueKind.Binary);
                users.Flush();
            }
        });
        var found = Find(file, [Kept]);
        Assert.Empty(found.Deleted);
        Assert.Equal(0, found.Old);
        // Windows rewrites the value where it is: no freed copy of it is left behind at all.
        Assert.Equal(0, found.ListedAgain);
    }

    [Fact]
    public void An_entry_deleted_and_then_written_again_is_not_reported()
    {
        var file = AppHive.Make("again", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(Now.AddHours(-2)), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(Gone);
            users.Flush();
            users.SetValue(Gone, Value(Now.AddMinutes(-5)), RegistryValueKind.Binary);
        });
        var found = Find(file, [Kept, Gone]);
        Assert.Empty(found.Deleted);
        Assert.InRange(found.ListedAgain, 0, 1); // the freed copy may already have been written over by the new entry
    }

    [Fact]
    public void An_entry_old_enough_for_Windows_own_clean_up_is_counted_but_not_reported()
    {
        var file = AppHive.Make("old", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(Now.AddDays(-9)), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(Gone);
        });
        var found = Find(file, [Kept]);
        Assert.Empty(found.Deleted);
        Assert.Equal(1, found.Old);
    }

    [Fact]
    public void An_entry_from_before_the_last_boot_whose_program_is_gone_is_Windows_own_clean_up()
    {
        // Run a program, delete it, restart: Windows drops the entry itself when it starts.
        var file = AppHive.Make("gone-program", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(Boot.AddHours(-20)), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(Gone);
        });
        var found = Find(file, [Kept], onDisk: false);
        Assert.Empty(found.Deleted);
        Assert.Equal(1, found.ProgramGone);
        Assert.Equal(0, found.Old);
    }

    [Fact]
    public void An_entry_from_before_the_last_boot_whose_program_is_still_there_is_reported()
    {
        var ran = Boot.AddHours(-20);
        var file = AppHive.Make("kept-program", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(ran), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(Gone);
        });
        var found = Find(file, [Kept], onDisk: true);
        Assert.Equal(ran, Assert.Single(found.Deleted).TimeUtc);
        Assert.Equal(0, found.ProgramGone);
    }

    [Fact]
    public void An_entry_from_a_run_since_the_last_boot_is_reported_even_when_its_program_is_gone()
    {
        // Run, delete the program, delete the entry, no restart: Windows has not started since, so it removed nothing.
        var ran = Boot.AddHours(2);
        var file = AppHive.Make("this-boot", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            users.SetValue(Gone, Value(ran), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(Gone);
        });
        var found = Find(file, [Kept], onDisk: false);
        Assert.Equal(ran, Assert.Single(found.Deleted).TimeUtc);
    }

    [Fact]
    public void A_deleted_value_that_is_not_a_BAM_entry_is_ignored()
    {
        var file = AppHive.Make("other", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            // The right kind of name with text in it, a time no entry could carry, and a name that is not a device path.
            users.SetValue(@"\Device\HarddiskVolume3\Users\bob\notes.exe", "some text", RegistryValueKind.String);
            users.SetValue(@"\Device\HarddiskVolume3\Users\bob\zero.exe", new byte[24], RegistryValueKind.Binary);
            users.SetValue("SequenceNumber", Value(Now.AddHours(-1)), RegistryValueKind.Binary);
            users.Flush();
            users.DeleteValue(@"\Device\HarddiskVolume3\Users\bob\notes.exe");
            users.DeleteValue(@"\Device\HarddiskVolume3\Users\bob\zero.exe");
            users.DeleteValue("SequenceNumber");
        });
        var found = Find(file, [Kept]);
        Assert.Empty(found.Deleted);
        Assert.Equal(0, found.Old);
    }

    [Fact]
    public void Many_deleted_entries_are_all_found_wherever_Windows_merged_their_cells()
    {
        var names = Enumerable.Range(0, 40).Select(i => $@"\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\run{i:00}\tool{i:00}.exe").ToList();
        var file = AppHive.Make("many", root =>
        {
            using var users = UsersKey(root);
            users.SetValue(Kept, Value(Now.AddHours(-3)), RegistryValueKind.Binary);
            for (int i = 0; i < names.Count; i++) users.SetValue(names[i], Value(Now.AddMinutes(-60 + i)), RegistryValueKind.Binary);
            users.Flush();
            foreach (var n in names) users.DeleteValue(n);
        });
        var found = Find(file, [Kept]);
        Assert.Equal(names.Order(), found.Deleted.Select(e => e.DevicePath).Order());
        Assert.All(found.Deleted, e => Assert.Equal(Now.AddMinutes(-60 + names.IndexOf(e.DevicePath)), e.TimeUtc));
    }

    // ---- what the finding says ---------------------------------------------------------------------------

    static FileRecord Record(DateTime ran, DateTime boot, bool freed = true)
    {
        const string path = @"C:\Users\bob\Downloads\loader.exe";
        var correlator = new Correlator(Now, TimeSpan.FromMinutes(2), [], [], fileExists: _ => false, driveExists: _ => true,
            lastWriteUtc: _ => null, routine: _ => null, bootUtc: boot);
        return Assert.Single(correlator.Build([new Evidence
        {
            Source = EvidenceSource.Bam, Kind = EvidenceKind.Execution, Path = path, TimeUtc = ran,
            Detail = BamRecovery.Mark + (freed ? BamRecovery.FromFreeSpace : BamRecovery.FromStaleFile) + ": last execution for bob",
        }]));
    }

    [Fact]
    public void A_deleted_entry_from_a_run_since_the_last_boot_is_flagged_high_on_the_file()
    {
        var r = Record(Now.AddMinutes(-40), boot: Now.AddHours(-5));
        var f = Assert.Single(r.Findings, f => f.Title == "BAM entry deleted");
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(r.Path, f.Path);
        Assert.Contains("read from freed space in the registry file", f.Detail);
        Assert.Contains("This run was since the last boot", f.Detail);
        Assert.Equal(Now.AddMinutes(-40), r.LastExecutionUtc);
    }

    [Fact]
    public void A_deleted_entry_from_before_the_last_boot_is_a_weaker_lead()
    {
        var r = Record(Now.AddDays(-2), boot: Now.AddHours(-5), freed: false);
        var f = Assert.Single(r.Findings, f => f.Title == "BAM entry deleted");
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains("still in the registry file on disk but gone from the registry", f.Detail);
        Assert.Contains("the file was still on disk", f.Detail);
        Assert.DoesNotContain("This run was since the last boot", f.Detail);
    }

    [Fact]
    public void An_ordinary_BAM_entry_is_not_a_deleted_one()
    {
        var correlator = new Correlator(Now, TimeSpan.FromMinutes(2), [], [], fileExists: _ => true, driveExists: _ => true,
            lastWriteUtc: _ => null, routine: _ => null, bootUtc: Now.AddHours(-5));
        var r = Assert.Single(correlator.Build([new Evidence
        {
            Source = EvidenceSource.Bam, Kind = EvidenceKind.Execution, Path = @"C:\Users\bob\Downloads\loader.exe",
            TimeUtc = Now.AddMinutes(-40), Detail = "Last execution for bob",
        }]));
        Assert.DoesNotContain(r.Findings, f => f.Title == "BAM entry deleted");
    }
}
