using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

/// <summary>
/// Folding the copies of one library under one row. Every case is either clutter that must fold (build outputs, old
/// unpacked runtimes) or something a person hiding a file could try, which must not.
/// </summary>
public class RepeatsTests
{
    static readonly DateTime T0 = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    static FileRecord Dll(string path, string? sha = "AA", double minutes = 0, bool loaded = false, FileStatus status = FileStatus.Exists) => new()
    {
        Path = path, Name = Path.GetFileName(path), Type = FileType.Dll, Sha256 = sha, Status = status, WasLoaded = loaded,
        LastActivityUtc = T0.AddMinutes(minutes), LastExecutionUtc = loaded ? T0.AddMinutes(minutes) : null,
    };

    [Fact]
    public void Identical_copies_fold_under_the_newest_and_all_stay_listed()
    {
        var group = Assert.Single(Repeats.Find([
            Dll(@"C:\src\a\bin\Core.dll", minutes: 1), Dll(@"C:\src\b\bin\Core.dll", minutes: 3), Dll(@"C:\src\c\obj\Core.dll", minutes: 2),
        ]));
        Assert.Equal(@"C:\src\b\bin\Core.dll", group.Lead);
        Assert.Equal([@"C:\src\c\obj\Core.dll", @"C:\src\a\bin\Core.dll"], group.Copies);
        Assert.Equal(Repeats.SameContents, group.Why);
    }

    [Fact]
    public void A_different_build_of_the_same_name_is_a_different_file()
    {
        var groups = Repeats.Find([Dll(@"C:\src\a\Core.dll", "AA"), Dll(@"C:\src\b\Core.dll", "BB")]);
        Assert.Empty(groups);
    }

    [Fact]
    public void A_copy_that_was_loaded_keeps_its_own_row_and_leads()
    {
        // Three copies; two were loaded by a program. Each load is evidence of its own, so only the idle copy folds.
        var group = Assert.Single(Repeats.Find([
            Dll(@"C:\a\x.dll", minutes: 9), Dll(@"C:\b\x.dll", minutes: 1, loaded: true), Dll(@"C:\c\x.dll", minutes: 5, loaded: true),
        ]));
        Assert.Equal(@"C:\c\x.dll", group.Lead);
        Assert.Equal([@"C:\a\x.dll"], group.Copies);
    }

    [Fact]
    public void A_flagged_copy_never_folds()
    {
        var flagged = Dll(@"C:\Users\p\Downloads\x.dll", minutes: 1);
        flagged.Findings.Add(new Finding { Severity = Severity.Medium, Category = FindingCategory.Deletion, Title = "t", Detail = "d" });
        Assert.Empty(Repeats.Find([Dll(@"C:\a\x.dll", minutes: 5), flagged]));

        // Nor one with a Low finding (the antivirus caught this copy, say): the mark is on that row, so that row stays.
        var low = Dll(@"C:\b\x.dll", minutes: 1);
        low.Findings.Add(new Finding { Severity = Severity.Low, Category = FindingCategory.Defender, Title = "t", Detail = "d" });
        Assert.Empty(Repeats.Find([Dll(@"C:\a\x.dll", minutes: 5), low]));
    }

    [Fact]
    public void The_same_bytes_under_another_name_keep_their_own_row()
    {
        // A newer copy under a harmless name must not become the row that stands for the first one.
        Assert.Empty(Repeats.Find([Dll(@"C:\Users\p\AppData\Roaming\.minecraft\inject.dll", "AA", minutes: 1), Dll(@"D:\tools\helper.dll", "AA", minutes: 9)]));
        // The same name still folds, whatever the letter case.
        Assert.Single(Repeats.Find([Dll(@"C:\a\Core.dll", "AA", minutes: 1), Dll(@"C:\b\core.DLL", "aa", minutes: 9)]));
    }

    [Fact]
    public void Programs_jars_scripts_and_drivers_keep_one_row_each()
    {
        FileRecord Of(string path, FileType type) => new() { Path = path, Name = Path.GetFileName(path), Type = type, Sha256 = "AA", Status = FileStatus.Exists };
        Assert.Empty(Repeats.Find([
            Of(@"C:\a\mod.jar", FileType.Jar), Of(@"C:\b\mod.jar", FileType.Jar),
            Of(@"C:\a\tool.exe", FileType.Exe), Of(@"C:\b\tool.exe", FileType.Exe),
            Of(@"C:\a\run.bat", FileType.Script), Of(@"C:\b\run.bat", FileType.Script),
            Of(@"C:\a\drv.sys", FileType.Dll), Of(@"C:\b\drv.sys", FileType.Dll),
        ]));
    }

    [Fact]
    public void Routine_files_and_this_suites_own_are_left_to_their_own_switches()
    {
        var routine = Dll(@"C:\a\x.dll");
        routine.Routine = "signed";
        var own = Dll(@"C:\b\x.dll");
        own.IsThisTool = true;
        Assert.Empty(Repeats.Find([routine, own, Dll(@"C:\c\x.dll")]));
    }

    [Fact]
    public void Gone_files_of_one_name_in_folders_side_by_side_fold_from_three_up()
    {
        FileRecord Gone(string build, double minutes) => Dll($@"C:\Users\p\AppData\Local\Temp\.net\Tool\{build}\wpfgfx_cor3.dll", sha: null, minutes, status: FileStatus.Deleted);
        Assert.Empty(Repeats.Find([Gone("aaa=", 1), Gone("bbb=", 2)])); // two could be anything

        var group = Assert.Single(Repeats.Find([Gone("aaa=", 1), Gone("bbb=", 3), Gone("ccc=", 2)]));
        Assert.EndsWith(@"\bbb=\wpfgfx_cor3.dll", group.Lead);
        Assert.Equal(2, group.Copies.Count);
        Assert.Equal(Repeats.SameNameGone, group.Why);
    }

    [Fact]
    public void A_gone_file_that_was_loaded_or_sits_elsewhere_does_not_fold()
    {
        var loaded = Dll(@"C:\t\.net\Tool\ccc=\x.dll", sha: null, minutes: 9, loaded: true, status: FileStatus.Deleted);
        var groups = Repeats.Find([
            Dll(@"C:\t\.net\Tool\aaa=\x.dll", sha: null, status: FileStatus.Deleted), Dll(@"C:\t\.net\Tool\bbb=\x.dll", sha: null, status: FileStatus.Deleted), loaded,
            Dll(@"C:\Users\p\Downloads\x.dll", sha: null, status: FileStatus.Deleted), // same name, another place
            Dll(@"C:\t\.net\Tool\ddd=\x.dll", sha: null), // still on disk but never hashed: nothing to compare, stays
        ]);
        Assert.Empty(groups);
    }

    [Theory]
    [InlineData(@"C:\a\b\1234\x.dll", @"C:\a\b\*\x.dll")]
    [InlineData(@"C:\x.dll", "")]
    [InlineData(@"C:\a\x.dll", @"C:\*\x.dll")]
    public void The_sibling_key_swaps_the_last_folder_for_a_star(string path, string key) => Assert.Equal(key, Repeats.SiblingKey(path));
}
