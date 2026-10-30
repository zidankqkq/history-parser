using System.Text;
using HistoryParser.Core.Models;
using RatChecker.Core;

namespace HistoryParser.Core.Tests;

public class GameDiffTests
{
    static ulong N(string s) => GameDiff.Normalized(Encoding.ASCII.GetBytes(s));

    [Theory]
    [InlineData("[12:04:31] [Render thread/INFO]: Loaded 812 recipes", "[09:59:02] [Render thread/INFO]: Loaded 17 recipes")]
    [InlineData("Session id 3f2a9c81e4b7 started", "Session id 0b1c2d3e4f5a started")]
    [InlineData("chunk x=12 z=-40", "chunk x=900 z=-3")]
    public void Times_counters_and_ids_are_not_differences(string a, string b) => Assert.Equal(N(a), N(b));

    [Theory]
    [InlineData("KillAuraModule", "KillAuraModules")]
    [InlineData("module.reach.enabled", "module.speed.enabled")]
    public void Different_words_stay_different(string a, string b) => Assert.NotEqual(N(a), N(b));

    [Fact]
    public void Cores_cut_a_few_characters_but_never_too_many()
    {
        var cores = GameDiff.Cores("BWednesdayK").ToList();
        Assert.Contains("Wednesday", cores);          // the ordinary string inside stray bytes
        Assert.All(cores, c => Assert.True(c.Length >= 8));
        Assert.Single(GameDiff.Cores("Velocity")); // too short to cut: only itself
    }

    [Fact]
    public void A_saved_list_holds_exactly_the_chosen_strings()
    {
        var r = new GameDiffResult { Clean = "clean", Injected = "injected" };
        var proven = new DiffString("me/client/module/KillAura", DiffKind.ClassName, 70, "me/client/module", 12, false, true);
        var key = new DiffString("module.killaura.range", DiffKind.Identifier, 45, "module", 1, false, true);
        var ticked = new DiffString("JXcwjMGQi", DiffKind.Identifier, 33, "", 1, false, false);
        r.Strings.AddRange([proven, key, ticked]);
        var path = Scratch.File("lists", "test - strings.txt", Encoding.UTF8.GetBytes(GameDiff.ToText(r, "Test", [proven, ticked])));
        var (core, supporting) = GameDiff.ReadList(path);
        Assert.Empty(core);
        Assert.Equal(["me/client/module/KillAura", "JXcwjMGQi"], supporting);
    }

    [Fact]
    public void A_list_from_the_previous_build_still_reads_its_sections()
    {
        var path = Scratch.File("lists", "older.txt", "# old\n[core]\nme/x/A\nme/x/B\n[supporting]\nsome text here\n"u8.ToArray());
        var (core, supporting) = GameDiff.ReadList(path);
        Assert.Equal(["me/x/A", "me/x/B"], core);
        Assert.Equal(["some text here"], supporting);
    }

    [Theory]
    [InlineData("ABZhFqK_Casoubj", true)]
    [InlineData("JXcwjMGQi", true)]
    [InlineData("KillAuraModule", false)]
    [InlineData("module.killaura.range", false)]
    [InlineData("Press Right Shift to open the menu", false)]
    public void Random_looking_names_are_told_from_readable_ones(string text, bool random) => Assert.Equal(random, GameDiff.LooksRandom(text));

    [Fact]
    public void An_old_list_without_sections_is_all_supporting()
    {
        var path = Scratch.File("lists", "old.txt", "# comment\nme/x/Y\nsome text here\n"u8.ToArray());
        var (core, supporting) = GameDiff.ReadList(path);
        Assert.Empty(core);
        Assert.Equal(2, supporting.Count);
    }

    static ClientScan.StringListInput List(int core, int supporting) =>
        new("l.txt", Enumerable.Range(0, core).Select(i => $"core/string/C{i}").ToList(), Enumerable.Range(0, supporting).Select(i => $"supporting {i}").ToList());

    [Theory]
    [InlineData(3, 0, Severity.High)]
    [InlineData(2, 2, Severity.High)]
    [InlineData(2, 1, Severity.Medium)]
    [InlineData(1, 0, Severity.Medium)]
    [InlineData(0, 3, Severity.Medium)]
    [InlineData(0, 2, Severity.Low)]
    [InlineData(0, 1, Severity.Low)]
    public void A_list_is_judged_on_how_much_of_it_is_there(int coreHits, int supportingHits, Severity expected) =>
        Assert.Equal(expected, ClientScan.JudgeList(List(20, 20), coreHits, supportingHits));

    [Fact]
    public void Nothing_found_is_no_finding() => Assert.Null(ClientScan.JudgeList(List(20, 20), 0, 0));

    [Theory]
    [InlineData(5, Severity.High)]
    [InlineData(4, Severity.Medium)]
    [InlineData(1, Severity.Low)]
    public void Lists_without_sections_need_more_hits(int hits, Severity expected) =>
        Assert.Equal(expected, ClientScan.JudgeList(List(0, 30), 0, hits));
}
