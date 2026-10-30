using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

public class CommandSnippetTests
{
    [Fact]
    public void A_command_padded_past_the_display_limit_is_still_flagged_and_shown()
    {
        // Padding must not push the part that matters out of the check or out of view.
        var command = "Write-Output '" + new string('a', 9000) + "'; Remove-Item C:\\Windows\\Prefetch\\*";
        var hit = KeywordLists.Default().ClassifyAt(command);
        Assert.NotNull(hit);
        var shown = KeywordLists.Around(command, hit.Value.Index, hit.Value.Length, 300);
        Assert.Contains("Prefetch", shown);
        Assert.StartsWith("…", shown);
        Assert.True(shown.Length <= 302);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(500)]
    [InlineData(995)]
    public void The_window_always_holds_the_match(int at)
    {
        var text = new string('x', at) + "MATCH" + new string('y', 1000 - at);
        var shown = KeywordLists.Around(text, at, 5, 120);
        Assert.Contains("MATCH", shown);
        Assert.True(shown.Trim('…').Length == 120);
    }

    [Fact]
    public void Short_text_is_shown_whole() => Assert.Equal("fsutil usn deletejournal", KeywordLists.Around("fsutil usn deletejournal", 0, 6, 300));

    [Fact]
    public void Classify_and_ClassifyAt_agree()
    {
        var rules = KeywordLists.Default();
        foreach (var command in new[] { "wevtutil cl Security", "fsutil usn deletejournal /d c:", "dir", "Set-Date -Date 2020-01-01" })
            Assert.Equal(rules.Classify(command), rules.ClassifyAt(command)?.Meaning);
    }
}
