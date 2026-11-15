using HistoryParser.Core.Export;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

public class ReportFilesTests
{
    static readonly DateTime Started = new(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);

    static ScanResult Scan() => new()
    {
        Machine = new MachineInfo { ComputerName = "BOB-PC", UserName = @"BOB-PC\Bob" },
        StartedUtc = Started, FinishedUtc = Started,
        Files = [], Findings = [], Checks = [], Sources = [], ClockChanges = [], MemoryHits = [], Timeline = [], Commands = [],
    };

    static string Stamp => Started.ToLocalTime().ToString("yyyyMMdd-HHmm");

    [Fact]
    public void File_name_keeps_the_computer_name_out_when_private_details_are_hidden()
    {
        var name = ReportFiles.DefaultName(Scan(), privateHidden: true, "-timeline", "csv");
        Assert.Equal($"HistoryParser-{Stamp}-timeline-private-hidden.csv", name);
        Assert.DoesNotContain("BOB-PC", name);
    }

    [Fact]
    public void File_name_names_the_computer_otherwise()
    {
        Assert.Equal($"HistoryParser-BOB-PC-{Stamp}.html", ReportFiles.DefaultName(Scan(), privateHidden: false, "", "html"));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("plain", "plain")]
    [InlineData("=cmd|' /c calc'!A1", "'=cmd|' /c calc'!A1")]
    [InlineData("+1", "'+1")]
    [InlineData("-1", "'-1")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("two\nlines", "\"two\nlines\"")]
    public void Cells_are_quoted_and_never_run_as_formulas(string? value, string expected)
    {
        Assert.Equal(expected, ReportFiles.CsvCell(value));
    }

    [Fact]
    public void Csv_has_the_header_then_one_line_per_row()
    {
        var csv = ReportFiles.Csv(["Name", "Path"], [["a.exe", @"C:\a.exe"], ["b, c.exe", null]]);
        var nl = Environment.NewLine;
        Assert.Equal($"Name,Path{nl}a.exe,C:\\a.exe{nl}\"b, c.exe\",{nl}", csv);
    }
}
