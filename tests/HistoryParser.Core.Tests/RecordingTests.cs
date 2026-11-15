using HistoryParser.Core.Bypass;
using HistoryParser.Core.Collectors;

namespace HistoryParser.Core.Tests;

/// <summary>The small rules behind "is this PC still recording", and the exceptions a script could try to hide behind.</summary>
public class RecordingTests
{
    [Theory]
    [InlineData("NOTEPAD.EXE-D8414F97.pf", "NOTEPAD.EXE")]
    [InlineData("notepad.exe", "NOTEPAD.EXE")]
    [InlineData("A-PROGRAM-WITH-DASHES.EXE-1A2B3C4D.pf", "A-PROGRAM-WITH-DASHES.EXE")]
    // Prefetch keeps 29 characters of a name; the process list keeps all of it.
    [InlineData("a-very-long-program-name-that-keeps-going.exe", "A-VERY-LONG-PROGRAM-NAME-THAT")]
    public void A_running_program_and_its_Prefetch_file_are_matched_by_the_same_name(string name, string expected) =>
        Assert.Equal(expected, RecordingAudit.PrefetchName(name));

    [Fact]
    public void The_same_program_flagged_on_every_launch_is_one_finding_that_names_each_launch()
    {
        static Models.Finding Launch(int minute, string program = "powershell.exe", Models.Severity severity = Models.Severity.Medium) => new()
        {
            Severity = severity, Category = Models.FindingCategory.Arguments, Title = $"Flagged arguments: {program}",
            Detail = $"PowerShell started (event 400): {program} starts hidden. Command line: run-{minute}", TimeUtc = new DateTime(2026, 11, 12, 18, minute, 0, DateTimeKind.Utc),
        };
        var other = new Models.Finding { Severity = Models.Severity.High, Category = Models.FindingCategory.LogTampering, Title = "Event log disabled: System", Detail = "x" };
        var merged = BypassScanner.MergeRepeats([Launch(1), Launch(5), Launch(3), Launch(7, "javaw.exe", Models.Severity.Low), Launch(9, severity: Models.Severity.Low), other]);

        Assert.Equal(4, merged.Count); // three powershell launches in one, the javaw one, the Low powershell one, the other finding
        var one = Assert.Single(merged, f => f.Title == "Flagged arguments: powershell.exe (3 times)");
        Assert.Equal(new DateTime(2026, 11, 12, 18, 5, 0, DateTimeKind.Utc), one.TimeUtc); // dated by the newest launch
        Assert.Contains("run-1", one.Detail);
        Assert.Contains("run-3", one.Detail);
        Assert.True(one.Detail.IndexOf("run-5", StringComparison.Ordinal) < one.Detail.IndexOf("run-1", StringComparison.Ordinal)); // newest first
        Assert.Contains(other, merged);
        Assert.Contains(merged, f => f.Title == "Flagged arguments: javaw.exe"); // a single launch is left as it is
    }

    [Fact]
    public void A_script_is_only_the_interpreters_own_inside_the_interpreters_folder()
    {
        const string python = @"C:\Users\me\AppData\Local\Programs\Python\Python312\python.exe";
        // Python's standard library: inside the folder python.exe runs from.
        Assert.True(PrefetchCollector.IsInterpreterLibrary(@"C:\Users\me\AppData\Local\Programs\Python\Python312\Lib\os.py", python, "PYTHON.EXE"));

        // Folders merely named like a library folder are where a clicker script would be put.
        Assert.False(PrefetchCollector.IsInterpreterLibrary(@"C:\Users\me\Downloads\Lib\clicker.py", python, "PYTHON.EXE"));
        Assert.False(PrefetchCollector.IsInterpreterLibrary(@"C:\Users\me\Desktop\site-packages\macro.py", python, "PYTHON.EXE"));
        Assert.False(PrefetchCollector.IsInterpreterLibrary(@"D:\Program Files\x\macro.ahk", @"C:\Program Files\AutoHotkey\AutoHotkey.exe", "AUTOHOTKEY.EXE"));
        // A script right next to the interpreter is not a library either.
        Assert.False(PrefetchCollector.IsInterpreterLibrary(@"C:\Users\me\AppData\Local\Programs\Python\Python312\clicker.py", python, "PYTHON.EXE"));

        // Windows' own interpreters: "inside their folder" would be all of System32, parts of which anyone can write to.
        string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        Assert.False(PrefetchCollector.IsInterpreterLibrary(Path.Combine(system32, @"spool\drivers\color\x.vbs"), Path.Combine(system32, "wscript.exe"), "WSCRIPT.EXE"));
        Assert.False(PrefetchCollector.IsInterpreterLibrary(Path.Combine(system32, @"Tasks\x.js"), Path.Combine(system32, "wscript.exe"), "WSCRIPT.EXE"));

        // Node resolves packages from node_modules; nothing else gets that.
        Assert.True(PrefetchCollector.IsInterpreterLibrary(@"C:\dev\app\node_modules\lib\index.js", @"C:\Program Files\nodejs\node.exe", "NODE.EXE"));
        Assert.False(PrefetchCollector.IsInterpreterLibrary(@"C:\dev\app\node_modules\lib\index.js", Path.Combine(system32, "wscript.exe"), "WSCRIPT.EXE"));
    }
}
