using System.Diagnostics;
using System.Text;
using HistoryParser.Core.Bypass;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Tests;

/// <summary>Fileless clickers, USN replace patterns and the IFEO-copy name check.</summary>
public class ScriptInputTests
{
    const string Clicker = """
        Add-Type @"
        using System; using System.Runtime.InteropServices;
        public class M {
          [DllImport("user32.dll")] public static extern void mouse_event(int f, int x, int y, int d, int e);
          [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int k);
        }
        "@
        while ($true) {
          if ([M]::GetAsyncKeyState(0x01) -lt 0) { [M]::mouse_event(2,0,0,0,0); [M]::mouse_event(4,0,0,0,0) }
          Start-Sleep -Milliseconds (Get-Random -Minimum 60 -Maximum 90)
        }
        """;

    [Fact]
    public void A_powershell_autoclicker_is_high_and_says_it_varies_its_timing()
    {
        var v = ScriptInput.Judge(Clicker);
        Assert.NotNull(v);
        Assert.True(v.High);
        Assert.Contains("random", v.Why);
        Assert.Contains("mouse_event", Clicker.Substring(v.Index, v.Length));
    }

    [Theory]
    // The import renamed so the function's own name is never written as a declaration or a call.
    [InlineData("""
        Add-Type '[DllImport("user32.dll", EntryPoint = "mouse_event")] public static extern void Press(int a,int b,int c,int d,int e);
                  [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int k);' -Name W -Namespace N
        while (1) { if ([N.W]::GetAsyncKeyState(1)) { [N.W]::Press(2,0,0,0,0) } }
        """)]
    // A P/Invoke stub built at runtime instead of compiled C#.
    [InlineData("""
        $t = $mb.DefinePInvokeMethod('SendInput', 'user32.dll', $attrs, $conv, [uint32], $types, $nat, $set)
        if ([K]::GetAsyncKeyState(0x01) -lt 0) { $send.Invoke(1, $inputs, 40) }
        """)]
    public void Renamed_and_runtime_built_imports_still_count(string script) =>
        Assert.True(ScriptInput.Judge(script)?.High);

    [Theory]
    // A detection script that searches files for these names: a list of strings, plus an unrelated Add-Type.
    // (Seen for real on the developer's PC - it was flagged as an autoclicker before this rule.)
    [InlineData("Add-Type -AssemblyName System.IO.Compression.FileSystem; $words = 'GetAsyncKeyState','SetWindowsHookExW','SendInput','mouse_event','PostMessageA'; " +
                "foreach ($w in $words) { if ($text.Contains($w)) { $w } }")]
    // Notes or documentation that talk about clickers.
    [InlineData("Autoclickers typically import `SendInput`/`mouse_event` + `GetAsyncKeyState` (DllImport) and a high-resolution timer.")]
    // A screenshare tool's own search strings.
    [InlineData("$needles = @(\"mouse_event\", \"SendInput\", \"GetAsyncKeyState\", \"DllImport\", \"Add-Type\")")]
    public void Scripts_that_only_name_the_functions_are_not_clickers(string script) =>
        Assert.Null(ScriptInput.Judge(script));

    [Fact]
    public void A_key_macro_is_medium()
    {
        var macro = Clicker.Replace("mouse_event", "keybd_event");
        var v = ScriptInput.Judge(macro);
        Assert.NotNull(v);
        Assert.False(v.High);
    }

    [Theory]
    // Fakes input but never watches the keyboard: a one-shot automation script.
    [InlineData("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')")]
    // Watches keys but makes no input: a hotkey script.
    [InlineData("Add-Type '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int k);' -Name K -Namespace W")]
    // Just the words, as PowerShell's own list of suspicious terms holds them - one separate string each.
    [InlineData("GetAsyncKeyState")]
    [InlineData("mouse_event")]
    public void Scripts_that_do_not_both_fake_and_watch_input_are_not_flagged(string script) =>
        Assert.Null(ScriptInput.Judge(script));

    /// <summary>The same clicker with the key check and the click on different lines: only the whole script shows both.</summary>
    const string SplitClicker = """
        Add-Type @"
        using System; using System.Runtime.InteropServices;
        public class M {
          [DllImport("user32.dll")] public static extern void mouse_event(int f, int x, int y, int d, int e);
          [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int k);
        }
        "@
        while ($true) {
          $held = [M]::GetAsyncKeyState(0x01) -lt 0
          if ($held) {
            [M]::mouse_event(2,0,0,0,0)
          }
        }
        """;

    [Fact]
    public void A_whole_multi_line_script_is_read_out_of_memory_as_one_string()
    {
        // Heap layout: object header bytes, the UTF-16 script, more header bytes, another string.
        var bytes = new List<byte> { 0x10, 0x00, 0x00, 0x00, 0x88, 0x13, 0x01, 0x00 };
        bytes.AddRange(Encoding.Unicode.GetBytes(SplitClicker));
        bytes.AddRange(new byte[] { 0x00, 0x00, 0x7F, 0x01, 0x00, 0x00 });
        bytes.AddRange(Encoding.Unicode.GetBytes("GetAsyncKeyState"));
        var found = new List<string>();
        StringExtractor.Extract(bytes.ToArray(), 8, found.Add, StringExtractor.InputNeedlesAscii, StringExtractor.InputNeedlesWide, multiLine: true);
        var script = Assert.Single(found);
        Assert.Equal(SplitClicker, script);
        Assert.NotNull(ScriptInput.Judge(script));

        // Without multiLine the same bytes come out line by line, and no single line is a clicker.
        found.Clear();
        StringExtractor.Extract(bytes.ToArray(), 8, found.Add, StringExtractor.InputNeedlesAscii, StringExtractor.InputNeedlesWide);
        Assert.All(found, s => Assert.Null(ScriptInput.Judge(s)));
    }

    // Starts a real PowerShell and reads its memory for the clicker - timing- and privilege-dependent, so a headless
    // CI runner cannot run it reliably. Runs on a real machine; excluded from CI (Category=Integration).
    [Fact]
    [Trait("Category", "Integration")]
    public void A_clicker_held_by_a_running_powershell_is_found_in_its_memory()
    {
        // Starting PowerShell and reading its memory is timing- and privilege-dependent; a headless CI runner cannot run it.
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        // The clicker text is handed to PowerShell as data on stdin and only stored in a variable, never run. It must never be
        // part of a script: Windows writes any script using Add-Type / DllImport to the PowerShell log (event 4104) even with
        // logging off, and an earlier version of this test left two "autoclickers" in the developer's log that way.
        var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command \"$s = [Console]::In.ReadToEnd(); Start-Sleep -Seconds 60\"")
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardInput = true };
        using var ps = Process.Start(psi)!;
        ps.StandardInput.Write(Clicker);
        ps.StandardInput.Close();
        try
        {
            ScriptInput.Verdict? verdict = null;
            for (int attempt = 0; attempt < 20 && verdict == null; attempt++)
            {
                Thread.Sleep(500);
                ProcessMemoryCollector.ScanProcess(ps.Id, long.MaxValue, CancellationToken.None, s => verdict ??= ScriptInput.Judge(s),
                    StringExtractor.InputNeedlesAscii, StringExtractor.InputNeedlesWide, multiLine: true);
            }
            Assert.NotNull(verdict);
            Assert.True(verdict.High);
        }
        finally { ps.Kill(); }
    }
}

public class UsnPatternTests
{
    [Fact]
    public void How_contents_were_replaced_is_read_from_the_journal_reasons()
    {
        Assert.Contains("copy", UsnJournalCollector.ContentChange(UsnReason.DataTruncation | UsnReason.DataExtend | UsnReason.SecurityChange | UsnReason.Close));
        Assert.Contains("type a > b", UsnJournalCollector.ContentChange(UsnReason.DataTruncation | UsnReason.DataExtend | UsnReason.Close));
        Assert.Equal("File contents changed", UsnJournalCollector.ContentChange(UsnReason.DataExtend | UsnReason.Close));
        Assert.Equal("File contents changed", UsnJournalCollector.ContentChange(UsnReason.DataOverwrite | UsnReason.Close));
        Assert.Contains("emptied", UsnJournalCollector.ContentChange(UsnReason.DataTruncation | UsnReason.Close));
    }
}

public class HidingTests
{
    [Theory]
    [InlineData("Image File Execution Options_old", true)]
    [InlineData("Image File Execution Options2", true)]
    [InlineData("ImageFileExecutionOptions", true)]
    [InlineData("IFEO", true)]
    [InlineData("Image File Execution Options", true)]  // the real one is skipped by name before this check
    [InlineData("Winlogon", false)]
    [InlineData("AppCompatFlags", false)]
    [InlineData("SilentProcessExit", false)]
    public void Renamed_copies_of_the_ifeo_key_are_recognised(string name, bool expected) =>
        Assert.Equal(expected, HidingAudit.LooksLikeIfeo(name));
}
