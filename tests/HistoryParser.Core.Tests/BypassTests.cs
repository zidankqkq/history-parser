using System.Text;
using HistoryParser.Core.Bypass;

namespace HistoryParser.Core.Tests;

public class ArgumentRuleTests
{
    static readonly ArgumentRules Defaults = ArgumentRules.Default();

    [Theory]
    [InlineData("javaw.exe", "javaw.exe -javaagent:C:\\cheat\\agent.jar -jar mc.jar", "loads a Java agent")]
    [InlineData("javaw.exe", "javaw -Xmx4G -noverify -cp x net.minecraft.Main", "turns off bytecode verification")]
    [InlineData("javaw.exe", "javaw -Xbootclasspath/a:C:\\x.jar Main", "changes the boot class path")]
    [InlineData("javaw.exe", "javaw -agentpath:C:\\x\\native.dll Main", "loads a native JVM agent")]
    [InlineData("powershell.exe", "powershell -w hidden -c dir", "hidden window")]
    [InlineData("loader.exe", "loader.exe --inject minecraft", "suspicious word")]
    public void Default_rules_flag_known_tricks(string program, string commandLine, string expected) =>
        Assert.Contains(Defaults.Match(program, commandLine), r => r.Contains(expected));

    [Theory]
    [InlineData("javaw.exe", "javaw -Xmx4G -XX:+UseG1GC -cp a.jar net.minecraft.client.main.Main --username Steve")]
    [InlineData("javaw.exe", "javaw -agentlib:jdwp=transport=dt_socket Main")] // debugger, reported separately, not as a native agent
    [InlineData("powershell.exe", "powershell -NoProfile -ExecutionPolicy Bypass -File script.ps1")]
    [InlineData("chrome.exe", "chrome.exe --proxy-bypass-list=*.local --type=renderer")]
    public void Normal_command_lines_are_not_flagged_for_injection(string program, string commandLine)
    {
        var reasons = Defaults.Match(program, commandLine);
        Assert.DoesNotContain(reasons, r => r.Contains("Java agent (") || r.Contains("native JVM agent") || r.Contains("suspicious word"));
    }

    [Fact]
    public void Rules_only_apply_to_their_program()
    {
        Assert.Empty(Defaults.Match("notepad.exe", "notepad -javaagent:x.jar"));
        Assert.NotEmpty(Defaults.Match("JAVAW.EXE", "javaw -javaagent:x.jar")); // case-insensitive
        Assert.NotEmpty(Defaults.Match("javaw", "javaw -javaagent:x.jar"));     // extension optional
    }

    [Fact]
    public void Wildcard_rules_can_be_left_out_for_game_logs()
    {
        const string line = "[Render thread/INFO]: Mixin @Inject handler applied";
        Assert.NotEmpty(Defaults.Match("javaw.exe", line));
        Assert.Empty(Defaults.Match("javaw.exe", line, includeWildcard: false));
    }

    [Fact]
    public void Custom_rules_parse_and_report_bad_lines()
    {
        var rules = ArgumentRules.Parse("# comment\njavaw.exe: myloader.jar => loads MyLoader\n*: /--ghost\\b/ => ghost mode flag\n");
        Assert.Equal(["loads MyLoader"], rules.Match("javaw.exe", "javaw -cp C:\\x\\MyLoader.jar Main"));
        Assert.Equal(["ghost mode flag"], rules.Match("anything.exe", "anything --ghost"));

        var (bad, errors) = ArgumentRules.TryParse("no colon here\njavaw.exe: /([/ => broken\nbad name!: x => y\n");
        Assert.Null(bad);
        Assert.Equal(3, errors.Count);
        Assert.StartsWith("Line 1:", errors[0]);
    }

    [Fact]
    public void Default_rules_round_trip_through_text() =>
        Assert.Equal(Defaults.Rules.Count, ArgumentRules.Parse(Defaults.ToText()).Rules.Count);

    [Fact]
    public void Known_launcher_agents_are_recognised()
    {
        var agents = ArgumentAudit.AgentsIn(@"javaw -javaagent:C:\Users\x\AppData\Local\Temp\.tmpUgsFaC\theseus.jar -cp a Main");
        Assert.Equal([@"C:\Users\x\AppData\Local\Temp\.tmpUgsFaC\theseus.jar"], agents);
        Assert.Equal("Modrinth App", ArgumentAudit.KnownLauncher(agents));
        Assert.Null(ArgumentAudit.KnownLauncher(ArgumentAudit.AgentsIn("javaw -javaagent:\"C:\\My Stuff\\vape.jar\" Main")));
        Assert.Null(ArgumentAudit.KnownLauncher([]));
    }

    [Fact]
    public void Encoded_powershell_is_decoded()
    {
        var b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("Remove-Item C:\\Windows\\Prefetch\\* -Force"));
        Assert.Equal("Remove-Item C:\\Windows\\Prefetch\\* -Force", ArgumentAudit.DecodePowerShell($"powershell.exe -NoProfile -EncodedCommand {b64}"));
        Assert.Equal("Remove-Item C:\\Windows\\Prefetch\\* -Force", ArgumentAudit.DecodePowerShell($"powershell -enc {b64}"));
        Assert.Null(ArgumentAudit.DecodePowerShell("powershell -NoProfile -Command dir"));
    }
}

public class BypassParserTests
{
    [Fact]
    public void Record_number_gaps_are_found()
    {
        var t = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
        var gaps = LogAudit.GapsIn("System", [(100, t), (101, t), (102, t), (150, t.AddHours(1)), (151, t), (160, t)]);
        Assert.Equal(2, gaps.Count);
        Assert.Equal(47, gaps[0].Missing);
        Assert.Equal(8, gaps[1].Missing);
        Assert.Empty(LogAudit.GapsIn("System", [(1, t), (2, t), (3, t)]));
    }

    [Fact]
    public void Partition_events_for_usb_drives()
    {
        var connect = UsbAudit.ParsePartitionEvent(new Dictionary<string, string>
        {
            ["BusType"] = "7", ["Manufacturer"] = "SanDisk", ["Model"] = "Cruzer Blade", ["SerialNumber"] = "4C530001.", ["Capacity"] = "16008609792",
        });
        Assert.NotNull(connect);
        Assert.Equal("SanDisk Cruzer Blade", connect!.Device);
        Assert.Equal("4C530001", connect.Serial);
        Assert.Equal("Connected", connect.Action);
        Assert.Equal("16 GB", connect.Detail);

        var removal = UsbAudit.ParsePartitionEvent(new Dictionary<string, string> { ["BusType"] = "7", ["Model"] = "X", ["Capacity"] = "0" });
        Assert.Equal("Disconnected", removal!.Action);

        // Internal NVMe disk (bus type 17), as on the development PC: not a USB event.
        Assert.Null(UsbAudit.ParsePartitionEvent(new Dictionary<string, string> { ["BusType"] = "17", ["Manufacturer"] = "NULL", ["Capacity"] = "1000204886016" }));
    }

    [Theory]
    [InlineData(@"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001230913112450&0", "4C530001230913112450")]
    [InlineData(@"USB\VID_0781&PID_5567\4C530001230913112450", "4C530001230913112450")]
    [InlineData(@"USBSTOR\Disk&Ven_Generic&Prod_Flash\7&2a1b3c4d&0", "7&2a1b3c4d")]
    public void Serial_numbers_from_instance_ids(string instance, string serial) => Assert.Equal(serial, UsbAudit.SerialOf(instance));

    [Fact]
    public void Mounted_device_entries_map_to_a_serial() =>
        Assert.Equal("4C530001230913112450", UsbAudit.ParseMountedDevice(
            @"_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001230913112450&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"));

    [Fact]
    public void Defender_exclusion_values_are_readable()
    {
        Assert.Equal(@"C:\SS1 (folder or file)",DefenderAudit.ExclusionTarget(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\SS1 = 0x0"));
        Assert.Equal("javaw.exe (process)", DefenderAudit.ExclusionTarget(@"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\javaw.exe = 0x0"));
    }

    [Theory]
    [InlineData("System.evtx", @"C:\Windows\System32\winevt\Logs\System.evtx", "Event log file")]
    [InlineData("Amcache.hve", @"C:\Windows\AppCompat\Programs\Amcache.hve", "Amcache")]
    [InlineData("ConsoleHost_history.txt", @"C:\Users\x\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt", "Shell history")]
    [InlineData("cheat.jar.lnk", @"C:\Users\x\AppData\Roaming\Microsoft\Windows\Recent\cheat.jar.lnk", "Shortcut")]
    [InlineData(".attach_pid12345", @"C:\Users\x\AppData\Local\Temp\.attach_pid12345", "Java attach")]
    [InlineData("game.lnk", @"C:\Users\x\Desktop\game.lnk", null)]          // a desktop shortcut is not evidence
    [InlineData("notes_history.txt", @"C:\Users\x\notes_history.txt", null)]
    // Copies Windows Error Reporting, diagnostics and updaters make in temp folders and delete again are not the evidence.
    [InlineData("System.evtx", @"C:\ProgramData\Microsoft\Windows\WER\Temp\WER1A2B.tmp.dir\System.evtx", null)]
    [InlineData("Application.evtx", @"C:\Users\x\AppData\Local\Temp\Diag\Application.evtx", null)]
    [InlineData("Amcache.hve", @"C:\Windows\Temp\Amcache.hve", null)]
    [InlineData("SRUDB.dat", @"C:\Users\x\AppData\Local\Temp\SRUDB.dat", null)]
    [InlineData("PcaGeneralDb0.txt", @"C:\Users\x\Downloads\PcaGeneralDb0.txt", null)]
    [InlineData("SRUDB.dat", @"C:\Windows\System32\sru\SRUDB.dat", "SRUM")]
    [InlineData("PcaAppLaunchDic.txt", @"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt", "PCA log")]
    public void Artifact_kinds(string name, string path, string? kind) => Assert.Equal(kind, ArtifactAudit.Classify(name, path));

    [Fact]
    public void Evidence_moved_out_of_its_folder_still_counts()
    {
        // Moving the real log to Temp is a wipe; the rename's old path is in the real folder.
        Assert.Equal("Event log file", ArtifactAudit.Classify("System.evtx", @"C:\Users\x\AppData\Local\Temp\System.evtx", @"C:\Windows\System32\winevt\Logs\System.evtx"));
    }

    [Fact]
    public void Driver_paths_are_normalised()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.Equal(Path.Combine(windows, @"System32\drivers\tcpip.sys"), ProcessAudit.NormalizeDriverPath(@"\SystemRoot\System32\drivers\tcpip.sys"));
        Assert.Equal(@"C:\Users\x\mapper.sys", ProcessAudit.NormalizeDriverPath(@"\??\C:\Users\x\mapper.sys"));
        Assert.Equal(Path.Combine(windows, @"System32\drivers\ntfs.sys"), ProcessAudit.NormalizeDriverPath("ntfs.sys"));
    }
}
