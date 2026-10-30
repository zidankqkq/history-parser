using RatChecker.Core;

namespace HistoryParser.Core.Tests;

public class PathListTests
{
    [Fact]
    public void Paths_are_read_from_plain_lists_everything_exports_and_tool_output()
    {
        var real = Scratch.File("pathlist", "a,b.jar", "PK"u8.ToArray()); // a comma in the name, as Everything quotes it
        // On a long build path Windows hands the scratch file back with a \\?\ extended-length prefix, which ReadPathList
        // strips by design; expect the stripped form so the test does not depend on how deep the repo sits.
        var expectedReal = real.StartsWith(@"\\?\", StringComparison.Ordinal) ? real[4..] : real;
        var lines = new[]
        {
            "Filename,Size,Date Modified,Date Created,Attributes",          // Everything .efu header: no path
            $"\"{real}\",2,133800000000000000,133800000000000000,32",       // Everything .efu row
            @"C:\Games\cheat.exe",                                           // paths.txt
            @"  ""C:\Program Files\Tool\tool.dll""  ",                       // quoted
            @"12:01:33 | Executed | C:\Users\x\Downloads\loader.exe | BAM",  // some tool's output
            @"\Device\HarddiskVolume3\Temp\x.jar",                           // device path
            "# comment",
            "",
            @"C:\Games\cheat.exe",                                           // duplicate
        };
        var paths = RatFiles.ReadPathList(lines, p => p.Replace(@"\Device\HarddiskVolume3\", @"D:\"));
        Assert.Equal([expectedReal, @"C:\Games\cheat.exe", @"C:\Program Files\Tool\tool.dll", @"C:\Users\x\Downloads\loader.exe", @"D:\Temp\x.jar"], paths);
    }

    [Fact]
    public void Custom_game_folders_and_instance_folders_are_found_in_launcher_settings()
    {
        var json = Scratch.File("launcher", "launcher_profiles.json", """
            { "profiles": { "a": { "name": "Fabric", "gameDir": "D:\\MC\\fabric" }, "b": { "name": "Latest" }, "c": { "gameDir": 5 } } }
            """u8.ToArray());
        Assert.Equal([@"D:\MC\fabric"], RatFiles.LauncherGameDirs(json));
        Assert.Empty(RatFiles.LauncherGameDirs(json + ".missing"));

        var cfg = Scratch.File("prism", "prismlauncher.cfg", "Language=en\nInstanceDir=E:/Instances\n"u8.ToArray());
        Assert.Equal(@"E:\Instances", RatFiles.InstanceDir(Path.GetDirectoryName(cfg)!, "prismlauncher.cfg"));
        var relative = Scratch.File("prism2", "prismlauncher.cfg", "InstanceDir=instances\n"u8.ToArray());
        Assert.Equal(Path.Combine(Path.GetDirectoryName(relative)!, "instances"), RatFiles.InstanceDir(Path.GetDirectoryName(relative)!, "prismlauncher.cfg"));
    }
}
