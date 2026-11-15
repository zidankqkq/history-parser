using HistoryParser.Core.Bypass;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Tests;

/// <summary>Which games a PC shows: the ones running, the earlier starts Prefetch keeps, and what tells one from another.</summary>
public class GameTests
{
    static readonly DateTime T0 = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData(@"javaw.exe --username Steve --version 1.21.1 --gameDir C:\Users\p\.minecraft", "--gameDir", @"C:\Users\p\.minecraft")]
    [InlineData("javaw.exe --gameDir \"C:\\my games\\mc\" --version 1.8.9", "--gameDir", @"C:\my games\mc")]
    [InlineData("javaw.exe --VERSION fabric-loader-0.16 --width 854", "--version", "fabric-loader-0.16")]
    [InlineData("javaw.exe -jar server.jar", "--username", "")]
    public void A_games_arguments_say_which_game_it_is(string command, string name, string value) =>
        Assert.Equal(value, SessionTimes.Argument(command, name));

    // The shape the Prefetch collector writes: one run per kept time under the .pf file's name, and one record per file
    // the program opened, naming that .pf file in its detail.
    static IEnumerable<Evidence> Prefetch(string pf, string program, DateTime[] runs, params string[] opened) =>
        runs.Select(t => new Evidence { Source = EvidenceSource.Prefetch, Kind = EvidenceKind.Execution, Path = program, TimeUtc = t, Origin = pf })
            .Concat(opened.Select(path => new Evidence
            {
                Source = EvidenceSource.Prefetch, Kind = EvidenceKind.LoadedModule, Path = path, TimeUtc = runs[0], Origin = Path.GetFileName(program).ToUpperInvariant(),
                Detail = $"Listed in {pf}: loaded by {Path.GetFileName(program).ToUpperInvariant()} during one of its runs (time shown is its latest run)",
            }));

    [Fact]
    public void Earlier_starts_come_from_a_program_that_opened_a_java_runtime_and_the_games_files()
    {
        var evidence = Prefetch("JAVAW.EXE-11111111.pf", @"C:\jre\bin\javaw.exe", [T0, T0.AddDays(-1)],
                @"C:\jre\bin\server\jvm.dll", @"C:\Users\p\AppData\Roaming\.minecraft\mods\sodium.jar")
            // The same Java, another Prefetch file: it ran a server, not the game.
            .Concat(Prefetch("JAVAW.EXE-22222222.pf", @"D:\tools\jre\bin\javaw.exe", [T0.AddHours(-3)], @"D:\tools\jre\bin\server\jvm.dll", @"D:\srv\server.jar"))
            // A scanner that read the game's files has no Java runtime loaded.
            .Concat(Prefetch("SCANNER.EXE-33333333.pf", @"C:\x\scanner.exe", [T0.AddHours(-1)], @"C:\Users\p\AppData\Roaming\.minecraft\mods\sodium.jar"));

        var games = SessionTimes.PastGames(evidence).OrderByDescending(g => g.StartUtc).ToList();
        Assert.Equal([T0, T0.AddDays(-1)], games.Select(g => g.StartUtc));
        Assert.All(games, g => Assert.Equal(@"C:\jre\bin\javaw.exe", g.Path));
        Assert.All(games, g => Assert.Null(g.Pid));
    }

    [Fact]
    public void A_renamed_java_is_still_found_by_what_it_opened()
    {
        var games = SessionTimes.PastGames(Prefetch("SVCHOST.EXE-44444444.pf", @"C:\x\svchost.exe", [T0],
            @"C:\x\server\jvm.dll", @"C:\Users\p\AppData\Local\Temp\lwjgl\lwjgl_opengl.dll"));
        Assert.Equal("svchost.exe", Assert.Single(games).Program);
    }

    [Fact]
    public void A_running_game_and_its_own_prefetch_entry_are_one_start()
    {
        var running = new GameStart { StartUtc = T0, Pid = 4242, Program = "javaw.exe", Path = @"C:\jre\bin\javaw.exe", How = "Running" };
        var evidence = Prefetch("JAVAW.EXE-11111111.pf", @"C:\jre\bin\javaw.exe", [T0.AddSeconds(8), T0.AddDays(-2)],
            @"C:\jre\bin\server\jvm.dll", @"C:\g\lwjgl.dll");
        var all = SessionTimes.AllGames([running], evidence);
        Assert.Equal(2, all.Count);
        Assert.Equal(4242, all[0].Pid);            // the running one, newest
        Assert.Null(all[1].Pid);                   // the start two days ago
        Assert.Equal(T0.AddDays(-2), all[1].StartUtc);
    }

    [Fact]
    public void Every_running_game_is_on_the_sessions_list()
    {
        var machine = new MachineInfo
        {
            BootTimeUtc = T0.AddHours(-5), SignInUtc = T0.AddHours(-4), GameStartUtc = T0.AddHours(-2), GameProgram = "javaw.exe (pid 1)",
            Games =
            [
                new GameStart { StartUtc = T0.AddHours(-1), Pid = 2, Program = "javaw.exe" },
                new GameStart { StartUtc = T0.AddHours(-2), Pid = 1, Program = "javaw.exe" },
                new GameStart { StartUtc = T0.AddDays(-1), Program = "javaw.exe" }, // an earlier start: listed with the games, not a mark
            ],
        };
        var marks = SessionAudit.Marks(machine, T0, T0, [], [], [], null).Where(m => m.What == "Game started").ToList();
        Assert.Equal(["javaw.exe (pid 1)", "javaw.exe (pid 2)"], marks.Select(m => m.Detail));
    }

    // ---- Java that is not recognisably the game -----------------------------------------------------------

    static readonly string[] Jvm = [@"C:\jre\bin\java.dll", @"C:\jre\bin\server\jvm.dll"];

    [Fact]
    public void A_java_program_is_the_game_only_by_its_arguments_or_its_graphics_library()
    {
        Assert.Equal(SessionTimes.JavaKind.Game, SessionTimes.Kind(Jvm, startedAsGame: true, javaBesideIt: true));
        Assert.Equal(SessionTimes.JavaKind.Game, SessionTimes.Kind([.. Jvm, @"C:\Temp\lwjgl_opengl.dll"], startedAsGame: false, javaBesideIt: false));
        // Java running something else: listed as Java, never as the game.
        Assert.Equal(SessionTimes.JavaKind.Java, SessionTimes.Kind(Jvm, startedAsGame: false, javaBesideIt: true));
        // The game's words in the arguments of a program with no Java runtime loaded (a launcher that passes them on).
        Assert.Equal(SessionTimes.JavaKind.None, SessionTimes.Kind([@"C:\x\launcher.dll"], startedAsGame: true, javaBesideIt: false));
    }

    [Fact]
    public void With_its_modules_unreadable_the_runtime_beside_the_program_decides()
    {
        Assert.Equal(SessionTimes.JavaKind.Game, SessionTimes.Kind([], startedAsGame: true, javaBesideIt: true));
        Assert.Equal(SessionTimes.JavaKind.Java, SessionTimes.Kind([], startedAsGame: false, javaBesideIt: true));
        Assert.Equal(SessionTimes.JavaKind.None, SessionTimes.Kind([], startedAsGame: true, javaBesideIt: false));
    }

    [Fact]
    public void A_java_program_is_listed_with_the_games_but_is_not_a_game_start()
    {
        var game = new GameStart { StartUtc = T0.AddHours(-2), Pid = 1, Program = "javaw.exe", How = "Running" };
        var other = new GameStart { StartUtc = T0.AddHours(-1), Pid = 7, Program = "java.exe", Path = @"C:\jre\bin\java.exe", How = "Running", Unrecognised = true, Runs = @"C:\tools\thing.jar" };
        // Prefetch wrote the Java program's start too: the same process, not an earlier game.
        var evidence = Prefetch("JAVA.EXE-55555555.pf", @"C:\jre\bin\java.exe", [T0.AddHours(-1).AddSeconds(6)], @"C:\jre\bin\server\jvm.dll", @"C:\g\lwjgl.dll");
        var all = SessionTimes.AllGames([game], evidence, [other]);
        Assert.Equal([7, 1], all.Select(g => g.Pid));
        Assert.True(all[0].Unrecognised);

        var machine = new MachineInfo { BootTimeUtc = T0.AddHours(-5), GameStartUtc = game.StartUtc, Games = all };
        var marks = SessionAudit.Marks(machine, T0, T0, [], [], [], null).Where(m => m.What == "Game started").ToList();
        Assert.Equal("javaw.exe (pid 1)", Assert.Single(marks).Detail);
    }

    [Fact]
    public void A_note_added_to_a_files_row_is_its_own_sentence()
    {
        var file = new FileRecord { Path = @"C:\x\a.exe", Name = "a.exe", StatusDetail = "File is present" };
        HistoryParser.Core.Analysis.SelfTraces.Note(file, "Says it is part of the suite.");
        Assert.Equal("File is present. Says it is part of the suite.", file.StatusDetail);
        var empty = new FileRecord { Path = @"C:\x\b.exe", Name = "b.exe" };
        HistoryParser.Core.Analysis.SelfTraces.Note(empty, "Only this.");
        Assert.Equal("Only this.", empty.StatusDetail);
    }

    [Fact]
    public void The_period_can_start_from_a_game_the_reader_picked()
    {
        DateTime boot = T0.AddHours(-9), signIn = T0.AddHours(-8), first = T0.AddHours(-6), second = T0.AddHours(-1);
        var files = new List<FileRecord>
        {
            new() { Path = @"C:\a.exe", Name = "a.exe", LastActivityUtc = first.AddMinutes(30) },
            new() { Path = @"C:\b.exe", Name = "b.exe", LastActivityUtc = second.AddMinutes(5) },
        };
        var scan = new ScanResult
        {
            Machine = new MachineInfo { BootTimeUtc = boot, SignInUtc = signIn, GameStartUtc = first },
            StartedUtc = T0, FinishedUtc = T0, Files = files, Findings = [], Checks = [], Sources = [], ClockChanges = [], MemoryHits = [], Timeline = [],
        };
        Assert.Equal(2, Scanner.Trim(scan, TimeWindow.Game).Files.Count);            // from the scan's own game: the earliest
        var picked = Scanner.Trim(scan, TimeWindow.Game, second);
        Assert.Equal(@"C:\b.exe", Assert.Single(picked.Files).Path);                 // from the second game
        Assert.Equal(second, picked.SinceUtc);
        Assert.Equal(2, Scanner.Trim(scan, TimeWindow.SignIn, second).Files.Count);  // a picked game only moves the game period
    }
}
