using HistoryParser.Core.Bypass;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Tests;

/// <summary>The session's reference times: sign-in, the desktop shell, the running game, and the periods measured from them.</summary>
public class SessionTests
{
    static readonly DateTime Boot = new(2026, 11, 10, 8, 0, 0, DateTimeKind.Utc);
    static readonly DateTime SignIn = new(2026, 11, 14, 9, 0, 0, DateTimeKind.Utc);
    static readonly DateTime Now = new(2026, 11, 14, 15, 0, 0, DateTimeKind.Utc);

    // ---- the sign-in record ---------------------------------------------------------------------------

    [Fact]
    public void A_sign_in_is_taken_only_from_a_record_whose_own_now_is_now()
    {
        long logon = SignIn.ToFileTimeUtc();
        Assert.Equal(SignIn, SessionTimes.SignInFrom(logon, Now.ToFileTimeUtc(), Now));
        // The record's "now" is hours off: the layout is not the one expected, so no time is better than a wrong one.
        Assert.Null(SessionTimes.SignInFrom(logon, Now.AddHours(-3).ToFileTimeUtc(), Now));
        Assert.Null(SessionTimes.SignInFrom(0, Now.ToFileTimeUtc(), Now));
        Assert.Null(SessionTimes.SignInFrom(Now.AddHours(1).ToFileTimeUtc(), Now.ToFileTimeUtc(), Now)); // a sign-in in the future
    }

    [Fact]
    public void This_session_has_a_sign_in_before_now_and_a_shell()
    {
        // Read live. A session without a desktop (a service, some build agents) has neither, and that is not a failure.
        if (SessionTimes.SignInUtc() is { } signIn) Assert.InRange(signIn, DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddMinutes(1));
        if (SessionTimes.ShellStart() is { } shell) Assert.InRange(shell.StartUtc, DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddMinutes(1));
        Assert.NotNull(SessionTimes.RunningGames());
    }

    // ---- the desktop shell ----------------------------------------------------------------------------

    [Fact]
    public void A_shell_started_with_the_sign_in_is_fine_however_old_the_boot()
    {
        // Fast Startup: the boot is four days old, the sign-in is this morning, Explorer started with it.
        var (state, detail, finding) = SystemStateCollector.JudgeShell(SignIn.AddSeconds(20), Boot, SignIn, null);
        Assert.Equal(CheckState.Ok, state);
        Assert.Null(finding);
        Assert.Contains("with the sign-in", detail);
    }

    [Fact]
    public void A_shell_started_well_after_the_sign_in_was_restarted()
    {
        var (state, _, finding) = SystemStateCollector.JudgeShell(SignIn.AddHours(3), Boot, SignIn, null);
        Assert.Equal(CheckState.Warning, state);
        Assert.Equal(Severity.Low, finding!.Value.Severity);
        Assert.Equal(SystemStateCollector.ShellRestarted, finding.Value.Title);
    }

    [Fact]
    public void A_restart_while_the_game_was_running_weighs_more()
    {
        var game = SignIn.AddHours(1);
        Assert.Equal(Severity.Medium, SystemStateCollector.JudgeShell(game.AddMinutes(30), Boot, SignIn, game).Finding!.Value.Severity);
        // Restarted before the game was started: the game's own launch is still in the new Explorer.
        Assert.Equal(Severity.Low, SystemStateCollector.JudgeShell(game.AddMinutes(-20), Boot, SignIn, game).Finding!.Value.Severity);
    }

    [Fact]
    public void Without_a_sign_in_time_a_late_shell_is_only_a_warning()
    {
        var (state, detail, finding) = SystemStateCollector.JudgeShell(Boot.AddDays(4), Boot, null, null);
        Assert.Equal(CheckState.Warning, state);
        Assert.Null(finding); // it may be a late sign-in: not enough to raise a finding on
        Assert.Contains("could not be read", detail);
        Assert.Equal(CheckState.Ok, SystemStateCollector.JudgeShell(Boot.AddMinutes(2), Boot, null, null).State);
    }

    // ---- the running game -----------------------------------------------------------------------------

    [Fact]
    public void A_game_is_a_java_runtime_started_as_the_game_or_holding_its_graphics_library()
    {
        string[] java = [@"C:\jre\bin\javaw.exe", @"C:\jre\bin\server\jvm.dll"];
        Assert.True(SessionTimes.IsGame(java, startedAsGame: true));
        Assert.False(SessionTimes.IsGame(java, startedAsGame: false)); // Java running something else
        Assert.True(SessionTimes.IsGame([.. java, @"C:\Users\p\AppData\Local\Temp\lwjgl\lwjgl_opengl.dll"], startedAsGame: false)); // arguments hidden in a file
        Assert.False(SessionTimes.IsGame([@"C:\tools\search.exe"], startedAsGame: true)); // the words in a command line, no Java
        // A renamed Java is still a Java: the name of the program plays no part.
        Assert.True(SessionTimes.IsGame([@"C:\x\svchost.exe", @"C:\x\server\jvm.dll"], startedAsGame: true));
    }

    [Theory]
    [InlineData(@"javaw.exe -cp x net.minecraft.client.main.Main --gameDir C:\g", true)]
    [InlineData(@"javaw.exe @C:\args.txt", false)]
    [InlineData(@"java.exe -jar server.jar", false)]
    public void The_games_arguments_are_recognised(string command, bool game) => Assert.Equal(game, SessionTimes.IsGameCommand(command));

    // ---- periods --------------------------------------------------------------------------------------

    [Fact]
    public void Periods_start_at_the_sign_in_and_at_the_game()
    {
        var game = SignIn.AddHours(2);
        Assert.Equal(SignIn, TimeWindows.Since(TimeWindow.SignIn, Now, Boot, SignIn, game));
        Assert.Equal(game, TimeWindows.Since(TimeWindow.Game, Now, Boot, SignIn, game));
        Assert.Equal(Boot, TimeWindows.Since(TimeWindow.ThisBoot, Now, Boot, SignIn, game));
    }

    [Fact]
    public void A_period_without_its_start_widens_and_never_narrows()
    {
        Assert.Equal(SignIn, TimeWindows.Since(TimeWindow.Game, Now, Boot, SignIn, null)); // no game: the sign-in
        Assert.Equal(Boot, TimeWindows.Since(TimeWindow.Game, Now, Boot, null, null));     // neither: the boot
        Assert.Equal(Boot, TimeWindows.Since(TimeWindow.SignIn, Now, Boot, null, null));
        Assert.Equal(TimeWindow.SignIn, TimeWindows.Parse("signin"));
        Assert.Equal(TimeWindow.Game, TimeWindows.Parse("game"));
    }

    // ---- the list of marks ----------------------------------------------------------------------------

    static MachineInfo Machine(DateTime? shell = null, DateTime? game = null) => new()
    {
        BootTimeUtc = Boot, OsInstallUtc = Boot.AddYears(-1), SignInUtc = SignIn, ShellStartUtc = shell ?? SignIn.AddSeconds(15),
        GameStartUtc = game, GameProgram = game == null ? "" : "javaw.exe (pid 4242)",
    };

    static List<SessionMark> Marks(MachineInfo machine, IEnumerable<ServiceRow>? services = null, IEnumerable<UsbDevice>? usb = null,
        IEnumerable<ClockChange>? clock = null, DateTime? bin = null, DateTime? opened = null) =>
        SessionAudit.Marks(machine, Now, opened ?? Now.AddMinutes(-5), services ?? [], usb ?? [], clock ?? [], bin);

    [Fact]
    public void Marks_come_in_the_order_they_happened_and_undated_ones_last()
    {
        var marks = Marks(Machine(game: SignIn.AddHours(4)));
        Assert.Equal(["Windows installed", "PC started", "Signed in", "Explorer started", "Game started", "Scanned"], marks.Select(m => m.What));
        Assert.All(marks, m => Assert.Equal(CheckState.Ok, m.State));
        Assert.Equal("javaw.exe (pid 4242)", marks.Single(m => m.What == "Game started").Detail);

        var none = Marks(Machine());
        Assert.Equal("Game", none[^1].What); // no game running: said, and last because it has no time
        Assert.Null(none[^1].TimeUtc);
    }

    [Fact]
    public void A_restarted_shell_and_a_late_service_are_marked()
    {
        var marks = Marks(Machine(shell: SignIn.AddHours(2)), services:
        [
            new ServiceRow { Name = "SysMain", ProcessStartUtc = Boot.AddMinutes(1) },
            new ServiceRow { Name = "DPS", ProcessStartUtc = SignIn.AddHours(5) },
        ]);
        Assert.Equal(CheckState.Warning, marks.Single(m => m.What == "Explorer started").State);
        Assert.Equal(CheckState.Warning, marks.Single(m => m.What == "DPS started").State);
        Assert.DoesNotContain(marks, m => m.What == "Recording services started"); // one late service is named instead
    }

    [Fact]
    public void Services_that_started_with_the_PC_are_one_quiet_mark()
    {
        var mark = Marks(Machine(), services: [new ServiceRow { Name = "SysMain", ProcessStartUtc = Boot.AddMinutes(1) }, new ServiceRow { Name = "bam" }])
            .Single(m => m.What == "Recording services started");
        Assert.Equal(CheckState.Ok, mark.State);
        Assert.Equal(Boot.AddMinutes(1), mark.TimeUtc);
    }

    [Fact]
    public void What_changed_after_this_program_was_opened_is_marked()
    {
        var opened = Now.AddMinutes(-10);
        var marks = Marks(Machine(), bin: Now.AddMinutes(-2), opened: opened,
            usb: [new UsbDevice { Name = "Stick", LastRemovedUtc = Now.AddMinutes(-3) }, new UsbDevice { Name = "Old", LastRemovedUtc = Boot }]);
        Assert.Equal(CheckState.Warning, marks.Single(m => m.What == "Recycle Bin last changed").State);
        var usb = marks.Single(m => m.What == "USB device removed");
        Assert.Equal(CheckState.Warning, usb.State);
        Assert.StartsWith("Stick", usb.Detail); // the latest removal, not the oldest

        var before = Marks(Machine(), bin: opened.AddHours(-1), opened: opened);
        Assert.Equal(CheckState.Ok, before.Single(m => m.What == "Recycle Bin last changed").State);
    }

    [Fact]
    public void A_clock_change_is_marked_and_a_small_correction_is_not()
    {
        var moved = new ClockChange { Source = "Security 4616", OldTimeUtc = Now.AddHours(-1), NewTimeUtc = Now.AddHours(-3) };
        Assert.Equal(CheckState.Warning, Marks(Machine(), clock: [moved]).Single(m => m.What == "Clock changed").State);
        var sync = new ClockChange { Source = "Time service", OldTimeUtc = Now.AddHours(-1), NewTimeUtc = Now.AddHours(-1).AddSeconds(2), Severity = Severity.Low };
        Assert.DoesNotContain(Marks(Machine(), clock: [sync]), m => m.What == "Clock changed");
    }

    [Fact]
    public void A_fresh_install_and_a_fresh_start_are_marked()
    {
        var machine = Machine() with { OsInstallUtc = Now.AddHours(-20), BootTimeUtc = Now.AddMinutes(-5), SignInUtc = Now.AddMinutes(-4), ShellStartUtc = Now.AddMinutes(-4) };
        var marks = Marks(machine);
        Assert.Equal(CheckState.Warning, marks.Single(m => m.What == "Windows installed").State);
        Assert.Equal(CheckState.Warning, marks.Single(m => m.What == "PC started").State);
    }
}

/// <summary>Search boxes: every word must match, "!" takes rows away, quotes keep words together.</summary>
public class SearchQueryTests
{
    static bool Match(string query, string text) => SearchQuery.Parse(query).Matches(text);

    [Fact]
    public void Nothing_typed_matches_everything()
    {
        Assert.True(SearchQuery.Parse("").IsEmpty);
        Assert.True(SearchQuery.Parse("   ").IsEmpty);
        Assert.True(SearchQuery.Parse(null).Matches("anything"));
        Assert.True(SearchQuery.Parse("!").IsEmpty); // a lone mark asks for nothing
    }

    [Fact]
    public void Every_word_must_be_there_in_any_order_and_any_case()
    {
        Assert.True(Match("lunar client", @"C:\Users\p\AppData\Local\Programs\Lunar Client\Lunar Client.exe"));
        Assert.True(Match("CLIENT lunar", @"c:\lunar client.exe"));
        Assert.False(Match("lunar badlion", @"C:\Lunar Client.exe"));
    }

    [Fact]
    public void A_pasted_path_with_spaces_still_finds_its_row()
    {
        Assert.True(Match(@"C:\Program Files\Java\bin\javaw.exe", @"c:\program files\java\bin\javaw.exe signed oracle"));
    }

    [Fact]
    public void An_exclamation_mark_takes_rows_away()
    {
        Assert.False(Match("!microsoft", "signed by Microsoft Corporation"));
        Assert.True(Match("!microsoft", "signed by Oracle"));
        Assert.True(Match(".jar !mods", @"C:\Users\p\Downloads\x.jar"));
        Assert.False(Match(".jar !mods", @"C:\Users\p\.minecraft\mods\x.jar"));
    }

    [Fact]
    public void A_dash_is_an_ordinary_character_so_arguments_can_be_searched()
    {
        Assert.True(Match("-javaagent", "javaw.exe -javaagent:C:\\a.jar"));
        Assert.False(Match("-javaagent", "javaw.exe -Xmx2G"));
        Assert.True(Match("-enc", "powershell -nop -enc AAAA"));
    }

    [Fact]
    public void Quotes_keep_words_together()
    {
        Assert.True(Match("\"program files\"", @"c:\program files\x.exe"));
        Assert.False(Match("\"program files\"", @"c:\files\program.exe"));
        Assert.False(Match("!\"program files\"", @"c:\program files\x.exe"));
        Assert.True(Match("!\"program files\"", @"c:\files\program.exe"));
        Assert.True(Match("\"unclosed quote", "an unclosed quote still searches"));
    }

    [Fact]
    public void Only_a_search_that_looks_for_something_brings_hidden_rows_back()
    {
        Assert.True(SearchQuery.Parse("javaw").Seeks);
        Assert.True(SearchQuery.Parse("javaw !temp").Seeks);
        Assert.False(SearchQuery.Parse("!temp").Seeks);
        Assert.False(SearchQuery.Empty.Seeks);
    }
}
