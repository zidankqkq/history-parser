using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Native;

/// <summary>
/// The times a screenshare is read against: when the user signed in, when the desktop shell started, when the game started.
/// Each is Windows' own answer, read live; nothing here is a judgement.
/// </summary>
public static partial class SessionTimes
{
    /// <summary>When the user of the session this program runs in signed in (the terminal-services record of that session).</summary>
    public static DateTime? SignInUtc()
    {
        int session;
        using (var self = Process.GetCurrentProcess()) session = self.SessionId;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, WTSSessionInfo, out var buffer, out int bytes) || buffer == IntPtr.Zero) return null;
        try
        {
            // WTSINFOW: eight 32-bit fields, three names (32, 17 and 21 UTF-16 characters), then five 64-bit times
            // (connect, disconnect, last input, logon, current) from offset 176.
            return bytes < 216 ? null : SignInFrom(Marshal.ReadInt64(buffer, 200), Marshal.ReadInt64(buffer, 208), DateTime.UtcNow);
        }
        finally { WTSFreeMemory(buffer); }
    }

    /// <summary>
    /// The sign-in time, only when the record reads sensibly. The record carries its own "now": when that is not now, the
    /// layout is not the one expected and nothing is returned rather than a wrong time.
    /// </summary>
    internal static DateTime? SignInFrom(long logonFileTime, long currentFileTime, DateTime nowUtc)
    {
        if (Util.FileTime.ToUtc(currentFileTime) is not { } current || (current - nowUtc).Duration() > TimeSpan.FromMinutes(5)) return null;
        if (Util.FileTime.ToUtc(logonFileTime) is not { } logon || logon > nowUtc.AddMinutes(1) || logon.Year < 2005) return null;
        return logon;
    }

    /// <summary>
    /// The desktop shell: the Explorer process that owns the desktop and the taskbar, and when it started. Found by the
    /// window it owns, so the extra Explorer processes Windows starts for folder windows are never mistaken for it.
    /// </summary>
    public static (int Pid, DateTime StartUtc)? ShellStart()
    {
        IntPtr shell = GetShellWindow();
        if (shell == IntPtr.Zero) return null;
        GetWindowThreadProcessId(shell, out uint pid);
        return pid != 0 && WinApi.GetProcessStartUtc((int)pid) is { } start ? ((int)pid, start) : null;
    }

    /// <summary>
    /// Games running now, earliest start first, found by what they do: a process with a Java runtime loaded that was started
    /// with the game's arguments or has the game's graphics library loaded. A name plays no part: a renamed Java is found,
    /// and Java running something else is not.
    /// </summary>
    public static List<GameStart> RunningGames() => RunningJava().Where(g => !g.Unrecognised).ToList();

    /// <summary>
    /// Every running program with a Java runtime, earliest start first: the games, and the Java programs that are not
    /// recognisably the game (marked <see cref="GameStart.Unrecognised"/>). The second kind is listed because a game
    /// started in a way that hides its arguments and its graphics library would otherwise be nowhere on screen.
    /// </summary>
    public static List<GameStart> RunningJava()
    {
        var games = new List<GameStart>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                    string command = WinApi.GetCommandLine(process.Id) ?? "";
                    bool starts = IsGameCommand(command);
                    string? image = Bypass.ProcessAudit.ImagePath(process.Id);
                    bool holdsJava = image != null && HoldsJava(image);
                    if (!starts && !holdsJava) continue;
                    var kind = Kind(Bypass.ArgumentAudit.Modules(process.Id), starts, holdsJava);
                    if (kind != JavaKind.None && WinApi.GetProcessStartUtc(process.Id) is { } start)
                        games.Add(new GameStart
                        {
                            StartUtc = start, Pid = process.Id, Path = image ?? "", Program = Path.GetFileName(image ?? process.ProcessName + ".exe"),
                            GameDir = Argument(command, "--gameDir"), Version = Argument(command, "--version"), Account = Argument(command, "--username"),
                            How = "Running", Unrecognised = kind == JavaKind.Java, Runs = kind == JavaKind.Java ? Argument(command, "-jar") : "",
                        });
                }
                catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { } // ended while it was looked at
            }
        }
        return games.OrderBy(g => g.StartUtc).ToList();
    }

    /// <summary>A Java runtime is loaded, and either the process was started as the game or the game's graphics library is loaded too.</summary>
    internal static bool IsGame(IReadOnlyCollection<string> modules, bool startedAsGame) =>
        modules.Any(m => Path.GetFileName(m).Equals("jvm.dll", StringComparison.OrdinalIgnoreCase)) &&
        (startedAsGame || modules.Any(m => Path.GetFileName(m).Contains("lwjgl", StringComparison.OrdinalIgnoreCase)));

    internal enum JavaKind { None, Java, Game }

    /// <summary>
    /// What a process is, from what it has loaded: the game, a Java program that is not recognisably the game, or neither.
    /// When its modules cannot be read, the arguments and the runtime beside the program have to do.
    /// </summary>
    internal static JavaKind Kind(IReadOnlyCollection<string> modules, bool startedAsGame, bool javaBesideIt)
    {
        if (modules.Count == 0) return !javaBesideIt ? JavaKind.None : startedAsGame ? JavaKind.Game : JavaKind.Java;
        if (IsGame(modules, startedAsGame)) return JavaKind.Game;
        return modules.Any(m => Path.GetFileName(m).Equals("jvm.dll", StringComparison.OrdinalIgnoreCase)) ? JavaKind.Java : JavaKind.None;
    }

    /// <summary>The value given to one of the game's arguments ("--gameDir C:\x" or "--gameDir "C:\my games""); empty when it is not there.</summary>
    internal static string Argument(string commandLine, string name)
    {
        var match = Regex.Match(commandLine, Regex.Escape(name) + """\s+(?:"([^"]*)"|(\S+))""", RegexOptions.IgnoreCase);
        return !match.Success ? "" : match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
    }

    /// <summary>
    /// Earlier starts of the game that Prefetch still records (it keeps the last eight runs of each program). A program
    /// counts when the files it opened show a Java runtime together with the game's graphics library or its mods: the same
    /// test as for a running game, on what Windows wrote down instead of on a live process.
    /// </summary>
    internal static List<GameStart> PastGames(IEnumerable<Evidence> evidence)
    {
        var prefetch = evidence.Where(e => e.Source == EvidenceSource.Prefetch).ToList();
        // What a program opened is recorded per Prefetch file; the collector names that file in the detail ("Listed in X.pf: …").
        var opened = prefetch.Where(e => e.Kind == EvidenceKind.LoadedModule)
            .Select(e => (File: ListedIn().Match(e.Detail), e.Path)).Where(x => x.File.Success)
            .GroupBy(x => x.File.Groups[1].Value, x => x.Path, StringComparer.OrdinalIgnoreCase);
        var games = new List<GameStart>();
        foreach (var record in opened)
        {
            if (!IsGame(record.ToList(), record.Any(IsGameFile))) continue;
            foreach (var run in prefetch.Where(e => e.Kind == EvidenceKind.Execution && e.TimeUtc.HasValue && record.Key.Equals(e.Origin, StringComparison.OrdinalIgnoreCase)))
                games.Add(new GameStart { StartUtc = run.TimeUtc!.Value, Path = run.Path, Program = Path.GetFileName(run.Path), How = "Prefetch" });
        }
        return games;
    }

    [GeneratedRegex(@"^Listed in (\S+\.pf):", RegexOptions.IgnoreCase)]
    private static partial Regex ListedIn();

    /// <summary>A file only the game opens: its graphics library, something in a .minecraft folder, a jar in a mods folder.</summary>
    static bool IsGameFile(string path) =>
        Path.GetFileName(path).Contains("lwjgl", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\.minecraft\", StringComparison.OrdinalIgnoreCase) ||
        (path.Contains(@"\mods\", StringComparison.OrdinalIgnoreCase) && path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The running games and the earlier starts in one list, newest first. Prefetch writes a running game's start too, a few
    /// seconds late; that entry is the running game again, not another start.
    /// </summary>
    public static List<GameStart> AllGames(IReadOnlyList<GameStart> running, IEnumerable<Evidence> evidence, IReadOnlyList<GameStart>? otherJava = null)
    {
        // The Java programs that are not recognisably the game are listed with the games, each marked as what it is.
        var all = running.Concat(otherJava ?? []).ToList();
        foreach (var past in PastGames(evidence).OrderByDescending(g => g.StartUtc))
            if (!all.Any(g => g.Program.Equals(past.Program, StringComparison.OrdinalIgnoreCase) && (g.StartUtc - past.StartUtc).Duration() < TimeSpan.FromMinutes(2)))
                all.Add(past);
        return all.OrderByDescending(g => g.StartUtc).ToList();
    }

    internal static bool IsGameCommand(string commandLine) =>
        commandLine.Contains("net.minecraft", StringComparison.OrdinalIgnoreCase) || commandLine.Contains("--gameDir", StringComparison.OrdinalIgnoreCase) ||
        commandLine.Contains("lwjgl", StringComparison.OrdinalIgnoreCase);

    static bool HoldsJava(string image) =>
        Path.GetDirectoryName(image) is { } folder && File.Exists(Path.Combine(folder, "server", "jvm.dll"));

    const int WTSSessionInfo = 24;

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("user32.dll")]
    static extern IntPtr GetShellWindow();

    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
}
