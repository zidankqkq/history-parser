using System.Diagnostics;
using System.Text.RegularExpressions;
using HistoryParser.Core.Models;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Analysis;

/// <summary>
/// Ways a program that ran can be made to look like it did not run, or like something else:
/// faked file dates, renamed or disguised programs, known names in the wrong folder, programs hidden
/// in alternate data streams or behind a fake extension, run from a network share, or run through a
/// host program (rundll32, regsvr32, script interpreters) so the cheat itself never appears as a program.
/// </summary>
public static class TamperAnalysis
{
    static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public static void Run(IEnumerable<FileRecord> files, bool readNtfs)
    {
        using var ntfs = readNtfs ? new NtfsRecord.Reader() : null;
        foreach (var r in files)
        {
            bool ran = r.WasExecutedDirectly || r.WasLoaded;
            if (!ran) continue;
            PathTricks(r);
            HostedByAnotherProgram(r);
            if (r.IsWindowsFile || r.Status != FileStatus.Exists) continue;
            WrongPlace(r);
            if (!FileInspector.ShouldInspect(r)) continue; // same set that was hashed and signature-checked
            SoftenSignedUpdates(r);
            if (r.Type is FileType.Exe or FileType.Dll) VersionInfo(r);
            if (ntfs != null) Timestamps(r, ntfs);
        }
    }

    static void Add(FileRecord r, Severity s, FindingCategory c, string title, string detail, DateTime? time = null) =>
        r.Findings.Add(new Finding { Severity = s, Category = c, Title = title, Detail = detail, Path = r.Path, TimeUtc = time ?? r.LastExecutionUtc });

    /// <summary>
    /// Signed programs replace themselves on every update (OneDrive, Discord, browsers, drivers' helpers), which
    /// the run-time checks cannot tell apart from a swap until the signature is known. A valid publisher
    /// signature on the file now makes an update the likely story.
    /// </summary>
    static void SoftenSignedUpdates(FileRecord r)
    {
        if (r.Signature != SignatureStatus.Signed) return;
        var cached = r.Evidence.Where(e => e.Source == EvidenceSource.ShimCache).Max(e => e.FileModifiedUtc);
        for (int i = r.Findings.Count - 1; i >= 0; i--)
        {
            var f = r.Findings[i];
            // Newer on disk than Windows cached = updated. Older would mean dates were wound back, which updates never do.
            if (f.Title == "File differs from the one Windows cached" && f.TimeUtc > cached)
                r.Findings.RemoveAt(i);
            else if (f.Title == "File replaced after its last run" && f.Severity > Severity.Low)
                r.Findings[i] = f with
                {
                    Severity = Severity.Low,
                    Detail = f.Detail + $" It is signed by {r.Signer ?? "its publisher"}, so this is most likely an update.",
                };
        }
    }

    // ---- 1. Faked dates -------------------------------------------------------------------------

    static void Timestamps(FileRecord r, NtfsRecord.Reader reader)
    {
        NtfsTimes? t;
        try { t = reader.Read(r.Path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return; }
        if (t == null) return;
        r.Ntfs = t;

        foreach (var finding in CheckTimes(t, r.LastExecutionUtc)) Add(r, finding.Severity, FindingCategory.TimelineInconsistency, finding.Title, finding.Detail);
    }

    /// <summary>Rules on the two NTFS timestamp sets (pure, for tests).</summary>
    public static List<(Severity Severity, string Title, string Detail)> CheckTimes(NtfsTimes t, DateTime? lastRun)
    {
        var list = new List<(Severity, string, string)>();
        // $FILE_NAME "created" is set when the file arrives in its folder and only Windows changes it.
        // $STANDARD_INFORMATION "created" earlier than that means it was set back by a program.
        if (t.SiCreated is { } si && t.FnCreated is { } fn && si < fn - TimeSpan.FromMinutes(1))
        {
            list.Add((Severity.Medium, "File dates set back (timestomped)",
                $"Explorer shows it created {Util.When.L(si)}, but NTFS's own record says the file arrived {Util.When.L(fn)}. Programs that fake dates change " +
                "only the first. Copy tools that keep original dates (robocopy, some unzippers) do this too — check where the file came from."));
        }
        // Real timestamps carry a 100-ns fraction; date-editing tools usually write whole seconds.
        if (t.SiCreated is { } c && c.Ticks % TimeSpan.TicksPerSecond == 0 && t.FnCreated is { } fc && fc.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            list.Add((Severity.Low, "File creation date is a round number",
                $"The visible creation date {Util.When.L(c)} has no fraction of a second, while NTFS's own record ({Util.When.L(fc)}) does. Date-editing tools typically produce this."));
        }
        // A file cannot have run before NTFS says it arrived (unless it was replaced afterwards — reported separately).
        if (lastRun is { } run && t.FnCreated is { } arrived && t.SiModified is { } mod && mod < run && arrived > run + TimeSpan.FromMinutes(2))
        {
            list.Add((Severity.Low, "File arrived after its last recorded run",
                $"It last ran {Util.When.L(run)} but this copy of the file only arrived {Util.When.L(arrived)}: the file that ran was replaced with this one."));
        }
        return list;
    }

    // ---- 2. Renamed / disguised programs --------------------------------------------------------

    /// <summary>Publishers whose names are worth faking, with the text their real signatures contain.</summary>
    static readonly (string Claim, string[] Signers)[] Publishers =
    [
        ("Microsoft", ["Microsoft"]), ("Oracle", ["Oracle"]), ("Google", ["Google"]), ("Mojang", ["Mojang", "Microsoft"]),
        ("Discord", ["Discord"]), ("Valve", ["Valve"]), ("NVIDIA", ["NVIDIA"]), ("Intel", ["Intel"]), ("Advanced Micro Devices", ["Advanced Micro Devices", "AMD"]),
        ("Mozilla", ["Mozilla"]), ("Logitech", ["Logitech"]), ("Razer", ["Razer"]), ("Adoptium", ["Eclipse", "Adoptium"]),
        ("Azul", ["Azul"]), ("Apple", ["Apple"]), ("OBS", ["OBS"]), ("Steam", ["Valve"]),
    ];

    static void VersionInfo(FileRecord r)
    {
        FileVersionInfo v;
        try { v = FileVersionInfo.GetVersionInfo(r.Path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FileNotFoundException) { return; }
        r.Company = Clean(v.CompanyName);
        r.OriginalName = Clean(v.OriginalFilename);
        r.Description = Clean(v.FileDescription);

        // Publishers routinely ship builds under other names (VS Code is built as electron.exe); a rename only
        // matters when nobody vouches for the file.
        if (r.Signature != SignatureStatus.Signed && Renamed(r.Name, r.OriginalName, Clean(v.InternalName)) is { } original)
            Add(r, r.Type == FileType.Exe ? Severity.Medium : Severity.Low, FindingCategory.AntiForensics, "Renamed program",
                $"{r.Name} was built as \"{original}\"{(r.Description is { Length: > 0 } d ? $" ({d})" : "")} and is not signed. " +
                "The file was renamed — check what the original is.");

        // Vendors ship unsigned helpers inside their own folders (Mojang's Java runtime says "Microsoft");
        // a "Microsoft" program sitting in Downloads, on the Desktop or in Temp is the case that matters.
        bool throwaway = Regex.IsMatch(r.Path, @"\\(Downloads|Desktop|Temp|Tmp)\\|^[A-Za-z]:\\[^\\]+$", RegexOptions.IgnoreCase);
        if (Disguised(r.Company, r.Signature, r.Signer) is { } claim)
            Add(r, throwaway ? Severity.Medium : Severity.Low, FindingCategory.AntiForensics, $"Claims to be from {claim} but is not signed by them",
                $"{r.Name} says its publisher is \"{r.Company}\", but it is {Display.Signature(r.Signature).ToLowerInvariant()}" +
                $"{(r.Signer is { } s ? $" by {s}" : "")}. Cheats copy a real program's details to look harmless.");
    }

    static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim().TrimEnd('\0');

    static string Squash(string s) => Regex.Replace(Path.GetFileNameWithoutExtension(s).ToLowerInvariant(), "[^a-z0-9]", "");

    /// <summary>The built-in original name when it clearly differs from the file's name, else null.</summary>
    public static string? Renamed(string fileName, string? originalName, string? internalName)
    {
        if (originalName == null) return null;
        var name = Squash(fileName);
        var original = Squash(originalName.Replace(".mui", "", StringComparison.OrdinalIgnoreCase));
        if (original.Length < 3 || name.Length == 0) return null;
        // "MBSetup-8.8 (2).exe" built as "MBSetup.exe" is a download copy, not a rename.
        if (name.Contains(original) || original.Contains(name)) return null;
        if (internalName != null && Squash(internalName) is { Length: >= 3 } inner && (name.Contains(inner) || inner.Contains(name))) return null;
        return originalName;
    }

    /// <summary>The well-known publisher a program claims to be from when its signature does not back that up.</summary>
    public static string? Disguised(string? company, SignatureStatus signature, string? signer)
    {
        if (company == null || signature is SignatureStatus.NotChecked or SignatureStatus.NotApplicable or SignatureStatus.WindowsFile) return null;
        foreach (var (claim, signers) in Publishers)
        {
            if (!company.Contains(claim, StringComparison.OrdinalIgnoreCase)) continue;
            bool backed = signature == SignatureStatus.Signed && signer != null &&
                          signers.Any(s => signer.Contains(s, StringComparison.OrdinalIgnoreCase));
            return backed ? null : claim;
        }
        return null;
    }

    // ---- 3. Known programs in the wrong folder ---------------------------------------------------

    /// <summary>Program names cheats like to borrow, and folders the real ones live in.</summary>
    static readonly Dictionary<string, string[]> KnownHomes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["javaw.exe"] = [@"\Java\", @"\jdk", @"\jre", @"\runtime\", @"\Eclipse Adoptium\", @"\Zulu\", @"\Microsoft\jdk", @"\.lunarclient\", @"\Packages\Microsoft.4297127D64EC6", @"\BellSoft\", @"\Amazon Corretto\", @"\graalvm", @"\ModrinthApp\", @"\PrismLauncher\", @"\.feather\", @"\Badlion Client\"],
        ["java.exe"] = [@"\Java\", @"\jdk", @"\jre", @"\runtime\", @"\Eclipse Adoptium\", @"\Zulu\", @"\Microsoft\jdk", @"\.lunarclient\", @"\BellSoft\", @"\Amazon Corretto\", @"\graalvm", @"\ModrinthApp\", @"\PrismLauncher\"],
        ["discord.exe"] = [@"\Discord\", @"\DiscordPTB\", @"\DiscordCanary\"],
        ["chrome.exe"] = [@"\Google\Chrome\"],
        ["msedge.exe"] = [@"\Microsoft\Edge\"],
        ["firefox.exe"] = [@"\Mozilla Firefox\"],
        ["steam.exe"] = [@"\Steam\"],
        ["obs64.exe"] = [@"\obs-studio\"],
        ["minecraft.exe"] = [@"\Minecraft Launcher\", @"\Packages\Microsoft.4297127D64EC6", @"\XboxGames\"],
        ["minecraftlauncher.exe"] = [@"\Minecraft Launcher\", @"\Minecraft\"],
        ["lunar client.exe"] = [@"\Lunar Client\", @"\Programs\launcher\"],
    };

    static readonly HashSet<string> WindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe", "winlogon.exe", "dwm.exe", "conhost.exe",
        "taskhostw.exe", "runtimebroker.exe", "spoolsv.exe", "searchindexer.exe", "sihost.exe", "dllhost.exe", "ctfmon.exe",
        "rundll32.exe", "regsvr32.exe", "cmd.exe", "powershell.exe", "notepad.exe", "explorer.exe", "taskmgr.exe", "mshta.exe",
    };

    static void WrongPlace(FileRecord r)
    {
        // Files under C:\Windows are excluded before this runs, so a Windows name here is always out of place.
        if (WindowsNames.Contains(r.Name))
        {
            Add(r, Severity.High, FindingCategory.AntiForensics, $"Windows program name outside Windows: {r.Name}",
                $"{r.Name} is a Windows component, but this copy ran from {Path.GetDirectoryName(r.Path)}. Cheats use system names to blend in.");
            return;
        }
        if (KnownHomes.TryGetValue(r.Name, out var homes) && !homes.Any(h => r.Path.Contains(h, StringComparison.OrdinalIgnoreCase)))
            Add(r, Severity.Medium, FindingCategory.AntiForensics, $"Known program in an unusual folder: {r.Name}",
                $"{r.Name} normally lives in a folder like {homes[0].Trim('\\')}, but this one ran from {Path.GetDirectoryName(r.Path)}.");
    }

    // ---- 4. Path tricks -----------------------------------------------------------------------------

    static readonly HashSet<string> RunnableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi", ".cpl", ".jar", ".ahk",
        ".py", ".pyw", ".dll", ".sys", ".ocx", ".lnk", ".msc", "",
    };

    /// <summary>The PC's own administrative/loopback share: \\localhost\C$\..., \\127.0.0.1\..., \\?\UNC\localhost\..., \Device\Mup\localhost\...</summary>
    internal static readonly Regex Loopback = new(@"^(\\\\(\?\\UNC\\)?|\\Device\\Mup\\)(localhost|127\.0\.0\.1|\[?::1\]?)\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static void PathTricks(FileRecord r)
    {
        // C:\folder\notes.txt:cheat.exe — a program stored inside another file's hidden data stream.
        if (r.Path.IndexOf(':', 2) > 0)
        {
            Add(r, Severity.High, FindingCategory.AntiForensics, "Ran from a hidden data stream",
                $"{r.Path} is stored inside another file (an alternate data stream), which hides it from Explorer and most scanners.");
            return;
        }
        if (Loopback.IsMatch(r.Path))
            Add(r, Severity.High, FindingCategory.AntiForensics, "Started through this PC's own network share",
                $"{r.Path} is a file on this PC, but it was started through the loopback share (\\\\localhost) instead of its normal path. " +
                "Windows' BAM does not record programs started from network paths, so this is a known way to keep a program out of BAM.");
        else if (r.Path.StartsWith(@"\\", StringComparison.Ordinal) || r.Path.StartsWith(@"\Device\Mup", StringComparison.OrdinalIgnoreCase))
            Add(r, Severity.Medium, FindingCategory.AntiForensics, "Ran from a network location",
                $"{r.Path} ran from another computer or a network share, so the file is not on this PC to check.");

        // C:\.exe, Desktop\.dll: a program whose name is only an extension, which some tools fail to list.
        if (r.WasExecutedDirectly && Path.GetFileNameWithoutExtension(r.Name).Length == 0 && Path.GetExtension(r.Name).Length > 1)
            Add(r, Severity.High, FindingCategory.AntiForensics, "Program with no name",
                $"{r.Path} has an extension but no name. Some screenshare tools and filters skip such files; nothing normal is named like this.");

        // Windows Installer runs its own custom actions from .tmp files in the Installer folder (a Windows file), and
        // Inno Setup runs its setup.tmp from an is-XXXX.tmp folder in Temp; any other program under a .tmp/.png/.txt name
        // is a program pretending to be a data or temporary file.
        if (r.WasExecutedDirectly && !r.IsWindowsFile && !RunnableExtensions.Contains(Path.GetExtension(r.Path)))
        {
            bool installer = Util.FileTypes.IsInstallerTemp(r.Path);
            Add(r, installer ? Severity.Low : Severity.Medium, FindingCategory.AntiForensics, "Program with a disguised extension",
                $"{r.Name} was started as a program although its extension says it is not one. Renaming a program to " +
                ".tmp/.png/.txt makes it look like a temporary or data file." +
                (installer ? " It sits in an installer's own unpack folder in Temp, which is how Inno Setup and similar installers run." : ""));
        }
    }

    // ---- 5. Run through a host program ------------------------------------------------------------

    static readonly (string Host, string What, Severity Severity)[] Hosts =
    [
        ("RUNDLL32.EXE", "rundll32 (runs a DLL as a program)", Severity.Medium),
        ("REGSVR32.EXE", "regsvr32 (runs code from a DLL)", Severity.Medium),
        ("MSHTA.EXE", "mshta (runs an HTML application)", Severity.Medium),
        ("WSCRIPT.EXE", "Windows Script Host", Severity.Low),
        ("CSCRIPT.EXE", "Windows Script Host", Severity.Low),
        ("AUTOHOTKEY", "AutoHotkey (common for autoclickers and macros)", Severity.Medium),
        ("PYTHON", "Python", Severity.Low),
        ("POWERSHELL.EXE", "PowerShell", Severity.Low),
    ];

    static void HostedByAnotherProgram(FileRecord r)
    {
        if (r.IsWindowsFile || r.WasExecutedDirectly) return;
        foreach (var e in r.Evidence.Where(e => e.Kind == EvidenceKind.LoadedModule && e.Origin != null))
        {
            var host = Hosts.FirstOrDefault(h => e.Origin!.StartsWith(h.Host, StringComparison.OrdinalIgnoreCase));
            if (host.Host == null) continue;
            if (r.Type == FileType.Dll && host.Host is not ("RUNDLL32.EXE" or "REGSVR32.EXE")) continue;
            if (r.Type == FileType.Script && host.Host is "RUNDLL32.EXE" or "REGSVR32.EXE") continue;
            Add(r, host.Severity, FindingCategory.AntiForensics, $"Run through {e.Origin}",
                $"{r.Name} never ran as a program of its own: it was run by {host.What} (last {Util.When.L(e.TimeUtc)}). Running code through " +
                "a Windows host program keeps it out of most execution records.", e.TimeUtc);
            return;
        }
    }
}
