using System.Globalization;
using System.Xml.Linq;
using Microsoft.Win32;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Bypass;

/// <summary>Scheduled tasks: any that run a cleaner or a program from a throwaway folder; recent ones are noted.</summary>
public static class TaskAudit
{
    static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    static readonly string[] RiskyFolders = [@"\Temp\", "%TEMP%", "%TMP%", @"\Downloads\", @"\Desktop\"];

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
        if (!Directory.Exists(root)) return 0;
        int items = 0;
        foreach (var file in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
        {
            ct.ThrowIfCancellationRequested();
            var fi = new FileInfo(file);
            string command = "";
            try
            {
                var xml = XDocument.Parse(File.ReadAllText(file));
                command = string.Join(" | ", xml.Descendants(Ns + "Exec").Select(e =>
                    $"{(string?)e.Element(Ns + "Command")} {(string?)e.Element(Ns + "Arguments")}".Trim()));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Xml.XmlException) { }

            string name = Path.GetRelativePath(root, file);
            var notes = new List<string>();
            bool flagged = false;
            if (ctx.Keywords.Classify(command) is { } meaning) { notes.Add($"runs a command that {meaning}"); flagged = true; }
            // Updaters (OneDrive, Discord, Edge, Google) run from AppData by design, so only throwaway
            // folders count: programs rarely schedule themselves from Temp, Downloads or the Desktop.
            bool throwaway = RiskyFolders.Any(f => command.Contains(f, StringComparison.OrdinalIgnoreCase));
            bool appData = !throwaway && (command.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ||
                                          command.Contains("%APPDATA%", StringComparison.OrdinalIgnoreCase) ||
                                          command.Contains("%LOCALAPPDATA%", StringComparison.OrdinalIgnoreCase));
            bool recent = ctx.NowUtc - fi.CreationTimeUtc < TimeSpan.FromDays(14);
            if (recent) notes.Add("created in the last 14 days");
            if (throwaway) { notes.Add("runs something from Temp, Downloads or the Desktop"); flagged = true; }
            else if (appData) notes.Add("runs a program from AppData (normal for app updaters)");

            if (flagged)
                ctx.Flag(notes.Any(n => n.StartsWith("runs a command")) ? Severity.High : Severity.Medium, FindingCategory.Persistence,
                    $"Suspicious scheduled task: {name}",
                    $"Task \"{name}\" (created {Util.When.L(fi.CreationTimeUtc)}) runs: {command}. {string.Join("; ", notes)}.", file, fi.CreationTimeUtc);

            ctx.Tasks.Add(new TaskRow
            {
                Name = name, CreatedUtc = fi.CreationTimeUtc, ModifiedUtc = fi.LastWriteTimeUtc, Command = command,
                Note = string.Join("; ", notes), Flagged = flagged,
            });
            items++;
        }
        return items;
    }
}

/// <summary>Installed programs (with install dates) and recent uninstalls from the Windows Installer log.</summary>
public static class SoftwareAudit
{
    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        var keys = new List<(RegistryKey Root, string Path)>
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        };
        foreach (var sid in WinApi.LoadedUserSids())
            keys.Add((Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall"));

        foreach (var (root, path) in keys)
        {
            using var uninstall = root.OpenSubKey(path);
            if (uninstall == null) continue;
            foreach (var sub in uninstall.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var k = uninstall.OpenSubKey(sub);
                if (k?.GetValue("DisplayName") is not string name || name.Length == 0) continue;
                var installed = DateTime.TryParseExact(k.GetValue("InstallDate") as string, "yyyyMMdd", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var d) ? d.ToUniversalTime() : WinApi.GetKeyLastWriteUtc(k);
                Add(ctx, name, k.GetValue("DisplayVersion") as string ?? "", k.GetValue("Publisher") as string ?? "", installed, "Installed");
                items++;
            }
        }

        // Windows Installer: 11724 = product removed, 1034 = removal completed.
        foreach (var r in Events.Read("Application", "*[System[Provider[@Name='MsiInstaller'] and (EventID=11724 or EventID=1034)]]", 2000))
        {
            string product = r.Properties.Count > 0 ? r.Properties[0].Value as string ?? "" : "";
            if (product.Length == 0) continue;
            Add(ctx, product, r.Properties.Count > 1 ? r.Properties[1].Value as string ?? "" : "", "", Events.Utc(r), "Uninstalled");
            items++;
        }
        return items;
    }

    static void Add(BypassContext ctx, string name, string version, string publisher, DateTime? time, string action)
    {
        bool recentRemoval = action == "Uninstalled" && time is { } t && ctx.NowUtc - t < TimeSpan.FromDays(2);
        string note = recentRemoval ? "removed in the last 2 days" : "";
        ctx.Software.Add(new SoftwareRow
        {
            Name = name, Version = version, Publisher = publisher, TimeUtc = time, Action = action, Note = note, Flagged = recentRemoval,
        });
    }
}

/// <summary>Microsoft Defender configuration changes: exclusions added, protection turned off.</summary>
public static class DefenderAudit
{
    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        const string log = "Microsoft-Windows-Windows Defender/Operational";
        foreach (var r in Events.Read(log, "*[System[(EventID=5007 or EventID=5001 or EventID=5010 or EventID=5012)]]", 3000))
        {
            var t = Events.Utc(r);
            if (r.Id == 5007)
            {
                var d = Events.Data(r);
                string newValue = d.GetValueOrDefault("New Value") ?? "", oldValue = d.GetValueOrDefault("Old Value") ?? "";
                bool exclusion = (newValue + oldValue).Contains(@"\Exclusions\", StringComparison.OrdinalIgnoreCase);
                bool added = exclusion && newValue.Contains(@"\Exclusions\", StringComparison.OrdinalIgnoreCase);
                string setting = exclusion ? (added ? "Exclusion added" : "Exclusion removed") : "Setting changed";
                ctx.Defender.Add(new DefenderChange { TimeUtc = t, Setting = setting, NewValue = newValue, OldValue = oldValue, Suspicious = added });
                if (added)
                    ctx.Flag(Severity.Medium, FindingCategory.Defender, "Defender exclusion added",
                        $"At {Util.When.L(t)} Microsoft Defender was told to ignore: {ExclusionTarget(newValue)}. Cheats are often excluded so Defender " +
                        "does not delete or report them.", timeUtc: t);
            }
            else
            {
                string what = r.Id switch
                {
                    5001 => "Real-time protection turned off",
                    5010 => "Scanning for malware and spyware turned off",
                    _ => "Scanning for viruses turned off",
                };
                ctx.Defender.Add(new DefenderChange { TimeUtc = t, Setting = what, Suspicious = true });
                ctx.Flag(Severity.Low, FindingCategory.Defender, what, $"{what} at {Util.When.L(t)}.", timeUtc: t);
            }
            items++;
        }
        return items;
    }

    /// <summary>"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\cheat = 0x0" → "C:\cheat (path)".</summary>
    public static string ExclusionTarget(string value)
    {
        int i = value.IndexOf(@"\Exclusions\", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return value;
        var rest = value[(i + 12)..];
        int slash = rest.IndexOf('\\');
        if (slash < 0) return rest;
        string kind = rest[..slash].ToLowerInvariant() switch
        {
            "paths" => "folder or file", "processes" => "process", "extensions" => "file type", "ipaddresses" => "IP address",
            var other => other,
        };
        var target = rest[(slash + 1)..];
        int eq = target.LastIndexOf(" = ", StringComparison.Ordinal);
        if (eq > 0) target = target[..eq];
        return $"{target} ({kind})";
    }
}

/// <summary>
/// Forensic artifacts that were deleted, emptied or tampered with: event log files, prefetch,
/// Amcache, recent-item shortcuts and jump lists, shell history, PCA logs, SRUM, plus Java attach
/// files (a tool attached to a running Java process) and programs deleted right before the scan.
/// </summary>
public static class ArtifactAudit
{
    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        var usn = ctx.History.Timeline.Where(e => e.Source == EvidenceSource.UsnJournal && e.TimeUtc.HasValue).ToList();

        // Windows saves several of these files by writing a new copy and deleting the old one, so a
        // deletion followed by the same path being created again moments later is a save, not a wipe.
        var created = usn.Where(e => e.Kind == EvidenceKind.Created).ToLookup(e => e.Path, e => e.TimeUtc!.Value, StringComparer.OrdinalIgnoreCase);
        bool Rewritten(Evidence d) => created[d.Path].Any(c => c >= d.TimeUtc!.Value && c - d.TimeUtc!.Value <= TimeSpan.FromMinutes(2));
        // The same path back within two minutes, created anew or renamed into place (the second half of a safe save).
        var arrived = usn.Where(e => e.Kind == EvidenceKind.Created || (e.Kind == EvidenceKind.Renamed && e.Detail.StartsWith("Renamed from", StringComparison.Ordinal)))
            .ToLookup(e => e.Path, e => e.TimeUtc!.Value, StringComparer.OrdinalIgnoreCase);
        bool Reappears(Evidence d) => arrived[d.Path].Any(c => c >= d.TimeUtc!.Value && c - d.TimeUtc!.Value <= TimeSpan.FromMinutes(2));

        // 1. Changes recorded by the USN journal.
        var bulk = new Dictionary<string, List<DateTime>>();
        foreach (var e in usn)
        {
            var name = Path.GetFileName(e.Path);
            // A rename is judged by both names: System.evtx renamed to x.tmp (or moved to Temp) is still the event log.
            if ((Classify(name, e.Path, e.RelatedPath) ?? (e.RelatedPath is { } old ? Classify(Path.GetFileName(old), old, e.Path) : null)) is not { } kind) continue;
            if (e.Kind == EvidenceKind.Deleted && Rewritten(e)) continue;
            // PCA keeps PcaGeneralDb0/1 and rotates between them on its own.
            if (e.Kind == EvidenceKind.Deleted && name.StartsWith("PcaGeneralDb", StringComparison.OrdinalIgnoreCase)) continue;
            bool deleted = e.Kind == EvidenceKind.Deleted;
            // Java creates and deletes the attach file within seconds; count each attach once.
            bool attach = kind == "Java attach" && e.Kind == EvidenceKind.Created;
            if (kind == "Java attach" && !attach) continue;
            if (!deleted && !attach && e.Kind != EvidenceKind.Renamed) continue;
            string change = attach ? "A tool attached to a running Java process" : e.Kind switch
            {
                EvidenceKind.Deleted => "Deleted",
                EvidenceKind.Modified => "Contents changed",
                EvidenceKind.TimestampChanged => "Timestamps changed",
                EvidenceKind.Renamed => e.Detail,
                _ => "Created",
            };
            // Windows saves jump lists, shortcuts and other files through a temporary copy: the new copy is renamed into
            // place ("HHWZHXDGANS078K1L5WX.temp" → the jump list) and/or the old file is moved aside ("…~RF1c4bb6a.TMP").
            // All three must hold: Windows' exact name pattern, the same folder, and the original name present again
            // (renamed into place, or back within two minutes). Renamed to a temp name and gone for good is a wipe.
            bool safeSave = e.Kind == EvidenceKind.Renamed && e.RelatedPath is { } other &&
                            Util.FileTypes.IsWindowsSaveCopy(other, e.Path) &&
                            (e.Detail.StartsWith("Renamed from", StringComparison.Ordinal) || Reappears(e));
            if (safeSave) change = $"Saved by Windows (a temporary copy is swapped in during a save): {e.Detail}";
            bool suspicious = deleted || attach || (e.Kind == EvidenceKind.Renamed && !safeSave);
            ctx.Artifacts.Add(new ArtifactChange { TimeUtc = e.TimeUtc, Artifact = kind, Change = change, Path = e.Path, Detail = e.Origin ?? "", Suspicious = suspicious });
            items++;

            if (kind is "Shortcut" or "Jump list")
            {
                if (deleted) (bulk.TryGetValue(kind, out var l) ? l : bulk[kind] = new()).Add(e.TimeUtc!.Value);
                continue;
            }
            if (attach)
                ctx.Flag(Severity.Medium, FindingCategory.Process, "Something attached to a running Java process",
                    $"{e.Path} was created at {Util.When.L(e.TimeUtc)}. Java creates this file when a tool attaches to a running game, which is " +
                    "how many injection clients load. Developer tools (IDEs, profilers) do it too.", e.Path, e.TimeUtc);
            else if (deleted && kind != "Prefetch") // prefetch deletions are reported by History Parser
            {
                // Windows drops logs of removed features and providers during updates; only the logs that
                // record activity matter.
                bool minorLog = kind == "Event log file" && !MainLogs.Contains(Path.GetFileNameWithoutExtension(e.Path));
                var severity = minorLog ? Severity.Low
                    : kind is "Event log file" or "Amcache" or "Shell history" or "PCA log" or "SRUM" ? Severity.High : Severity.Medium;
                ctx.Flag(severity, FindingCategory.LogTampering, $"{kind} deleted",
                    $"{e.Path} was deleted at {Util.When.L(e.TimeUtc)}." +
                    (minorLog ? " This is not one of the logs that records programs or commands; Windows removes such logs itself during updates." : ""),
                    e.Path, e.TimeUtc);
            }
        }

        // Shortcuts and jump lists churn normally (Windows trims old ones itself); dozens deleted within
        // minutes is a cleaner or "Clear recent files".
        foreach (var (kind, times) in bulk)
        {
            times.Sort();
            for (int i = 0, j = 0; i < times.Count; i++)
            {
                while (times[i] - times[j] > TimeSpan.FromMinutes(5)) j++;
                if (i - j + 1 >= 40)
                {
                    ctx.Flag(Severity.Medium, FindingCategory.LogTampering, $"{kind}s wiped",
                        $"{i - j + 1}+ {kind.ToLowerInvariant()} files were deleted within 5 minutes around {Util.When.L(times[j])} — the recent-items " +
                        "history was cleared.", timeUtc: times[j]);
                    break;
                }
            }
        }

        // 2. Programs deleted right before the scan.
        foreach (var e in usn.Where(e => e.Kind == EvidenceKind.Deleted && ctx.NowUtc - e.TimeUtc!.Value < TimeSpan.FromHours(1) &&
                                         ctx.NowUtc >= e.TimeUtc!.Value && !Util.FileTypes.IsWindowsFile(e.Path) &&
                                         Util.FileTypes.FromPath(e.Path) is FileType.Exe or FileType.Jar or FileType.Dll &&
                                         !Util.FileTypes.IsInstallerTemp(e.Path)))
        {
            bool update = Rewritten(e) || LooksLikeUpdate(e.Path);
            ctx.Flag(update ? Severity.Low : Severity.Medium, FindingCategory.Deletion, "Program deleted right before the scan",
                $"{e.Path} was deleted at {Util.When.L(e.TimeUtc)}, {(ctx.NowUtc - e.TimeUtc!.Value).TotalMinutes:0} min before the scan." +
                (update ? " It sits in an app's update or version folder (or was replaced straight away), which is what an auto-update looks like." : ""),
                e.Path, e.TimeUtc);
        }

        // 3. Jars removed from a Minecraft mods folder. Launchers update mods by deleting the old jar and
        // writing the new one, so a jar created in the same folder minutes later points to an update.
        foreach (var e in usn.Where(e => e.Kind == EvidenceKind.Deleted && e.Path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) &&
                                         e.Path.Contains(@"\mods\", StringComparison.OrdinalIgnoreCase) &&
                                         ctx.NowUtc - e.TimeUtc!.Value < TimeSpan.FromDays(1)))
        {
            var dir = Path.GetDirectoryName(e.Path);
            var replacement = usn.FirstOrDefault(c => c.Kind == EvidenceKind.Created && c.Path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) &&
                                                      string.Equals(Path.GetDirectoryName(c.Path), dir, StringComparison.OrdinalIgnoreCase) &&
                                                      (c.TimeUtc!.Value - e.TimeUtc!.Value).Duration() <= TimeSpan.FromMinutes(10));
            ctx.Flag(replacement != null ? Severity.Low : Severity.Medium, FindingCategory.Deletion, "Mod removed in the last day",
                $"{Path.GetFileName(e.Path)} was deleted from {dir} at {Util.When.L(e.TimeUtc)}." +
                (replacement != null ? $" {Path.GetFileName(replacement.Path)} was added to the same folder at {Util.When.L(replacement.TimeUtc)}, so this was most likely a mod update." : ""),
                e.Path, e.TimeUtc);
        }

        items += CurrentState(ctx);
        return items;
    }

    /// <summary>Event logs that record logons, programs, commands, services and tasks.</summary>
    static readonly HashSet<string> MainLogs = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Security", "Application", "Windows PowerShell", "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational", "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-Windows Defender%4Operational", "Microsoft-Windows-CodeIntegrity%4Operational",
        "Microsoft-Windows-Kernel-PnP%4Configuration", "Microsoft-Windows-DriverFrameworks-UserMode%4Operational",
        "Microsoft-Windows-Partition%4Diagnostic", "Microsoft-Windows-Storage-ClassPnP%4Operational",
    };

    /// <summary>
    /// Paths auto-updaters write and clean up: Squirrel's app-1.2.3, Chromium/Electron version folders, Roblox's version-xxxx.
    /// Never for Minecraft folders: .minecraft\versions\1.8.9-client\ is where injected clients are installed.
    /// Never in Temp, Downloads or the Desktop either: anyone can name a folder there "update".
    /// </summary>
    internal static bool LooksLikeUpdate(string path) =>
        !path.Contains("minecraft", StringComparison.OrdinalIgnoreCase) && !path.Contains(@"\mods\", StringComparison.OrdinalIgnoreCase) &&
        !System.Text.RegularExpressions.Regex.IsMatch(path, @"\\(Temp|Tmp|Downloads|Desktop)\\", System.Text.RegularExpressions.RegexOptions.IgnoreCase) &&
        System.Text.RegularExpressions.Regex.IsMatch(path,
            @"\\(app-\d+(\.\d+)+|version-[0-9a-f]+|\d+\.\d+\.\d+(\.\d+)?|Versions?|Update|Updates|packages|_update_|\.old)\\",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>
    /// Kind of forensic artifact a file is, or null. Only the real file in its real folder counts: Windows Error Reporting,
    /// diagnostics, updaters and backup tools copy .evtx logs, hives and databases into Temp and delete the copies, and
    /// deleting a copy hides nothing — the original is untouched. A file moved out of its real folder is still caught,
    /// because the rename's old path (<paramref name="otherPath"/>) is in the real folder.
    /// </summary>
    public static string? Classify(string name, string path, string? otherPath = null)
    {
        bool In(string folder) => path.Contains(folder, StringComparison.OrdinalIgnoreCase) ||
                                  otherPath?.Contains(folder, StringComparison.OrdinalIgnoreCase) == true;
        if (name.StartsWith(".attach_pid", StringComparison.OrdinalIgnoreCase)) return "Java attach";
        if (name.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)) return In(@"\winevt\Logs\") ? "Event log file" : null;
        if (name.Equals("Amcache.hve", StringComparison.OrdinalIgnoreCase)) return In(@"\AppCompat\Programs\") ? "Amcache" : null;
        if (name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)) return In(@"\Prefetch\") ? "Prefetch" : null;
        if (name.EndsWith("_history.txt", StringComparison.OrdinalIgnoreCase) && In(@"\PSReadLine\")) return "Shell history";
        if (name.StartsWith("PcaAppLaunchDic", StringComparison.OrdinalIgnoreCase) || name.StartsWith("PcaGeneralDb", StringComparison.OrdinalIgnoreCase))
            return In(@"\appcompat\pca\") ? "PCA log" : null;
        if (name.Equals("SRUDB.dat", StringComparison.OrdinalIgnoreCase)) return In(@"\System32\sru\") ? "SRUM" : null;
        if (name.EndsWith("Destinations-ms", StringComparison.OrdinalIgnoreCase)) return In(@"\Recent\") ? "Jump list" : null;
        if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && In(@"\Recent\")) return "Shortcut";
        return null;
    }

    /// <summary>Evidence folders that are empty or switched off right now.</summary>
    static int CurrentState(BypassContext ctx)
    {
        int items = 0;
        bool usedPowerShell = ctx.History.Commands.Any(c => c.Source.StartsWith("PowerShell started", StringComparison.Ordinal));
        foreach (var profile in JavaUsageCollector.UserProfiles())
        {
            string user = Path.GetFileName(profile);
            // Windows' template profiles are copied for new users; nobody uses them.
            if (user is "Default" or "Default User" or "Public" or "All Users" or "defaultuser0") continue;
            var recent = Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Recent");
            if (!Directory.Exists(recent)) continue; // not a real, used profile
            int shortcuts = SafeCount(recent, "*.lnk");
            int jumpLists = SafeCount(Path.Combine(recent, "AutomaticDestinations"), "*");
            var lastWrite = Directory.GetLastWriteTimeUtc(recent);
            bool active = ctx.NowUtc - lastWrite < TimeSpan.FromDays(30);
            Add(ctx, "Recent items", user, shortcuts == 0 && active ? "Empty" : $"{shortcuts} shortcut(s)", recent, shortcuts == 0 && active);
            Add(ctx, "Jump lists", user, jumpLists == 0 && active ? "Empty" : $"{jumpLists} jump list(s)", Path.Combine(recent, "AutomaticDestinations"),
                jumpLists == 0 && active);
            if (shortcuts == 0 && active)
            {
                // "Show recently opened items" off (Settings > Personalization > Start) keeps the folder empty by design.
                bool trackingOff = user.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase) && RecentTrackingOff();
                ctx.Flag(trackingOff ? Severity.Low : Severity.Medium, FindingCategory.LogTampering, $"Recent items cleared ({user})",
                    trackingOff
                        ? $"{recent} is empty, and Windows is set not to keep recently opened items. That is a normal privacy setting, " +
                          "but it also means this history was never recorded — check when it was switched off."
                        : $"{recent} is empty although the account is in use — the list of recently opened files was cleared (by a cleaner, by hand, or with 'Clear File Explorer history').");
            }
            items += 2;

            var psDir = Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine");
            bool history = File.Exists(Path.Combine(psDir, "ConsoleHost_history.txt"));
            if (!history && usedPowerShell)
            {
                Add(ctx, "Shell history", user, "Missing", psDir, true);
                ctx.Flag(Severity.Low, FindingCategory.LogTampering, $"No PowerShell history ({user})",
                    "PowerShell has been used on this PC but this user has no ConsoleHost_history.txt: it was deleted, disabled, or " +
                    "PowerShell was only run by another account.");
                items++;
            }

            foreach (var profileScript in new[]
                     {
                         Path.Combine(profile, @"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
                         Path.Combine(profile, @"Documents\PowerShell\Microsoft.PowerShell_profile.ps1"),
                         Path.Combine(profile, @"OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
                     })
            {
                string text;
                try { text = File.Exists(profileScript) ? File.ReadAllText(profileScript) : ""; }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
                if (!text.Contains("SaveNothing", StringComparison.OrdinalIgnoreCase) && !text.Contains("HistorySavePath", StringComparison.OrdinalIgnoreCase)) continue;
                Add(ctx, "Shell history", user, "Turned off by profile script", profileScript, true);
                ctx.Flag(Severity.High, FindingCategory.LogTampering, $"PowerShell history turned off ({user})",
                    $"{profileScript} changes where or whether PowerShell saves command history.", profileScript);
                items++;
            }
        }

        var amcache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"AppCompat\Programs\Amcache.hve");
        bool amcacheExists = File.Exists(amcache);
        Add(ctx, "Amcache", "", amcacheExists ? $"Present, last written {Util.When.L(File.GetLastWriteTimeUtc(amcache))}" : "Missing", amcache, !amcacheExists);
        if (!amcacheExists)
            ctx.Flag(Severity.High, FindingCategory.LogTampering, "Amcache missing",
                $"{amcache} does not exist. Windows normally keeps this file, so it was most likely deleted.");
        return items + 1;
    }

    static void Add(BypassContext ctx, string artifact, string user, string state, string path, bool suspicious) =>
        ctx.Artifacts.Add(new ArtifactChange
        {
            Artifact = artifact, Change = state, Path = path, Detail = user.Length > 0 ? $"user {user} (current state)" : "current state",
            Suspicious = suspicious,
        });

    static bool RecentTrackingOff()
    {
        using var advanced = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced");
        using var policy = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
        return advanced?.GetValue("Start_TrackDocs") is int track && track == 0 ||
               policy?.GetValue("NoRecentDocsHistory") is int no && no == 1 ||
               policy?.GetValue("ClearRecentDocsOnExit") is int clear && clear == 1;
    }

    static int SafeCount(string dir, string pattern)
    {
        try { return Directory.Exists(dir) ? Directory.GetFiles(dir, pattern).Length : 0; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return 0; }
    }
}
