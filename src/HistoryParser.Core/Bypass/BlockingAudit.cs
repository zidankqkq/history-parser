using System.Text.RegularExpressions;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Settings that stop a screenshare from working or switch evidence off without deleting anything: tools blocked
/// (DisallowRun, cmd/regedit/Task Manager policies, hosts file, firewall, browser block lists), commands that run on
/// every cmd.exe start, hijacked "open" handlers, logging switched off, and Prefetch files frozen read-only.
/// Each was taken from bypass guides; each is a plain read of one setting, and normal PCs leave all of them alone.
/// </summary>
public static class BlockingAudit
{
    const string Area = "Blocking";

    /// <summary>Sites a checker or the player needs during a screenshare: tool downloads, scanners, remote access.</summary>
    static readonly string[] ToolDomains =
    [
        "virustotal.com", "github.com", "githubusercontent.com", "discord.com", "discordapp.com", "discord.gg", "anydesk.com",
        "teamviewer.com", "voidtools.com", "nirsoft.net", "ericzimmerman.github.io", "ericzimmermanstools.com",
        "systeminformer", "sourceforge.net", "sysinternals.com", "echo.ac", "detect.ac", "tria.ge", "any.run",
        "hybrid-analysis.com", "majorgeeks.com", "osforensics.com", "exterro.com", "magnetforensics.com",
    ];

    /// <summary>Program names of screenshare and inspection tools, as they appear in firewall rules and block lists.</summary>
    static readonly Regex ToolNames = new(
        @"anydesk|teamviewer|rustdesk|systeminformer|processhacker|procexp|procmon|everything|historyparser|logparser|ratchecker|" +
        @"echo\.ac|detect\.ac|bamparser|prefetchview|winprefetchview|journaltrace|ftkimager|ftk imager|regedit|taskmgr|eventvwr|mmc\.exe|" +
        @"cmd\.exe|powershell|virustotal",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly Regex Destructive = new(@"taskkill|tskill|\bdel\b|\berase\b|\brd\b|rmdir|reg(\.exe)?\s+delete|wevtutil|fsutil|cls\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int Safe(string what, Func<int> check)
        {
            ct.ThrowIfCancellationRequested();
            try { return check(); }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                ctx.Route(Area, what, "Could not be read", CheckState.Unknown, "Run as administrator to check this.");
                return 0;
            }
        }
        return Safe("Open handlers", () => Handlers(ctx)) +
               Safe("Command Processor AutoRun", () => CmdAutoRun(ctx)) +
               Safe("Kill commands at startup", () => KillAtStartup(ctx)) +
               Safe("Tool policies", () => ToolPolicies(ctx)) +
               Safe("Hosts file", () => Hosts(ctx)) +
               Safe("Firewall rules", () => Firewall(ctx)) +
               Safe("Browser block lists", () => BrowserBlocks(ctx)) +
               Safe("Console colours", () => ConsoleColours(ctx)) +
               Safe("Logging switches", () => LoggingSwitches(ctx)) +
               Safe("Prefetch file attributes", () => PrefetchAttributes(ctx));
    }

    static RegistryKey? Open(RegistryKey root, string path)
    {
        try { return root.OpenSubKey(path); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }

    static IEnumerable<(RegistryKey Root, string Prefix, string User)> UserHives() =>
        WinApi.LoadedUserSids().Select(sid => (Registry.Users, sid + "\\", WinApi.SidToName(sid)));

    // ---- "open" handlers -----------------------------------------------------------------------

    /// <summary>
    /// What Windows runs to open .msc consoles (Event Viewer, Services) and programs. A per-user override of these is how
    /// the well-known UAC bypasses work, and pointing them elsewhere breaks or replaces the tools staff open.
    /// </summary>
    static int Handlers(BypassContext ctx)
    {
        int items = 0;
        foreach (var (cls, expected) in new[] { ("mscfile", "mmc.exe"), ("exefile", "\"%1\" %*") })
        {
            using var key = Open(Registry.LocalMachine, $@"SOFTWARE\Classes\{cls}\shell\open\command");
            var value = key?.GetValue("") as string;
            if (value == null) continue;
            items++;
            bool ok = value.Contains(expected, StringComparison.OrdinalIgnoreCase);
            ctx.Route(Area, $"Open command for {cls}", value, ok ? CheckState.Ok : CheckState.Bad,
                ok ? "Windows default." : "Not the Windows default.");
            if (!ok)
                ctx.Flag(Severity.High, FindingCategory.Injection, $"Windows' {cls} open command was replaced",
                    $"Opening {(cls == "mscfile" ? "a management console such as Event Viewer or Services" : "any program")} now runs \"{value}\" " +
                    $"instead of the Windows default. That can hide or replace the tools used to check this PC.", timeUtc: WinApi.GetKeyLastWriteUtc(key!));
        }
        foreach (var (root, prefix, user) in UserHives())
            foreach (var cls in new[] { "mscfile", "ms-settings", "exefile", "Folder" })
            {
                using var key = Open(root, $@"{prefix}Software\Classes\{cls}\shell\open\command");
                if (key == null) continue;
                var value = (key.GetValue("") as string ?? "").Trim();
                bool delegateExecute = key.GetValueNames().Contains("DelegateExecute", StringComparer.OrdinalIgnoreCase);
                if (value.Length == 0 && !delegateExecute) continue;
                var changed = WinApi.GetKeyLastWriteUtc(key);
                items++;
                ctx.Route(Area, $"Per-user open command for {cls} ({user})", value.Length > 0 ? value : "(DelegateExecute)", CheckState.Bad,
                    "Windows has no per-user command here by default.", timeUtc: changed);
                ctx.Flag(Severity.High, FindingCategory.Injection, $"Per-user {cls} open command set ({user})",
                    $"{user} has its own \"open\" command for {cls}: \"{value}\"{(delegateExecute ? " (with DelegateExecute)" : "")}, last changed " +
                    $"{Util.When.L(changed)}. Windows doesn't create this; it is the classic way to run something elevated through " +
                    $"{(cls == "ms-settings" ? "Settings / fodhelper" : cls == "mscfile" ? "Event Viewer" : "Explorer")} or to replace what those tools open.",
                    timeUtc: changed);
            }
        return items;
    }

    // ---- commands that run when cmd starts, or kill tools at logon ------------------------------

    static int CmdAutoRun(BypassContext ctx)
    {
        int items = 0;
        var places = new List<(RegistryKey Root, string Path, string Who)> { (Registry.LocalMachine, @"SOFTWARE\Microsoft\Command Processor", "All users") };
        places.AddRange(UserHives().Select(h => (h.Root, h.Prefix + @"Software\Microsoft\Command Processor", h.User)));
        foreach (var (root, path, who) in places)
        {
            using var key = Open(root, path);
            var value = (key?.GetValue("AutoRun") as string ?? "").Trim();
            if (value.Length == 0) continue;
            items++;
            bool destructive = IsDestructive(value);
            var changed = WinApi.GetKeyLastWriteUtc(key!);
            ctx.Route(Area, $"cmd.exe AutoRun ({who})", value, destructive ? CheckState.Bad : CheckState.Warning,
                "Runs every time Command Prompt starts. Developer tools (conda, clink) use it; deleting or killing commands do not belong here.",
                timeUtc: changed);
            ctx.Flag(destructive ? Severity.High : Severity.Low, FindingCategory.Persistence, $"Command runs every time Command Prompt opens ({who})",
                $"\"{value}\" runs automatically each time cmd.exe starts (Command Processor AutoRun, last changed {Util.When.L(changed)})." +
                (destructive ? " It deletes, kills or clears something - a way to interfere with a check run from Command Prompt."
                             : " Developer tools such as conda or clink set this legitimately; check what it runs."), timeUtc: changed);
        }
        return items;
    }

    static int KillAtStartup(BypassContext ctx)
    {
        int items = 0;
        var places = new List<(RegistryKey Root, string Path, string Who)>
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "All users"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "All users"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "All users (32-bit)"),
        };
        foreach (var (root, prefix, user) in UserHives())
        {
            places.Add((root, prefix + @"Software\Microsoft\Windows\CurrentVersion\Run", user));
            places.Add((root, prefix + @"Software\Microsoft\Windows\CurrentVersion\RunOnce", user));
        }
        foreach (var (root, path, who) in places)
        {
            using var key = Open(root, path);
            if (key == null) continue;
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is not string command || !Regex.IsMatch(command, @"\b(taskkill|tskill)\b", RegexOptions.IgnoreCase)) continue;
                items++;
                bool tool = ToolNames.IsMatch(command);
                ctx.Route(Area, $"Startup kill command ({who})", command, CheckState.Bad, "Ends programs every time the user logs in.");
                ctx.Flag(tool ? Severity.High : Severity.Medium, FindingCategory.Persistence, $"Programs are killed at every logon ({who})",
                    $"The startup entry \"{name}\" runs \"{command}\" each time {who} logs in." +
                    (tool ? " It targets screenshare or inspection tools." : " Check which programs it ends."));
            }
        }
        return items;
    }

    // ---- policies that block tools or hide drives ------------------------------------------------

    static int ToolPolicies(BypassContext ctx)
    {
        int items = 0;
        foreach (var (root, prefix, user) in UserHives())
        {
            using var system = Open(root, prefix + @"Software\Policies\Microsoft\Windows\System");
            using var sysPolicy = Open(root, prefix + @"Software\Microsoft\Windows\CurrentVersion\Policies\System");
            using var explorer = Open(root, prefix + @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");

            void Block(RegistryKey? key, string value, string what)
            {
                if (key?.GetValue(value) is not int v || v == 0) return;
                items++;
                ctx.Route(Area, $"{what} ({user})", "Blocked", CheckState.Bad, $"Policy {value} = {v}.", timeUtc: WinApi.GetKeyLastWriteUtc(key));
                ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"{what} is blocked ({user})",
                    $"The policy {value} = {v} stops {user} from using {what.ToLowerInvariant()}. Bypass guides set this before a screenshare; " +
                    "school and work PCs sometimes set it too.", timeUtc: WinApi.GetKeyLastWriteUtc(key));
            }
            Block(system, "DisableCMD", "Command Prompt");
            Block(sysPolicy, "DisableRegistryTools", "Registry Editor");
            Block(sysPolicy, "DisableTaskMgr", "Task Manager");
            Block(explorer, "NoRun", "The Run dialog (Win+R)");

            foreach (var value in new[] { "NoDrives", "NoViewOnDrive" })
            {
                if (explorer?.GetValue(value) is not int mask || mask == 0) continue;
                var letters = string.Concat(Enumerable.Range(0, 26).Where(i => (mask & (1 << i)) != 0).Select(i => (char)('A' + i)));
                items++;
                ctx.Route(Area, $"{value} ({user})", letters, CheckState.Bad, "Drives hidden from Explorer.");
                ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"Drives hidden from Explorer ({user})",
                    $"The {value} policy hides drive(s) {string.Join(", ", letters.Select(c => c + ":"))} from {user}'s Explorer. " +
                    "The drives still work by typed path - a way to keep a drive out of sight during a check.");
            }

            using var disallow = Open(root, prefix + @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun");
            if (disallow != null && explorer?.GetValue("DisallowRun") is int on && on != 0)
            {
                var blocked = disallow.GetValueNames().Select(n => disallow.GetValue(n) as string).Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
                if (blocked.Count == 0) continue;
                items++;
                bool tools = blocked.Any(b => ToolNames.IsMatch(b!));
                ctx.Route(Area, $"Blocked programs ({user})", string.Join(", ", blocked), CheckState.Bad, "DisallowRun list.");
                ctx.Flag(tools ? Severity.High : Severity.Medium, FindingCategory.AntiForensics, $"Programs blocked from starting ({user})",
                    $"Windows refuses to start these for {user} (DisallowRun): {string.Join(", ", blocked)}." +
                    (tools ? " They include screenshare or inspection tools." : ""));
            }
        }
        using (var appCompat = Open(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat"))
            items += AppCompatPolicy(ctx, appCompat, "All users");
        foreach (var (root, prefix, user) in UserHives())
        {
            using var appCompat = Open(root, prefix + @"Software\Policies\Microsoft\Windows\AppCompat");
            items += AppCompatPolicy(ctx, appCompat, user);
        }
        return items;
    }

    static int AppCompatPolicy(BypassContext ctx, RegistryKey? key, string who)
    {
        if (key == null) return 0;
        int items = 0;
        foreach (var (value, what, severity) in new[]
        {
            ("DisablePCA", "Program Compatibility Assistant (a record of programs that ran)", Severity.High),
            ("DisableEngine", "the application compatibility engine", Severity.Medium),
        })
        {
            // Registry value names are case-insensitive, so DisablePca matches too.
            if (key.GetValue(value) is not int v || v == 0) continue;
            items++;
            var changed = WinApi.GetKeyLastWriteUtc(key);
            ctx.Route(Area, $"{value} ({who})", "On", CheckState.Bad, $"Turns off {what}.", timeUtc: changed);
            ctx.Flag(severity, FindingCategory.LogTampering, $"{value} policy set ({who})",
                $"A policy turns off {what} (last changed {Util.When.L(changed)}). Windows never sets this on its own; bypass guides do, " +
                "so that programs run afterwards leave no PCA record.", timeUtc: changed);
        }
        return items;
    }

    // ---- network blocks of tools ----------------------------------------------------------------------

    static int Hosts(BypassContext ctx)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
        if (!File.Exists(path)) return 0;
        var (entries, blocked) = ParseHosts(File.ReadLines(path));
        ctx.Route(Area, "Hosts file", entries.Count == 0 ? "No entries" : $"{entries.Count} entr{(entries.Count == 1 ? "y" : "ies")}",
            blocked.Count > 0 ? CheckState.Bad : entries.Count > 0 ? CheckState.Warning : CheckState.Ok,
            entries.Count == 0 ? "" : "Ad blockers and some programs add entries; only redirects of screenshare/tool sites are flagged.", path);
        if (blocked.Count > 0)
            ctx.Flag(Severity.High, FindingCategory.AntiForensics, "Screenshare and tool websites blocked in the hosts file",
                $"The hosts file sends {string.Join(", ", blocked.Select(b => $"{b.Host} → {b.Address}").Distinct().Take(12))} somewhere else, " +
                "so tool downloads, VirusTotal or remote access fail on this PC.", path, File.GetLastWriteTimeUtc(path));
        return entries.Count;
    }

    /// <summary>All host entries, and the ones that point a screenshare/tool site somewhere else.</summary>
    internal static (List<(string Address, string Host)> Entries, List<(string Address, string Host)> ToolBlocks) ParseHosts(IEnumerable<string> lines)
    {
        var entries = new List<(string Address, string Host)>();
        foreach (var raw in lines)
        {
            var parts = raw.Split('#')[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 1; i < parts.Length; i++) entries.Add((parts[0], parts[i].ToLowerInvariant()));
        }
        return (entries, entries.Where(e => ToolDomains.Any(d => e.Host == d || e.Host.EndsWith("." + d) || e.Host.Contains(d))).ToList());
    }

    /// <summary>For an active outbound block rule aimed at a screenshare/inspection tool's program: its label; otherwise null.</summary>
    internal static string? ToolBlockRule(string rule, out bool outboundBlock)
    {
        var fields = rule.Split('|');
        outboundBlock = fields.Contains("Action=Block", StringComparer.OrdinalIgnoreCase) && fields.Contains("Dir=Out", StringComparer.OrdinalIgnoreCase) &&
                        !fields.Contains("Active=FALSE", StringComparer.OrdinalIgnoreCase);
        if (!outboundBlock) return null;
        var app = fields.FirstOrDefault(f => f.StartsWith("App=", StringComparison.OrdinalIgnoreCase))?[4..];
        var label = fields.FirstOrDefault(f => f.StartsWith("Name=", StringComparison.OrdinalIgnoreCase))?[5..] ?? "";
        // Windows' own rules carry resource names (@FirewallAPI.dll,...); only rules aimed at a tool's program matter.
        return app != null && !label.StartsWith('@') && ToolNames.IsMatch(Path.GetFileName(app)) ? $"{label} ({app})" : null;
    }

    /// <summary>A console colour value whose text colour equals its background colour.</summary>
    internal static bool InvisibleText(int screenColors) => (screenColors & 0xF) == ((screenColors >> 4) & 0xF);

    internal static bool IsDestructive(string command) => Destructive.IsMatch(command);

    static int Firewall(BypassContext ctx)
    {
        using var key = Open(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
        if (key == null) return 0;
        int outbound = 0;
        var hits = new List<string>();
        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is not string rule) continue;
            var hit = ToolBlockRule(rule, out bool outboundBlock);
            if (outboundBlock) outbound++;
            if (hit != null) hits.Add(hit);
        }
        ctx.Route(Area, "Outbound firewall blocks", outbound == 0 ? "None" : $"{outbound} active", hits.Count > 0 ? CheckState.Bad : CheckState.Ok,
            "Sandboxes and privacy tools add outbound blocks; only blocks aimed at screenshare or inspection tools are flagged.");
        if (hits.Count > 0)
            ctx.Flag(Severity.High, FindingCategory.AntiForensics, "Screenshare or inspection tools blocked in the firewall",
                $"Windows Firewall blocks these from connecting: {string.Join("; ", hits.Take(8))}.");
        return outbound;
    }

    static int BrowserBlocks(BypassContext ctx)
    {
        int items = 0;
        var browsers = new[] { @"Google\Chrome", @"Microsoft\Edge", @"BraveSoftware\Brave", "Vivaldi" };
        var places = new List<(RegistryKey Root, string Prefix, string Who)> { (Registry.LocalMachine, "", "All users") };
        places.AddRange(UserHives().Select(h => (h.Root, h.Prefix, h.User)));
        foreach (var (root, prefix, who) in places)
            foreach (var browser in browsers)
            {
                using var list = Open(root, $@"{prefix}Software\Policies\{browser}\URLBlocklist");
                if (list == null) continue;
                var urls = list.GetValueNames().Select(n => list.GetValue(n) as string).Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u!).ToList();
                if (urls.Count == 0) continue;
                items++;
                var tools = urls.Where(u => u == "*" || ToolDomains.Any(d => u.Contains(d, StringComparison.OrdinalIgnoreCase))).ToList();
                string browserName = browser.Split('\\').Last();
                ctx.Route(Area, $"{browserName} block list ({who})", string.Join(", ", urls.Take(6)), tools.Count > 0 ? CheckState.Bad : CheckState.Warning);
                if (tools.Count > 0)
                    ctx.Flag(Severity.High, FindingCategory.AntiForensics, $"{browserName} blocks screenshare and tool websites ({who})",
                        $"A browser policy blocks {string.Join(", ", tools.Take(8))}" + (tools.Contains("*") ? " (\"*\" blocks every site not on the allow list)" : "") +
                        ", so tool downloads and lookups fail in that browser.");
            }
        return items;
    }

    // ---- invisible command prompt -------------------------------------------------------------------

    static int ConsoleColours(BypassContext ctx)
    {
        int items = 0;
        foreach (var (root, prefix, user) in UserHives())
        {
            using var console = Open(root, prefix + "Console");
            if (console == null) continue;
            void Check(RegistryKey key, string window)
            {
                if (key.GetValue("ScreenColors") is not int colours) return;
                items++;
                if (!InvisibleText(colours)) return;
                ctx.Route(Area, $"Console colours: {window} ({user})", $"text = background ({colours & 0xF})", CheckState.Bad);
                ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"Command window text is invisible ({user})",
                    $"{window} is set to draw text in the same colour as its background, so whatever is typed or printed there can't be seen " +
                    "on screen during a screenshare.", timeUtc: WinApi.GetKeyLastWriteUtc(key));
            }
            Check(console, "Default console");
            foreach (var sub in console.GetSubKeyNames())
            {
                using var key = Open(console, sub);
                if (key != null) Check(key, sub.Replace('_', '\\'));
            }
        }
        return items;
    }

    // ---- evidence switched off ------------------------------------------------------------------------

    static int LoggingSwitches(BypassContext ctx)
    {
        int items = 0;
        using (var eventLog = Open(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\EventLog\Parameters"))
            if (eventLog?.GetValue("Disabled") is int off && off != 0)
            {
                items++;
                ctx.Route(Area, "Event logging switch", "Disabled", CheckState.Bad, @"Services\EventLog\Parameters\Disabled = 1");
                ctx.Flag(Severity.High, FindingCategory.LogTampering, "Event logging switched off in the registry",
                    @"The value EventLog\Parameters\Disabled is set. Windows doesn't use it; bypass guides set it to stop event logs being written.",
                    timeUtc: WinApi.GetKeyLastWriteUtc(eventLog));
            }

        foreach (var (root, prefix, user) in UserHives())
        {
            using var net = Open(root, prefix + @"Software\Microsoft\.NETFramework");
            if (net?.GetValue("NGenAssemblyUsageLog") is not { } value) continue;
            items++;
            ctx.Route(Area, $".NET usage logs ({user})", $"NGenAssemblyUsageLog = {value}", CheckState.Bad);
            ctx.Flag(Severity.Medium, FindingCategory.LogTampering, $".NET usage logging changed ({user})",
                $"NGenAssemblyUsageLog is set to \"{value}\" for {user}. .NET writes a usage log for every .NET program that runs; bypass guides set " +
                "this value to stop it. Nothing normal sets it.", timeUtc: WinApi.GetKeyLastWriteUtc(net));
        }

        using (var fs = Open(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\FileSystem"))
            if (fs?.GetValue("NtfsDisableLastAccessUpdate") is int lastAccess)
            {
                items++;
                // 0x80000000-0x80000003 = managed by Windows; 1 = turned off by hand (fsutil behavior set disablelastaccess 1).
                bool manual = lastAccess == 1;
                ctx.Route(Area, "File last-access times", manual ? "Turned off by hand" : "Managed by Windows", manual ? CheckState.Warning : CheckState.Ok,
                    $"NtfsDisableLastAccessUpdate = 0x{lastAccess:X}");
                if (manual)
                    ctx.Flag(Severity.Low, FindingCategory.AntiForensics, "File last-access times turned off by hand",
                        "NtfsDisableLastAccessUpdate is 1 (set with fsutil), not one of Windows' managed values. Timestomping guides do this first; " +
                        "some performance-tweak tools do it too.");
            }

        foreach (var (path, value, what) in new[]
        {
            (@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", "PowerShell script block logging (event 4104)"),
            (@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", "the Windows activity history (ActivitiesCache)"),
        })
        {
            using var key = Open(Registry.LocalMachine, path);
            if (key?.GetValue(value) is not int v || v != 0) continue;
            items++;
            ctx.Route(Area, value, "0 (off by policy)", CheckState.Warning, $"Turns off {what}.");
            ctx.Flag(Severity.Low, FindingCategory.LogTampering, $"{what} turned off by policy",
                $"{value} = 0 explicitly turns off {what}. Privacy and \"debloat\" tools set this as well, so it is context, not proof.",
                timeUtc: WinApi.GetKeyLastWriteUtc(key));
        }
        return items;
    }

    // ---- Prefetch files frozen ------------------------------------------------------------------------

    /// <summary>SysMain cannot update a read-only .pf, so its run count and last-run time stop moving. Windows never sets these attributes.</summary>
    static int PrefetchAttributes(BypassContext ctx)
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        var info = new DirectoryInfo(dir);
        if (!info.Exists) return 0;
        // IgnoreInaccessible = false: without admin rights the folder can't be listed, and that must read
        // "could not be read", never "normal".
        var odd = info.EnumerateFiles("*.pf", new EnumerationOptions { AttributesToSkip = 0, IgnoreInaccessible = false })
            .Where(f => (f.Attributes & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System)) != 0).ToList();
        ctx.Route(Area, "Prefetch file attributes", odd.Count == 0 ? "Normal" : $"{odd.Count} file(s) read-only/hidden",
            odd.Count == 0 ? CheckState.Ok : CheckState.Bad, "Windows never marks Prefetch files read-only or hidden.", dir);
        foreach (var f in odd.Take(20))
        {
            var attrs = string.Join(", ", new[] { FileAttributes.ReadOnly, FileAttributes.Hidden, FileAttributes.System }
                .Where(a => (f.Attributes & a) != 0).Select(a => a.ToString().ToLowerInvariant()));
            ctx.Flag(Severity.High, FindingCategory.LogTampering, $"Prefetch file frozen: {f.Name}",
                $"{f.Name} is marked {attrs}. Windows cannot update a read-only Prefetch file, so the program's later runs are not recorded there " +
                "and its last-run time looks older than it is. Windows never sets these attributes on Prefetch files.", f.FullName, f.LastWriteTimeUtc);
        }
        return odd.Count;
    }
}
