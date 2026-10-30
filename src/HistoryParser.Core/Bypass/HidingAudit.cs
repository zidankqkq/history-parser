using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// More settings bypass tools change so evidence stops being written or tools stop working, without deleting anything:
/// the FileInfo filter Prefetch depends on, drives disabled in Device Manager, jars opened in an archiver, Smart App
/// Control / certificate blocks that stop tools from running, hidden Settings pages, recent-file lists switched off,
/// tool sites put in the Restricted zone, and copies of the IFEO key. Every check only reads; nothing is changed back.
/// </summary>
public static class HidingAudit
{
    const string Area = "Blocking";

    /// <summary>
    /// Words in a blocked certificate's name that point at a screenshare or inspection tool's publisher. Not Microsoft, Google or
    /// Mozilla: Windows itself ships revoked certificates with those names in this store (the 2011 fraudulent certificates).
    /// </summary>
    static readonly Regex ToolPublisher = new(
        @"github|discord|sysinternals|voidtools|nirsoft|zimmerman|systeminformer|winitor|anydesk|teamviewer|echo\.ac|detect\.ac|virustotal|" +
        @"oracle|java|7-zip|winrar|rarlab|notepad\+\+|python|adoptium|azul|amazon corretto|jetbrains",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int Safe(string what, Func<int> check)
        {
            ct.ThrowIfCancellationRequested();
            try { return check(); }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException
                                          or System.Security.Cryptography.CryptographicException)
            {
                ctx.Route(Area, what, "Could not be read", CheckState.Unknown, "Run as administrator to check this.");
                return 0;
            }
        }
        return Safe("FileInfo filter", () => FileInfoFilter(ctx)) +
               Safe("Disabled drives", () => DisabledDrives(ctx)) +
               Safe("Archive tool history", () => ArchiveHistory(ctx)) +
               Safe("Smart App Control", () => SmartAppControl(ctx)) +
               Safe("Blocked certificates", () => DisallowedCertificates(ctx)) +
               Safe("Hidden Settings pages", () => SettingsPages(ctx)) +
               Safe("Recent-file lists", () => RecentLists(ctx)) +
               Safe("Restricted sites", () => RestrictedSites(ctx)) +
               Safe("IFEO copies", () => IfeoCopies(ctx));
    }

    static RegistryKey? Open(RegistryKey root, string path)
    {
        try { return root.OpenSubKey(path); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }

    static IEnumerable<(RegistryKey Root, string Prefix, string User)> UserHives() =>
        WinApi.LoadedUserSids().Select(sid => (Registry.Users, sid + "\\", WinApi.SidToName(sid)));

    // ---- FileInfo -----------------------------------------------------------------------------------

    /// <summary>
    /// FileInfo is the file-system filter that tells SysMain which files a program opens; Prefetch is built from it. Unloading it
    /// (fltmc unload fileinfo) or disabling it stops Prefetch recording while SysMain still looks fine.
    /// </summary>
    static int FileInfoFilter(BypassContext ctx)
    {
        var s = WinApi.QueryService("FileInfo");
        if (!s.Exists)
        {
            ctx.Route(Area, "FileInfo filter", "Missing", CheckState.Bad, "The FileInfo driver's service entry is gone.");
            ctx.Flag(Severity.High, FindingCategory.ServiceTampering, "FileInfo filter removed",
                "The FileInfo file-system filter, which tells SysMain what each program opens so Prefetch can be written, is not registered at all. " +
                "Every Windows install has it; without it Prefetch stops being recorded.");
            return 1;
        }
        bool stopped = !s.IsRunning && s.State != "Unknown";
        var state = s.IsDisabled || stopped ? CheckState.Bad : CheckState.Ok;
        ctx.Route(Area, "FileInfo filter", $"{WinApi.StartTypeName(s.StartType)}, {s.State}", state,
            "The file-system filter Prefetch is built from. Windows loads it at boot and never unloads it.");
        if (state == CheckState.Bad)
            ctx.Flag(Severity.High, FindingCategory.ServiceTampering, s.IsDisabled ? "FileInfo filter disabled" : "FileInfo filter unloaded",
                $"The FileInfo file-system filter is {(s.IsDisabled ? "set to Disabled" : $"not loaded ({s.State})")}. SysMain builds Prefetch from it, " +
                "so while it is off Prefetch stops recording programs even though SysMain still shows as running. " +
                "\"fltmc unload fileinfo\" is the bypass command that does this.");
        return 1;
    }

    // ---- drives disabled in Device Manager ----------------------------------------------------------------

    static readonly string[] DriveEnums = [@"USBSTOR", @"SCSI", @"IDE", @"NVME", @"STORAGE\Volume", @"SWD\WPDBUSENUM"];

    /// <summary>ConfigFlags bit 0 (CONFIGFLAG_DISABLED) is set when a device is disabled in Device Manager: a drive kept plugged in but out of sight.</summary>
    static int DisabledDrives(BypassContext ctx)
    {
        var disabled = new List<(string Name, DateTime? When)>();
        foreach (var bus in DriveEnums)
        {
            using var root = Open(Registry.LocalMachine, $@"SYSTEM\CurrentControlSet\Enum\{bus}");
            if (root == null) continue;
            foreach (var device in root.GetSubKeyNames())
            {
                using var dev = Open(root, device);
                if (dev == null) continue;
                foreach (var instance in dev.GetSubKeyNames())
                {
                    using var inst = Open(dev, instance);
                    if (inst?.GetValue("ConfigFlags") is not int flags || (flags & 1) == 0) continue;
                    // Only storage: SCSI / IDE also enumerate CD drives and controllers.
                    var cls = inst.GetValue("Class") as string;
                    if (bus is "SCSI" or "IDE" && cls is not ("DiskDrive" or "Volume")) continue;
                    var name = inst.GetValue("FriendlyName") as string ?? inst.GetValue("DeviceDesc") as string ?? device;
                    if (name.Contains(';')) name = name[(name.LastIndexOf(';') + 1)..];
                    disabled.Add(($"{name} ({bus})", WinApi.GetKeyLastWriteUtc(inst)));
                }
            }
        }
        ctx.Route(Area, "Disabled drives", disabled.Count == 0 ? "None" : string.Join(", ", disabled.Select(d => d.Name)),
            disabled.Count == 0 ? CheckState.Ok : CheckState.Bad, "Drives and volumes disabled in Device Manager.");
        if (disabled.Count > 0)
        {
            var latest = disabled.Max(d => d.When);
            ctx.Flag(Severity.Medium, FindingCategory.Usb, disabled.Count == 1 ? $"A drive is disabled in Device Manager: {disabled[0].Name}" : $"{disabled.Count} drives are disabled in Device Manager",
                $"Disabled: {string.Join("; ", disabled.Select(d => $"{d.Name}, changed {Util.When.L(d.When)}"))}. A disabled drive stays connected but gets no " +
                "drive letter, so its files are out of sight during a check. Enable it in Device Manager to look inside.", timeUtc: latest);
        }
        return disabled.Count;
    }

    // ---- archive tools ----------------------------------------------------------------------------------

    static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".rar", ".zip", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso", ".arj", ".lzh", ".z", ".zst", ".wim",
    };

    /// <summary>
    /// The files WinRAR and 7-Zip opened. A jar opened in an archiver is how classes are swapped into a mod by hand (a cheat hidden
    /// inside a normal-looking mod); a program opened as an archive is a self-extracting or packed program being looked into.
    /// </summary>
    static int ArchiveHistory(BypassContext ctx)
    {
        int items = 0;
        foreach (var (root, prefix, user) in UserHives())
        {
            var entries = new List<(string Tool, string Path, DateTime? When)>();
            foreach (var (tool, path) in new[] { ("WinRAR", @"Software\WinRAR\ArcHistory"), ("WinRAR extract", @"Software\WinRAR\DialogEditHistory\ArcName") })
            {
                using var key = Open(root, prefix + path);
                if (key == null) continue;
                var when = WinApi.GetKeyLastWriteUtc(key);
                foreach (var n in key.GetValueNames())
                    if (key.GetValue(n) is string v && v.Length > 0) entries.Add((tool, v, n == "0" ? when : null));
            }
            using (var fm = Open(root, prefix + @"Software\7-Zip\FM"))
                if (fm?.GetValue("FolderHistory") is byte[] raw)
                    foreach (var v in System.Text.Encoding.Unicode.GetString(raw).Split('\0', StringSplitOptions.RemoveEmptyEntries))
                        entries.Add(("7-Zip", v, null));

            var jars = entries.Where(e => Path.GetExtension(e.Path).ToLowerInvariant() is ".jar" or ".litemod").ToList();
            var programs = entries.Where(e => Path.GetExtension(e.Path).ToLowerInvariant() is ".exe" or ".dll").ToList();
            items += entries.Count;
            if (entries.Count == 0) continue;
            ctx.Route(Area, $"Archive tool history ({user})", $"{entries.Count} entries", jars.Count + programs.Count > 0 ? CheckState.Bad : CheckState.Ok,
                string.Join("; ", entries.Take(10).Select(e => $"{e.Tool}: {e.Path}")) + (entries.Count > 10 ? " …" : ""));
            if (jars.Count > 0)
                ctx.Flag(Severity.Medium, FindingCategory.Injection, $"Jar opened in an archiver ({user})",
                    $"{string.Join("; ", jars.Select(j => $"{j.Tool}: {j.Path}"))}. Opening a jar in WinRAR or 7-Zip is how classes are added to or swapped " +
                    "inside a mod by hand - a cheat hidden in a normal-looking mod. Check that jar with the Program Checker.",
                    jars[0].Path, jars.Max(j => j.When));
            if (programs.Count > 0)
                ctx.Flag(Severity.Low, FindingCategory.AntiForensics, $"Program opened in an archiver ({user})",
                    $"{string.Join("; ", programs.Select(p => $"{p.Tool}: {p.Path}"))}. Archivers open self-extracting and packed programs; " +
                    "unpacking a program to run its contents leaves only the archiver in the records.", programs[0].Path);
        }
        return items;
    }

    // ---- Smart App Control and certificate blocks ---------------------------------------------------------

    /// <summary>
    /// Smart App Control blocks unsigned and unknown programs - which includes most screenshare tools. It is on only on fresh Windows 11
    /// installs; turning it on later needs a reinstall, so on an older install it was switched on deliberately or by a tool.
    /// </summary>
    static int SmartAppControl(BypassContext ctx)
    {
        using var policy = Open(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Policy");
        if (policy?.GetValue("VerifiedAndReputablePolicyState") is not int state) return 0;
        string text = state switch { 0 => "Off", 1 => "On (enforced)", 2 => "Evaluation", var x => $"State {x}" };
        ctx.Route(Area, "Smart App Control", text, state == 1 ? CheckState.Warning : CheckState.Ok,
            "When on, Windows refuses to start unsigned programs - most screenshare tools among them.", timeUtc: WinApi.GetKeyLastWriteUtc(policy));
        if (state == 1)
            ctx.Flag(Severity.Low, FindingCategory.AntiForensics, "Smart App Control is blocking unsigned programs",
                "Smart App Control is enforced, so Windows refuses to start unsigned programs - most screenshare tools among them. It comes on by itself only " +
                "on a fresh Windows 11 install. If a tool will not start, this is why; it is not proof on its own.", timeUtc: WinApi.GetKeyLastWriteUtc(policy));

        // AicEnabled ("Choose where to get apps"): "StoreOnly" lets only Store apps install / run from the shell.
        if (Open(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") is { } explorer)
            using (explorer)
                if (explorer.GetValue("AicEnabled") is string aicValue && aicValue.Contains("StoreOnly", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.Route(Area, "Where apps can come from", aicValue, CheckState.Bad, "Only Microsoft Store apps are allowed.", timeUtc: WinApi.GetKeyLastWriteUtc(explorer));
                    ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, "Only Store apps are allowed to install",
                        $"\"Choose where to get apps\" is set to {aicValue}: Windows refuses to run downloaded installers, which blocks screenshare tools. Home PCs " +
                        "almost never set this.", timeUtc: WinApi.GetKeyLastWriteUtc(explorer));
                }
        return 1;
    }

    /// <summary>Certificates in the Untrusted ("Disallowed") store: a publisher put there cannot run signed programs on this PC.</summary>
    static int DisallowedCertificates(BypassContext ctx)
    {
        int items = 0;
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            using var store = new X509Store(StoreName.Disallowed, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            // Microsoft ships a handful of known-bad certificates (DigiNotar, leaked keys) here: only certificates of
            // publishers screenshare tools come from matter.
            var tool = store.Certificates.Cast<X509Certificate2>()
                .Where(c => ToolPublisher.IsMatch(c.Subject) && !IsMicrosoftRevocation(c)).ToList();
            items += store.Certificates.Count;
            string where = location == StoreLocation.LocalMachine ? "all users" : "this user";
            ctx.Route(Area, $"Blocked certificates ({where})", $"{store.Certificates.Count} total, {tool.Count} of tool publishers",
                tool.Count > 0 ? CheckState.Bad : CheckState.Ok, "Programs signed with a certificate in this store will not run.");
            if (tool.Count > 0)
                ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"Tool publishers' certificates blocked ({where})",
                    $"These certificates are in the Untrusted store, so programs signed with them are refused: " +
                    $"{string.Join("; ", tool.Take(8).Select(c => c.GetNameInfo(X509NameType.SimpleName, false)))}. Windows ships a few bad certificates here, " +
                    "but not these; putting a tool's publisher in this store stops that tool from running.");
        }
        return items;
    }

    /// <summary>Entries Windows Update puts in Disallowed itself: certificates revoked after a leak or a fraudulent issue.</summary>
    static bool IsMicrosoftRevocation(X509Certificate2 c) =>
        c.Subject.Contains("Enforced Licensing", StringComparison.OrdinalIgnoreCase) || c.Subject.Contains("DigiNotar", StringComparison.OrdinalIgnoreCase) ||
        c.Issuer.Contains("DigiNotar", StringComparison.OrdinalIgnoreCase) || c.Issuer.Contains("UTN-USERFirst", StringComparison.OrdinalIgnoreCase);

    // ---- settings and recent lists switched off --------------------------------------------------------------

    static int SettingsPages(BypassContext ctx)
    {
        int items = 0;
        foreach (var (root, path, who) in new[] { (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "All users") }
                     .Concat(UserHives().Select(h => (h.Root, h.Prefix + @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", h.User))))
        {
            using var key = Open(root, path);
            if (key?.GetValue("SettingsPageVisibility") is not string value || value.Length == 0) continue;
            items++;
            ctx.Route(Area, $"Hidden Settings pages ({who})", value, CheckState.Bad, "SettingsPageVisibility policy.", timeUtc: WinApi.GetKeyLastWriteUtc(key));
            ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"Settings pages hidden ({who})",
                $"SettingsPageVisibility = \"{value}\" hides (or limits to) these pages in Settings. Hiding pages such as Date & time, Apps or " +
                "Windows Security keeps a checker from looking there.", timeUtc: WinApi.GetKeyLastWriteUtc(key));
        }
        return items;
    }

    /// <summary>Policies that stop Windows from keeping recent-file lists (the Explorer and dialog history a screenshare reads).</summary>
    static int RecentLists(BypassContext ctx)
    {
        int items = 0;
        foreach (var (root, prefix, user) in UserHives())
        {
            using var explorer = Open(root, prefix + @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
            using var comdlg = Open(root, prefix + @"Software\Microsoft\Windows\CurrentVersion\Policies\Comdlg32");
            var on = new List<string>();
            foreach (var (key, value, meaning) in new[]
                     {
                         (explorer, "NoRecentDocsHistory", "recent files are not recorded"),
                         (explorer, "ClearRecentDocsOnExit", "recent files are wiped at sign-out"),
                         (explorer, "NoFileMru", "file dialogs keep no history"),
                         (comdlg, "NoFileMru", "file dialogs keep no history"),
                         (comdlg, "NoBackButton", "file dialogs have no back history"),
                         (explorer, "NoInstrumentation", "UserAssist / usage tracking is off"),
                     })
                if (key?.GetValue(value) is int v && v != 0) on.Add($"{value} ({meaning})");
            // NotFileMru is not a real policy: a look-alike value bypass guides tell people to add next to NoFileMru.
            foreach (var key in new[] { explorer, comdlg })
                foreach (var n in key?.GetValueNames() ?? [])
                    if (n.Contains("FileMru", StringComparison.OrdinalIgnoreCase) && !n.Equals("NoFileMru", StringComparison.OrdinalIgnoreCase))
                        on.Add($"{n} = {key!.GetValue(n)} (a look-alike value; not a Windows setting)");
            if (on.Count == 0) continue;
            items++;
            ctx.Route(Area, $"Recent-file lists ({user})", string.Join(", ", on), CheckState.Bad, "Policies that stop recent-file history.");
            ctx.Flag(Severity.Medium, FindingCategory.LogTampering, $"Recent-file history switched off ({user})",
                $"{string.Join("; ", on)}. These stop Windows from keeping the recent-file and dialog history a screenshare reads. " +
                "Home PCs leave them unset.");
        }
        return items;
    }

    /// <summary>Tool and download sites put in Internet Explorer's Restricted zone (still used by Windows' download and SmartScreen checks).</summary>
    static int RestrictedSites(BypassContext ctx)
    {
        int items = 0;
        foreach (var (root, prefix, user) in UserHives())
        {
            var restricted = new List<string>();
            foreach (var map in new[] { "Domains", "EscDomains" })
            {
                using var domains = Open(root, prefix + $@"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\{map}");
                if (domains == null) continue;
                foreach (var domain in domains.GetSubKeyNames())
                {
                    using var d = Open(domains, domain);
                    if (d == null) continue;
                    if (d.GetValueNames().Any(n => d.GetValue(n) is int zone && zone == 4)) restricted.Add(domain);
                    foreach (var sub in d.GetSubKeyNames())
                    {
                        using var s = Open(d, sub);
                        if (s != null && s.GetValueNames().Any(n => s.GetValue(n) is int zone && zone == 4)) restricted.Add($"{sub}.{domain}");
                    }
                }
            }
            if (restricted.Count == 0) continue;
            items += restricted.Count;
            ctx.Route(Area, $"Restricted sites ({user})", string.Join(", ", restricted.Take(10)), CheckState.Bad, "ZoneMap domains in zone 4 (Restricted).");
            ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"Sites put in the Restricted zone ({user})",
                $"{string.Join(", ", restricted.Take(20))}{(restricted.Count > 20 ? " …" : "")} are in the Restricted zone: files downloaded from them are blocked " +
                "or stripped. Bypass guides use it to stop screenshare tools from downloading.");
        }
        return items;
    }

    /// <summary>
    /// A copy of the Image File Execution Options key under another name: debugger entries that hijack a tool can be kept there and
    /// swapped in, and a checker reading only the real key sees nothing.
    /// </summary>
    static int IfeoCopies(BypassContext ctx)
    {
        int items = 0;
        foreach (var parent in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion" })
        {
            using var key = Open(Registry.LocalMachine, parent);
            if (key == null) continue;
            foreach (var name in key.GetSubKeyNames())
            {
                if (name.Equals("Image File Execution Options", StringComparison.OrdinalIgnoreCase) || !LooksLikeIfeo(name)) continue;
                using var copy = Open(key, name);
                var withDebugger = copy?.GetSubKeyNames().Where(exe =>
                {
                    using var e = Open(copy, exe);
                    return e?.GetValue("Debugger") is string { Length: > 0 } || e?.GetValue("GlobalFlag") is not null;
                }).ToList() ?? [];
                items++;
                ctx.Route(Area, $"IFEO copy: {name}", withDebugger.Count > 0 ? string.Join(", ", withDebugger) : "no hijacks inside", CheckState.Bad,
                    $@"HKLM\{parent}\{name}", timeUtc: copy != null ? WinApi.GetKeyLastWriteUtc(copy) : null);
                ctx.Flag(withDebugger.Count > 0 ? Severity.High : Severity.Medium, FindingCategory.Injection, $"Copy of the IFEO key: {name}",
                    $@"HKLM\{parent}\{name} looks like a renamed Image File Execution Options key. Windows only reads the real one, so a copy is kept by " +
                    "a person or tool: hijacks (\"Debugger\" entries that run something else when a tool starts) can be parked there and swapped in." +
                    (withDebugger.Count > 0 ? $" It holds hijacks for: {string.Join(", ", withDebugger)}." : ""),
                    timeUtc: copy != null ? WinApi.GetKeyLastWriteUtc(copy) : null);
            }
        }
        return items;
    }

    internal static bool LooksLikeIfeo(string name)
    {
        var squashed = Regex.Replace(name.ToLowerInvariant(), "[^a-z]", "");
        return squashed.Contains("imagefileexecution") || squashed.Contains("executionoptions") || squashed == "ifeo";
    }
}
