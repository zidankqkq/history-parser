using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;

namespace RatChecker.Core;

/// <summary>
/// Looks for the things account stealers and RATs do, in files that are only read (never run or loaded).
/// Rules are deliberately conservative: a single generic sign (network access, starting a process, loading classes)
/// is never enough on its own, because ordinary mods do those too. A file is only called dangerous when it carries
/// something no normal mod needs (a hard-coded webhook, paths to other apps' passwords) or when it both collects
/// private data and has a way to send it out.
/// </summary>
public static class RatScanner
{
    public static readonly string[] ScanExtensions = [".jar", ".zip", ".exe", ".dll", ".class", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".scr"];

    public static RatFileReport Scan(string path)
    {
        var report = new RatFileReport { Path = path };
        try
        {
            var info = new FileInfo(path);
            report.Size = info.Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                report.Sha256 = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
            var content = RatReader.Read(path);
            report.Kind = content.Kind;
            report.ModInfo = content.ModInfo;
            report.ItemsRead = content.Items;
            report.Notes.AddRange(content.Notes);
            if (content.Kind is ".NET program" or "Windows program")
            {
                report.Signature = FileInspector.Verify(path);
                report.Signer = FileInspector.SignerName(path);
            }
            Evaluate(content, report.Signs);
            NameRules(path, content, report.Signs);
            if (report.Signature is SignatureStatus.Signed or SignatureStatus.WindowsFile) CheatScanner.TrustSigned(report.Signs);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            report.Error = e.Message;
        }
        return report;
    }

    /// <summary>
    /// Checks a file held in memory under the given name. No signature check (that needs the file on disk). The tests use
    /// this so they never write fake stealer jars to Temp - files created and deleted there look exactly like a cheat
    /// cleaning up, and Log Parser rightly reports them.
    /// </summary>
    public static RatFileReport Scan(string name, byte[] bytes)
    {
        var report = new RatFileReport { Path = name, Size = bytes.Length, Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() };
        try
        {
            var content = RatReader.Read(bytes, name);
            report.Kind = content.Kind;
            report.ModInfo = content.ModInfo;
            report.ItemsRead = content.Items;
            report.Notes.AddRange(content.Notes);
            Evaluate(content, report.Signs);
            NameRules(name, content, report.Signs);
        }
        catch (InvalidDataException e) { report.Error = e.Message; }
        return report;
    }

    /// <summary>
    /// The file itself named as something it is not: a jar or a program called .png / .txt. Java and loaders run it
    /// anyway; the name only keeps it out of searches and file lists.
    /// </summary>
    static void NameRules(string path, RatContent c, List<RatSign> signs)
    {
        string ext = Path.GetExtension(path), name = Path.GetFileName(path);
        string named = ext.Length > 0 ? $"ends in \"{ext}\"" : "has no extension";
        if (c.Kind is "Zip archive" or "Java mod / jar" && c.Classes.Count > 0 && !HistoryParser.Core.Util.FileTypes.IsJavaContainerName(path))
            signs.Add(new RatSign(Severity.Medium, RatCategory.Obfuscation, "Java archive under another name",
                $"\"{name}\" is a jar full of compiled Java code, but its name {named}. Java runs it all the same (java -jar, or loaded by " +
                "another program); renaming it keeps it out of jar lists and searches.", name, "the file itself"));
        else if (c.Kind is ".NET program" or "Windows program" &&
                 ext.ToLowerInvariant() is not (".exe" or ".dll" or ".sys" or ".scr" or ".com" or ".cpl" or ".ocx" or ".drv" or ".efi" or ".mui" or ".node" or ".pyd" or ".winmd" or ".ax" or ".tlb"))
            signs.Add(new RatSign(Severity.Medium, RatCategory.Obfuscation, "Windows program under another name",
                $"\"{name}\" is a Windows program, but its name {named}. Loaders start programs named like this; the name keeps it out of program lists.",
                name, "the file itself"));
    }

    /// <summary>Applies every rule to what was read. Public for tests.</summary>
    public static void Evaluate(RatContent c, List<RatSign> signs)
    {
        var seen = new HashSet<string>();
        void Sign(Severity s, RatCategory cat, string title, string why, string evidence, string where)
        {
            if (seen.Add(title + "|" + evidence)) signs.Add(new RatSign(s, cat, title, why, Trim(evidence), where));
        }

        // Known samples first.
        foreach (var sha1 in c.Sha1s)
            if (Ioc.KnownBadSha1.Contains(sha1))
                Sign(Severity.High, RatCategory.KnownMalware, "Matches a known malware sample", "This exact file (or a jar inside it) is a published sample of known Minecraft malware.", sha1, "file hash");

        var strings = new List<(string Text, string Where)>(c.Strings);
        foreach (var (text, where) in c.Strings)
            if (DecodeBase64(text) is { } decoded)
            {
                strings.Add((decoded, where + " (hidden as Base64)"));
                if (decoded.StartsWith("https://") || decoded.StartsWith("http://"))
                    Sign(Severity.Medium, RatCategory.Obfuscation, "Web address hidden as Base64", "The address is encoded so it doesn't show up in a quick look. Normal mods have no reason to hide where they connect to.", decoded, where);
            }

        foreach (var (text, where) in strings) StringRules(text, where, Sign);
        RefRules(c, Sign);
        EntryRules(c, Sign);
        // A mod has no reason to open another launcher's logins; a launcher or client does (Lunar imports the official
        // launcher's accounts). Outside a mod it is a lead - unless the file can also send data out anonymously, which
        // Combine still rates as a stealer.
        if (c.ModInfo == null)
            for (int i = 0; i < signs.Count; i++)
                if (signs[i].Category == RatCategory.AccountTheft && signs[i].Severity == Severity.High && signs[i].Title == "Reads another launcher's login files")
                    signs[i] = signs[i] with
                    {
                        Severity = Severity.Medium,
                        Why = signs[i].Why + " This file is not a mod (no mod metadata) - launchers and clients import accounts this way - so on its own it is a lead, not a verdict.",
                    };
        Combine(signs, Sign);
        // A fault in a cheat rule must never cost the malware verdict.
        try { CheatScanner.Evaluate(c, signs); }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or IndexOutOfRangeException or NullReferenceException)
        {
            c.Notes.Add($"The cheat check could not finish on this file ({e.GetType().Name}); the malware check is complete.");
        }
    }

    // ---- strings --------------------------------------------------------------------------------

    delegate void SignFn(Severity s, RatCategory cat, string title, string why, string evidence, string where);

    static readonly Regex IpUrl = new(@"(?:https?|tcp|wss?)://(\d{1,3}(?:\.\d{1,3}){3})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex IpPort = new(@"^(\d{1,3}(?:\.\d{1,3}){3}):\d{2,5}$", RegexOptions.Compiled);

    static void StringRules(string s, string where, SignFn sign)
    {
        if (s.Length < 4) return;

        if (Ioc.WebhookFull.Match(s) is { Success: true } wh)
            sign(Severity.High, RatCategory.Exfiltration, "Hard-coded Discord webhook", "A webhook is a Discord address anyone can post to. Built into a mod, it is the most common way stealers send your account, token or files to the attacker.", wh.Value, where);
        else if (Ioc.WebhookAny.IsMatch(s))
            sign(Severity.Medium, RatCategory.Exfiltration, "Posts to Discord webhooks", "The mod sends data to a Discord webhook. Server plugins can do this for chat bridges; a client mod rarely has a reason.", s, where);

        if (Ioc.TelegramFull.Match(s) is { Success: true } tg)
            sign(Severity.High, RatCategory.Exfiltration, "Hard-coded Telegram bot", "A Telegram bot with its key built in — used by stealers to send stolen data to the attacker's chat.", tg.Value, where);
        else if (Ioc.TelegramAny.IsMatch(s))
            sign(Severity.Medium, RatCategory.Exfiltration, "Talks to a Telegram bot", "Uses the Telegram bot API, a common drop point for stolen data.", s, where);

        if (Ioc.SlackFull.Match(s) is { Success: true } slack)
            sign(Severity.High, RatCategory.Exfiltration, "Hard-coded Slack webhook", "A Slack webhook with its secret built in - anyone holding it can post, and stealers use it the same way as Discord webhooks.", slack.Value, where);
        else if (Ioc.SlackAny.IsMatch(s))
            sign(Severity.Medium, RatCategory.Exfiltration, "Posts to Slack webhooks", "Sends data to a Slack webhook. A game mod has no reason to.", s, where);

        if (Ioc.BotToken.Match(s) is { Success: true } bot)
            sign(Severity.High, RatCategory.Exfiltration, "Hard-coded Discord bot token", "The login key of a Discord bot is built into the file. Stealers use bots instead of webhooks to post stolen data to the attacker's channel - and anyone holding the key controls the bot.", bot.Value[..Math.Min(bot.Value.Length, 12)] + "… (key shortened)", where);
        if (Ioc.BotApi.IsMatch(s))
            sign(Severity.Medium, RatCategory.Exfiltration, "Posts messages to a Discord channel as a bot", "Uses Discord's bot API to send messages to a fixed channel - a stealer's \"living off the cloud\" drop point.", s, where);

        foreach (var lic in Ioc.Licensing)
            if (s.Contains(lic, StringComparison.OrdinalIgnoreCase))
                sign(Severity.Low, RatCategory.Network, "Uses KeyAuth licensing", "KeyAuth is a licence-key service used by many paid cheats and loaders. It says the file is a paid loader, not that it steals.", lic, where);

        foreach (var host in Ioc.DropHosts)
            if (s.Contains(host, StringComparison.OrdinalIgnoreCase))
                sign(Severity.Low, RatCategory.Exfiltration, "Uses an upload, paste or tunnel service", $"{host} lets anyone upload data or host a file. Crash-log uploaders and text loaders use these legitimately; stealers use them to receive data or fetch their next stage.", s, where);

        if (IpUrl.Match(s) is { Success: true } ip && IsPublicIp(ip.Groups[1].Value))
            sign(Severity.Medium, RatCategory.Exfiltration, "Connects to a raw IP address", "Normal mods talk to named websites. A bare IP address is typical of a private attacker server.", ip.Value, where);
        else if (IpPort.Match(s) is { Success: true } ipp && IsPublicIp(ipp.Groups[1].Value))
            sign(Severity.Medium, RatCategory.Exfiltration, "Contains a raw IP address and port", "A bare IP and port, typical of a private attacker server. (This can also be a Minecraft server address in a server-list mod.)", s, where);

        foreach (var ioc in Ioc.Fractureiser)
            if (s.Contains(ioc, StringComparison.OrdinalIgnoreCase))
                sign(Severity.High, RatCategory.KnownMalware, "Known malware: Fractureiser", "This exact address or name belongs to Fractureiser, malware that stole accounts and infected other mods in 2023.", s, where);

        foreach (var (needle, what) in Ioc.AccountFiles)
            if (s.Contains(needle, StringComparison.OrdinalIgnoreCase))
                sign(Severity.High, RatCategory.AccountTheft, "Reads another launcher's login files", $"Points at {what}. A mod has no reason to open other launchers' login data — this is how Minecraft account stealers work.", s, where);
        foreach (var folder in Ioc.LauncherFolders)
            if (IsPathPart(s, folder) && !s.Contains("://"))
            {
                if (ContainsAny(s, Ioc.LoginFiles))
                    sign(Severity.High, RatCategory.AccountTheft, "Reads another launcher's login files", $"Points at the saved logins of {folder}. A mod has no reason to open them — this is how Minecraft account stealers work.", s, where);
                else
                    sign(Severity.Low, RatCategory.AccountTheft, "Mentions another launcher's folder", $"A path into {folder}. Some mods detect their launcher this way; it only matters if the file also reads login files.", s, where);
            }

        foreach (var (needle, cat, sev, what) in Ioc.OtherAppFiles)
            if (IdentifierNeedle.IsMatch(needle) ? ContainsWord(s, needle) : s.Contains(needle, StringComparison.OrdinalIgnoreCase))
                sign(sev, cat, cat switch
                {
                    RatCategory.DiscordTheft => "Looks for Discord's login token",
                    RatCategory.BrowserTheft => "Looks for browser passwords or cookies",
                    RatCategory.WalletTheft => "Looks for crypto wallets",
                    _ => "Looks for other apps' logins",
                }, $"Points at {what}. Minecraft mods never need this.", s, where);

        if (Ioc.TokenPattern.IsMatch(s))
            sign(Severity.High, RatCategory.DiscordTheft, "Contains a Discord token pattern", "A search pattern shaped exactly like a Discord login token. Used to pick tokens out of Discord's files.", s, where);
        if (Ioc.WalletPattern.IsMatch(s))
            sign(Severity.Medium, RatCategory.WalletTheft, "Recognises crypto wallet addresses", "A pattern for Bitcoin/Ethereum addresses — used by \"clippers\" that swap a copied address for the attacker's.", s, where);

        foreach (var (needle, what) in Ioc.AnalysisTools)
            if (s.Contains(needle, StringComparison.OrdinalIgnoreCase) && s.Length < 200)
                sign(Severity.Low, RatCategory.AntiAnalysis, "Checks for analysis tools or virtual machines", $"Mentions {what}. Malware looks for these to stay quiet while being examined. Some cheat clients check for them too, so on its own this proves little.", s, where);

        foreach (var lookup in Ioc.IpLookups)
            if (s.Contains(lookup, StringComparison.OrdinalIgnoreCase))
                sign(Severity.Low, RatCategory.Spying, "Looks up your public IP address", $"{lookup} returns the public IP of whoever runs the mod. Stealers send this along with the stolen data.", s, where);

        foreach (var bin in Ioc.LolBins)
            if (s.Contains(bin, StringComparison.OrdinalIgnoreCase))
                sign(Severity.Medium, RatCategory.RunsPrograms, "Uses a Windows tool favoured by malware", $"{bin.Split(' ')[0]} is a built-in Windows program that malware uses to download or run code without its own files. Some self-updating mods use it to swap their jar; check what the command does.", s, where);
        if (s.Contains(Ioc.PowerShell, StringComparison.OrdinalIgnoreCase) && Ioc.PsHidden.IsMatch(s))
            sign(Severity.Medium, RatCategory.RunsPrograms, "Runs hidden or downloaded PowerShell", "A PowerShell command that is hidden, encoded, or downloads and runs something. Some self-updating mods run a hidden script to replace their jar; check what the command does.", s, where);
        if (ContainsAny(s, Ioc.DefenderOff))
            sign(Severity.High, RatCategory.Persistence, "Tries to switch off Windows Defender", "Adds Defender exclusions or turns protection off so its other parts aren't caught.", s, where);

        if (ContainsAny(s, Ioc.StartupFolder))
            sign(Severity.Medium, RatCategory.Persistence, "Puts something in the Startup folder", "Files there start every time you log in — how malware survives a restart.", s, where);
        if (s.Contains(Ioc.RunKey, StringComparison.OrdinalIgnoreCase))
            sign(Severity.Medium, RatCategory.Persistence, "Uses the Windows auto-start registry key", "Programs listed there start with Windows — how malware survives a restart.", s, where);
        if (Ioc.ScheduledTask.IsMatch(s))
            sign(Severity.Medium, RatCategory.Persistence, "Creates a scheduled task", "Scheduled tasks can start a program on a timer or at login — a common way to stay on the PC.", s, where);
        if (ContainsAny(s, Ioc.UnixAutostart))
            sign(Severity.Medium, RatCategory.Persistence, "Sets itself to start automatically (Linux/macOS)", "Writes a login service so it keeps running after a restart.", s, where);

        foreach (var o in Ioc.Obfuscators)
            if (s.Contains(o, StringComparison.OrdinalIgnoreCase))
                sign(Severity.Low, RatCategory.Obfuscation, "Code is obfuscated", $"Made with {o}, which scrambles code so it is hard to read. Paid and cheat clients often do this legitimately, but it also means this scan can see less.", o, where);
        if (s.Length > 4000 && Regex.IsMatch(s, @"^[A-Za-z0-9+/=]+$"))
            sign(Severity.Low, RatCategory.Obfuscation, "Large block of encoded data", "A long Base64 block can hide a whole program or class. Check what it decodes to.", s, where);
    }

    static bool IsPublicIp(string ip)
    {
        var parts = ip.Split('.').Select(p => int.TryParse(p, out int n) ? n : 999).ToArray();
        if (parts.Any(p => p > 255)) return false;
        return parts[0] switch
        {
            0 or 10 or 127 => false,
            169 when parts[1] == 254 => false,
            172 when parts[1] is >= 16 and <= 31 => false,
            192 when parts[1] == 168 => false,
            >= 224 => false,
            _ => true,
        };
    }

    // ---- code references ------------------------------------------------------------------------

    static void RefRules(RatContent c, SignFn sign)
    {
        // Native/P-Invoke import names arrive as strings or refs; treat exact names as references.
        var names = new HashSet<string>(c.Refs.Keys, StringComparer.OrdinalIgnoreCase);
        var whereOf = new Dictionary<string, string>(c.Refs, StringComparer.OrdinalIgnoreCase);
        foreach (var (text, where) in c.Strings)
            if (text.Length < 40 && Regex.IsMatch(text, @"^[A-Za-z_][A-Za-z0-9_]+$") && names.Add(text)) whereOf[text] = where;

        (string Name, string Where)? Find(IEnumerable<string> list)
        {
            foreach (var r in list)
                foreach (var n in names)
                    if (n.Equals(r, StringComparison.OrdinalIgnoreCase) || n.StartsWith(r + ".", StringComparison.OrdinalIgnoreCase) || r.StartsWith('.') && n.EndsWith(r, StringComparison.Ordinal))
                        return (n, whereOf[n]);
            return null;
        }

        foreach (var (r, what) in Ioc.SessionToken)
            if (Find([r]) is { } hit)
                sign(Severity.Low, RatCategory.AccountTheft, "Reads your Minecraft login token", $"Calls {what}. The token is the password-equivalent of your account. Many mods use it to talk to Mojang (account switchers, skin uploads, server auth); it is only dangerous if the mod can also send it somewhere anonymous.", hit.Name, hit.Where);

        if (Find(Ioc.Keylogging) is { } key)
            sign(Severity.Low, RatCategory.Spying, "Can record key presses outside the game", $"Uses {key.Name}, which reads the keyboard directly. Input and windowing libraries use it; keyloggers do too.", key.Name, key.Where);
        if (Find(Ioc.ScreenCapture) is { } screen)
            sign(Severity.Low, RatCategory.Spying, "Takes screenshots of the whole screen", $"Uses {screen.Name}, which captures the desktop, not just the game.", screen.Name, screen.Where);
        if (Find(Ioc.ClipboardRead) is { } clip)
            sign(Severity.Low, RatCategory.Spying, "Reads the clipboard", "Common in normal mods (paste support). Matters only together with wallet patterns or a way to send data out.", clip.Name, clip.Where);
        if (Find(Ioc.Dpapi) is { } dpapi)
            sign(Severity.Low, RatCategory.BrowserTheft, "Decrypts Windows-protected data", "Browsers and Discord protect saved passwords and tokens with this. Many programs use it for their own settings, so it matters together with browser or Discord paths.", dpapi.Name, dpapi.Where);

        var net = Find(Ioc.NetworkRefs);
        if (net is { } n0) sign(Severity.Low, RatCategory.Network, "Can connect to the internet", "Most mods with update checkers or online features do. Shown for context.", n0.Name, n0.Where);
        if (Find(Ioc.ClassLoading) is { } load)
            sign(Severity.Low, RatCategory.RemoteCode, "Loads code at runtime", net != null
                ? "Builds or loads Java/.NET code while running, and can reach the internet. Some legit loaders (Essential, library downloaders) do this; it's dangerous only together with an anonymous server or upload service."
                : "Builds or loads code while running. Libraries such as Mixin and Kotlin do this too.", load.Name, load.Where);
        if (Find(Ioc.ProcessRefs) is { } proc)
            sign(Severity.Low, RatCategory.RunsPrograms, "Can start other programs", "Mods do this to open links or folders. Dangerous only together with hidden PowerShell/commands or downloaded files.", proc.Name, proc.Where);
    }

    // ---- archive entries ------------------------------------------------------------------------

    static readonly HashSet<string> RiskyEmbedded = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".hta", ".lnk", ".msi", ".com", ".pif" };
    static readonly HashSet<string> NativeLibs = new(StringComparer.OrdinalIgnoreCase) { ".dll", ".so", ".dylib", ".jnilib" };

    static void EntryRules(RatContent c, SignFn sign)
    {
        foreach (var (name, head, where) in c.Entries)
        {
            string ext = Path.GetExtension(name);
            bool pe = head.Length > 1 && head[0] == 'M' && head[1] == 'Z';
            bool cls = head.Length > 3 && head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE;
            if (RiskyEmbedded.Contains(ext))
                sign(Severity.Medium, RatCategory.Embedded, "Carries a Windows program or script", $"A {ext} file packed inside. Mods don't ship programs; droppers carry their next stage this way.", name, where);
            else if (pe && !NativeLibs.Contains(ext) && !ext.Equals(".sys", StringComparison.OrdinalIgnoreCase))
                sign(Severity.Medium, RatCategory.Embedded, "Program disguised as another file", $"A Windows program named \"{Path.GetFileName(name)}\" — the extension hides what it is.", name, where);
            else if (pe && NativeLibs.Contains(ext))
                sign(Severity.Low, RatCategory.Embedded, "Carries a native library", "Some mods need these (Discord Rich Presence, hotkeys, audio). Its strings were scanned too.", name, where);
            if (cls && !ext.Equals(".class", StringComparison.OrdinalIgnoreCase))
                sign(Severity.Low, RatCategory.Embedded, "Java code stored under another name", $"Compiled Java code named \"{Path.GetFileName(name)}\". Some libraries do this (Kotlin's DebugProbesKt.bin); loaders also hide code this way. Its code was scanned like any other class.", name, where);
        }

        foreach (var (what, where) in c.HiddenPayloads)
            sign(what == "a zip / jar archive" ? Severity.Medium : Severity.High, RatCategory.Embedded, "File hidden inside an image",
                $"An image in this file has {what} appended after the end of the picture. The picture still opens normally, so the payload " +
                "goes unnoticed; loaders unpack their real code from such images. Its contents were scanned too.", what, where);
        foreach (var (name, where) in c.Packers.DistinctBy(p => p.Name))
            sign(Severity.Low, RatCategory.Obfuscation, "Packed with a protector",
                $"Protected with {name}, which encrypts the program's code. Paid software and cheats use it; it also means this scan sees only part of the file.",
                name, where);

        foreach (var key in new[] { "Premain-Class", "Agent-Class", "Launcher-Agent-Class" })
            if (c.Manifest.TryGetValue(key, out var v))
                sign(Severity.Low, RatCategory.RemoteCode, "Can attach to Java as an agent", $"{key} lets the jar change any class in the game or launcher. Unusual for a mod; profilers and some clients use it.", $"{key}: {v}", "META-INF/MANIFEST.MF");
    }

    // ---- combinations ---------------------------------------------------------------------------

    static readonly HashSet<RatCategory> Collects = [RatCategory.AccountTheft, RatCategory.DiscordTheft, RatCategory.BrowserTheft, RatCategory.WalletTheft, RatCategory.AppTheft, RatCategory.Spying];

    /// <summary>Signs too common in normal mods to complete a "steals and sends" pairing.</summary>
    static readonly HashSet<string> WeakCollect = ["Reads the clipboard", "Mentions another launcher's folder", "Decrypts Windows-protected data", "Looks up your public IP address"];

    static void Combine(List<RatSign> signs, SignFn sign)
    {
        var stolen = signs.Where(s => Collects.Contains(s.Category) && !WeakCollect.Contains(s.Title)).ToList();
        // Only a real anonymous channel completes a pairing: paste/upload hosts are used by crash uploaders,
        // and a bare ip:port may be a Minecraft server address.
        var sends = signs.Where(s => s.Category == RatCategory.Exfiltration && s.Severity >= Severity.Medium && s.Title != "Contains a raw IP address and port").ToList();
        if (stolen.Count > 0 && sends.Count > 0)
            sign(Severity.High, RatCategory.Exfiltration, "Collects private data and can send it out",
                $"It reaches for {string.Join(", ", stolen.Select(s => RatDisplay.Category(s.Category)).Distinct())} and also has an anonymous way to send data. That pairing is what a stealer is. Both signs are listed separately with their evidence.",
                $"{stolen[0].Title}  +  {sends[0].Title}", "whole file");

        var loads = signs.FirstOrDefault(s => s.Category == RatCategory.RemoteCode && s.Title == "Loads code at runtime");
        var drop = sends.FirstOrDefault(s => s.Title == "Connects to a raw IP address");
        if (loads != null && drop != null)
            sign(Severity.High, RatCategory.RemoteCode, "Downloads code from an anonymous server and runs it",
                "It can load code at runtime and connects to a bare IP address. That is how multi-stage loaders (like Fractureiser) fetch the real malware.",
                $"{loads.Evidence}  +  {drop.Evidence}", "whole file"); // both short: a method name and the address itself
    }

    // ---- helpers --------------------------------------------------------------------------------

    static readonly Regex Base64 = new(@"^[A-Za-z0-9+/]{20,}={0,2}$", RegexOptions.Compiled);

    internal static string? DecodeBase64(string s)
    {
        if (s.Length < 20 || s.Length > 100_000 || s.Length % 4 != 0 || !Base64.IsMatch(s)) return null;
        try
        {
            var bytes = Convert.FromBase64String(s);
            int printable = bytes.Count(b => b is >= 0x20 and < 0x7F or (byte)'\n' or (byte)'\r' or (byte)'\t');
            return printable >= bytes.Length * 0.95 ? Encoding.ASCII.GetString(bytes) : null;
        }
        catch (FormatException) { return null; }
    }

    /// <summary>True when <paramref name="part"/> is a whole folder name in a path ("…\PrismLauncher\…"), not part of a word like "BlockLightLauncher".</summary>
    internal static bool IsPathPart(string s, string part)
    {
        for (int i = s.IndexOf(part, StringComparison.OrdinalIgnoreCase); i >= 0; i = s.IndexOf(part, i + 1, StringComparison.OrdinalIgnoreCase))
        {
            int end = i + part.Length;
            bool before = i > 0 && s[i - 1] is '\\' or '/', after = end < s.Length && s[end] is '\\' or '/';
            if (before && after || before && end == s.Length) return true;
        }
        return false;
    }

    static bool ContainsAny(string s, string[] needles) => needles.Any(n => s.Contains(n, StringComparison.OrdinalIgnoreCase));

    /// <summary>Indicators that are a single identifier ("encrypted_key").</summary>
    static readonly Regex IdentifierNeedle = new(@"^[a-z][a-z0-9_]*$", RegexOptions.Compiled);

    /// <summary>
    /// The identifier as a word of its own, case-insensitively: "encrypted_key" in Chrome's Local State, not the crypto
    /// constant CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM that every .NET single-file program carries.
    /// </summary>
    internal static bool ContainsWord(string s, string word)
    {
        for (int i = s.IndexOf(word, StringComparison.OrdinalIgnoreCase); i >= 0; i = s.IndexOf(word, i + 1, StringComparison.OrdinalIgnoreCase))
        {
            int end = i + word.Length;
            bool before = i > 0 && (char.IsLetterOrDigit(s[i - 1]) || s[i - 1] == '_');
            bool after = end < s.Length && (char.IsLetterOrDigit(s[end]) || s[end] == '_');
            if (!before && !after) return true;
        }
        return false;
    }

    static string Trim(string s) => s.Length > 300 ? s[..300] + "…" : s;
}
