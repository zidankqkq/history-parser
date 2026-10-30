using System.Text;
using System.Text.RegularExpressions;
using HistoryParser.Core.Models;

namespace RatChecker.Core;

/// <summary>
/// The indicator list: names, paths, addresses and patterns that stealers use.
/// Each value is stored Base64-encoded with its plain text in a comment beside it. Stored as plain text, these are
/// exactly the strings antivirus looks for in stealers, and Windows Defender quarantined the checker itself as a
/// trojan. Encoding only the data stops that; the logic in RatScanner stays plain, readable code.
/// To add one: [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('value')) and keep the comment.
/// </summary>
internal static class Ioc
{
    static string D(string b64) => Encoding.UTF8.GetString(Convert.FromBase64String(b64));
    static Regex R(string b64, RegexOptions extra = RegexOptions.None) => new(D(b64), RegexOptions.Compiled | RegexOptions.CultureInvariant | extra);

    public static readonly Regex WebhookFull = R("ZGlzY29yZCg/OmFwcCk/XC5jb20vYXBpLyg/OnZcZCsvKT93ZWJob29rcy9cZHsxNSwyMH0vW1x3LV17NTAsfQ==" /* discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d{15,20}/[\w-]{50,} */, RegexOptions.IgnoreCase);
    public static readonly Regex WebhookAny = R("ZGlzY29yZCg/OmFwcCk/XC5jb20vYXBpLyg/OnZcZCsvKT93ZWJob29rcw==" /* discord(?:app)?\.com/api/(?:v\d+/)?webhooks */, RegexOptions.IgnoreCase);
    public static readonly Regex TelegramFull = R("YXBpXC50ZWxlZ3JhbVwub3JnL2JvdFxkezYsMTJ9Oltcdy1dezMwLH0=" /* api\.telegram\.org/bot\d{6,12}:[\w-]{30,} */, RegexOptions.IgnoreCase);
    public static readonly Regex TelegramAny = R("YXBpXC50ZWxlZ3JhbVwub3JnL2JvdA==" /* api\.telegram\.org/bot */, RegexOptions.IgnoreCase);
    public static readonly Regex SlackFull = R("aG9va3NcLnNsYWNrXC5jb20vc2VydmljZXMvVFtBLVowLTldezYsfS9CW0EtWjAtOV17Nix9L1tBLVphLXowLTldezIwLH0=" /* hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,} */);
    public static readonly Regex SlackAny = R("aG9va3NcLnNsYWNrXC5jb20vc2VydmljZXM=" /* hooks\.slack\.com/services */, RegexOptions.IgnoreCase);
    /// <summary>A Discord bot token (base64 user id . timestamp . HMAC), which lets the file post as a bot.</summary>
    public static readonly Regex BotToken = R("KD88IVtcdy1dKVtNTk9dW0EtWmEtelxkXy1dezIzLDI3fVwuW0EtWmEtelxkXy1dezZ9XC5bQS1aYS16XGRfLV17MjcsMzh9KD8hW1x3LV0p" /* (?<![\w-])[MNO][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}(?![\w-]) */);
    public static readonly Regex BotApi = R("ZGlzY29yZCg/OmFwcCk/XC5jb20vYXBpLyg/OnZcZCsvKT9jaGFubmVscy9cZHsxNSwyMH0vbWVzc2FnZXM=" /* discord(?:app)?\.com/api/(?:v\d+/)?channels/\d{15,20}/messages */, RegexOptions.IgnoreCase);
    /// <summary>Paid-loader licensing services.</summary>
    public static readonly string[] Licensing = [D("a2V5YXV0aC53aW4=") /* keyauth.win */, D("S2V5QXV0aEFwcA==") /* KeyAuthApp */, D("a2V5YXV0aC5jYw==") /* keyauth.cc */];
    /// <summary>A search pattern for Discord tokens written inside the file.</summary>
    public static readonly Regex TokenPattern = R("XFtcXHctXF1cezJbNC02XVx9fFx7MjRcfVxcXC58bWZhXFxcLlxb" /* \[\\w-\]\{2[4-6]\}|\{24\}\\\.|mfa\\\.\[ */);
    /// <summary>A search pattern for Bitcoin/Ethereum addresses written inside the file.</summary>
    public static readonly Regex WalletPattern = R("XChiYzFcfHxcWzEzXF1cW2Eta20tekEtSEotTlAtWjEtOVxdfDB4XFthLWZBLUYwLTlcXVx7NDBcfQ==" /* \(bc1\||\[13\]\[a-km-zA-HJ-NP-Z1-9\]|0x\[a-fA-F0-9\]\{40\} */);

    /// <summary>Upload / paste / tunnel / request-catcher services.</summary>
    public static readonly string[] DropHosts =
    [
        D("cGFzdGViaW4uY29tL3Jhdw==") /* pastebin.com/raw */, D("aGFzdGViaW4uY29t") /* hastebin.com */, D("aHN0LnNo") /* hst.sh */, D("cmVudHJ5LmNv") /* rentry.co */, D("cmVudHJ5Lm9yZw==") /* rentry.org */, D("cGFzdGUuZWU=") /* paste.ee */, D("Z2hvc3RiaW4=") /* ghostbin */, D("cGFzdGVzLmRldg==") /* pastes.dev */, D("Y29udHJvbGMuY29t") /* controlc.com */,
        D("Z29maWxlLmlv") /* gofile.io */, D("dHJhbnNmZXIuc2g=") /* transfer.sh */, D("ZmlsZS5pbw==") /* file.io */, D("Y2F0Ym94Lm1vZQ==") /* catbox.moe */, D("bGl0dGVyYm94") /* litterbox */, D("YW5vbmZpbGVz") /* anonfiles */, D("YmFzaHVwbG9hZA==") /* bashupload */, D("dGVtcC5zaA==") /* temp.sh */, D("MHgwLnN0") /* 0x0.st */, D("dWd1dS5zZQ==") /* uguu.se */,
        D("bmdyb2suaW8=") /* ngrok.io */, D("bmdyb2stZnJlZS5hcHA=") /* ngrok-free.app */, D("bmdyb2suYXBw") /* ngrok.app */, D("dHJ5Y2xvdWRmbGFyZS5jb20=") /* trycloudflare.com */, D("c2VydmVvLm5ldA==") /* serveo.net */, D("bG9jYWx0dW5uZWw=") /* localtunnel */, D("cGxheWl0Lmdn") /* playit.gg */,
        D("d2ViaG9vay5zaXRl") /* webhook.site */, D("cmVxdWVzdGJpbg==") /* requestbin */, D("cGlwZWRyZWFtLm5ldA==") /* pipedream.net */, D("YmVlY2VwdG9y") /* beeceptor */, D("aW50ZXJhY3RzaA==") /* interactsh */, D("b2FzdC5mdW4=") /* oast.fun */, D("YnVycGNvbGxhYm9yYXRvcg==") /* burpcollaborator */, D("Y2FuYXJ5dG9rZW5z") /* canarytokens */,
    ];

    /// <summary>Exact login files of launchers and clients.</summary>
    public static readonly (string Needle, string What)[] AccountFiles =
    [
        (D("bGF1bmNoZXJfYWNjb3VudHM=") /* launcher_accounts */, "the official launcher's saved accounts"),
        (D("bGF1bmNoZXJfbXNhX2NyZWRlbnRpYWxz") /* launcher_msa_credentials */, "the official launcher's Microsoft login"),
        (D("bWljcm9zb2Z0X2FjY291bnRzLmpzb24=") /* microsoft_accounts.json */, "Essential's saved Microsoft accounts"),
        (D("VGxhdW5jaGVyUHJvZmlsZXM=") /* TlauncherProfiles */, "TLauncher's saved accounts"),
    ];

    public static readonly string[] LauncherFolders =
    [
        D("Lmx1bmFyY2xpZW50") /* .lunarclient */, D("QmFkbGlvbiBDbGllbnQ=") /* Badlion Client */, D("LmZlYXRoZXI=") /* .feather */, D("UHJpc21MYXVuY2hlcg==") /* PrismLauncher */, D("UG9seU1D") /* PolyMC */, D("TXVsdGlNQw==") /* MultiMC */, D("TW9kcmludGhBcHA=") /* ModrinthApp */, D("Y3Vyc2Vmb3JnZQ==") /* curseforge */,
        D("R0RMYXVuY2hlcg==") /* GDLauncher */, D("QVRMYXVuY2hlcg==") /* ATLauncher */, D("VExhdW5jaGVy") /* TLauncher */,
    ];

    /// <summary>File names that hold a launcher's logins.</summary>
    public static readonly string[] LoginFiles = [D("YWNjb3VudHMuanNvbg==") /* accounts.json */, D("YWNjb3VudHMuZGF0") /* accounts.dat */, D("c3RvcmFnZS5qc29u") /* storage.json */];

    public static readonly (string Needle, RatCategory Cat, Severity Sev, string What)[] OtherAppFiles =
    [
        (D("TG9jYWwgU3RvcmFnZVxsZXZlbGRi") /* Local Storage\leveldb */, RatCategory.DiscordTheft, Severity.Medium, "the browser/Discord storage where Discord keeps its login token"),
        (D("TG9jYWwgU3RvcmFnZS9sZXZlbGRi") /* Local Storage/leveldb */, RatCategory.DiscordTheft, Severity.Medium, "the browser/Discord storage where Discord keeps its login token"),
        (D("ZFF3NHc5V2dYY1E6") /* dQw4w9WgXcQ: */, RatCategory.DiscordTheft, Severity.High, "the marker Discord puts in front of its encrypted login token — only token stealers look for it"),
        (D("XExvZ2luIERhdGE=") /* \Login Data */, RatCategory.BrowserTheft, Severity.High, "the browser file that stores saved passwords"),
        (D("ZW5jcnlwdGVkX2tleQ==") /* encrypted_key */, RatCategory.BrowserTheft, Severity.Medium, "the key browsers use to encrypt saved passwords and cookies"),
        (D("bG9naW5zLmpzb24=") /* logins.json */, RatCategory.BrowserTheft, Severity.Medium, "Firefox's saved passwords"),
        (D("a2V5NC5kYg==") /* key4.db */, RatCategory.BrowserTheft, Severity.High, "Firefox's password key"),
        (D("XE5ldHdvcmtcQ29va2llcw==") /* \Network\Cookies */, RatCategory.BrowserTheft, Severity.High, "the browser's cookie file (logged-in sessions)"),
        (D("XFdlYiBEYXRh") /* \Web Data */, RatCategory.BrowserTheft, Severity.Medium, "the browser file with saved cards and autofill"),
        (D("d2FsbGV0LmRhdA==") /* wallet.dat */, RatCategory.WalletTheft, Severity.High, "a Bitcoin-style wallet file"),
        (D("ZXhvZHVzLndhbGxldA==") /* exodus.wallet */, RatCategory.WalletTheft, Severity.High, "the Exodus crypto wallet"),
        (D("RWxlY3RydW1cd2FsbGV0cw==") /* Electrum\wallets */, RatCategory.WalletTheft, Severity.High, "Electrum crypto wallets"),
        (D("RXRoZXJldW1ca2V5c3RvcmU=") /* Ethereum\keystore */, RatCategory.WalletTheft, Severity.High, "Ethereum wallet keys"),
        (D("bmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4=") /* nkbihfbeogaeaoehlefnkodbefgpgknn */, RatCategory.WalletTheft, Severity.High, "the MetaMask browser extension's storage"),
        (D("YmZuYWVsbW9tZWltaGxwbWdqbmpvcGhocGtrb2xqcGE=") /* bfnaelmomeimhlpmgjnjophhpkkoljpa */, RatCategory.WalletTheft, Severity.High, "the Phantom wallet extension's storage"),
        (D("YXRvbWljXExvY2FsIFN0b3JhZ2U=") /* atomic\Local Storage */, RatCategory.WalletTheft, Severity.High, "the Atomic crypto wallet"),
        (D("VGVsZWdyYW0gRGVza3RvcFx0ZGF0YQ==") /* Telegram Desktop\tdata */, RatCategory.AppTheft, Severity.High, "Telegram Desktop's login folder"),
        (D("bG9naW51c2Vycy52ZGY=") /* loginusers.vdf */, RatCategory.AppTheft, Severity.High, "Steam's saved logins"),
        (D("cmVjZW50c2VydmVycy54bWw=") /* recentservers.xml */, RatCategory.AppTheft, Severity.High, "FileZilla's saved server passwords"),
        (D("c2l0ZW1hbmFnZXIueG1s") /* sitemanager.xml */, RatCategory.AppTheft, Severity.High, "FileZilla's saved server passwords"),
        (D("Tm9yZFZQTg==") /* NordVPN */, RatCategory.AppTheft, Severity.Medium, "NordVPN's files"),
        (D("UHJvdG9uVlBO") /* ProtonVPN */, RatCategory.AppTheft, Severity.Medium, "ProtonVPN's files"),
        (D("T3BlblZQTiBDb25uZWN0XHByb2ZpbGVz") /* OpenVPN Connect\profiles */, RatCategory.AppTheft, Severity.High, "OpenVPN logins"),
    ];

    public static readonly (string Needle, string What)[] AnalysisTools =
    [
        (D("VkJveFNlcnZpY2U=") /* VBoxService */, "VirtualBox"), (D("dmJveHRyYXk=") /* vboxtray */, "VirtualBox"), (D("dm10b29sc2Q=") /* vmtoolsd */, "VMware"), (D("dm13YXJldHJheQ==") /* vmwaretray */, "VMware"), (D("VkJPWCBIQVJERElTSw==") /* VBOX HARDDISK */, "VirtualBox"),
        (D("d2lyZXNoYXJr") /* wireshark */, "Wireshark"), (D("ZmlkZGxlcg==") /* fiddler */, "Fiddler"), (D("aHR0cGRlYnVnZ2Vy") /* httpdebugger */, "HTTP Debugger"), (D("dGNwdmlldw==") /* tcpview */, "TCPView"), (D("cHJvY21vbg==") /* procmon */, "Process Monitor"),
        (D("eDY0ZGJn") /* x64dbg */, "x64dbg"), (D("b2xseWRiZw==") /* ollydbg */, "OllyDbg"), (D("ZG5zcHk=") /* dnspy */, "dnSpy"), (D("aWRhNjQ=") /* ida64 */, "IDA"), (D("c2FuZGJveGll") /* sandboxie */, "Sandboxie"), (D("U2JpZURsbA==") /* SbieDll */, "Sandboxie"),
        (D("cmVjYWY=") /* recaf */, "Recaf (Java decompiler)"), (D("amQtZ3Vp") /* jd-gui */, "JD-GUI (Java decompiler)"),
    ];

    public static readonly string[] IpLookups =
    [
        D("aXAtYXBpLmNvbQ==") /* ip-api.com */, D("aXBpbmZvLmlv") /* ipinfo.io */, D("YXBpLmlwaWZ5Lm9yZw==") /* api.ipify.org */, D("aWNhbmhhemlwLmNvbQ==") /* icanhazip.com */, D("Y2hlY2tpcC5hbWF6b25hd3MuY29t") /* checkip.amazonaws.com */, D("aXBhcGkuY28=") /* ipapi.co */, D("aWZjb25maWcubWU=") /* ifconfig.me */, D("bXlleHRlcm5hbGlwLmNvbQ==") /* myexternalip.com */, D("d3RmaXNteWlw") /* wtfismyip */,
    ];

    /// <summary>Built-in Windows programs malware uses to download or run code.</summary>
    public static readonly string[] LolBins =
    [
        D("bXNodGE=") /* mshta */, D("Y2VydHV0aWwgLXVybGNhY2hl") /* certutil -urlcache */, D("Y2VydHV0aWwuZXhlIC11cmxjYWNoZQ==") /* certutil.exe -urlcache */, D("Yml0c2FkbWluIC90cmFuc2Zlcg==") /* bitsadmin /transfer */, D("cmVnc3ZyMzIgL3MgL24gL3UgL2k6") /* regsvr32 /s /n /u /i: */, D("cnVuZGxsMzIgamF2YXNjcmlwdDo=") /* rundll32 javascript: */, D("d3NjcmlwdC5leGU=") /* wscript.exe */, D("Y3NjcmlwdC5leGU=") /* cscript.exe */,
    ];

    public static readonly string PowerShell = D("cG93ZXJzaGVsbA==") /* powershell */;
    public static readonly Regex PsHidden = R("LSg/OmV8ZW58ZW5jfGVuY29kZWRjb21tYW5kKVxzfC13KD86aW5kb3dzdHlsZSk/XHMraGlkZGVufERvd25sb2FkU3RyaW5nfEludm9rZS1XZWJSZXF1ZXN0fFxiaWV4XGI=" /* -(?:e|en|enc|encodedcommand)\s|-w(?:indowstyle)?\s+hidden|DownloadString|Invoke-WebRequest|\biex\b */, RegexOptions.IgnoreCase);
    public static readonly string[] DefenderOff = [D("QWRkLU1wUHJlZmVyZW5jZQ==") /* Add-MpPreference */, D("RXhjbHVzaW9uUGF0aA==") /* ExclusionPath */, D("RGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZw==") /* DisableRealtimeMonitoring */];
    public static readonly string[] StartupFolder = [D("U3RhcnQgTWVudVxQcm9ncmFtc1xTdGFydHVw") /* Start Menu\Programs\Startup */, D("U3RhcnQgTWVudS9Qcm9ncmFtcy9TdGFydHVw") /* Start Menu/Programs/Startup */];
    public static readonly string RunKey = D("Q3VycmVudFZlcnNpb25cUnVu") /* CurrentVersion\Run */;
    public static readonly Regex ScheduledTask = R("c2NodGFza3MoPzpcLmV4ZSk/XHMrL2NyZWF0ZQ==" /* schtasks(?:\.exe)?\s+/create */, RegexOptions.IgnoreCase);
    public static readonly string[] UnixAutostart = [D("Ly5jb25maWcvc3lzdGVtZC91c2Vy") /* /.config/systemd/user */, D("TGF1bmNoQWdlbnRz") /* LaunchAgents */];

    public static readonly string[] Obfuscators =
    [
        D("QUxMQVRPUkl4REVNTw==") /* ALLATORIxDEMO */, D("YWxsYXRvcmk=") /* allatori */, D("c2tpZGZ1c2NhdG9y") /* skidfuscator */, D("YnJhbmNobG9jaw==") /* branchlock */, D("U3RyaW5nZXIgSmF2YSBPYmZ1c2NhdG9y") /* Stringer Java Obfuscator */, D("emVsaXg=") /* zelix */, D("cGFyYW1vcnBoaXNt") /* paramorphism */, D("Q2Flc2l1bQ==") /* Caesium */,
        D("cmFkb24gb2JmdXNjYXRvcg==") /* radon obfuscator */, D("c3VwZXJibGF1YmVlcmU=") /* superblaubeere */, D("Ymluc2N1cmU=") /* binscure */,
    ];

    /// <summary>Fractureiser (2023): its servers, package names and dropped file.</summary>
    public static readonly string[] Fractureiser =
    [
        D("ODUuMjE3LjE0NC4xMzA=") /* 85.217.144.130 */, D("MTA3LjE4OS4zLjEwMQ==") /* 107.189.3.101 */, D("ZmlsZXMtOGllLnBhZ2VzLmRldg==") /* files-8ie.pages.dev */, D("c2t5cmFnZS5kZQ==") /* skyrage.de */, D("ZGV2L25la28vbmVrb2NsaWVudA==") /* dev/neko/nekoclient */, D("ZGV2L25la28vbmVrb2luamVjdG9y") /* dev/neko/nekoinjector */, D("bGliV2ViR0w2NC5qYXI=") /* libWebGL64.jar */,
    ];

    /// <summary>SHA-1 of published samples (Fractureiser stage 0, from the CurseForge/Prism advisories).</summary>
    public static readonly HashSet<string> KnownBadSha1 = new(StringComparer.OrdinalIgnoreCase) { D("ZGM0M2M0Njg1YzNmNDc4MDhhYzIwN2QxNjY3Y2MxZWI5MTViMmQ4Mg==") /* dc43c4685c3f47808ac207d1667cc1eb915b2d82 */ };

    /// <summary>Ways to read the Minecraft session token, in each mapping a mod can be compiled against.</summary>
    public static readonly (string Ref, string What)[] SessionToken =
    [
        (D("bmV0L21pbmVjcmFmdC9jbGFzc18zMjAubWV0aG9kXzE2NzQ=") /* net/minecraft/class_320.method_1674 */, "Fabric: Session.getAccessToken"),
        (D("bmV0L21pbmVjcmFmdC9jbGFzc18zMjAubWV0aG9kXzE2NzU=") /* net/minecraft/class_320.method_1675 */, "Fabric: Session.getSessionId (contains the token)"),
        (D("bmV0L21pbmVjcmFmdC9jbGFzc18zMjAuZmllbGRfMTk4Mw==") /* net/minecraft/class_320.field_1983 */, "Fabric: Session.accessToken"),
        (D("bmV0L21pbmVjcmFmdC9jbGllbnQvc2Vzc2lvbi9TZXNzaW9uLmdldEFjY2Vzc1Rva2Vu") /* net/minecraft/client/session/Session.getAccessToken */, "Session.getAccessToken"),
        (D("bmV0L21pbmVjcmFmdC9jbGllbnQvdXRpbC9TZXNzaW9uLmdldEFjY2Vzc1Rva2Vu") /* net/minecraft/client/util/Session.getAccessToken */, "Session.getAccessToken"),
        (D("bmV0L21pbmVjcmFmdC9jbGllbnQvVXNlci5nZXRBY2Nlc3NUb2tlbg==") /* net/minecraft/client/User.getAccessToken */, "User.getAccessToken"),
        (D("bmV0L21pbmVjcmFmdC9jbGllbnQvVXNlci5nZXRTZXNzaW9uSWQ=") /* net/minecraft/client/User.getSessionId */, "User.getSessionId"),
        (D("bmV0L21pbmVjcmFmdC91dGlsL1Nlc3Npb24uZ2V0VG9rZW4=") /* net/minecraft/util/Session.getToken */, "Session.getToken"),
        (D("bmV0L21pbmVjcmFmdC91dGlsL1Nlc3Npb24uZ2V0U2Vzc2lvbklE") /* net/minecraft/util/Session.getSessionID */, "Session.getSessionID"),
        (D("LmZ1bmNfMTQ4MjU0X2Q=") /* .func_148254_d */, "Forge 1.8–1.12: Session.getToken"),
        (D("LmZ1bmNfMTExMjg2X2I=") /* .func_111286_b */, "Forge 1.8–1.12: Session.getSessionID"),
        (D("LmZpZWxkXzE0ODI1OF9j") /* .field_148258_c */, "Forge 1.8–1.12: Session.token"),
    ];

    public static readonly string[] Keylogging = [D("R2V0QXN5bmNLZXlTdGF0ZQ==") /* GetAsyncKeyState */, D("U2V0V2luZG93c0hvb2tFeEE=") /* SetWindowsHookExA */, D("U2V0V2luZG93c0hvb2tFeFc=") /* SetWindowsHookExW */, D("R2V0S2V5Ym9hcmRTdGF0ZQ==") /* GetKeyboardState */];
    public static readonly string[] ScreenCapture = [D("amF2YS9hd3QvUm9ib3QuY3JlYXRlU2NyZWVuQ2FwdHVyZQ==") /* java/awt/Robot.createScreenCapture */, D("Qml0Qmx0") /* BitBlt */, D("U3lzdGVtLkRyYXdpbmcuR3JhcGhpY3MuQ29weUZyb21TY3JlZW4=") /* System.Drawing.Graphics.CopyFromScreen */];
    public static readonly string[] ClipboardRead =
    [
        D("amF2YS9hd3QvZGF0YXRyYW5zZmVyL0NsaXBib2FyZC5nZXRDb250ZW50cw==") /* java/awt/datatransfer/Clipboard.getContents */, D("amF2YS9hd3QvZGF0YXRyYW5zZmVyL0NsaXBib2FyZC5nZXREYXRh") /* java/awt/datatransfer/Clipboard.getData */, D("R2V0Q2xpcGJvYXJkRGF0YQ==") /* GetClipboardData */, D("U3lzdGVtLldpbmRvd3MuRm9ybXMuQ2xpcGJvYXJkLkdldFRleHQ=") /* System.Windows.Forms.Clipboard.GetText */,
    ];
    public static readonly string[] Dpapi =
    [
        D("Q3J5cHRVbnByb3RlY3REYXRh") /* CryptUnprotectData */, D("U3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5Qcm90ZWN0ZWREYXRhLlVucHJvdGVjdA==") /* System.Security.Cryptography.ProtectedData.Unprotect */, D("Y29tL3N1bi9qbmEvcGxhdGZvcm0vd2luMzIvQ3J5cHQzMlV0aWwuY3J5cHRVbnByb3RlY3REYXRh") /* com/sun/jna/platform/win32/Crypt32Util.cryptUnprotectData */,
    ];

    public static readonly string[] NetworkRefs =
    [
        D("amF2YS9uZXQvSHR0cFVSTENvbm5lY3Rpb24=") /* java/net/HttpURLConnection */, D("amF2YS9uZXQvVVJMLm9wZW5Db25uZWN0aW9u") /* java/net/URL.openConnection */, D("amF2YS9uZXQvVVJMLm9wZW5TdHJlYW0=") /* java/net/URL.openStream */, D("amF2YS9uZXQvU29ja2V0") /* java/net/Socket */, D("amF2YS9uZXQvaHR0cC9IdHRwQ2xpZW50") /* java/net/http/HttpClient */,
        D("b2todHRwMy9Pa0h0dHBDbGllbnQ=") /* okhttp3/OkHttpClient */, D("b3JnL2FwYWNoZS9odHRwL2NsaWVudA==") /* org/apache/http/client */, D("amF2YXgvbmV0L3NzbC9IdHRwc1VSTENvbm5lY3Rpb24=") /* javax/net/ssl/HttpsURLConnection */,
        D("U3lzdGVtLk5ldC5XZWJDbGllbnQ=") /* System.Net.WebClient */, D("U3lzdGVtLk5ldC5IdHRwLkh0dHBDbGllbnQ=") /* System.Net.Http.HttpClient */, D("U3lzdGVtLk5ldC5Tb2NrZXRzLlRjcENsaWVudA==") /* System.Net.Sockets.TcpClient */, D("U3lzdGVtLk5ldC5IdHRwV2ViUmVxdWVzdA==") /* System.Net.HttpWebRequest */,
        D("SW50ZXJuZXRPcGVuVXJsQQ==") /* InternetOpenUrlA */, D("SW50ZXJuZXRPcGVuVXJsVw==") /* InternetOpenUrlW */, D("VVJMRG93bmxvYWRUb0ZpbGVB") /* URLDownloadToFileA */, D("VVJMRG93bmxvYWRUb0ZpbGVX") /* URLDownloadToFileW */, D("V2luSHR0cE9wZW4=") /* WinHttpOpen */, D("SHR0cFNlbmRSZXF1ZXN0QQ==") /* HttpSendRequestA */, D("SHR0cFNlbmRSZXF1ZXN0Vw==") /* HttpSendRequestW */,
    ];

    public static readonly string[] ClassLoading =
    [
        D("amF2YS9uZXQvVVJMQ2xhc3NMb2FkZXIuPGluaXQ+") /* java/net/URLClassLoader.<init> */, D("amF2YS9sYW5nL0NsYXNzTG9hZGVyLmRlZmluZUNsYXNz") /* java/lang/ClassLoader.defineClass */, D("amF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cC5kZWZpbmVDbGFzcw==") /* java/lang/invoke/MethodHandles$Lookup.defineClass */,
        D("c3VuL21pc2MvVW5zYWZlLmRlZmluZUNsYXNz") /* sun/misc/Unsafe.defineClass */, D("c3VuL21pc2MvVW5zYWZlLmRlZmluZUFub255bW91c0NsYXNz") /* sun/misc/Unsafe.defineAnonymousClass */, D("amRrL2ludGVybmFsL21pc2MvVW5zYWZlLmRlZmluZUNsYXNz") /* jdk/internal/misc/Unsafe.defineClass */, D("amF2YS9zZWN1cml0eS9TZWN1cmVDbGFzc0xvYWRlci5kZWZpbmVDbGFzcw==") /* java/security/SecureClassLoader.defineClass */,
        D("U3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkuTG9hZA==") /* System.Reflection.Assembly.Load */,
    ];

    public static readonly string[] ProcessRefs =
    [
        D("amF2YS9sYW5nL1J1bnRpbWUuZXhlYw==") /* java/lang/Runtime.exec */, D("amF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyLjxpbml0Pg==") /* java/lang/ProcessBuilder.<init> */, D("amF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyLnN0YXJ0") /* java/lang/ProcessBuilder.start */, D("U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MuU3RhcnQ=") /* System.Diagnostics.Process.Start */,
        D("Q3JlYXRlUHJvY2Vzc0E=") /* CreateProcessA */, D("Q3JlYXRlUHJvY2Vzc1c=") /* CreateProcessW */, D("U2hlbGxFeGVjdXRlQQ==") /* ShellExecuteA */, D("U2hlbGxFeGVjdXRlVw==") /* ShellExecuteW */, D("V2luRXhlYw==") /* WinExec */,
    ];
}
