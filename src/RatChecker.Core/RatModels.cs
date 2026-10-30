using HistoryParser.Core.Models;

namespace RatChecker.Core;

/// <summary>What a warning sign is about.</summary>
public enum RatCategory
{
    KnownMalware,
    Exfiltration,
    AccountTheft,
    DiscordTheft,
    BrowserTheft,
    WalletTheft,
    AppTheft,
    RemoteCode,
    RunsPrograms,
    Persistence,
    Spying,
    AntiAnalysis,
    Network,
    Obfuscation,
    Embedded,
    CheatCombat,
    CheatMovement,
    CheatClicker,
    CheatInjector,
    CheatLoader,
    CheatStructure,
}

/// <summary>One warning sign: what was found, why it matters, the exact text, and where in the file.</summary>
public sealed record RatSign(Severity Severity, RatCategory Category, string Title, string Why, string Evidence, string Where);

public enum RatVerdict { Clean, Suspicious, Dangerous, Unreadable }

/// <summary>Everything found in one file (a jar's nested jars are scanned as part of it).</summary>
public sealed class RatFileReport
{
    public required string Path { get; init; }
    public string Name => System.IO.Path.GetFileName(Path);
    /// <summary>"Java mod / jar", ".NET program", "Windows program", "Script" …</summary>
    public string Kind { get; set; } = "File";
    public long Size { get; set; }
    public string? Sha256 { get; set; }
    public SignatureStatus Signature { get; set; } = SignatureStatus.NotApplicable;
    public string? Signer { get; set; }
    /// <summary>Mod name and version from fabric.mod.json / mods.toml / plugin.yml, when present.</summary>
    public string? ModInfo { get; set; }
    public List<RatSign> Signs { get; } = new();
    /// <summary>Context: nested jars scanned, packers found, limits hit.</summary>
    public List<string> Notes { get; } = new();
    public string? Error { get; set; }
    /// <summary>A listed file that is no longer on disk (from a path list): nothing could be read because it is gone.</summary>
    public bool Missing { get; init; }
    public int ItemsRead { get; set; }

    /// <summary>The stealer / RAT verdict. Cheat signs have their own verdict and never make a file "dangerous" as malware.</summary>
    public RatVerdict Verdict =>
        Error != null && Signs.Count == 0 ? RatVerdict.Unreadable :
        RatSigns.Any(s => s.Severity == Severity.High) ? RatVerdict.Dangerous :
        RatSigns.Any(s => s.Severity == Severity.Medium) ? RatVerdict.Suspicious : RatVerdict.Clean;

    public string VerdictText => Verdict switch
    {
        RatVerdict.Dangerous => "Strong signs of a stealer / RAT",
        RatVerdict.Suspicious => "Suspicious — check by hand",
        RatVerdict.Unreadable => Missing ? "File no longer exists" : "Could not be read",
        _ => "No signs found",
    };

    IEnumerable<RatSign> RatSigns => Signs.Where(s => !CheatScanner.IsCheat(s.Category));

    public CheatVerdict CheatVerdict =>
        Signs.Any(s => CheatScanner.IsCheat(s.Category) && s.Severity == Severity.High) ? CheatVerdict.Cheat :
        Signs.Any(s => CheatScanner.IsCheat(s.Category) && s.Severity == Severity.Medium) ? CheatVerdict.Possible : CheatVerdict.None;

    public string CheatVerdictText => CheatVerdict switch
    {
        CheatVerdict.Cheat => "Cheat code found",
        CheatVerdict.Possible => "Possible cheat — check by hand",
        _ => Error != null && Signs.Count == 0 ? (Missing ? "File no longer exists" : "Could not be read") : "No cheat code found",
    };
}

public enum CheatVerdict { None, Possible, Cheat }

public static class RatDisplay
{
    public static string Category(RatCategory c) => c switch
    {
        RatCategory.KnownMalware => "Known malware",
        RatCategory.Exfiltration => "Sends data out",
        RatCategory.AccountTheft => "Minecraft accounts",
        RatCategory.DiscordTheft => "Discord",
        RatCategory.BrowserTheft => "Browser passwords",
        RatCategory.WalletTheft => "Crypto wallets",
        RatCategory.AppTheft => "Other apps",
        RatCategory.RemoteCode => "Downloads & runs code",
        RatCategory.RunsPrograms => "Starts programs",
        RatCategory.Persistence => "Stays on the PC",
        RatCategory.Spying => "Spying",
        RatCategory.AntiAnalysis => "Hides from analysis",
        RatCategory.Network => "Network",
        RatCategory.Obfuscation => "Hidden code",
        RatCategory.Embedded => "Files inside",
        RatCategory.CheatCombat => "Cheat: combat",
        RatCategory.CheatMovement => "Cheat: movement",
        RatCategory.CheatClicker => "Cheat: autoclicker",
        RatCategory.CheatInjector => "Cheat: injection",
        RatCategory.CheatLoader => "Cheat: hidden loader",
        RatCategory.CheatStructure => "Cheat: structure",
        _ => c.ToString(),
    };
}
