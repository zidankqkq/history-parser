using System.Text;

namespace HistoryParser.Core.Util;

public static class FileTime
{
    static readonly long Min = new DateTime(1990, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
    static readonly long Max = new DateTime(2200, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

    /// <summary>FILETIME to UTC, or null for zero/garbage values.</summary>
    public static DateTime? ToUtc(long fileTime) =>
        fileTime < Min || fileTime > Max ? null : DateTime.FromFileTimeUtc(fileTime);
}

public static class Rot13
{
    public static string Decode(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c is >= 'a' and <= 'z') chars[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c is >= 'A' and <= 'Z') chars[i] = (char)('A' + (c - 'A' + 13) % 26);
        }
        return new string(chars);
    }
}

public static class TextDecoding
{
    /// <summary>Decodes text that may be UTF-16LE (with or without BOM) or UTF-8.</summary>
    public static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);

        // No BOM: UTF-16LE text of ASCII-range characters has a zero in nearly every odd byte.
        int sample = Math.Min(bytes.Length, 512) & ~1, oddZeros = 0;
        for (int i = 1; i < sample; i += 2) if (bytes[i] == 0) oddZeros++;
        return sample > 0 && oddZeros > sample / 4
            ? Encoding.Unicode.GetString(bytes)
            : Encoding.UTF8.GetString(bytes);
    }
}

internal static class SafeFile
{
    /// <summary>Reads a file without blocking the writer (Windows keeps some artifacts open).</summary>
    public static byte[] ReadAllBytesShared(string path, int maxBytes = 64 * 1024 * 1024)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (fs.Length > maxBytes) throw new InvalidDataException($"{path} is larger than {maxBytes} bytes.");
        var buffer = new byte[fs.Length];
        fs.ReadExactly(buffer);
        return buffer;
    }
}

public static class FileTypes
{
    public static Models.FileType FromPath(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".exe" or ".com" or ".scr" => Models.FileType.Exe,
        ".dll" or ".sys" => Models.FileType.Dll,
        ".jar" => Models.FileType.Jar,
        ".bat" or ".cmd" or ".ps1" or ".vbs" or ".js" or ".jse" or ".wsf" or ".hta" or ".ahk" or ".py" or ".pyw" => Models.FileType.Script,
        _ => Models.FileType.Other,
    };

    /// <summary>Names Java code legitimately travels under (old mods were .zip, LiteLoader mods .litemod).</summary>
    public static bool IsJavaContainerName(string path) =>
        Path.GetExtension(path).ToLowerInvariant() is ".jar" or ".zip" or ".litemod" or ".jmod" or ".war" or ".ear";

    /// <summary>
    /// True when the file holds compiled Java classes whatever its name says. Java finds a jar's contents from the end
    /// of the file, so a picture with a jar appended still runs; this reads it the same way.
    /// </summary>
    public static bool IsJavaArchive(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < 22 || fs.Length > 512L * 1024 * 1024) return false;
            // The end record is in the last 64 KB + 22 bytes (its comment is at most 64 KB).
            int tailLength = (int)Math.Min(fs.Length, 65_557);
            var tail = new byte[tailLength];
            fs.Seek(-tailLength, SeekOrigin.End);
            fs.ReadExactly(tail);
            int end = -1;
            for (int i = tailLength - 22; i >= 0; i--)
                if (BitConverter.ToUInt32(tail, i) == 0x06054B50) { end = i; break; }
            if (end < 0) return false;
            uint directorySize = BitConverter.ToUInt32(tail, end + 12);
            // Like Java, place the central directory just before the end record, wherever the file says it starts:
            // anything put in front of the archive (a picture) shifts it, and that must not hide it.
            long endAt = fs.Length - tailLength + end, start = endAt - directorySize;
            if (directorySize == 0 || directorySize > 64L * 1024 * 1024 || start < 0) return false;
            var dir = new byte[directorySize];
            fs.Seek(start, SeekOrigin.Begin);
            fs.ReadExactly(dir);
            for (int p = 0, n = 0; p + 46 <= dir.Length && n < 50_000; n++)
            {
                if (BitConverter.ToUInt32(dir, p) != 0x02014B50) return false;
                int nameLength = BitConverter.ToUInt16(dir, p + 28), extra = BitConverter.ToUInt16(dir, p + 30), comment = BitConverter.ToUInt16(dir, p + 32);
                if (p + 46 + nameLength > dir.Length) return false;
                if (nameLength > 6 && IsCode(Encoding.UTF8.GetString(dir, p + 46, nameLength))) return true;
                p += 46 + nameLength + extra + comment;
            }
            return false;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or EndOfStreamException)
        {
            return false;
        }

        // Compiled classes, or jars nested the way Fabric (META-INF/jars) and Forge (META-INF/jarjar) bundle them.
        static bool IsCode(string name) =>
            name.EndsWith(".class", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) &&
            (name.StartsWith("META-INF/jars/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("META-INF/jarjar/", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Extensions that say "not code": a jar renamed to one of these is hiding.</summary>
    public static bool LooksHarmless(string path) =>
        Path.GetExtension(path).ToLowerInvariant() is ".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp" or ".ico" or ".webp" or ".txt" or ".log"
            or ".ini" or ".cfg" or ".json" or ".xml" or ".pdf" or ".doc" or ".docx" or ".mp3" or ".mp4" or ".wav" or ".ogg" or ".exe" or ".dll";

    public static bool IsInteresting(ReadOnlySpan<char> name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".ahk", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Files Windows uses as evidence of activity: event logs, Amcache/registry hives, recent-item
    /// shortcuts and jump lists, shell history, PCA logs, SRUM, and the files Java creates when a tool
    /// attaches to a running JVM. Deleting or rewriting them is a classic bypass.
    /// </summary>
    public static bool IsArtifact(ReadOnlySpan<char> name) =>
        name.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".hve", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".customDestinations-ms", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("_history.txt", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("PcaAppLaunchDic", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("PcaGeneralDb", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("SRUDB.dat", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith(".attach_pid", StringComparison.OrdinalIgnoreCase);

    static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    /// <summary>Files shipped with Windows; hidden by default in the UI to cut noise.</summary>
    public static bool IsWindowsFile(string path) =>
        path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);

    // Inno Setup (is-XXXX.tmp), NSIS (nsXXXX.tmp), 7-Zip SFX (7zSXXXX) and WiX Burn ({GUID}\.be / .cr) unpack folders.
    static readonly System.Text.RegularExpressions.Regex InstallerFolder = new(
        @"\\Temp\\(is-[^\\]+\.tmp|ns[a-z][^\\]*\.tmp|7z[SO][^\\]+|\{[0-9A-F-]{36}\}\\\.(be|cr))\\",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    static readonly System.Text.RegularExpressions.Regex InstallerName = new(
        @"(^|[-_. ])(setup|install|installer|uninstall|unins\d*|update|updater|vc_?redist|redist)([-_. ]|\.exe$)|^dotnet-.*\.exe$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// An installer's or updater's own helper in Temp. Being in Temp alone proves nothing — cheats run from there
    /// too — so only files that look like installer parts get the "installers do this all the time" allowance.
    /// </summary>
    public static bool IsInstallerTemp(string path) =>
        path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) &&
        (InstallerFolder.IsMatch(path) || InstallerName.IsMatch(Path.GetFileName(path)));

    // The exact names Windows gives the temporary copy while it saves a file: ReplaceFile's "<name>~RF<hex>.TMP", and
    // the 20-character uppercase ".temp" name Explorer writes before swapping a jump list into CustomDestinations.
    static readonly System.Text.RegularExpressions.Regex ReplaceFileCopy = new(@"~RF[0-9a-f]+\.TMP$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    static readonly System.Text.RegularExpressions.Regex JumpListCopy = new(@"^[A-Z0-9]{20}\.temp$",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Whether <paramref name="copy"/> is the temporary copy Windows uses while saving <paramref name="target"/>:
    /// one of Windows' exact naming patterns, in the same folder as the file being saved. A name like "loader.tmp", or a
    /// .tmp somewhere else, does not qualify.
    /// </summary>
    public static bool IsWindowsSaveCopy(string copy, string target)
    {
        if (!string.Equals(Path.GetDirectoryName(copy), Path.GetDirectoryName(target), StringComparison.OrdinalIgnoreCase)) return false;
        string name = Path.GetFileName(copy);
        return ReplaceFileCopy.IsMatch(name) && name.StartsWith(Path.GetFileName(target), StringComparison.OrdinalIgnoreCase) ||
               JumpListCopy.IsMatch(name) && target.Contains(@"\CustomDestinations\", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// How times are written inside findings and checks: the scanned PC's local time, the same clock the tables
/// show, so a finding never shows two different times for one event.
/// </summary>
public static class When
{
    public static string L(DateTime? utc) =>
        utc is { } t ? t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) : "unknown time";
}
