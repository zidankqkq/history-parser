using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using HistoryParser.Core.Native;
using static HistoryParser.Core.Native.NativeMethods;

namespace RatChecker.Core;

public enum DiffKind { ClassName, Identifier, Text, WebAddress }

/// <summary>A string only the injected game holds.</summary>
/// <param name="Group">Its package (class names) or "" — strings of one package came in together.</param>
/// <param name="Verified">Searched for exactly as Client Parser searches: found in the injected game, not in the clean one.</param>
public sealed record DiffString(string Text, DiffKind Kind, int Score, string Group, int GroupSize, bool InCheatFile, bool Verified)
{
    /// <summary>Why it is or is not in the list, in plain words.</summary>
    public string Note { get; init; } = "";
}

public sealed class GameDiffResult
{
    public string Clean { get; set; } = "";
    public string Injected { get; set; } = "";
    public long CleanBytes { get; set; }
    public long InjectedBytes { get; set; }
    public int CleanStrings { get; set; }
    /// <summary>Strings only the injected game had on the first read.</summary>
    public int FirstDifference { get; set; }
    /// <summary>Of those, still only in the injected game after both games were read again.</summary>
    public int Stable { get; set; }
    public List<DiffString> Strings { get; } = new();
    /// <summary>The two games are not as identical as they should be; differences there show up as strings too.</summary>
    public List<string> Warnings { get; } = new();
    /// <summary>Other things only the injected game has: DLLs, Java agents, hand-mapped code, file paths.</summary>
    public List<string> Differences { get; } = new();
    public List<string> Notes { get; } = new();

    /// <summary>The strings to save for Client Parser: verified, strongest first.</summary>
    public IEnumerable<DiffString> List => Strings.Where(s => s.Verified);
}

/// <summary>
/// Finds cheat strings by comparing two copies of the same game left on the title screen: one clean, one with the client
/// injected. Everything both share is the game; what only the injected copy holds is the client. Every readable byte of
/// both games is read (heap, class data, loaded DLLs, mapped files), twice each, so strings that come and go (garbage,
/// timestamps, counters) are dropped and only what the client keeps loaded remains. The final list is then searched for
/// in both games exactly the way Client Parser searches, so a saved list finds nothing in the clean game. Read-only.
/// </summary>
public static class GameDiff
{
    const int MinString = 6, MinCandidate = 8, MaxCandidate = 300, MaxCandidates = 1_500_000;
    /// <summary>How many strings the saved list holds at most, and at most how many from one package.</summary>
    public const int ListSize = 250, PerGroup = 40;

    delegate void StringSink(ReadOnlySpan<byte> text, bool stored, ulong raw, ulong norm);

    sealed class Candidate(string text, ulong norm)
    {
        public string Text { get; } = text;
        public ulong Norm { get; } = norm;
        public bool Seen { get; set; }
    }

    public static GameDiffResult Compare(GameProcess clean, GameProcess injected, string? cheatFile, Action<string>? progress = null, CancellationToken ct = default)
    {
        if (clean.Pid == injected.Pid) throw new ArgumentException("Pick two different games: the clean one and the injected one.");
        var r = new GameDiffResult { Clean = clean.ToString(), Injected = injected.ToString() };
        progress?.Invoke("Comparing how the two games were started…");
        CompareSetup(clean.Pid, injected.Pid, r);

        // 1. Everything the clean game holds (by hash: millions of strings).
        var cleanRaw = new HashSet<ulong>();
        var cleanNorm = new HashSet<ulong>();
        r.CleanBytes = Read(clean.Pid, (text, _, raw, norm) =>
        {
            cleanRaw.Add(raw);
            cleanNorm.Add(norm);
        }, "the clean game (1 of 4)", progress, ct);
        r.CleanStrings = cleanRaw.Count;

        // 2. What only the injected game holds. Text with numbers in it ("[12:04:31] Loaded 812 recipes") is compared
        //    with its numbers blanked out, so times, counters and IDs are never a difference; class names are compared
        //    exactly (a client's a/b/C1 must not vanish because the game has an a/b/C2).
        var candidates = new Dictionary<ulong, Candidate>();
        var byNorm = new Dictionary<ulong, List<ulong>>();
        r.InjectedBytes = Read(injected.Pid, (text, stored, raw, norm) =>
        {
            if (cleanRaw.Contains(raw) || !LooksClassName(text) && cleanNorm.Contains(norm) || candidates.ContainsKey(raw)) return;
            // Only a properly stored string can be a candidate: pieces of strings left in freed memory differ between any
            // two processes and would look like a difference.
            if (!stored || candidates.Count >= MaxCandidates || !Worth(text)) return;
            candidates[raw] = new Candidate(Encoding.ASCII.GetString(text), norm);
            (byNorm.TryGetValue(norm, out var list) ? list : byNorm[norm] = new()).Add(raw);
        }, "the injected game (2 of 4)", progress, ct);
        r.FirstDifference = candidates.Count;
        if (candidates.Count >= MaxCandidates)
            r.Warnings.Add($"The games differ in more than {MaxCandidates:N0} strings - they are probably not the same version, mods or screen. Only the first ones were compared.");
        cleanRaw.Clear(); cleanNorm.Clear();

        // 3. Read both again: the clean game now may hold what it lacked a minute ago (then it is the game, not the
        //    client), and the injected game must still hold it (then it is loaded for good, not passing garbage).
        Read(clean.Pid, (text, _, raw, norm) =>
        {
            if (candidates.Remove(raw)) return;
            if (!LooksClassName(text) && byNorm.Remove(norm, out var list)) foreach (var k in list) candidates.Remove(k);
        }, "the clean game again (3 of 4)", progress, ct);
        Read(injected.Pid, (_, _, raw, _) =>
        {
            if (candidates.TryGetValue(raw, out var c)) c.Seen = true;
        }, "the injected game again (4 of 4)", progress, ct);
        var stable = candidates.Values.Where(c => c.Seen).Select(c => c.Text).ToList();
        r.Stable = stable.Count;

        // Code the clean game's own files define - its libraries and mods - is never the client, even when the clean game
        // had not loaded that class yet. (A client injected into one game is in neither game's files.)
        progress?.Invoke("Reading the clean game's own files…");
        var cleanJars = CheatStrings.GameJars(clean.Pid, r.Notes);
        var cleanCode = CheatStrings.ReadClean(cleanJars, null, null, out _, ct);
        var cleanPackages = cleanCode.Where(t => t.Contains('/') && !t.Contains(' ')).Select(t => t[..t.LastIndexOf('/')]).ToHashSet(StringComparer.Ordinal);
        int fromFiles = stable.RemoveAll(t => CheatStrings.NormalizeClassName(t.TrimEnd(';')) is { } c && (cleanCode.Contains(c) || cleanPackages.Contains(c[..c.LastIndexOf('/')])));
        if (fromFiles > 0) r.Notes.Add($"{fromFiles:N0} class name(s) were dropped because the clean game's own files ({cleanJars.Count:N0} jars) define them.");
        var injectedJars = CheatStrings.GameJars(injected.Pid, []).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // 4. What each string is, and what it is worth.
        HashSet<string>? fileStrings = null;
        if (cheatFile != null)
        {
            progress?.Invoke("Reading the cheat file…");
            var (classes, texts) = CheatStrings.FromContent(RatReader.Read(File.ReadAllBytes(cheatFile), System.IO.Path.GetFileName(cheatFile)));
            fileStrings = new HashSet<string>(classes.Concat(texts), StringComparer.Ordinal);
        }
        var rows = Classify(stable, fileStrings, r, injectedJars);

        // 5. Prove the best of them. Against the clean game: dropped if it is there anywhere, even inside longer text, and
        //    also if its core is (the string with a character or two cut from either end) - that is a piece of an ordinary
        //    string with stray bytes beside it, left in freed memory. Against the injected game: found exactly as Client
        //    Parser will search, as a whole string in any region, ASCII or UTF-16.
        var shortlist = Shortlist(rows, ListSize * 3);
        var cores = shortlist.SelectMany(s => Cores(s.Text).Select(c => (Core: c, s.Text))).ToList();
        progress?.Invoke("Checking the list against the clean game…");
        var inClean = new HashSet<string>(StringComparer.Ordinal);
        CheatStrings.ScanMemory(clean.Pid, cores.Select(c => c.Core).Distinct().ToList(), inClean, null, null, ct, allRegions: true, wholeStrings: false);
        var dropped = cores.Where(c => inClean.Contains(c.Core)).Select(c => c.Text).ToHashSet(StringComparer.Ordinal);
        progress?.Invoke("Checking the list against the injected game…");
        var inInjected = new HashSet<string>(StringComparer.Ordinal);
        CheatStrings.ScanMemory(injected.Pid, shortlist.Select(s => s.Text).ToList(), inInjected, null, null, ct, allRegions: true, wholeStrings: true);
        var verified = Shortlist(shortlist.Where(s => !dropped.Contains(s.Text) && inInjected.Contains(s.Text)), ListSize)
            .Select(s => s.Text).ToHashSet(StringComparer.Ordinal);
        var shortlisted = shortlist.Select(s => s.Text).ToHashSet(StringComparer.Ordinal);
        foreach (var row in rows.Where(x => !dropped.Contains(x.Text))
                     .OrderByDescending(x => verified.Contains(x.Text)).ThenByDescending(x => x.Score).ThenBy(x => x.Text, StringComparer.Ordinal))
            r.Strings.Add(row with
            {
                Verified = verified.Contains(row.Text),
                Note = verified.Contains(row.Text) ? "Proven: in the injected game, nowhere in the clean game"
                    : !shortlisted.Contains(row.Text) ? $"Below the cut: the list keeps the {ListSize} strongest - tick it to add it"
                    : !inInjected.Contains(row.Text) ? "Not found as a whole string on the final check (it sits inside longer text)"
                    : $"Below the cut: the list keeps the {ListSize} strongest - tick it to add it",
            });
        if (dropped.Count > 0)
            r.Notes.Add($"{dropped.Count:N0} candidate(s) were dropped because the clean game holds them, or their core, inside longer text (pieces of ordinary strings).");

        if (verified.Count == 0)
            r.Notes.Add(r.Differences.Count > 0
                ? "No usable strings, but the games differ in other ways (see above). Native clients keep their text encrypted; the DLL / hidden code is the evidence."
                : "Almost nothing differs between the two games. Check the cheat is really injected into the game picked as injected, that both are on the same screen, and try again.");
        return r;
    }

    // ---- reading memory -----------------------------------------------------------------------------

    /// <summary>
    /// Every string in every committed, readable region of the process — private memory (heap, class data), loaded
    /// modules and mapped files — as ASCII and UTF-16. Strings are cut at the length the JVM stores right before them
    /// (byte[] length for heap strings, the 2-byte length of class-name symbols), so neighbouring bytes never stick on.
    /// </summary>
    static long Read(int pid, StringSink sink, string what, Action<string>? progress, CancellationToken ct)
    {
        progress?.Invoke($"Reading {what}…");
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) throw new UnauthorizedAccessException($"The game's memory could not be opened (error {Marshal.GetLastWin32Error()}). Run as administrator, and check the game is still running.");
        const int Chunk = 16 << 20, Overlap = 4096;
        var buffer = new byte[Chunk];
        var wide = new byte[MaxCandidate * 4];
        long total = 0, lastReport = 0;
        IntPtr address = IntPtr.Zero;
        var mbiSize = (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        while (VirtualQueryEx(h, address, out var mbi, mbiSize) != UIntPtr.Zero)
        {
            ct.ThrowIfCancellationRequested();
            long size = (long)(ulong)mbi.RegionSize;
            // Readable: READONLY, READWRITE, WRITECOPY and their EXECUTE forms; never guard or no-access pages.
            if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xEE) != 0 && (mbi.Protect & PAGE_GUARD) == 0)
            {
                for (long offset = 0; offset < size; offset += Chunk - Overlap)
                {
                    int want = (int)Math.Min(Chunk, size - offset);
                    if (!ReadProcessMemory(h, mbi.BaseAddress + (nint)offset, buffer, (UIntPtr)want, out var got)) break;
                    int n = (int)(ulong)got;
                    bool first = offset == 0, last = offset + n >= size;
                    Scan(buffer.AsSpan(0, n), first, last, sink, wide);
                    total += n;
                    if (n < want || last) break;
                }
                if (total - lastReport > (512L << 20)) { lastReport = total; progress?.Invoke($"Reading {what}: {total >> 20:N0} MB…"); }
            }
            long next = (long)mbi.BaseAddress + size;
            if (next <= (long)address) break;
            address = (IntPtr)next;
        }
        return total;
    }

    static bool Printable(byte b) => b is >= 0x20 and < 0x7F;

    /// <summary>
    /// The strings in one buffer. A string running into the buffer's start or end (except at the region's own edges) is
    /// left to the overlapping neighbour chunk, which sees it whole.
    /// </summary>
    static void Scan(ReadOnlySpan<byte> d, bool regionStart, bool regionEnd, StringSink sink, byte[] wide)
    {
        // ASCII / Latin-1 (Java's compact strings, class names, C strings).
        for (int i = 0; i < d.Length;)
        {
            if (!Printable(d[i])) { i++; continue; }
            int start = i;
            while (i < d.Length && Printable(d[i])) i++;
            int length = i - start;
            if (length < MinString || start == 0 && !regionStart || i == d.Length && !regionEnd) continue;
            var (cut, stored) = Cut(d, start, length, 1);
            // A C string: zero bytes on both sides.
            stored |= start > 0 && d[start - 1] == 0 && (start + cut == d.Length || d[start + cut] == 0);
            Emit(d.Slice(start, cut), stored, sink);
        }
        // UTF-16 (Java strings with other characters, Windows text).
        for (int i = 0; i + 1 < d.Length;)
        {
            if (!(Printable(d[i]) && d[i + 1] == 0)) { i++; continue; }
            int start = i;
            while (i + 1 < d.Length && Printable(d[i]) && d[i + 1] == 0) i += 2;
            int chars = (i - start) / 2;
            if (chars < MinString || start == 0 && !regionStart || i + 1 >= d.Length && !regionEnd) continue;
            var (cut, stored) = Cut(d, start, chars, 2);
            int end = start + 2 * cut;
            stored |= start >= 2 && d[start - 2] == 0 && d[start - 1] == 0 && (end + 1 >= d.Length || d[end] == 0 && d[end + 1] == 0);
            int n = Math.Min(cut, MaxCandidate * 2);
            for (int k = 0; k < n; k++) wide[k] = d[start + 2 * k];
            Emit(wide.AsSpan(0, n), stored, sink);
        }
    }

    /// <summary>
    /// The string's real length when the runtime's own length sits right before it — a Java byte[] / string's 4-byte
    /// length (bytes or characters), a class-name symbol's 2-byte length, a .NET array's length 8 bytes before — and
    /// whether one did. A string stored like that is a real string, not a piece of one left in freed memory.
    /// </summary>
    static (int Length, bool Stored) Cut(ReadOnlySpan<byte> d, int start, int length, int unit)
    {
        if (start >= 4 && BinaryPrimitives.ReadInt32LittleEndian(d[(start - 4)..]) is var l32 && l32 >= MinString)
        {
            if (l32 % unit == 0 && l32 / unit <= length) return (l32 / unit, true);
            if (unit == 2 && l32 <= length) return (l32, true);
        }
        if (unit == 1 && start >= 2 && (d[start - 2] | d[start - 1] << 8) is var l16 and >= MinString && l16 <= length) return (l16, true);
        if (start >= 8 && BinaryPrimitives.ReadInt32LittleEndian(d[(start - 8)..]) is var l64 && l64 >= MinString && l64 <= length && d[start - 4] == 0 && d[start - 3] == 0)
            return (l64, true);
        return (length, false);
    }

    static void Emit(ReadOnlySpan<byte> s, bool stored, StringSink sink)
    {
        if (s.Length > 4096) s = s[..4096];
        sink(s, stored, Fnv(s), Normalized(s));
    }

    const ulong Offset = 14695981039346656037, Prime = 1099511628211;

    static ulong Fnv(ReadOnlySpan<byte> s)
    {
        ulong h = Offset;
        foreach (var b in s) h = (h ^ b) * Prime;
        return h;
    }

    static bool IsHex(byte b) => b is >= (byte)'0' and <= (byte)'9' or >= (byte)'a' and <= (byte)'f' or >= (byte)'A' and <= (byte)'F';
    static bool IsLetter(byte b) => b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z';

    /// <summary>The hash with every number, and every hex token of 6+ characters holding a digit (IDs, hashes, addresses), as "#".</summary>
    internal static ulong Normalized(ReadOnlySpan<byte> s)
    {
        ulong h = Offset;
        for (int i = 0; i < s.Length;)
        {
            if (IsHex(s[i]))
            {
                int j = i;
                bool digit = false, allDigits = true;
                while (j < s.Length && IsHex(s[j])) { if (s[j] <= '9') digit = true; else allDigits = false; j++; }
                bool standalone = (i == 0 || !IsLetter(s[i - 1])) && (j == s.Length || !IsLetter(s[j]));
                if (digit && (allDigits || j - i >= 6 && standalone))
                {
                    h = (h ^ (byte)'#') * Prime;
                    i = j;
                    continue;
                }
            }
            h = (h ^ s[i]) * Prime;
            i++;
        }
        return h;
    }

    static bool LooksClassName(ReadOnlySpan<byte> s) => s.IndexOf((byte)'/') > 0 && s.IndexOf((byte)' ') < 0 && s.IndexOf((byte)':') < 0;

    /// <summary>Worth keeping as a candidate at all: a useful length, and text rather than bytes that happen to be printable.</summary>
    static bool Worth(ReadOnlySpan<byte> s)
    {
        if (s.Length is < MinCandidate or > MaxCandidate) return false;
        int letters = 0;
        foreach (var b in s) if (IsLetter(b)) letters++;
        return letters >= 4 && letters * 2 >= s.Length;
    }

    // ---- judging the strings ------------------------------------------------------------------------

    static readonly Regex Web = new(@"^(https?|wss?)://[\w.-]+\.[a-z]{2,}(/\S*)?$|^(?:[a-z0-9-]+\.)+(?:com|net|org|io|gg|dev|xyz|me|cc|club|pro|lol|ru|cn|de|uk|us|co|app|tk|ml|ga|cf|gq|top|site|online|store|shop|cloud|tech|space|fun|win|vip)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex GameHosts = new(@"(minecraft\.net|mojang\.com|minecraftservices\.com|microsoft\.com|microsoftonline\.com|live\.com|xboxlive\.com|msauth\.net|msftauth\.net|java\.com|oracle\.com|openjdk|apache\.org|w3\.org|xml\.org|sun\.com|eclipse\.org|github\.com/(lwjgl|FabricMC|MinecraftForge))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    // Java names classes with a capital; module.killaura.enabled is a setting key, not a class.
    static readonly Regex DottedClass = new(@"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\.[A-Z_$][\w$]*$", RegexOptions.Compiled);
    static readonly Regex Identifier = new(@"^[A-Za-z_$][\w$.\-]{7,}$", RegexOptions.Compiled);
    /// <summary>pkg/sub/Name - every part a Java identifier, the first one lower case as packages are.</summary>
    static readonly Regex SlashClass = new(@"^[a-z_$][a-z0-9_$]*(/[A-Za-z_$][\w$]*)+$", RegexOptions.Compiled);
    static readonly Regex Words = new(@"[A-Za-z]{2,}", RegexOptions.Compiled);
    static readonly Regex VanillaOrRuntime = new(@"^(net/minecraft/|com/mojang/|net/fabricmc/|cpw/mods/|net/neoforged/|net/minecraftforge/|org/lwjgl/|io/netty/|com/google/|org/apache/|org/slf4j/|it/unimi/|org/joml/|com/ibm/icu/|oshi/|org/objectweb/asm/|org/spongepowered/)|(^|/)(class|method|field|comp)_\d+",
        RegexOptions.Compiled);
    static readonly Regex FilePath = new(@"^[A-Za-z]:\\|^\\\\|^/(usr|home|tmp|proc)/", RegexOptions.Compiled);

    static List<DiffString> Classify(List<string> stable, HashSet<string>? fileStrings, GameDiffResult r, ISet<string> gameFiles)
    {
        var rows = new List<(string Text, DiffKind Kind, string Group)>();
        var paths = new List<string>();
        foreach (var raw in stable)
        {
            var t = raw.Trim();
            if (t.Length < MinCandidate) continue;
            // Paths are different on every PC, so they never go in a list. A program or jar path is worth showing, unless
            // it is one of the game's own files or a launcher's library / cache folder.
            if (FilePath.IsMatch(t) || t.Contains(@":\", StringComparison.Ordinal) || t.Contains(@"\\", StringComparison.Ordinal))
            {
                if (FilePath.IsMatch(t) && Regex.IsMatch(t, @"\.(jar|dll|exe|class|so|zip)$", RegexOptions.IgnoreCase) && !gameFiles.Contains(t) &&
                    !Regex.IsMatch(t, @"\\(libraries|natives|versions|\.fabric|assets)\\", RegexOptions.IgnoreCase))
                    paths.Add(t);
                continue;
            }
            if (Web.IsMatch(t))
            {
                if (!GameHosts.IsMatch(t)) rows.Add((t, DiffKind.WebAddress, ""));
                continue;
            }
            // A class name is made of Java identifiers only. Random bytes that merely contain a slash ("t/Q@!hNhPi") are not one.
            string? cls = SlashClass.IsMatch(t) ? t : DottedClass.IsMatch(t) ? t.Replace('.', '/') : null;
            if (cls == null && t.Contains('/') && !t.Contains(' ')) continue;
            if (cls != null)
            {
                if (CheatStrings.Runtime.IsMatch(cls) || VanillaOrRuntime.IsMatch(cls)) continue;
                // Type descriptors (Lpkg/Name;) and generic signatures repeat a class name the game also holds plainly.
                if (t.Contains('<') || t.EndsWith(';') || t.Length > 1 && t[0] is 'L' or '[' && cls != t) continue;
                rows.Add((t, DiffKind.ClassName, cls[..Math.Max(0, cls.LastIndexOf('/'))]));
                continue;
            }
            if (!t.Contains(' '))
            {
                if (Identifier.IsMatch(t) && !Junk(t)) rows.Add((t, DiffKind.Identifier, t.Contains('.') ? t[..t.IndexOf('.')] : ""));
                continue;
            }
            // Text: real words make up most of it, with the punctuation sentences use - not the symbol soup of random bytes.
            int wordChars = Words.Matches(t).Sum(m => m.Length);
            int symbols = t.Count(c => !char.IsLetterOrDigit(c) && c is not (' ' or '.' or ',' or '\'' or '!' or '?' or ':' or ';' or '(' or ')' or '-' or '"' or '/' or '%' or '+' or '&'));
            if (Words.Matches(t).Count >= 2 && wordChars * 10 >= t.Length * 6 && symbols * 20 <= t.Length && !Junk(t)) rows.Add((t, DiffKind.Text, ""));
        }

        foreach (var p in paths.Distinct(StringComparer.OrdinalIgnoreCase).Take(15))
            r.Differences.Add($"The injected game holds this file path: {p}");

        var groupSize = rows.Where(x => x.Group.Length > 0).GroupBy(x => x.Group, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        return rows.Select(x =>
        {
            int size = x.Group.Length > 0 ? groupSize[x.Group] : 1;
            bool inFile = fileStrings?.Contains(x.Text) == true || fileStrings?.Contains(x.Text.Replace('.', '/')) == true;
            return new DiffString(x.Text, x.Kind, Score(x.Text, x.Kind, size, inFile), x.Group, size, inFile, false);
        }).ToList();
    }

    /// <summary>Byte noise that happens to be readable: long hex / Base64 runs, one character repeated, mostly digits.</summary>
    static bool Junk(string t) =>
        Regex.IsMatch(t, @"[A-Za-z0-9+/=]{40,}|[0-9a-fA-F]{16,}|(.)\1{5,}") || t.Count(char.IsDigit) * 10 >= t.Length * 3;

    /// <summary>
    /// Higher is better evidence. Class names in a package with many others are the client itself; addresses and
    /// identifiers (module and setting names) next; plain text last. A string also found in the client's own file ranks up.
    /// </summary>
    static int Score(string t, DiffKind kind, int groupSize, bool inFile)
    {
        int score = kind switch
        {
            DiffKind.ClassName => 50 + Math.Min(groupSize, 30) - (groupSize < 3 ? 15 : 0) - (Regex.IsMatch(t, @"\$\d+;?$") ? 15 : 0),
            DiffKind.WebAddress => 55,
            DiffKind.Identifier => 40 + (Regex.IsMatch(t, @"[a-z][A-Z]|\.[A-Za-z]") ? 5 : 0),
            _ => 30 + Math.Min(Words.Matches(t).Count, 8),
        };
        if (t.Length < 10) score -= 8;
        if (t.Length > 120) score -= 10;
        if (inFile) score += 25;
        // Readable names (KillAuraModule, module.reach.range) are the same in every injection. Random-looking ones
        // (ABZhFqK_Casoubj) may be the client's obfuscated names - or random data that changes every time - so they rank
        // below readable ones; cross-checking two lists tells them apart.
        if (LooksRandom(t)) score -= 12;
        return score;
    }

    static readonly Regex ConsonantRun = new(@"[bcdfghjklmnpqrstvwxz]{5,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Letters with no pronounceable shape: a run of five consonants, or the case flipping on most letters.</summary>
    internal static bool LooksRandom(string t)
    {
        var letters = t.Where(char.IsLetter).ToList();
        if (letters.Count < 6) return false;
        int flips = 0;
        for (int i = 1; i < letters.Count; i++) if (char.IsUpper(letters[i]) != char.IsUpper(letters[i - 1])) flips++;
        return ConsonantRun.IsMatch(t) || flips * 5 > letters.Count * 2;
    }

    /// <summary>
    /// The string and its cores: up to three characters cut from either end. A string whose core the clean game holds is
    /// an ordinary string with stray bytes beside it. Cores shorter than 8 characters, or than 3/4 of the string, are not
    /// used: they are too common to mean anything.
    /// </summary>
    internal static IEnumerable<string> Cores(string s)
    {
        yield return s;
        for (int from = 0; from <= 3; from++)
        for (int to = 0; to <= 3; to++)
            if (from + to > 0 && s.Length - from - to >= Math.Max(MinCandidate, s.Length * 3 / 4)) yield return s[from..(s.Length - to)];
    }

    /// <summary>The strongest strings, at most <see cref="PerGroup"/> from one package so one package cannot fill the list.</summary>
    static List<DiffString> Shortlist(IEnumerable<DiffString> rows, int size)
    {
        var perGroup = new Dictionary<string, int>(StringComparer.Ordinal);
        var list = new List<DiffString>();
        foreach (var s in rows.OrderByDescending(s => s.Score).ThenBy(s => s.Text, StringComparer.Ordinal))
        {
            if (s.Text.Length < MinCandidate) continue;
            if (s.Group.Length > 0 && (perGroup[s.Group] = perGroup.GetValueOrDefault(s.Group) + 1) > PerGroup) continue;
            list.Add(s);
            if (list.Count >= size) break;
        }
        return list;
    }

    // ---- how the games were started -----------------------------------------------------------------

    /// <summary>
    /// Both games should be the same version, mods and Java started the same way; anything that differs is reported
    /// (it adds strings of its own). A Java agent, a DLL or hand-mapped code only the injected game has is listed as a
    /// difference: that is how the client got in.
    /// </summary>
    static void CompareSetup(int cleanPid, int injectedPid, GameDiffResult r)
    {
        string? a = WinApi.GetCommandLine(cleanPid), b = WinApi.GetCommandLine(injectedPid);
        if (a == null || b == null) r.Notes.Add("The games' command lines could not be read (run as administrator) - whether they were started the same way was not checked.");
        else
        {
            string? Arg(string cmd, string name) => Regex.Match(cmd, $@"{Regex.Escape(name)}\s+(""[^""]+""|\S+)") is { Success: true } m ? m.Groups[1].Value.Trim('"') : null;
            foreach (var name in new[] { "--version", "--gameDir", "--assetIndex" })
                if (Arg(a, name) is var x && Arg(b, name) is var y && !string.Equals(x, y, StringComparison.OrdinalIgnoreCase))
                    r.Warnings.Add($"{name} differs: clean \"{x ?? "-"}\", injected \"{y ?? "-"}\".");
            var cpA = ClassPath(a); var cpB = ClassPath(b);
            if (cpA.Count > 0 && !cpA.SetEquals(cpB))
                r.Warnings.Add($"The games load different libraries ({cpB.Except(cpA).Count()} only in the injected game, {cpA.Except(cpB).Count()} only in the clean one) - start both from the same profile.");
            var agentsA = HistoryParser.Core.Bypass.ArgumentAudit.AgentsIn(a).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var agent in HistoryParser.Core.Bypass.ArgumentAudit.AgentsIn(b).Where(x => !agentsA.Contains(x)))
                r.Differences.Add(HistoryParser.Core.Bypass.ArgumentAudit.KnownLauncher([agent]) is { } launcher
                    ? $"Only the injected game was started with {launcher}'s own Java agent ({agent}) - the launchers differ."
                    : $"Only the injected game was started with the Java agent {agent} - a way clients load.");
        }

        // DLLs only the injected game has. Signed ones (Windows' audio drivers, Java's own libraries) come from what the game
        // did - played sound, opened a window - so they are only counted; unsigned or deleted ones are listed.
        var modsA = GameInspection.Modules(cleanPid);
        var namesA = modsA.Select(m => NormalizeName(m.Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        int signedOnly = 0;
        foreach (var m in GameInspection.Modules(injectedPid).Where(m => !namesA.Contains(NormalizeName(m.Name))))
        {
            var sig = File.Exists(m.Path) ? HistoryParser.Core.Analysis.FileInspector.Verify(m.Path) : (HistoryParser.Core.Models.SignatureStatus?)null;
            if (sig is HistoryParser.Core.Models.SignatureStatus.Signed or HistoryParser.Core.Models.SignatureStatus.WindowsFile) { signedOnly++; continue; }
            r.Differences.Add($"DLL loaded only in the injected game: {m.Path} ({(sig == null ? "its file is gone" : "not signed")}).");
        }
        if (signedOnly > 0) r.Notes.Add($"{signedOnly} signed DLL(s) (Windows, Java, drivers) are loaded only in the injected game - usually from what the game did, such as playing sound.");
        long kbA = CheatStrings.HiddenCodeKb(cleanPid), kbB = CheatStrings.HiddenCodeKb(injectedPid);
        if (kbB >= 64 && kbA < 64)
            r.Differences.Add($"The injected game holds {kbB:N0} KB of program code that belongs to no file (the clean one {kbA:N0} KB) - a hand-mapped native client.");
        if (r.Warnings.Count > 0)
            r.Warnings.Add("Strings caused by these differences can end up in the list; for the cleanest list, start both games the same way.");
    }

    static HashSet<string> ClassPath(string cmd) =>
        Regex.Matches(cmd, @"(?:-cp|-classpath|--class-path)\s+(""[^""]+""|\S+)").SelectMany(m => m.Groups[1].Value.Trim('"').Split(';'))
            .Where(p => p.Length > 0).Select(p => System.IO.Path.GetFileName(p)).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>A module name with its numbers blanked: Java libraries unpack DLLs under random names (jna1234567.dll).</summary>
    static string NormalizeName(string name) => Regex.Replace(name, @"\d+", "#");

    // ---- the saved list -------------------------------------------------------------------------------

    public static string ToText(GameDiffResult r, string? clientName) => ToText(r, clientName, r.List);

    /// <summary>The saved list holding <paramref name="chosen"/> - the proven strings, plus any the user ticked by hand.</summary>
    public static string ToText(GameDiffResult r, string? clientName, IEnumerable<DiffString> chosen)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Cheat strings{(string.IsNullOrWhiteSpace(clientName) ? "" : " - " + clientName)}");
        sb.AppendLine($"# Made {DateTime.Now:yyyy-MM-dd HH:mm} by Cheat String Finder by comparing two games on the title screen:");
        sb.AppendLine($"#   clean:    {r.Clean}");
        sb.AppendLine($"#   injected: {r.Injected}");
        sb.AppendLine("# Every string below is in the injected game and in no form in the clean game (searched the way Client Parser");
        sb.AppendLine("# searches: whole strings, ASCII and UTF-16, all of memory). Load this file in Client Parser, or search for the");
        sb.AppendLine("# strings in System Informer (Memory > Strings, minimum length 8, Extended Unicode ticked).");
        if (r.Warnings.Count > 0)
            sb.AppendLine("# WARNING: the two games were not set up the same, so this list can hold strings of their mods or settings. Make it again from one profile before relying on it.");
        foreach (var w in r.Warnings) sb.AppendLine($"# Warning: {w}");
        foreach (var d in r.Differences) sb.AppendLine($"# Also: {d}");
        sb.AppendLine("# Client Parser reports this list as one finding: High when 5 or more of its strings are in a game, Medium for 2-4,");
        sb.AppendLine("# Low for one (a single string can be chance).");
        var picked = chosen.ToList();
        if (picked.Any(s => !s.Verified)) sb.AppendLine($"# {picked.Count(s => !s.Verified)} string(s) were added by hand and not proven by the comparison.");
        foreach (var kind in picked.GroupBy(s => s.Kind).OrderBy(g => g.Key))
        {
            sb.AppendLine();
            sb.AppendLine(kind.Key switch
            {
                DiffKind.ClassName => "# Class names",
                DiffKind.WebAddress => "# Web addresses",
                DiffKind.Identifier => "# Names (modules, settings, keys, obfuscated names)",
                _ => "# Text",
            });
            foreach (var s in kind) sb.AppendLine(s.Text);
        }
        return sb.ToString();
    }

    /// <summary>A saved list: its [core] and [supporting] strings. A list without sections (older or hand-made) is all supporting.</summary>
    public static (List<string> Core, List<string> Supporting) ReadList(string path)
    {
        var core = new List<string>();
        var supporting = new List<string>();
        var target = supporting;
        foreach (var line in File.ReadLines(path).Select(l => l.Trim()))
        {
            if (line.Equals("[core]", StringComparison.OrdinalIgnoreCase)) { target = core; continue; }
            if (line.Equals("[supporting]", StringComparison.OrdinalIgnoreCase)) { target = supporting; continue; }
            if (line.Length >= 4 && !line.StartsWith('#')) target.Add(line);
        }
        return (core.Distinct(StringComparer.Ordinal).ToList(), supporting.Distinct(StringComparer.Ordinal).Except(core, StringComparer.Ordinal).ToList());
    }
}
