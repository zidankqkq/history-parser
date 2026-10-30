using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using HistoryParser.Core.Native;
using static HistoryParser.Core.Native.NativeMethods;

namespace RatChecker.Core;

/// <summary>Where a string came from.</summary>
public enum StringKind { ClassName, Text, WebAddress }

/// <summary>
/// One string a checker can search for in the game's memory (System Informer / Process Hacker → Memory → Strings).
/// <see cref="InMemory"/> / <see cref="InCleanGame"/> are null when that check was not run.
/// </summary>
public sealed record CheatString(string Text, StringKind Kind, int Score, bool? InMemory = null, bool? InCleanGame = null)
{
    /// <summary>
    /// Proven: seen in the injected game and not in a clean game. Strong: from the cheat file and seen in memory, or found
    /// in memory as code no file on disk provides. Likely: from the file, not checked against a running game.
    /// </summary>
    public string Confidence => InMemory == true && InCleanGame == false ? "Proven" : InMemory == true ? "Strong" : "Likely";
}

public sealed class CheatStringsResult
{
    public string? ClientName { get; set; }
    public string? FilePath { get; set; }
    public string? FileSha256 { get; set; }
    public string? GameProcess { get; set; }
    public string? CleanProcess { get; set; }
    public int CleanFiles { get; set; }
    public int DroppedAsClean { get; set; }
    public int DroppedInCleanGame { get; set; }
    public List<CheatString> Strings { get; } = new();
    public List<string> Notes { get; } = new();
}

/// <summary>A running Java game.</summary>
public sealed record GameProcess(int Pid, string Name, string Title, DateTime? Started)
{
    public override string ToString() => $"{Name} (PID {Pid}){(Title.Length > 0 ? " - " + Title : "")}";
}

/// <summary>
/// Finds the strings that prove a cheat client is loaded: from the client's file, from the memory of a game it was
/// injected into, or both — keeping only strings that no legitimate mod, library or clean game contains, so finding
/// them in a player's game is meaningful. Files are only read; game memory is only read.
/// </summary>
public static class CheatStrings
{
    const int MinLength = 8;
    const int MaxPerResult = 400;

    // ---- the cheat file ---------------------------------------------------------------------------

    /// <summary>The class names a file defines and the readable strings it carries.</summary>
    public static (HashSet<string> Classes, HashSet<string> Texts) FromContent(RatContent c)
    {
        var classes = new HashSet<string>(StringComparer.Ordinal);
        var texts = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (name, _, _) in c.Entries)
            if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase))
                classes.Add(name[..^6]);
        foreach (var (text, where) in c.Strings)
        {
            // Text from code (class constants, strings in a DLL/EXE) ends up in memory; config files (mods.toml, manifests) mostly don't.
            if (!FromCode(where)) continue;
            var t = text.Trim();
            if (Readable(t)) texts.Add(t);
        }
        return (classes, texts);
    }

    static bool FromCode(string where) =>
        where.EndsWith(".class", StringComparison.OrdinalIgnoreCase) || where.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
        where.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || where.EndsWith(".so", StringComparison.OrdinalIgnoreCase) ||
        where.Contains("(hidden after the image)", StringComparison.Ordinal);

    /// <summary>Readable text of a useful length: binary data decoded as text is random and differs between copies.</summary>
    internal static bool Readable(string t) =>
        t.Length is >= MinLength and <= 160 && t.Count(char.IsLetter) >= 4 && !t.Contains('�') &&
        t.Count(ch => ch is >= ' ' and <= '~') >= t.Length * 0.95 && !Noise.IsMatch(t);

    static readonly Regex Noise = new(@"^[\d\W_]+$|^[0-9a-f]{16,}$|^[A-Za-z0-9+/=]{60,}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Java, JDK and JVM-generated class names: in every game's memory, so never evidence.</summary>
    internal static readonly Regex Runtime = new(
        @"^(java|javax|jdk|sun|com/sun|org/w3c|org/xml|org/ietf|org/jcp|kotlin|kotlinx|scala|groovy|com/azul|com/oracle|com/ibm/(j9|oti|jit|lang|gpu)|openj9|org/graalvm|com/microsoft/java)/|^org/spongepowered/asm/synthetic/|\$\$Lambda|LambdaForm\$|GeneratedMethodAccessor|GeneratedConstructorAccessor|\$Proxy\d|^jdk\.|/\$\$",
        RegexOptions.Compiled);

    // ---- the clean set ------------------------------------------------------------------------------

    /// <summary>
    /// Every class name and string in the clean files (legitimate mods, the game, libraries). A clean file that is the
    /// cheat itself (same SHA-256) is skipped, or the cheat would clean its own strings away.
    /// </summary>
    public static HashSet<string> ReadClean(IEnumerable<string> files, string? skipSha256, Action<string>? progress, out int count, CancellationToken ct = default)
    {
        var all = new HashSet<string>(StringComparer.Ordinal);
        int n = 0;
        var lockObj = new object();
        files.AsParallel().WithDegreeOfParallelism(Math.Clamp(Environment.ProcessorCount / 2, 1, 6)).WithCancellation(ct).ForAll(path =>
        {
            try
            {
                var bytes = File.ReadAllBytes(path);
                if (skipSha256 != null && Sha256(bytes) == skipSha256) return;
                var content = RatReader.Read(bytes, Path.GetFileName(path));
                var (classes, texts) = FromContent(content);
                // Everything a legitimate jar mentions also explains a name in memory: its resource paths
                // (com/ibm/icu/.../rbnf/ar_SA.res) and the classes it refers to without containing them (org/osgi/...).
                var mentioned = content.Entries.Where(e => !e.Name.EndsWith('/')).Select(e => Path.ChangeExtension(e.Name, null)!.Replace('\\', '/'))
                    .Concat(content.Refs.Keys.Where(r => r.Contains('/') && !r.Contains('.')));
                lock (lockObj)
                {
                    all.UnionWith(classes);
                    all.UnionWith(texts);
                    all.UnionWith(mentioned);
                    if (++n % 100 == 0) progress?.Invoke($"Read {n:N0} clean files…");
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { }
        });
        count = n;
        return all;
    }

    /// <summary>The clean set by default: every jar in the launchers' mod folders, the game versions and its libraries.</summary>
    public static List<string> DefaultCleanFolders()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var folders = RatFiles.ModFolders();
        foreach (var extra in new[] { Path.Combine(appData, ".minecraft", "versions"), Path.Combine(appData, ".minecraft", "libraries"),
                                      Path.Combine(appData, "ModrinthApp", "meta", "libraries") })
            if (Directory.Exists(extra)) folders.Add(extra);
        return folders;
    }

    public static string Sha256(byte[] bytes) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

    // ---- running games ------------------------------------------------------------------------------

    public static List<GameProcess> JavaProcesses()
    {
        var list = new List<GameProcess>();
        foreach (var name in new[] { "javaw", "java" })
            foreach (var p in Process.GetProcessesByName(name))
                using (p)
                {
                    DateTime? started = null;
                    try { started = p.StartTime; } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                    list.Add(new GameProcess(p.Id, p.ProcessName + ".exe", p.MainWindowTitle, started));
                }
        return list;
    }

    /// <summary>
    /// Reads a process's private memory once and reports (a) which of <paramref name="needles"/> occur in it, as ASCII or
    /// UTF-16, (b) when <paramref name="classNames"/> is given, every class-name-shaped string it holds, and (c) when
    /// <paramref name="hosts"/> is given, the hosts of the plain HTTP requests it holds. Read-only.
    /// </summary>
    /// <param name="allRegions">Search every readable region: loaded DLLs and mapped files too, not only private memory.</param>
    /// <param name="wholeStrings">
    /// true: a needle only counts as a whole string, not inside a longer word or name (how lists are matched);
    /// false: anywhere, also inside longer text (how Cheat String Finder proves the clean game has none of it).
    /// null: class names whole, other text anywhere.
    /// </param>
    public static long ScanMemory(int pid, IReadOnlyCollection<string> needles, HashSet<string> found, HashSet<string>? classNames,
        Action<string>? progress, CancellationToken ct, HashSet<string>? hosts = null, bool allRegions = false, bool? wholeStrings = null)
    {
        var finder = new NeedleFinder(needles, wholeNames: wholeStrings != false, boundAll: wholeStrings == true);
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) throw new UnauthorizedAccessException($"The game's memory could not be opened (error {Marshal.GetLastWin32Error()}). Run as administrator.");
        long scanned = 0;
        IntPtr address = IntPtr.Zero;
        var buffer = new byte[8 << 20];
        var mbiSize = (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        const int Overlap = 256; // strings crossing a chunk border are read again with the next chunk
        while (VirtualQueryEx(h, address, out var mbi, mbiSize) != UIntPtr.Zero)
        {
            ct.ThrowIfCancellationRequested();
            long regionSize = (long)(ulong)mbi.RegionSize;
            bool readable = (mbi.Protect & 0xEE) != 0 && (mbi.Protect & PAGE_GUARD) == 0;
            if (mbi.State == MEM_COMMIT && readable && (allRegions || mbi.Type == MEM_PRIVATE))
            {
                for (long offset = 0; offset < regionSize; offset += buffer.Length - Overlap)
                {
                    int chunk = (int)Math.Min(buffer.Length, regionSize - offset);
                    if (!ReadProcessMemory(h, mbi.BaseAddress + (nint)offset, buffer, (UIntPtr)chunk, out var read)) break;
                    int n = (int)(ulong)read;
                    var data = buffer.AsSpan(0, n);
                    finder.Search(data, found);
                    if (classNames != null) CollectClassNames(data, classNames);
                    if (hosts != null) CollectHosts(data, hosts);
                    scanned += n;
                    if (n < chunk || offset + chunk >= regionSize) break;
                }
                if (scanned > 0 && scanned % (512L << 20) < (8 << 20)) progress?.Invoke($"Read {scanned / (1L << 20):N0} MB of game memory…");
            }
            long next = (long)mbi.BaseAddress + regionSize;
            if (next <= (long)address) break;
            address = (IntPtr)next;
        }
        return scanned;
    }

    /// <summary>
    /// The largest block of executable, non-writable code in the game that belongs to no file, in KB. The JVM compiles
    /// into writable+executable memory and every DLL is a mapped file, so code like this was put there by hand: a
    /// manually mapped (hidden) native module. Read-only; only the memory map is queried.
    /// </summary>
    public static long HiddenCodeKb(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (h.IsInvalid) return 0;
        var byAllocation = new Dictionary<long, long>();
        var mbiSize = (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        IntPtr address = IntPtr.Zero;
        while (VirtualQueryEx(h, address, out var mbi, mbiSize) != UIntPtr.Zero)
        {
            long size = (long)(ulong)mbi.RegionSize;
            const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20;
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && (mbi.Protect & 0xFF) is PAGE_EXECUTE or PAGE_EXECUTE_READ)
                byAllocation[(long)mbi.AllocationBase] = byAllocation.GetValueOrDefault((long)mbi.AllocationBase) + size;
            long next = (long)mbi.BaseAddress + size;
            if (next <= (long)address) break;
            address = (IntPtr)next;
        }
        return byAllocation.Count == 0 ? 0 : byAllocation.Values.Max() / 1024;
    }

    /// <summary>
    /// Class names in the game's memory that no legitimate file explains. Judged by package: an injected client lives in
    /// packages no legitimate jar has, so a name in a package a clean jar uses is dropped — including real names with stray
    /// bytes stuck on (At$ShiftC, .../PK from zip data in memory). Data paths with the same shape (wiki titles, item IDs,
    /// texture paths) are dropped by their form: numeric parts, Title_With_Underscores, or long all-lowercase final names
    /// (real classes are CamelCase; obfuscated ones are short).
    /// </summary>
    internal static List<string> Unexplained(IEnumerable<string> memoryClasses, HashSet<string> clean)
    {
        var cleanPackages = new HashSet<string>(StringComparer.Ordinal);
        foreach (var t in clean)
        {
            if (t.Contains(' ') || !t.Contains('/')) continue;
            for (int i = t.IndexOf('/'); i > 0; i = t.IndexOf('/', i + 1)) cleanPackages.Add(t[..i]);
        }
        var kept = new List<string>();
        foreach (var c in memoryClasses)
        {
            if (Runtime.IsMatch(c) || clean.Contains(c) || c.StartsWith("net/minecraft/", StringComparison.Ordinal) || c.StartsWith("com/mojang/", StringComparison.Ordinal)) continue;
            int last = c.LastIndexOf('/');
            if (cleanPackages.Contains(c[..last])) continue;
            var segments = c.Split('/');
            var name = segments[^1];
            if (segments.Any(s => s.Length == 0 || s.All(char.IsDigit))) continue;                       // essence/x/1/13705
            if (segments.Any(s => Regex.IsMatch(s, @"[A-Z][a-z]+_[A-Z]"))) continue;                     // wiki/w/Attack_Speed_Enrichment
            if (name.Length > 3 && name.All(ch => char.IsLower(ch) || char.IsDigit(ch) || ch == '_')) continue; // mob/parrot/fly1, .../disabled
            kept.Add(c);
        }
        // An injected client loads many classes into its own packages; a lone name is far more likely a fragment. Two
        // names are enough when both read as real class names (net/minecraft_26_1_2/SharedConstants, .../WorldVersion -
        // a client looking up the game's classes); random bytes almost never form two CamelCase words.
        return kept.GroupBy(c => c[..c.LastIndexOf('/')], StringComparer.Ordinal)
            .Where(g => g.Count() >= MinClustered || g.Count() >= 2 && g.All(c => Words.IsMatch(c[(c.LastIndexOf('/') + 1)..])))
            .SelectMany(g => g).ToList();
    }

    const int MinClustered = 3;
    static readonly Regex Words = new(@"^[A-Z][a-z]{2,}(?:[A-Z][a-z]{2,})+$", RegexOptions.Compiled);

    /// <summary>
    /// Hosts of plain HTTP requests in memory ("POST /x HTTP/1.1\r\nHost: example.xyz\r\n"). The game talks to Mojang and
    /// Microsoft; a client that phones home for its code, licence or config leaves its own host behind.
    /// </summary>
    internal static void CollectHosts(ReadOnlySpan<byte> data, HashSet<string> hosts)
    {
        ReadOnlySpan<byte> marker = "\r\nHost: "u8;
        for (int i = data.IndexOf(marker); i >= 0; )
        {
            int start = i + marker.Length, end = start;
            while (end < data.Length && end - start < 254 && (char.IsAsciiLetterOrDigit((char)data[end]) || data[end] is (byte)'.' or (byte)'-')) end++;
            if (end + 1 < data.Length && data[end] == '\r' && data[end + 1] == '\n')
            {
                var host = Encoding.ASCII.GetString(data[start..end]).ToLowerInvariant();
                if (HostName.IsMatch(host) && !GameHosts.IsMatch(host)) hosts.Add(host);
            }
            int next = data[start..].IndexOf(marker);
            i = next < 0 ? -1 : start + next;
        }
    }

    /// <summary>A host name with a real top-level domain; IP addresses are left out (a server's resource-pack host can be one).</summary>
    static readonly Regex HostName = new(@"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", RegexOptions.Compiled);

    /// <summary>The services every Minecraft game talks to.</summary>
    static readonly Regex GameHosts = new(
        @"(^|\.)(minecraft\.net|mojang\.com|minecraftservices\.com|microsoft\.com|microsoftonline\.com|live\.com|xboxlive\.com|msauth\.net|msftauth\.net)$",
        RegexOptions.Compiled);

    /// <summary>The candidates that occur anywhere inside a clean string (equal to it, or part of it).</summary>
    internal static HashSet<string> ContainedIn(IEnumerable<string> candidates, HashSet<string> clean, CancellationToken ct)
    {
        var hits = new HashSet<string>(StringComparer.Ordinal);
        var list = candidates.ToList();
        hits.UnionWith(list.Where(clean.Contains));
        var finder = new NeedleFinder(list.Where(c => !hits.Contains(c)), wholeNames: false);
        // Clean strings joined with a separator that never appears in a candidate, searched in 32 MB pieces.
        var sb = new StringBuilder(32 << 20);
        foreach (var t in clean)
        {
            sb.Append(t).Append('\n');
            if (sb.Length < (32 << 20)) continue;
            ct.ThrowIfCancellationRequested();
            finder.Search(Encoding.ASCII.GetBytes(sb.ToString()), hits);
            sb.Clear();
        }
        if (sb.Length > 0) finder.Search(Encoding.ASCII.GetBytes(sb.ToString()), hits);
        return hits;
    }

    /// <summary>A class name as the JVM stores it ("net/wurstclient/hacks/KillauraHack"), or a type descriptor wrapping one ("Lnet/...;").</summary>
    static readonly Regex ClassName = new(@"^[\[ZBCSIJFDV]*L?[A-Za-z_][\w$]*(?:/[\w$]+){2,};?$", RegexOptions.Compiled);

    /// <summary>
    /// Class names exactly as HotSpot keeps them: every name lives in a Symbol — a 2-byte length followed by the name's
    /// bytes. Only text whose own length sits right before it counts, which takes the name precisely (stray bytes after it
    /// are not included) and rejects fragments such as "a/lang/Obj3" cut out of other strings (their 2 bytes in front
    /// match their length about once in 65,000).
    /// </summary>
    internal static void CollectClassNames(ReadOnlySpan<byte> data, HashSet<string> names)
    {
        for (int i = 2; i < data.Length; i++)
        {
            // A name starts where text starts; the byte before it is the length's high byte (0 for names under 256 bytes).
            if (!Printable(data[i]) || Printable(data[i - 1])) continue;
            int length = data[i - 2] | (data[i - 1] << 8);
            if (length is < MinLength or > 200 || i + length > data.Length) continue;
            var body = data.Slice(i, length);
            if (body.IndexOf((byte)'/') < 0 || body.IndexOfAnyExceptInRange((byte)0x20, (byte)0x7E) >= 0) continue;
            var text = Encoding.ASCII.GetString(body);
            if (ClassName.IsMatch(text) && NormalizeClassName(text.TrimEnd(';')) is { } name) names.Add(name);
        }
    }

    /// <summary>Top folders of game resources (assets/minecraft/..., block/firefly_bush): paths, not classes.</summary>
    static readonly HashSet<string> ResourceRoots = new(StringComparer.Ordinal)
    {
        "assets", "data", "block", "blocks", "item", "items", "textures", "texture", "models", "model", "shaders", "shader", "sounds", "sound",
        "lang", "font", "particles", "particle", "minecraft", "entity", "gui", "recipes", "recipe", "tags", "advancements", "loot_tables",
        "worldgen", "structures", "structure", "blockstates", "atlases", "post_effect", "include", "core", "program", "environment",
        "effect", "mob_effect", "painting", "trim", "misc", "map", "colormap", "environment", "optifine", "META-INF", "versions",
    };

    /// <summary>
    /// The class name inside a JVM type descriptor ("Lcom/x/Y", "[Lcom/x/Y", "ILcom/x/Y" from "(ILcom/x/Y;)V"), or null when
    /// the text only looks like one: Java package names start lowercase, so "INF/versions/9/module" (from META-INF) and
    /// "BONUS_SPEED/asm/m" are fragments, and "assets/minecraft/..." is a resource path.
    /// </summary>
    internal static string? NormalizeClassName(string s)
    {
        var m = Regex.Match(s, @"^[\[ZBCSIJFDV]*L(?=[a-z])");
        if (m.Success) s = s[m.Length..];
        int slash = s.IndexOf('/');
        if (slash <= 0 || !Regex.IsMatch(s[..slash], @"^[a-z][a-z0-9_]*$") || ResourceRoots.Contains(s[..slash])) return null;
        return s.Length is >= MinLength and <= 200 ? s : null;
    }

    /// <summary>
    /// The jars a running game was started with: its class path, the mods folder of its game directory, and a launcher's
    /// own Java agent. These are the legitimate code in that game, so none of their classes can be evidence.
    /// A -javaagent outside a launcher's folder is left out on purpose - injected clients load that way.
    /// </summary>
    public static List<string> GameJars(int pid, List<string> notes)
    {
        var jars = new List<string>();
        if (WinApi.GetCommandLine(pid) is not { } cmd) { notes.Add("The game's command line could not be read, so its own libraries were not added to the clean set."); return jars; }
        foreach (Match m in Regex.Matches(cmd, @"(?:-cp|-classpath|--class-path|-p|--module-path)\s+(""[^""]+""|\S+)"))
            jars.AddRange(m.Groups[1].Value.Trim('"').Split(';').Where(p => p.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && File.Exists(p)));
        foreach (Match m in Regex.Matches(cmd, @"-javaagent:(""[^""]+""|[^\s=]+)"))
        {
            var agent = m.Groups[1].Value.Trim('"');
            if (File.Exists(agent) && Regex.IsMatch(agent, @"\\(ModrinthApp|PrismLauncher|PolyMC|MultiMC|\.minecraft|curseforge|GDLauncher|ATLauncher)\\", RegexOptions.IgnoreCase))
                jars.Add(agent);
        }
        if (Regex.Match(cmd, @"--gameDir\s+(""[^""]+""|\S+)") is { Success: true } dir)
        {
            var gameDir = dir.Groups[1].Value.Trim('"');
            foreach (var sub in new[] { "mods", ".fabric" })
            {
                var path = Path.Combine(gameDir, sub);
                if (Directory.Exists(path))
                    jars.AddRange(Directory.EnumerateFiles(path, "*.jar", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }));
            }
        }
        return jars.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    static bool Printable(byte b) => b is >= 0x20 and < 0x7F;

    /// <summary>
    /// Finds many fixed strings in large buffers fast: each needle is keyed by its first 8 bytes (ASCII, and the first
    /// 4 characters in UTF-16); a 16-million-bit table rejects almost every position before any comparison.
    /// </summary>
    sealed class NeedleFinder
    {
        readonly Dictionary<ulong, List<(byte[] Bytes, string Text, bool Whole, bool Wide)>> _byKey = new();
        readonly ulong[] _bits = new ulong[1 << 18]; // 2^24 bits

        /// <param name="wholeNames">Class names only count as whole names: "net/java/g" must not match inside "net/java/games/...".</param>
        /// <param name="boundAll">Every needle only counts as a whole string ("Velocity" not inside "setVelocity").</param>
        public NeedleFinder(IEnumerable<string> needles, bool wholeNames = true, bool boundAll = false)
        {
            foreach (var text in needles)
            {
                if (text.Length < MinLength) continue;
                bool whole = boundAll || wholeNames && IsClassName(text);
                Add(Encoding.ASCII.GetBytes(text), text, whole, wide: false);
                Add(Encoding.Unicode.GetBytes(text), text, whole, wide: true);
            }
        }

        static bool IsClassName(string t) => t.Contains('/') && !t.Contains(' ');

        void Add(byte[] bytes, string text, bool whole, bool wide)
        {
            ulong key = BitConverter.ToUInt64(bytes, 0);
            (_byKey.TryGetValue(key, out var list) ? list : _byKey[key] = new()).Add((bytes, text, whole, wide));
            ulong slot = Slot(key);
            _bits[slot >> 6] |= 1UL << (int)(slot & 63);
        }

        static bool NameChar(byte b) => b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'_' or (byte)'$' or (byte)'/';

        /// <summary>For whole names: the characters around the match are not part of a longer class name.</summary>
        static bool Bounded(ReadOnlySpan<byte> data, int start, int length, bool wide)
        {
            int step = wide ? 2 : 1;
            bool before = start - step < 0 || !NameChar(data[start - step]) || wide && data[start - 1] != 0;
            int after = start + length;
            bool afterOk = after >= data.Length || !NameChar(data[after]) || wide && after + 1 < data.Length && data[after + 1] != 0;
            return before && afterOk;
        }

        static ulong Slot(ulong key) => (key * 0x9E3779B97F4A7C15UL) >> 40;

        public void Search(ReadOnlySpan<byte> data, HashSet<string> found)
        {
            if (_byKey.Count == 0) return;
            for (int i = 0; i + 8 <= data.Length; i++)
            {
                ulong key = MemoryMarshal.Read<ulong>(data[i..]);
                ulong slot = Slot(key);
                if ((_bits[slot >> 6] & (1UL << (int)(slot & 63))) == 0) continue;
                if (!_byKey.TryGetValue(key, out var list)) continue;
                foreach (var (bytes, text, whole, wide) in list)
                    if (i + bytes.Length <= data.Length && data.Slice(i, bytes.Length).SequenceEqual(bytes) &&
                        (!whole || Bounded(data, i, bytes.Length, wide)))
                        found.Add(text);
            }
        }
    }

    // ---- putting it together ------------------------------------------------------------------------------

    /// <summary>Higher = better evidence: class names and names of cheat features rank first.</summary>
    internal static int Score(string t, StringKind kind)
    {
        int score = kind == StringKind.ClassName ? 3 : 0;
        if (CheatWords.IsMatch(t)) score += 4;
        if (t.Length is >= 10 and <= 60) score += 2;
        if (t.Length > 90) score -= 2;
        if (Regex.IsMatch(t, @"\d+\.\d+")) score -= 2; // versions change every release
        if (kind == StringKind.ClassName && Regex.IsMatch(t, @"\$\d+$")) score -= 2; // anonymous classes are numbered by the compiler
        return score;
    }

    static readonly Regex CheatWords = new(
        @"kill ?aura|aimbot|aim ?assist|trigger ?bot|auto ?clicker|reach|velocity|anti ?kb|knockback|esp\b|x-?ray|scaffold|no ?fall|" +
        @"criticals|fly|speed|nuker|freecam|self ?destruct|destruct|inject|bypass|ghost|cheat|hack|module",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// The whole job. <paramref name="cheatFile"/> and <paramref name="game"/> are each optional, but at least one is needed.
    /// <paramref name="cleanGame"/> (the same game running without the cheat) is optional extra safety.
    /// </summary>
    public static CheatStringsResult Find(string? cheatFile, GameProcess? game, GameProcess? cleanGame, IReadOnlyList<string> cleanFolders,
        Action<string>? progress = null, CancellationToken ct = default)
    {
        if (cheatFile == null && game == null) throw new ArgumentException("Give a cheat file, a running game, or both.");
        var result = new CheatStringsResult { FilePath = cheatFile, GameProcess = game?.ToString(), CleanProcess = cleanGame?.ToString() };

        // 1. Candidates from the file.
        var fromFile = new Dictionary<string, StringKind>(StringComparer.Ordinal);
        if (cheatFile != null)
        {
            progress?.Invoke("Reading the cheat file…");
            var bytes = File.ReadAllBytes(cheatFile);
            result.FileSha256 = Sha256(bytes);
            var content = RatReader.Read(bytes, Path.GetFileName(cheatFile));
            result.ClientName = content.ModInfo ?? Path.GetFileNameWithoutExtension(cheatFile);
            var (classes, texts) = FromContent(content);
            foreach (var c in classes.Where(c => c.Length >= MinLength && !Runtime.IsMatch(c))) fromFile[c] = StringKind.ClassName;
            foreach (var t in texts) fromFile.TryAdd(t, StringKind.Text);
            if (content.Packers.Count > 0 || content.Notes.Any(n => n.Contains("packed", StringComparison.OrdinalIgnoreCase)))
                result.Notes.Add("The file is packed or protected, so part of what it loads is only visible in memory. Scan a game with it injected for the full picture.");
            if (classes.Count < 20 && content.Kind.Contains("jar", StringComparison.OrdinalIgnoreCase))
                result.Notes.Add($"The file holds only {classes.Count} readable classes - most of the client is probably encrypted and decrypted in memory. A scan of an injected game finds those.");
        }

        // 2. The clean set.
        var cleanFiles = RatFiles.Expand(cleanFolders, result.Notes).Where(f => f.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var g in new[] { game, cleanGame })
            if (g != null) cleanFiles.AddRange(GameJars(g.Pid, result.Notes));
        cleanFiles = cleanFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        progress?.Invoke($"Reading {cleanFiles.Count:N0} clean files…");
        var clean = ReadClean(cleanFiles, result.FileSha256, progress, out int cleanCount, ct);
        result.CleanFiles = cleanCount;
        if (cleanCount < 100)
            result.Notes.Add($"Only {cleanCount} clean file(s) were read. The fewer legitimate mods it is compared with, the more likely a string is shared with a normal mod.");

        // 3. The injected game.
        HashSet<string>? memoryHits = null, memoryClasses = null;
        int fileHits = 0;
        if (game != null)
        {
            progress?.Invoke($"Reading the memory of {game}…");
            memoryHits = new HashSet<string>(StringComparer.Ordinal);
            memoryClasses = new HashSet<string>(StringComparer.Ordinal);
            var hosts = new HashSet<string>(StringComparer.Ordinal);
            ScanMemory(game.Pid, fromFile.Keys.ToList(), memoryHits, memoryClasses, progress, ct, hosts);
            fileHits = memoryHits.Count;
            if (HiddenCodeKb(game.Pid) is >= 64 and var kb)
                result.Notes.Add($"The game holds {kb:N0} KB of program code that belongs to no file - a hidden native module, which is how clients " +
                                 "written in C/C++ are injected. Their menu text is encrypted, so few or none of their strings can be searched; " +
                                 "any web addresses below are the best string evidence.");
            // Code loaded in the game that no file on disk provides.
            foreach (var c in Unexplained(memoryClasses, clean))
                fromFile.TryAdd(c, StringKind.ClassName);
            // Servers the game sent requests to that are not Mojang's (a mod's own update server is dropped in step 4
            // when the mod's jar names it).
            foreach (var host in hosts)
            {
                fromFile.TryAdd(host, StringKind.WebAddress);
                memoryHits.Add(host);
            }
        }

        // 4. Drop everything a legitimate file has — also as part of a longer string, because a "Contains" search for
        //    net/java/g also hits net/java/games/input/... (a library Minecraft 1.8 ships).
        int before = fromFile.Count;
        progress?.Invoke("Comparing with the clean files…");
        foreach (var t in ContainedIn(fromFile.Keys, clean, ct)) fromFile.Remove(t);
        result.DroppedAsClean = before - fromFile.Count;

        // 5. Optional clean game: drop everything it also has.
        HashSet<string>? cleanGameHits = null;
        if (cleanGame != null)
        {
            progress?.Invoke($"Reading the memory of the clean game {cleanGame}…");
            cleanGameHits = new HashSet<string>(StringComparer.Ordinal);
            ScanMemory(cleanGame.Pid, fromFile.Keys.ToList(), cleanGameHits, null, progress, ct);
            result.DroppedInCleanGame = cleanGameHits.Count;
        }

        var rows = fromFile
            .Where(kv => cleanGameHits == null || !cleanGameHits.Contains(kv.Key))
            .Select(kv => new CheatString(kv.Key, kv.Value, Score(kv.Key, kv.Value),
                InMemory: memoryHits == null ? null : memoryHits.Contains(kv.Key) || memoryClasses!.Contains(kv.Key),
                InCleanGame: cleanGameHits == null ? null : false))
            // With a game scanned, only what was actually found in its memory is evidence.
            .Where(r => r.InMemory != false)
            .OrderByDescending(r => r.InMemory == true).ThenByDescending(r => r.Score).ThenBy(r => r.Text, StringComparer.Ordinal)
            .ToList();
        result.Strings.AddRange(rows.Take(MaxPerResult));
        if (rows.Count > MaxPerResult)
            result.Notes.Add($"{rows.Count:N0} strings qualified; the {MaxPerResult} most telling are listed (found in the game first, then the most cheat-like names).");
        if (game != null && cheatFile != null && fileHits == 0)
            result.Notes.Add("None of the file's strings were found in the game's memory - the client may not be injected into that game, or it decrypts its strings only while in use.");
        return result;
    }

    // ---- the output file ---------------------------------------------------------------------------------

    public static string ToText(CheatStringsResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Cheat strings{(r.ClientName != null ? " - " + r.ClientName : "")}");
        sb.AppendLine($"# Made {DateTime.Now:yyyy-MM-dd HH:mm} by Cheat String Finder (files and memory are only read).");
        if (r.FilePath != null) sb.AppendLine($"# From file: {r.FilePath}  (SHA-256 {r.FileSha256})");
        if (r.GameProcess != null) sb.AppendLine($"# From the injected game: {r.GameProcess}");
        if (r.CleanProcess != null) sb.AppendLine($"# Checked against the clean game: {r.CleanProcess}");
        sb.AppendLine($"# Every string below is in none of the {r.CleanFiles:N0} legitimate mods / game files it was compared with.");
        sb.AppendLine("#");
        sb.AppendLine("# How to search: open System Informer (or Process Hacker) as administrator > double-click javaw.exe > Memory >");
        sb.AppendLine("#   Strings (minimum length 5, tick Extended Unicode) > Filter > Contains, and paste a string.");
        sb.AppendLine("# Search several: one hit can be chance, several from the same list mean the client was loaded in that game.");
        sb.AppendLine("# Confidence: Proven = in the injected game and not in a clean game; Strong = seen in an injected game;");
        sb.AppendLine("#             Likely = from the file only (not yet seen in a running game).");
        foreach (var n in r.Notes) sb.AppendLine($"# Note: {n}");
        foreach (var group in r.Strings.GroupBy(s => s.Confidence).OrderBy(g => g.Key switch { "Proven" => 0, "Strong" => 1, _ => 2 }))
        {
            sb.AppendLine();
            sb.AppendLine($"## {group.Key}");
            foreach (var kind in group.GroupBy(s => s.Kind).OrderBy(k => k.Key))
            {
                sb.AppendLine(kind.Key switch
                {
                    StringKind.ClassName => "# Class names (as the game stores them in memory)",
                    StringKind.WebAddress => "# Web addresses the game sent requests to",
                    _ => "# Text",
                });
                foreach (var s in kind) sb.AppendLine(s.Text);
            }
        }
        return sb.ToString();
    }
}
