using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;

namespace RatChecker.Core;

/// <summary>Everything readable inside a file: text constants, the code it calls, and the names of entries it carries.</summary>
public sealed class RatContent
{
    /// <summary>String constants and text, with where they were found.</summary>
    public List<(string Text, string Where)> Strings { get; } = new();
    /// <summary>Calls and type uses, as "owner/name" (Java: java/net/URLClassLoader.&lt;init&gt;; .NET: System.Net.WebClient.UploadData).</summary>
    public Dictionary<string, string> Refs { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Entries inside an archive (path, first bytes).</summary>
    public List<(string Name, byte[] Head, string Where)> Entries { get; } = new();
    /// <summary>Manifest attributes (Main-Class, Premain-Class …).</summary>
    public Dictionary<string, string> Manifest { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Notes { get; } = new();
    /// <summary>Protectors/packers found by their section names.</summary>
    public List<(string Name, string Where)> Packers { get; } = new();
    /// <summary>Programs, classes or archives found appended after the end of an image.</summary>
    public List<(string What, string Where)> HiddenPayloads { get; } = new();
    public HashSet<string> Sha1s { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? ModInfo { get; set; }
    public string Kind { get; set; } = "File";
    public int Items { get; set; }

    /// <summary>Archive entries locked with a password: their contents can't be checked, only their names.</summary>
    public List<(string Name, string Where)> Locked { get; } = new();
    /// <summary>Archives of a format this tool can't open (RAR, 7-Zip).</summary>
    public List<(string Kind, string Where)> Unopened { get; } = new();
    /// <summary>Entries of no known type whose bytes look encrypted or compressed (entropy ≥ 7.5 bits per byte), with their size.</summary>
    public List<(string Name, int Size, string Where)> Encrypted { get; } = new();
    /// <summary>Every Java class read, with what that one class calls and uses - behaviour is judged per class.</summary>
    public List<JavaClass> Classes { get; } = new();

    public void AddRef(string r, string where) => Refs.TryAdd(r, where);
}

/// <summary>
/// One Java class as read from its constant pool: its name, its parent, the game methods and fields it calls
/// ("net/minecraft/client/player/LocalPlayer.setYRot"), the types it uses, and the names in its annotations
/// (a mixin's target methods).
/// </summary>
public sealed record JavaClass(string Name, string? Super, string Where, HashSet<string> Refs, HashSet<string> Names)
{
    /// <summary>Fields this class's code assigns ("net/minecraft/entity/Entity.field_70177_z").</summary>
    public HashSet<string> Writes { get; init; } = new(StringComparer.Ordinal);
    /// <summary>The types of the fields it declares ("Z", "I", "Ljava/lang/String;") - its shape, whatever its names.</summary>
    public List<string> FieldTypes { get; init; } = new();
    public int MethodCount { get; init; }
    /// <summary>The string constants in its code.</summary>
    public HashSet<string> Texts { get; init; } = new(StringComparer.Ordinal);
    /// <summary>Field → the last text loaded before the code assigned it (a reflected game member's name, a mapped class).</summary>
    public Dictionary<string, string> FieldTexts { get; init; } = new(StringComparer.Ordinal);
}

/// <summary>
/// Reads a file the way an analyst would, without ever running or loading it: jar/zip entries and Java class
/// constant pools, .NET metadata, raw strings of native programs, and script text. Zip bombs and huge files are
/// cut off by fixed limits.
/// </summary>
public static class RatReader
{
    const long MaxFileBytes = 512L * 1024 * 1024;
    const long MaxEntryBytes = 256L * 1024 * 1024; // whole clients ship as one 60-100 MB jar inside a zip
    const long MaxTotalUnpacked = 1024L * 1024 * 1024;
    const int MaxEntries = 100_000;
    const int MaxNesting = 3;
    const int MaxStrings = 400_000;

    static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".json", ".txt", ".properties", ".cfg", ".conf", ".yml", ".yaml", ".toml", ".xml", ".js", ".ps1", ".bat", ".cmd", ".vbs",
        ".py", ".sh", ".mf", ".info", ".mcmeta", ".html", ".ini", ".lua",
    };

    public static RatContent Read(string path)
    {
        var content = new RatContent();
        var info = new FileInfo(path);
        if (info.Length > MaxFileBytes) throw new InvalidDataException($"The file is larger than {MaxFileBytes / 1024 / 1024} MB.");
        byte[] bytes;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            bytes = new byte[fs.Length];
            fs.ReadExactly(bytes);
        }
        return Read(bytes, Path.GetFileName(path), content);
    }

    /// <summary>Reads a file already in memory (used for files inside other files, and by the tests so they leave nothing on disk).</summary>
    public static RatContent Read(byte[] bytes, string name, RatContent? content = null)
    {
        content ??= new RatContent();
        content.Sha1s.Add(Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(bytes)));
        long budget = MaxTotalUnpacked;
        ReadBytes(content, bytes, name, 0, ref budget, top: true);
        return content;
    }

    static void ReadBytes(RatContent c, byte[] bytes, string where, int depth, ref long budget, bool top = false)
    {
        if (IsZip(bytes))
        {
            if (top) c.Kind = where.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) ? "Java mod / jar" : "Zip archive";
            ReadZip(c, bytes, where, depth, ref budget);
        }
        else if (IsPe(bytes))
        {
            ReadPe(c, bytes, where, depth, ref budget, top);
        }
        else if (bytes.AsSpan().StartsWith("Rar!"u8) || bytes.AsSpan().StartsWith((ReadOnlySpan<byte>)[(byte)'7', (byte)'z', 0xBC, 0xAF, 0x27, 0x1C]))
        {
            // RAR and 7-Zip need their own decompressors; guessing at the contents would be worse than saying so.
            string kind = bytes[0] == 'R' ? "RAR archive" : "7-Zip archive";
            if (top) c.Kind = kind;
            c.Notes.Add($"{where}: a {kind} - this tool can't open it. Extract it with 7-Zip and check the extracted files.");
            c.Unopened.Add((kind, where));
        }
        else if (IsClass(bytes))
        {
            if (top) c.Kind = "Java class";
            ReadClass(c, bytes, where);
        }
        else if (ImageEnd(bytes) > 0)
        {
            if (top) c.Kind = "Image";
            AfterImage(c, bytes, where, depth, ref budget);
        }
        else
        {
            if (top) c.Kind = "Script / text";
            AddText(c, Decode(bytes), where);
        }
    }

    static readonly Regex Descriptor = new(@"L([A-Za-z_][\w$]*(?:/[\w$]+)+);", RegexOptions.Compiled);
    static readonly Regex Identifier = new(@"^[A-Za-z_$][\w$]*$", RegexOptions.Compiled);

    static bool IsZip(byte[] b) => b.Length > 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4;
    static bool IsPe(byte[] b) => b.Length > 0x40 && b[0] == 'M' && b[1] == 'Z';
    static bool IsClass(byte[] b) => b.Length > 10 && b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && b[3] == 0xBE;

    // ---- archives ---------------------------------------------------------------------------------

    static void ReadZip(RatContent c, byte[] bytes, string where, int depth, ref long budget)
    {
        ZipArchive zip;
        try { zip = new ZipArchive(new MemoryStream(bytes, writable: false), ZipArchiveMode.Read); }
        catch (InvalidDataException) { c.Notes.Add($"{where}: not a readable zip archive."); return; }
        using (zip)
        {
            int count = 0;
            foreach (var entry in zip.Entries)
            {
                if (++count > MaxEntries) { c.Notes.Add($"{where}: more than {MaxEntries:N0} entries; the rest were skipped."); break; }
                if (entry.FullName.EndsWith('/')) continue;
                string at = depth == 0 ? entry.FullName : $"{where} → {entry.FullName}";
                if (entry.IsEncrypted)
                {
                    c.Locked.Add((entry.FullName, at));
                    c.Entries.Add((entry.FullName, [], at));
                    continue;
                }
                if (entry.Length > MaxEntryBytes || entry.Length > budget)
                {
                    c.Notes.Add($"{at}: too large to unpack ({entry.Length / 1024 / 1024} MB); skipped.");
                    c.Entries.Add((entry.FullName, [], at));
                    continue;
                }
                byte[] data;
                try
                {
                    using var s = entry.Open();
                    using var ms = new MemoryStream();
                    s.CopyTo(ms);
                    data = ms.ToArray();
                }
                catch (Exception e) when (e is InvalidDataException or IOException or NotSupportedException)
                {
                    c.Notes.Add($"{at}: could not be unpacked ({e.Message}).");
                    continue;
                }
                budget -= data.Length;
                c.Items++;
                c.Entries.Add((entry.FullName, data.AsSpan(0, Math.Min(16, data.Length)).ToArray(), at));
                string ext = Path.GetExtension(entry.Name);

                // The file's own manifest - or, for a plain zip, those of the jars it carries. A library bundled inside a
                // jar (Lombok's build agent in a mod) says nothing about the mod.
                if (entry.FullName.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase) && (depth == 0 || depth == 1 && c.Kind == "Zip archive"))
                    ReadManifest(c, Decode(data));
                if (depth == 0 && c.ModInfo == null) c.ModInfo = ModInfo(entry.FullName, Decode(data));

                if (IsClass(data)) ReadClass(c, data, at);
                else if (IsZip(data))
                {
                    c.Sha1s.Add(Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(data)));
                    if (depth + 1 > MaxNesting) c.Notes.Add($"{at}: nested too deep; not opened.");
                    else
                    {
                        c.Notes.Add($"Also scanned the archive inside it: {entry.FullName}");
                        ReadZip(c, data, at, depth + 1, ref budget);
                    }
                }
                else if (IsPe(data)) ReadPe(c, data, at, depth, ref budget, top: false);
                else if (IsDomainList(entry.Name)) continue; // lists every web domain, including upload services; read by HTTP libraries
                else if (ImageExtensions.Contains(ext)) AfterImage(c, data, at, depth, ref budget);
                else if (TextExtensions.Contains(ext) || entry.Name.Length > 0 && !ext.Contains('.') && LooksText(data)) AddText(c, Decode(data), at);
                else if (data.Length >= 4096 && !KnownBinary.Contains(ext) && Entropy(data) >= 7.5) c.Encrypted.Add((entry.FullName, data.Length, at));
            }
        }
    }

    /// <summary>Formats that are compressed by design, so high entropy means nothing (sounds, fonts, archives, natives).</summary>
    static readonly HashSet<string> KnownBinary = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ogg", ".mp3", ".wav", ".ttf", ".otf", ".woff", ".woff2", ".gz", ".xz", ".zst", ".lzma", ".bz2", ".7z", ".rar", ".nbt", ".dat", ".mca",
        ".dll", ".so", ".dylib", ".jnilib", ".bin", ".res", ".ser", ".pack", ".lz4", ".brotli", ".br", ".cer", ".der", ".crt", ".p12", ".jks",
        ".dict", ".icu", ".nrm", ".spp", ".cfu", ".brk", ".bundle", ".mcpack", ".mcmeta",
    };

    /// <summary>Shannon entropy in bits per byte: about 8 for encrypted or compressed data, 4-6 for code and text.</summary>
    static double Entropy(byte[] data)
    {
        Span<int> counts = stackalloc int[256];
        foreach (var x in data) counts[x]++;
        double e = 0;
        foreach (var n in counts)
            if (n > 0) { double p = (double)n / data.Length; e -= p * Math.Log2(p); }
        return e;
    }

    static void ReadManifest(RatContent c, string text)
    {
        foreach (var line in text.Split('\n'))
        {
            int colon = line.IndexOf(':');
            if (colon > 0) c.Manifest[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }
    }

    static string? ModInfo(string name, string text)
    {
        static string? Field(string t, string pattern) => Regex.Match(t, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline) is { Success: true } m ? m.Groups[1].Value.Trim() : null;
        return name.ToLowerInvariant() switch
        {
            "fabric.mod.json" or "quilt.mod.json" => Join(Field(text, "\"name\"\\s*:\\s*\"([^\"]+)\""), Field(text, "\"version\"\\s*:\\s*\"([^\"]+)\""), "Fabric"),
            "meta-inf/mods.toml" or "meta-inf/neoforge.mods.toml" => Join(Field(text, "displayName\\s*=\\s*\"([^\"]+)\""), Field(text, "^\\s*version\\s*=\\s*\"([^\"]+)\""), "Forge"),
            "mcmod.info" => Join(Field(text, "\"name\"\\s*:\\s*\"([^\"]+)\""), Field(text, "\"version\"\\s*:\\s*\"([^\"]+)\""), "Forge (old)"),
            "plugin.yml" or "paper-plugin.yml" => Join(Field(text, "^name:\\s*(.+)$"), Field(text, "^version:\\s*(.+)$"), "Server plugin"),
            _ => null,
        };

        static string? Join(string? n, string? v, string loader) => n == null ? null : $"{n}{(v != null ? " " + v : "")} ({loader})";
    }

    // ---- Java classes: the constant pool holds every string and every call the class makes ---------

    static void ReadClass(RatContent c, byte[] b, string where)
    {
        try
        {
            int count = (b[8] << 8) | b[9];
            var utf8 = new string?[count];
            var classIdx = new int[count];
            var natName = new int[count];
            var natDesc = new int[count];
            var refs = new List<(int Class, int Nat)>();
            var memberRef = new (int Class, int Nat)[count];
            var literals = new List<int>();
            var stringOf = new int[count]; // String constant → its text's UTF-8 entry, for ldc
            int p = 10;
            for (int i = 1; i < count; i++)
            {
                byte tag = b[p++];
                switch (tag)
                {
                    case 1:
                        int len = (b[p] << 8) | b[p + 1];
                        utf8[i] = Encoding.UTF8.GetString(b, p + 2, len);
                        p += 2 + len;
                        break;
                    case 7: classIdx[i] = (b[p] << 8) | b[p + 1]; p += 2; break;
                    case 8: stringOf[i] = (b[p] << 8) | b[p + 1]; literals.Add(stringOf[i]); p += 2; break;
                    case 9: case 10: case 11:
                        memberRef[i] = ((b[p] << 8) | b[p + 1], (b[p + 2] << 8) | b[p + 3]);
                        refs.Add(memberRef[i]); p += 4; break;
                    case 12: natName[i] = (b[p] << 8) | b[p + 1]; natDesc[i] = (b[p + 2] << 8) | b[p + 3]; p += 4; break;
                    case 3: case 4: case 17: case 18: p += 4; break;
                    case 5: case 6: p += 8; i++; break;
                    case 15: p += 3; break;
                    case 16: case 19: case 20: p += 2; break;
                    default: return; // unknown tag: stop rather than misread
                }
            }
            var own = new HashSet<string>(StringComparer.Ordinal);
            foreach (var li in literals)
                if (li > 0 && li < count && utf8[li] is { } s) Add(c, s, where);
            foreach (var (cls, nat) in refs)
            {
                if (cls <= 0 || cls >= count || nat <= 0 || nat >= count) continue;
                if (utf8[classIdx[cls]] is { } owner && utf8[natName[nat]] is { } member)
                {
                    own.Add($"{owner}.{member}");
                    // Obfuscated game classes (no package: ave, bda) reuse one-letter member names for many overloads, so
                    // only the full signature says which member it is: "bda.a (Lwn;Lpk;)V" is attackEntity.
                    if (!owner.Contains('/') && utf8[natDesc[nat]] is { } desc) own.Add($"{owner}.{member} {desc}");
                }
            }
            for (int i = 1; i < count; i++)
                if (classIdx[i] > 0 && classIdx[i] < count && utf8[classIdx[i]] is { } typeName) own.Add(typeName);
            // Types used only in signatures and annotations ("Lorg/checkerframework/.../Nullable;") are not class constants.
            for (int i = 1; i < count; i++)
                if (utf8[i] is { } u && u.Contains("L", StringComparison.Ordinal) && u.Contains(';'))
                    foreach (Match m in Descriptor.Matches(u)) own.Add(m.Groups[1].Value);
            foreach (var r in own) c.AddRef(r, where);

            // This class, its parent, and the plain identifiers it holds (a mixin's @Inject(method = "tick") targets).
            int after = p; // access_flags, this_class, super_class follow the constant pool
            string? Name(int idx) => idx > 0 && idx < count && classIdx[idx] is var u8 && u8 > 0 && u8 < count ? utf8[u8] : null;
            var self = Name((b[after + 2] << 8) | b[after + 3]);
            var super = Name((b[after + 4] << 8) | b[after + 5]);
            var names = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 1; i < count; i++)
                if (utf8[i] is { Length: >= 2 and <= 64 } n && Identifier.IsMatch(n)) names.Add(n);

            // Fields the code assigns (putfield / putstatic): setting the player's rotation or motion is not the same as reading it.
            var writes = new HashSet<string>(StringComparer.Ordinal);
            string? Member(int idx) => idx > 0 && idx < count && memberRef[idx] is var (cl, nt) && cl > 0 && cl < count && nt > 0 && nt < count &&
                                       Name(cl) is { } owner && utf8[natName[nt]] is { } member
                ? owner.Contains('/') ? $"{owner}.{member}" : $"{owner}.{member} {utf8[natDesc[nt]]}"
                : null;
            int q = after + 6;
            q += 2 + 2 * ((b[q] << 8) | b[q + 1]);                          // interfaces
            var fields = new List<string>();
            q = SkipMembers(b, q, utf8, null, fields);                        // fields
            int methods = (b[q] << 8) | b[q + 1];
            var fieldTexts = new Dictionary<string, string>(StringComparer.Ordinal);
            string? Text(int idx) => idx > 0 && idx < count && stringOf[idx] > 0 && stringOf[idx] < count ? utf8[stringOf[idx]] : null;
            SkipMembers(b, q, utf8, code => CodeWrites(code, Member, Text, writes, fieldTexts), null); // methods
            var texts = literals.Where(li => li > 0 && li < count && utf8[li] != null).Select(li => utf8[li]!).ToHashSet(StringComparer.Ordinal);
            if (self != null)
                c.Classes.Add(new JavaClass(self, super, where, own, names)
                { Writes = writes, FieldTypes = fields, MethodCount = methods, Texts = texts, FieldTexts = fieldTexts });
        }
        catch (IndexOutOfRangeException) { c.Notes.Add($"{where}: damaged class file, partly read."); }
        catch (ArgumentOutOfRangeException) { c.Notes.Add($"{where}: damaged class file, partly read."); }
    }

    /// <summary>Walks a field or method table; hands each method's bytecode to <paramref name="onCode"/>. Returns the offset after it.</summary>
    static int SkipMembers(byte[] b, int p, string?[] utf8, Action<ReadOnlyMemory<byte>>? onCode, List<string>? descriptors)
    {
        int n = (b[p] << 8) | b[p + 1];
        p += 2;
        for (int i = 0; i < n; i++)
        {
            int descIdx = (b[p + 4] << 8) | b[p + 5];
            if (descriptors != null && descIdx < utf8.Length && utf8[descIdx] is { } desc) descriptors.Add(desc);
            int attrs = (b[p + 6] << 8) | b[p + 7];
            p += 8;
            for (int a = 0; a < attrs; a++)
            {
                int nameIdx = (b[p] << 8) | b[p + 1];
                int len = (b[p + 2] << 24) | (b[p + 3] << 16) | (b[p + 4] << 8) | b[p + 5];
                if (onCode != null && nameIdx < utf8.Length && utf8[nameIdx] == "Code" && len >= 8)
                {
                    int codeLen = (b[p + 10] << 24) | (b[p + 11] << 16) | (b[p + 12] << 8) | b[p + 13];
                    if (codeLen > 0 && codeLen <= len - 8) onCode(b.AsMemory(p + 14, codeLen));
                }
                p += 6 + len;
            }
        }
        return p;
    }

    /// <summary>
    /// The fields a method's bytecode assigns, and for each the last text loaded before it - a field set from
    /// getDeclaredMethod("func_74507_a") carries that game member. Stops quietly at anything it does not understand.
    /// </summary>
    static void CodeWrites(ReadOnlyMemory<byte> memory, Func<int, string?> member, Func<int, string?> text, HashSet<string> writes, Dictionary<string, string> fieldTexts)
    {
        var code = memory.Span;
        string? lastText = null;
        for (int pc = 0; pc < code.Length; )
        {
            byte op = code[pc];
            if (op == 0x12 && pc + 1 < code.Length) lastText = text(code[pc + 1]) ?? lastText;                          // ldc
            else if (op == 0x13 && pc + 2 < code.Length) lastText = text((code[pc + 1] << 8) | code[pc + 2]) ?? lastText; // ldc_w
            if (op is 0xB5 or 0xB3 && pc + 2 < code.Length && member((code[pc + 1] << 8) | code[pc + 2]) is { } f)
            {
                writes.Add(f);
                if (lastText != null) { fieldTexts.TryAdd(f, lastText); lastText = null; }
            }
            int size = InstructionSize(code, pc);
            if (size <= 0) return;
            pc += size;
        }
    }

    /// <summary>Length of the JVM instruction at <paramref name="pc"/> (JVM spec §6.5), or 0 when it cannot be decoded.</summary>
    static int InstructionSize(ReadOnlySpan<byte> code, int pc)
    {
        byte op = code[pc];
        switch (op)
        {
            case 0x10: case 0x12: case 0xA9: case 0xBC: return 2;                 // bipush, ldc, ret, newarray
            case >= 0x15 and <= 0x19: case >= 0x36 and <= 0x3A: return 2;         // loads / stores with an index
            case 0x11: case 0x13: case 0x14: case 0x84: return 3;                 // sipush, ldc_w, ldc2_w, iinc
            case >= 0x99 and <= 0xA8: case 0xC6: case 0xC7: return 3;             // branches
            case >= 0xB2 and <= 0xB8: case 0xBB: case 0xBD: case 0xC0: case 0xC1: return 3; // field/method refs, new, checkcast …
            case 0xB9: case 0xBA: case 0xC8: case 0xC9: return 5;                 // invokeinterface, invokedynamic, goto_w, jsr_w
            case 0xC5: return 4;                                                  // multianewarray
            case 0xC4: return pc + 1 < code.Length && code[pc + 1] == 0x84 ? 6 : 4; // wide
            case 0xAA:                                                            // tableswitch
            {
                int at = (pc + 4) & ~3;
                if (at + 12 > code.Length) return 0;
                int low = ReadInt(code, at + 4), high = ReadInt(code, at + 8);
                long entries = (long)high - low + 1;
                return entries is < 0 or > 65536 ? 0 : at + 12 + (int)entries * 4 - pc;
            }
            case 0xAB:                                                            // lookupswitch
            {
                int at = (pc + 4) & ~3;
                if (at + 8 > code.Length) return 0;
                int pairs = ReadInt(code, at + 4);
                return pairs is < 0 or > 65536 ? 0 : at + 8 + pairs * 8 - pc;
            }
            case > 0xC9: return 0;                                                // reserved / impdep
            default: return 1;
        }
    }

    static int ReadInt(ReadOnlySpan<byte> b, int p) => (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];

    // ---- Windows programs --------------------------------------------------------------------------

    static void ReadPe(RatContent c, byte[] bytes, string where, int depth, ref long budget, bool top)
    {
        bool managed = false;
        var resources = new List<(string Name, byte[] Data)>();
        try
        {
            using var pe = new PEReader(new MemoryStream(bytes, writable: false));
            if (pe.HasMetadata)
            {
                managed = true;
                var md = pe.GetMetadataReader();
                // Embedded resources: a PowerShell script wrapped into an exe (PS2EXE), bundled DLLs, packed payloads.
                var dir = pe.PEHeaders.CorHeader!.ResourcesDirectory;
                if (dir.Size > 0)
                {
                    var block = pe.GetSectionData(dir.RelativeVirtualAddress);
                    foreach (var h in md.ManifestResources)
                    {
                        var r = md.GetManifestResource(h);
                        if (!r.Implementation.IsNil || r.Offset + 4 > dir.Size) continue;
                        var reader = block.GetReader((int)r.Offset, dir.Size - (int)r.Offset);
                        int len = reader.ReadInt32();
                        if (len > 0 && len <= reader.RemainingBytes && len <= budget) resources.Add((md.GetString(r.Name), reader.ReadBytes(len)));
                    }
                }
                for (var h = MetadataTokens.UserStringHandle(1); !h.IsNil; h = md.GetNextHandle(h))
                    Add(c, md.GetUserString(h), where);
                foreach (var h in md.TypeReferences)
                {
                    var t = md.GetTypeReference(h);
                    c.AddRef($"{md.GetString(t.Namespace)}.{md.GetString(t.Name)}", where);
                }
                foreach (var h in md.MemberReferences)
                {
                    var m = md.GetMemberReference(h);
                    string owner = m.Parent.Kind == HandleKind.TypeReference
                        ? md.GetString(md.GetTypeReference((TypeReferenceHandle)m.Parent).Namespace) + "." + md.GetString(md.GetTypeReference((TypeReferenceHandle)m.Parent).Name)
                        : "";
                    c.AddRef($"{owner}.{md.GetString(m.Name)}", where);
                }
                foreach (var h in md.MethodDefinitions)
                {
                    var m = md.GetMethodDefinition(h);
                    var import = m.GetImport();
                    if (!import.Name.IsNil) c.AddRef(md.GetString(import.Name), where); // P/Invoke into Windows
                }
            }
        }
        catch (Exception e) when (e is BadImageFormatException or InvalidOperationException) { }

        try
        {
            using var headers = new PEReader(new MemoryStream(bytes, writable: false));
            foreach (var section in headers.PEHeaders.SectionHeaders)
                if (Protectors.FirstOrDefault(p => section.Name.StartsWith(p.Section, StringComparison.OrdinalIgnoreCase)) is { Name: not null } hit)
                {
                    c.Packers.Add((hit.Name, where));
                    break;
                }
        }
        catch (Exception e) when (e is BadImageFormatException or InvalidOperationException) { }

        if (top) c.Kind = managed ? ".NET program" : "Windows program";
        // Raw strings catch native imports, URLs and paths in any program, packed or not.
        foreach (var s in Strings(bytes)) Add(c, s, where);
        string all = Encoding.Latin1.GetString(bytes);
        if (all.Contains("PYZ-00.pyz") || all.Contains("_MEIPASS")) c.Notes.Add($"{where}: a Python program packed with PyInstaller — its Python code is compressed inside and only partly readable here.");
        if (all.Contains("UPX0") && all.Contains("UPX1")) c.Notes.Add($"{where}: packed with UPX — most of its code is compressed and only partly readable here.");
        if (all.Contains("AU3!EA06")) c.Notes.Add($"{where}: a compiled AutoIt script (a language used for macros and autoclickers) — its script is stored compressed inside.");

        foreach (var (name, data) in resources)
        {
            string at = $"{where} → {name}";
            budget -= data.Length;
            if (IsZip(data) || IsPe(data) || IsClass(data)) { if (depth + 1 <= MaxNesting) ReadBytes(c, data, at, depth + 1, ref budget); }
            else if (LooksText(data))
            {
                c.Notes.Add($"Also read the text inside it: {name}");
                AddText(c, Decode(data), at);
            }
            else foreach (var s in Strings(data)) Add(c, s, at);
        }
    }

    /// <summary>Section names that commercial protectors and packers give the code they wrap.</summary>
    static readonly (string Section, string Name)[] Protectors =
    [
        (".themida", "Themida"), (".winlice", "WinLicense (Themida)"), (".vmp0", "VMProtect"), (".vmp1", "VMProtect"), (".vmp2", "VMProtect"),
        (".enigma1", "Enigma Protector"), (".enigma2", "Enigma Protector"), (".aspack", "ASPack"), (".adata", "ASPack"),
        (".mpress1", "MPRESS"), (".mpress2", "MPRESS"), (".petite", "Petite"), (".nsp0", "NsPack"), (".boom", "The Boomerang"),
    ];

    static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase) { ".png", ".jpg", ".jpeg", ".gif" };

    /// <summary>
    /// "copy /b picture.png + payload picture.png" hides a whole file after the end of an image: the picture still opens
    /// normally. Anything after the image's end marker is checked for a program, Java class or zip, and read if found.
    /// </summary>
    static void AfterImage(RatContent c, byte[] data, string where, int depth, ref long budget)
    {
        int end = ImageEnd(data);
        if (end <= 0 || data.Length - end < 64) return;
        var tail = data.AsSpan(end);
        int pe = FindPe(tail), cls = FindClass(tail), zip = tail.IndexOf("PK\u0003\u0004"u8);
        if (pe >= 0)
        {
            c.HiddenPayloads.Add(("a Windows program", where));
            ReadPe(c, tail[pe..].ToArray(), where + " (hidden after the image)", depth, ref budget, top: false);
        }
        else if (cls >= 0)
        {
            c.HiddenPayloads.Add(("compiled Java code", where));
            ReadClass(c, tail[cls..].ToArray(), where + " (hidden after the image)");
        }
        else if (zip >= 0 && tail.LastIndexOf("PK\u0005\u0006"u8) > zip && depth + 1 <= MaxNesting)
        {
            c.HiddenPayloads.Add(("a zip / jar archive", where));
            ReadZip(c, tail[zip..].ToArray(), where + " (hidden after the image)", depth + 1, ref budget);
        }
    }

    /// <summary>Offset just past the image's end marker (PNG IEND chunk, last JPEG EOI, GIF trailer), or -1.</summary>
    static int ImageEnd(byte[] b)
    {
        var s = b.AsSpan();
        if (s.StartsWith((ReadOnlySpan<byte>)[0x89, (byte)'P', (byte)'N', (byte)'G']))
        {
            int iend = s.LastIndexOf("IEND"u8);
            return iend < 0 ? -1 : iend + 8; // chunk type + CRC
        }
        if (s.Length > 4 && s[0] == 0xFF && s[1] == 0xD8)
        {
            int eoi = s.LastIndexOf((ReadOnlySpan<byte>)[0xFF, 0xD9]);
            return eoi < 0 ? -1 : eoi + 2;
        }
        if (s.StartsWith("GIF8"u8))
        {
            int trailer = s.LastIndexOf((byte)0x3B);
            return trailer < 0 ? -1 : trailer + 1;
        }
        return -1;
    }

    static int FindPe(ReadOnlySpan<byte> s)
    {
        for (int i = s.IndexOf("MZ"u8); i >= 0 && i + 0x80 < s.Length; )
        {
            if (s.Slice(i, Math.Min(0x200, s.Length - i)).IndexOf("This program cannot be run"u8) > 0) return i;
            int next = s[(i + 2)..].IndexOf("MZ"u8);
            if (next < 0) break;
            i += 2 + next;
        }
        return -1;
    }

    static int FindClass(ReadOnlySpan<byte> s)
    {
        for (int i = s.IndexOf((ReadOnlySpan<byte>)[0xCA, 0xFE, 0xBA, 0xBE]); i >= 0 && i + 10 < s.Length; )
        {
            int major = (s[i + 6] << 8) | s[i + 7];
            if (major is >= 45 and <= 75) return i; // Java 1.1 .. 31
            int next = s[(i + 4)..].IndexOf((ReadOnlySpan<byte>)[0xCA, 0xFE, 0xBA, 0xBE]);
            if (next < 0) break;
            i += 4 + next;
        }
        return -1;
    }

    /// <summary>Printable ASCII and UTF-16LE runs of 5+ characters, like the "strings" tool.</summary>
    internal static IEnumerable<string> Strings(byte[] b)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < b.Length; i++)
        {
            byte x = b[i];
            if (x >= 0x20 && x < 0x7F) sb.Append((char)x);
            else { if (sb.Length >= 5) yield return sb.ToString(); sb.Clear(); }
        }
        if (sb.Length >= 5) yield return sb.ToString();
        sb.Clear();
        for (int i = 0; i + 1 < b.Length; i += 2)
        {
            if (b[i + 1] == 0 && b[i] >= 0x20 && b[i] < 0x7F) sb.Append((char)b[i]);
            else { if (sb.Length >= 5) yield return sb.ToString(); sb.Clear(); }
        }
        if (sb.Length >= 5) yield return sb.ToString();
    }

    // ---- text ---------------------------------------------------------------------------------------

    static void AddText(RatContent c, string text, string where)
    {
        foreach (var line in text.Split('\n'))
            if (line.Trim().Length > 0) Add(c, line.Trim(), where);
    }

    static void Add(RatContent c, string s, string where)
    {
        if (c.Strings.Count < MaxStrings) c.Strings.Add((s, where));
    }

    static bool IsDomainList(string name) =>
        name.Equals("public-suffix-list.txt", StringComparison.OrdinalIgnoreCase) || name.Equals("effective_tld_names.dat", StringComparison.OrdinalIgnoreCase);

    static bool LooksText(byte[] b)
    {
        int n = Math.Min(b.Length, 512);
        for (int i = 0; i < n; i++) if (b[i] == 0) return false;
        return n > 0;
    }

    static string Decode(byte[] b) => HistoryParser.Core.Util.TextDecoding.Decode(b);
}
