using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Util;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Is each running program still the file the records say it is?
/// <para>
/// Every execution record (Prefetch, BAM, the process list itself) names the file a process was started from. Process
/// hollowing uses that: a normal program is started, its code is replaced in memory, and the cheat runs under the normal
/// program's name with nothing of its own in the records. The file on disk stays clean, so only the memory can show it.
/// </para>
/// Four things are compared for every process that can be opened, each a thing Windows itself never does:
/// <list type="bullet">
/// <item>The program's base address must be backed by its file. Private memory there is the classic hollow (unmap, allocate, write).</item>
/// <item>The header in memory must be the header of the file that is mapped there (herpaderping, overwriting in place).</item>
/// <item>Code sections the file marks read-only must still hold the file's code (overwriting, stomping). Small patches are
/// hooks and are ignored; a program that unpacks or decrypts itself is recognised from its own file and not compared.</item>
/// <item>The file mapped at the base must be the file the process was created from (a second image mapped in and swapped).</item>
/// </list>
/// Read-only: memory is read, never written; nothing is suspended, injected or dumped to disk. Protected processes cannot
/// be opened by any user-mode program and are counted as not checked, never as clean.
/// </summary>
public static class ProcessImageAudit
{
    const int HeaderBytes = 0x1000;
    const int Block = 64;                 // code is compared in blocks of this many bytes
    const int ReplacedBlock = 56;         // a block counts as replaced when this many of its bytes differ
    const int ReportFrom = 2 * Block;     // less than this is a hook or a patch, not replaced code
    const long MaxCodeBytes = 48L * 1024 * 1024;

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        WinApi.TryEnableDebugPrivilege();
        var paths = PathNormalizer.ForThisMachine();
        // What the change journal says happened to each program file, to tell an update while running from a swap.
        var journal = ctx.History.Timeline.Where(e => e.Source == EvidenceSource.UsnJournal && e.TimeUtc.HasValue).ToList();
        DateTime? journalFrom = journal.Count > 0 ? journal.Min(e => e.TimeUtc) : null;
        var changes = journal.Where(e => e.Kind is EvidenceKind.Created or EvidenceKind.Renamed or EvidenceKind.Modified or EvidenceKind.Deleted)
            .ToLookup(e => PathNormalizer.Key(e.Path), e => e.TimeUtc!.Value);

        int looked = 0, closed = 0, bare = 0, problems = 0, selfChanging = 0;
        var ids = Process.GetProcesses().Select(p => { using (p) return p.Id; }).Where(id => id is not (0 or 4)).ToList(); // Idle and System have no program file
        Parallel.ForEach(ids, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 4, 8), CancellationToken = ct }, id =>
        {
            var seen = Look(id);
            if (seen == null) { Interlocked.Increment(ref closed); return; }
            if (seen.NoImage) { Interlocked.Increment(ref bare); return; }
            Interlocked.Increment(ref looked);
            string dos = paths.Normalize(seen.StartedAs);
            var judged = Judge(seen, start => journalFrom is { } from && from <= start,
                start => changes[PathNormalizer.Key(dos)].Any(t => t > start.AddSeconds(-5)));
            if (judged == null) return;
            if (judged.Severity <= Severity.Low) { Interlocked.Increment(ref selfChanging); return; }
            Interlocked.Increment(ref problems);
            ctx.Flag(judged.Severity, FindingCategory.Process, judged.Title, judged.Detail, seen.Path ?? dos, seen.StartedUtc);
        });

        ctx.Check("Processes", "Running programs match their files",
            problems > 0 ? CheckState.Bad : looked == 0 ? CheckState.Unknown : CheckState.Ok,
            $"{looked} running programs compared with their files in memory: {(problems == 0 ? "all match" : $"{problems} do not")}." +
            (selfChanging > 0 ? $" {selfChanging} unpack or decrypt themselves and cannot be compared." : "") +
            (closed > 0 ? $" {closed} could not be opened (protected by Windows{(WinApi.IsElevated() ? "" : ", or owned by another account - run as administrator")})." : "") +
            (bare > 0 ? $" {bare} have no program file (Windows' own memory and registry processes)." : ""));
        return looked;
    }

    // ---- what one process looks like ---------------------------------------------------------------

    /// <summary>What was read from one process. Everything <see cref="Judge"/> needs, so the judging can be tested without a process.</summary>
    internal sealed record Seen
    {
        public int Pid { get; init; }
        public string Name { get; init; } = "";
        /// <summary>The file Windows created the process from, as the kernel recorded it then (device path).</summary>
        public string StartedAs { get; init; } = "";
        /// <summary>The same as a normal path, when Windows gives one.</summary>
        public string? Path { get; init; }
        public DateTime? StartedUtc { get; init; }
        public long ImageBase { get; init; }
        /// <summary>True for a process with no program in it (no PEB, or no base address).</summary>
        public bool NoImage { get; init; }
        /// <summary>True when the base address is backed by a file's image, as Windows loads every program.</summary>
        public bool BackedByImage { get; init; }
        /// <summary>The file mapped at the base address now (device path), or null when Windows cannot name one.</summary>
        public string? Mapped { get; init; }
        public PeImage? Memory { get; init; }
        public PeImage? Disk { get; init; }
        /// <summary>Bytes of read-only code that no longer match the file, and where the first of them is.</summary>
        public int ReplacedCode { get; init; }
        public string ReplacedIn { get; init; } = "";
        /// <summary>The mapped file is not the file at the path the process was started from (compared by file identity).</summary>
        public bool OtherFile { get; init; }
        /// <summary>The file now at that path, when it is another one: null if nothing is there.</summary>
        public DateTime? PathFileCreatedUtc { get; init; }
        public DateTime? PathFileWrittenUtc { get; init; }
        public bool PathFileExists { get; init; }
        /// <summary>The file on disk is validly signed by Microsoft itself.</summary>
        public bool MicrosoftFile { get; init; }
    }

    internal sealed record Judgement(Severity Severity, string Title, string Detail);

    /// <summary>
    /// One finding for a process, or null when it is what it says it is. <paramref name="journalCovers"/> says whether the
    /// change journal reaches back to a time; <paramref name="pathChangedSince"/> whether it shows the started-from path
    /// being written, replaced or renamed since then.
    /// </summary>
    internal static Judgement? Judge(Seen p, Func<DateTime, bool> journalCovers, Func<DateTime, bool> pathChangedSince)
    {
        string who = $"{p.Name} (PID {p.Pid})";
        string started = p.StartedUtc is { } s ? $", started {When.L(s)}" : "";
        const string explain = " Process hollowing does this: a normal program is started and its code is replaced in memory, so every record " +
                               "names the normal program while something else runs.";

        if (!p.BackedByImage)
            return new Judgement(Severity.High, $"Hollowed process: {who}",
                $"{p.Path ?? p.StartedAs}{started}: the memory at its base address (0x{p.ImageBase:X}) is not its program file but memory that was " +
                "allocated and written at run time. Windows always maps a program from its file; it never loads one this way." + explain);

        if (p.Memory == null)
            return new Judgement(p.MicrosoftFile ? Severity.High : Severity.Medium, $"Program header wiped in memory: {who}",
                $"{p.Path ?? p.StartedAs}{started}: the start of its image in memory no longer holds a program header. Windows leaves the header in " +
                "place; replaced or self-hiding code wipes it so the image cannot be compared or dumped." +
                (p.MicrosoftFile ? " The file on disk is Microsoft's own, which never does this." : " A few protected programs do this too."));

        if (p.Disk != null)
        {
            // A packed or encrypted program rewrites itself as it starts; its file says so (writable code, packer sections).
            bool selfChanging = p.Disk.ChangesItself;
            var differences = HeaderDifferences(p.Disk, p.Memory);
            if (differences.Count > 0)
                return selfChanging
                    ? new Judgement(Severity.Low, $"Program rewrites itself in memory: {who}", "A packed or protected program; it cannot be compared with its file.")
                    : new Judgement(Severity.High, $"Process image is not its file: {who}",
                        $"{p.Path ?? p.StartedAs}{started}: the program in memory is not the file it is mapped from ({string.Join("; ", differences)}). " +
                        "Windows does not let a mapped program file be changed, and the loader never alters these fields." + explain);
            if (p.ReplacedCode >= ReportFrom && !selfChanging)
                return new Judgement(p.MicrosoftFile ? Severity.High : Severity.Medium, $"Program code replaced in memory: {who}",
                    $"{p.Path ?? p.StartedAs}{started}: {p.ReplacedCode:N0} bytes of code in {p.ReplacedIn} no longer match the file, in a section the " +
                    "file marks read-only. A hook changes a few bytes; this is code written over the program's own." +
                    (p.MicrosoftFile ? " The file is Microsoft's own, which never rewrites itself." + explain
                                     : " Copy-protected programs that decrypt themselves at run time can look like this; a hollowed or overwritten program does too."));
        }

        if (p.OtherFile && p.Mapped != null)
        {
            // An updater renames a running program and puts the new version in its place: then the path holds a newer file.
            if (!p.PathFileExists || p.StartedUtc is not { } start) return null;
            bool newer = p.PathFileCreatedUtc > start.AddSeconds(-5) || p.PathFileWrittenUtc > start.AddSeconds(-5) || pathChangedSince(start);
            if (newer) return null;
            bool certain = journalCovers(start);
            return new Judgement(certain ? Severity.High : Severity.Medium, $"Process runs another file's image: {who}",
                $"Windows created this process from {p.StartedAs}{started}, and that file is still there, unchanged since before then. But the image " +
                $"at its base address is mapped from a different file: {p.Mapped}. " +
                (certain ? "The change journal covers the whole time and shows no update or rename of the program, so its image was swapped after it started." + explain
                         : "The change journal does not reach back to when it started, so a program that updated itself while running cannot be ruled out."));
        }
        return null;
    }

    // ---- program headers ---------------------------------------------------------------------------

    internal sealed record PeSection(string Name, uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics)
    {
        public bool Executable => (Characteristics & 0x20000000) != 0;
        public bool Writable => (Characteristics & 0x80000000) != 0;
    }

    /// <summary>The parts of a program's header that matter here. <see cref="Managed"/>: a .NET program, whose header Windows adjusts as it loads.</summary>
    internal sealed record PeImage(ushort Machine, uint TimeStamp, uint EntryPoint, uint SizeOfImage, bool Managed, (uint Rva, uint Size) ImportAddresses,
        IReadOnlyList<PeSection> Sections)
    {
        static readonly string[] Packers = ["UPX", ".vmp", ".themida", ".winlice", ".enigma", ".aspack", ".MPRESS", ".petite", ".nsp"];

        /// <summary>The file itself says its code is rewritten at run time: code sections that are writable or empty on disk, or a packer's sections.</summary>
        public bool ChangesItself => Sections.Any(s => s.Executable && (s.Writable || s.RawSize == 0) ||
                                                       Packers.Any(p => s.Name.StartsWith(p, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>Reads the header at the start of a program file or image. Null when it is not one.</summary>
    internal static PeImage? ParseHeader(ReadOnlySpan<byte> h)
    {
        if (h.Length < 0x100 || h[0] != 'M' || h[1] != 'Z') return null;
        int pe = BitConverter.ToInt32(h[0x3C..]);
        if (pe < 0x40 || pe > h.Length - 0x108 || h[pe] != 'P' || h[pe + 1] != 'E' || h[pe + 2] != 0 || h[pe + 3] != 0) return null;
        ushort machine = BitConverter.ToUInt16(h[(pe + 4)..]);
        int sectionCount = BitConverter.ToUInt16(h[(pe + 6)..]);
        uint stamp = BitConverter.ToUInt32(h[(pe + 8)..]);
        int optionalSize = BitConverter.ToUInt16(h[(pe + 20)..]);
        int opt = pe + 24;
        ushort magic = BitConverter.ToUInt16(h[opt..]);
        if (magic is not (0x10B or 0x20B) || sectionCount > 96) return null;
        bool plus = magic == 0x20B;
        uint entry = BitConverter.ToUInt32(h[(opt + 16)..]);
        uint size = BitConverter.ToUInt32(h[(opt + 56)..]);
        int directories = opt + (plus ? 112 : 96);
        int directoryCount = (int)Math.Min(16u, BitConverter.ToUInt32(h[(opt + (plus ? 108 : 92))..]));
        static (uint Rva, uint Size) Directory(ReadOnlySpan<byte> header, int first, int count, int index) =>
            index < count && first + index * 8 + 8 <= header.Length
                ? (BitConverter.ToUInt32(header[(first + index * 8)..]), BitConverter.ToUInt32(header[(first + index * 8 + 4)..])) : (0u, 0u);
        var imports = Directory(h, directories, directoryCount, 12);       // the table of imported functions' addresses
        bool managed = Directory(h, directories, directoryCount, 14).Size > 0; // a .NET program carries a CLR header

        var sections = new List<PeSection>(sectionCount);
        int table = opt + optionalSize;
        for (int i = 0; i < sectionCount; i++)
        {
            int at = table + i * 40;
            if (at + 40 > h.Length) return null;
            string name = System.Text.Encoding.ASCII.GetString(h.Slice(at, 8)).TrimEnd('\0');
            sections.Add(new PeSection(name, BitConverter.ToUInt32(h[(at + 12)..]), BitConverter.ToUInt32(h[(at + 8)..]),
                BitConverter.ToUInt32(h[(at + 20)..]), BitConverter.ToUInt32(h[(at + 16)..]), BitConverter.ToUInt32(h[(at + 36)..])));
        }
        return new PeImage(machine, stamp, entry, size, managed, imports, sections);
    }

    /// <summary>
    /// Fields that differ between the file and the image in memory, out of those the loader never touches: when it was built,
    /// and how its sections are laid out. For a native program also where it starts and how big it is (Windows adjusts those
    /// two, and the header format, when it loads a .NET program).
    /// </summary>
    internal static List<string> HeaderDifferences(PeImage disk, PeImage memory)
    {
        var differences = new List<string>();
        if (disk.TimeStamp != memory.TimeStamp) differences.Add($"built {disk.TimeStamp:X8} on disk, {memory.TimeStamp:X8} in memory");
        if (disk.Sections.Count != memory.Sections.Count)
            differences.Add($"{disk.Sections.Count} sections on disk, {memory.Sections.Count} in memory");
        else
            for (int i = 0; i < disk.Sections.Count; i++)
            {
                var (d, m) = (disk.Sections[i], memory.Sections[i]);
                if (d.Name == m.Name && d.VirtualAddress == m.VirtualAddress && d.VirtualSize == m.VirtualSize) continue;
                differences.Add($"section {i + 1} is \"{d.Name}\" at 0x{d.VirtualAddress:X} on disk, \"{m.Name}\" at 0x{m.VirtualAddress:X} in memory");
                break;
            }
        if (!disk.Managed && !memory.Managed)
        {
            if (disk.EntryPoint != memory.EntryPoint) differences.Add($"starts at 0x{disk.EntryPoint:X} on disk, 0x{memory.EntryPoint:X} in memory");
            if (disk.SizeOfImage != memory.SizeOfImage) differences.Add($"0x{disk.SizeOfImage:X} bytes on disk, 0x{memory.SizeOfImage:X} in memory");
        }
        return differences;
    }

    // ---- code ----------------------------------------------------------------------------------------

    /// <summary>
    /// How many bytes of <paramref name="memory"/> hold different code from <paramref name="disk"/>, counted in whole blocks
    /// that differ almost entirely. Loading a program changes addresses inside its code (at most half the bytes of any
    /// stretch) and a hook changes a handful, so neither reaches a whole block; code written over code changes nearly all of
    /// it. <paramref name="skip"/> is a range the loader fills in itself (the table of imported functions).
    /// </summary>
    internal static (int Bytes, int FirstAt) ReplacedCode(ReadOnlySpan<byte> disk, ReadOnlySpan<byte> memory, (int Start, int End) skip = default)
    {
        int length = Math.Min(disk.Length, memory.Length), replaced = 0, first = -1;
        for (int at = 0; at + Block <= length; at += Block)
        {
            if (at < skip.End && at + Block > skip.Start) continue;
            int different = 0;
            for (int i = at; i < at + Block; i++) if (disk[i] != memory[i]) different++;
            if (different < ReplacedBlock) continue;
            replaced += Block;
            if (first < 0) first = at;
        }
        return (replaced, first);
    }

    /// <summary>Bits per byte, 0 to 8. Compiled code sits around 6; compressed or encrypted data is close to 8.</summary>
    internal static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (byte b in data) counts[b]++;
        double bits = 0;
        foreach (int c in counts)
        {
            if (c == 0) continue;
            double p = (double)c / data.Length;
            bits -= p * Math.Log2(p);
        }
        return bits;
    }

    // ---- reading a live process ------------------------------------------------------------------------

    static bool Read(SafeProcessHandle h, long address, byte[] buffer, int count) =>
        ReadProcessMemory(h, (IntPtr)address, buffer, (UIntPtr)(uint)count, out var read) && (long)(ulong)read == count;

    const uint StillActive = 259;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    /// <summary>Whether the process behind the handle is still running. When Windows will not say, it is taken as running, so nothing is passed over for that.</summary>
    static bool StillRunning(SafeProcessHandle h) => !GetExitCodeProcess(h, out uint code) || code == StillActive;

    /// <summary>Null when the process cannot be opened (protected, or another account's without administrator rights).</summary>
    internal static Seen? Look(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) return null;
        string name = "";
        try { using var p = Process.GetProcessById(pid); name = p.ProcessName; }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException) { }

        // PROCESS_BASIC_INFORMATION: PebBaseAddress at +8. PEB (64-bit, also for 32-bit programs): ImageBaseAddress at +0x10.
        var basic = new byte[48];
        if (NtQueryInformationProcess(h, ProcessBasicInformation, basic, basic.Length, out _) != 0) return null;
        long peb = BitConverter.ToInt64(basic, 8);
        var pointer = new byte[8];
        if (peb == 0) return new Seen { Pid = pid, Name = name, NoImage = true };
        if (!Read(h, peb + 0x10, pointer, 8)) return null;
        long imageBase = BitConverter.ToInt64(pointer, 0);
        if (imageBase == 0) return new Seen { Pid = pid, Name = name, NoImage = true };

        string startedAs = KernelImageName(h) ?? "";
        string? path = Win32Name(h);
        if (name.Length == 0) name = System.IO.Path.GetFileNameWithoutExtension(path ?? startedAs);
        if (startedAs.Length == 0) return null;

        bool image = VirtualQueryEx(h, (IntPtr)imageBase, out var mbi, (UIntPtr)(uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != UIntPtr.Zero &&
                     mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE;
        // A program that ended while it was being looked at has no memory left to ask about. That is "not checked",
        // never "hollowed": programs start and end all the time during a scan.
        if (!image && !StillRunning(h)) return null;
        var seen = new Seen
        {
            Pid = pid, Name = name, StartedAs = startedAs, Path = path, StartedUtc = WinApi.GetProcessStartUtc(pid), ImageBase = imageBase,
            BackedByImage = image, MicrosoftFile = path != null && SignatureTrust.Of(path).IsMicrosoft,
        };
        if (!image) return seen;

        var mappedName = new char[1024];
        int length = GetMappedFileName(h, (IntPtr)imageBase, mappedName, mappedName.Length);
        string? mapped = length > 0 ? new string(mappedName, 0, length) : null;

        var header = new byte[HeaderBytes];
        bool headerRead = Read(h, imageBase, header, HeaderBytes);
        if (!headerRead && !StillRunning(h)) return null; // ended meanwhile: a read that fails for that reason is not a wiped header
        var memory = headerRead ? ParseHeader(header) : null;
        seen = seen with { Mapped = mapped, Memory = memory };
        if (memory == null) return seen;

        // The file to compare with is the one mapped there now - after an update that is the renamed old version, which is
        // the right one. Opened by its device path, so no drive letter is needed.
        string file = @"\\?\GLOBALROOT" + (mapped ?? startedAs);
        try
        {
            using var disk = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var diskHeader = new byte[HeaderBytes];
            int got = disk.ReadAtLeast(diskHeader, HeaderBytes, throwOnEndOfStream: false);
            var onDisk = ParseHeader(diskHeader.AsSpan(0, got));
            seen = seen with { Disk = onDisk };
            if (onDisk != null && HeaderDifferences(onDisk, memory).Count == 0 && !onDisk.ChangesItself)
            {
                var (bytes, where) = CompareCode(h, imageBase, disk, onDisk);
                seen = seen with { ReplacedCode = bytes, ReplacedIn = where };
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }

        if (mapped != null && !mapped.Equals(startedAs, StringComparison.OrdinalIgnoreCase))
        {
            var (now, _, _) = Identity(@"\\?\GLOBALROOT" + mapped);
            var (atPath, created, written) = Identity(@"\\?\GLOBALROOT" + startedAs);
            seen = seen with
            {
                OtherFile = now == null || atPath != now, PathFileExists = atPath != null, PathFileCreatedUtc = created, PathFileWrittenUtc = written,
            };
        }
        return seen;
    }

    /// <summary>Compares every read-only code section of the image in memory with the same bytes of the file.</summary>
    static (int Bytes, string Where) CompareCode(SafeProcessHandle h, long imageBase, FileStream disk, PeImage image)
    {
        int total = 0;
        string where = "";
        long budget = MaxCodeBytes;
        foreach (var section in image.Sections.Where(s => s.Executable && !s.Writable && s.RawSize > 0))
        {
            int size = (int)Math.Min(Math.Min(section.RawSize, section.VirtualSize == 0 ? section.RawSize : section.VirtualSize), budget);
            if (size < Block || section.RawOffset + (long)size > disk.Length) continue;
            budget -= size;
            var onDisk = new byte[size];
            disk.Position = section.RawOffset;
            if (disk.ReadAtLeast(onDisk, size, throwOnEndOfStream: false) != size) continue;
            // Encrypted or compressed on disk: the program decrypts itself, so memory is meant to differ.
            if (Entropy(onDisk.AsSpan(0, Math.Min(size, 1 << 20))) > 7.2) continue;

            // Memory is read page by page; a page that cannot be read (paged out and its file gone) is left as the file's bytes.
            var inMemory = (byte[])onDisk.Clone();
            var page = new byte[0x1000];
            for (int at = 0; at < size; at += 0x1000)
            {
                int count = Math.Min(0x1000, size - at);
                if (Read(h, imageBase + section.VirtualAddress + at, page, count)) Buffer.BlockCopy(page, 0, inMemory, at, count);
            }
            // The loader writes the addresses of imported functions into their table; that range is its own.
            var skip = image.ImportAddresses.Size > 0 && image.ImportAddresses.Rva >= section.VirtualAddress
                ? ((int)(image.ImportAddresses.Rva - section.VirtualAddress), (int)(image.ImportAddresses.Rva - section.VirtualAddress + image.ImportAddresses.Size))
                : default;
            var (bytes, first) = ReplacedCode(onDisk, inMemory, skip);
            if (bytes == 0) continue;
            if (total == 0) where = $"section \"{section.Name}\" (first at 0x{section.VirtualAddress + first:X})";
            total += bytes;
        }
        return (total, where);
    }

    /// <summary>Which file this is (volume and file number), and when it was created and last written. Null identity when it cannot be opened.</summary>
    static (string? Id, DateTime? CreatedUtc, DateTime? WrittenUtc) Identity(string path)
    {
        try
        {
            using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(file, out var info)) return (null, null, null);
            return ($"{info.VolumeSerialNumber:X8}:{info.FileIndexHigh:X8}{info.FileIndexLow:X8}", FileTime.ToUtc(info.CreationTime), FileTime.ToUtc(info.LastWriteTime));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return (null, null, null); }
    }

    /// <summary>The file the kernel created the process from, as it recorded it then: \Device\HarddiskVolume3\Windows\System32\notepad.exe.</summary>
    static string? KernelImageName(SafeProcessHandle h)
    {
        var buffer = new byte[2048];
        if (NtQueryInformationProcess(h, ProcessImageFileName, buffer, buffer.Length, out _) != 0) return null;
        int length = BitConverter.ToUInt16(buffer, 0);
        return length > 0 && 16 + length <= buffer.Length ? System.Text.Encoding.Unicode.GetString(buffer, 16, length) : null;
    }

    static string? Win32Name(SafeProcessHandle h)
    {
        var name = new char[1024];
        int size = name.Length;
        return QueryFullProcessImageName(h, 0, name, ref size) && size > 0 ? new string(name, 0, size) : null;
    }
}
