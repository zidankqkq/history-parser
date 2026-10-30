using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Util;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// The running game, from the inside: native libraries and JVMTI agents loaded into java(w).exe, code
/// hidden from its module list or mapped in by hand, threads started outside any module (remote-thread
/// injection), and other programs holding handles that can read or write its memory — or the memory of
/// the services that keep execution evidence. Read-only: nothing is written to any process.
/// </summary>
public static class GameProcessAudit
{
    const string Area = "Game process";
    const uint VM_OPERATION = 0x08, VM_READ = 0x10, VM_WRITE = 0x20, CREATE_THREAD = 0x02;

    /// <summary>Native libraries games and mods legitimately extract and load (prefix of the file name).</summary>
    static readonly string[] KnownNatives =
    [
        "lwjgl", "glfw", "openal", "jemalloc", "jinput", "discord", "jna", "jnidispatch", "netty", "sqlite", "zstd", "lz4",
        "snappy", "conscrypt", "libcef", "jcef", "chrome_elf", "icudtl", "rocksdb", "brotli", "oshi", "nvoptimus", "bnative",
        // Simple Voice Chat / Plasmo Voice audio codecs
        "libopus", "liblame", "libspeex", "librnnoise", "opus4j", "lame4j", "speex4j", "rnnoise4j",
    ];

    sealed record Module(string Path, long Base, long Size);

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        var games = new List<(int Pid, string Image)>();
        foreach (var p in Process.GetProcesses())
            using (p)
                if (p.ProcessName is "javaw" or "java" && p.Id != Environment.ProcessId && ProcessAudit.ImagePath(p.Id) is { } image)
                    games.Add((p.Id, image));

        if (games.Count == 0)
            ctx.Route(Area, "Minecraft (java / javaw)", "Not running", CheckState.Unknown,
                "Start the game before scanning to check it for injected code, attached agents and other programs reading its memory.");

        var paths = PathNormalizer.ForThisMachine();
        int items = 0;
        foreach (var (pid, image) in games)
        {
            ct.ThrowIfCancellationRequested();
            items += Inspect(ctx, pid, image, paths);
        }
        items += Handles(ctx, games.Select(g => g.Pid).ToList());
        return items;
    }

    static int Inspect(BypassContext ctx, int pid, string image, PathNormalizer paths)
    {
        string label = $"{Path.GetFileName(image)} (pid {pid})";
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h.IsInvalid)
        {
            ctx.Route(Area, label, "Could not be opened", CheckState.Unknown, "Run as administrator to inspect the game process.");
            return 0;
        }
        bool wow64 = IsWow64Process(h, out var w) && w;
        var modules = Modules(h);
        string jre = Path.GetDirectoryName(Path.GetDirectoryName(image) ?? "") ?? "";
        ctx.Route(Area, label, $"{modules.Count} modules loaded", CheckState.Ok, image, image, WinApi.GetProcessStartUtc(pid));

        int items = 1;
        items += NativeLibraries(ctx, label, modules, jre);
        if (!wow64 && Environment.Is64BitProcess)
        {
            items += HiddenCode(ctx, h, label, modules, paths);
            items += Threads(ctx, pid, label, modules);
        }
        return items;
    }

    /// <summary>Native code outside Windows and the Java runtime: unsigned libraries, JVMTI agents, system DLL names from the wrong folder.</summary>
    static int NativeLibraries(BypassContext ctx, string label, List<Module> modules, string jre)
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        int outside = 0, flagged = 0;
        foreach (var m in modules)
        {
            var name = Path.GetFileName(m.Path);
            bool inWindows = m.Path.StartsWith(windows, StringComparison.OrdinalIgnoreCase);
            bool inJre = jre.Length > 3 && m.Path.StartsWith(jre + "\\", StringComparison.OrdinalIgnoreCase);
            if (inWindows) continue;

            // A system DLL name loaded from anywhere but Windows is a hijack unless Microsoft signed that copy.
            if (HookAudit.HijackNames.Contains(name))
            {
                var hs = FileInspector.Verify(m.Path);
                if (!(hs == SignatureStatus.Signed && (FileInspector.SignerName(m.Path) ?? "").Contains("Microsoft", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.Route(Area, $"{label}: system DLL from the wrong folder: {name}", Display.Signature(hs), CheckState.Bad, "", m.Path);
                    ctx.Flag(Severity.High, FindingCategory.Injection, $"Hijacked system DLL loaded in {label}: {name}",
                        $"The game loaded {name} from {m.Path} instead of from Windows. A copy with a system name placed where the game " +
                        "looks first is a classic way to run code inside it.", m.Path);
                    flagged++;
                    continue;
                }
            }
            if (inJre) continue;
            outside++;

            var agent = AgentExports(m.Path);
            var sig = FileInspector.Verify(m.Path);
            string signer = sig == SignatureStatus.Signed ? FileInspector.SignerName(m.Path) ?? "signed" : Display.Signature(sig);
            if (agent != null)
            {
                bool attached = agent.Contains("Agent_OnAttach");
                ctx.Route(Area, $"{label}: native JVMTI agent {name}", signer, CheckState.Bad, $"Exports {agent}.", m.Path);
                ctx.Flag(sig == SignatureStatus.Signed ? Severity.Medium : Severity.High, FindingCategory.Injection, $"Native Java agent loaded in {label}: {name}",
                    $"{m.Path} exports {agent}, the entry points of a JVMTI agent — native code with full control over the game's classes " +
                    (attached ? "that can be attached to the game after it has started. " : ". ") + $"Signature: {signer}.", m.Path);
                flagged++;
                continue;
            }
            bool known = KnownNatives.Any(k => name.StartsWith(k, StringComparison.OrdinalIgnoreCase));
            if (sig == SignatureStatus.Signed || known)
            {
                ctx.Route(Area, $"{label}: {name}", known && sig != SignatureStatus.Signed ? "Known game/mod library" : signer, CheckState.Ok, "", m.Path);
                continue;
            }
            ctx.Route(Area, $"{label}: unsigned {name}", signer, CheckState.Bad, "Not part of Windows, the Java runtime or a known game library.", m.Path);
            ctx.Flag(Severity.Medium, FindingCategory.Injection, $"Unsigned native library loaded in {label}: {name}",
                $"The game has {m.Path} loaded. It is not part of Windows, the Java runtime or a common game/mod library, and it is not " +
                "signed. Some mods ship native code, and so do many injection clients.", m.Path);
            flagged++;
        }
        ctx.Route(Area, $"{label}: native code", $"{outside} libraries outside Windows and Java, {flagged} flagged",
            flagged > 0 ? CheckState.Bad : CheckState.Ok);
        return outside;
    }

    /// <summary>Names of JVMTI entry points the file exports, or null. A cheap scan of the file's bytes.</summary>
    internal static string? AgentExports(string path)
    {
        byte[] bytes;
        try { bytes = SafeFile.ReadAllBytesShared(path, 64 * 1024 * 1024); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
        var found = new[] { "Agent_OnAttach", "Agent_OnLoad" }.Where(n => bytes.AsSpan().IndexOf(Encoding.ASCII.GetBytes(n + "\0")) >= 0).ToList();
        return found.Count > 0 ? string.Join(", ", found) : null;
    }

    /// <summary>
    /// Executable images the loader does not know about: DLLs unlinked from the module list, and PE files
    /// copied into private memory by hand (manual mapping), which never touch the loader at all.
    /// </summary>
    static int HiddenCode(BypassContext ctx, SafeProcessHandle h, string label, List<Module> modules, PathNormalizer paths)
    {
        var known = modules.Select(m => m.Base).ToHashSet();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var hidden = new HashSet<long>();
        var header = new byte[0x400];
        var name = new char[1024];
        int items = 0;
        long address = 0;
        int size = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        while (VirtualQueryEx(h, (IntPtr)address, out var mbi, (UIntPtr)size) != UIntPtr.Zero)
        {
            long start = (long)mbi.BaseAddress, length = (long)(ulong)mbi.RegionSize;
            if (length <= 0) break;
            address = start + length;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) continue;
            long allocation = (long)mbi.AllocationBase;

            if (mbi.Type == MEM_IMAGE && !known.Contains(allocation) && hidden.Add(allocation))
            {
                int n = GetMappedFileName(h, (IntPtr)allocation, name, name.Length);
                var file = n > 0 ? paths.Normalize(new string(name, 0, n)) : "";
                // Resource-only loads (.mui, LoadLibraryEx as image resource) map Windows files without the loader list.
                if (file.Length == 0 || file.StartsWith(windows, StringComparison.OrdinalIgnoreCase) || file.EndsWith(".mui", StringComparison.OrdinalIgnoreCase)) continue;
                ctx.Route(Area, $"Hidden module: {Path.GetFileName(file)}", $"0x{allocation:X}", CheckState.Bad, "Mapped as code but missing from the module list.", file);
                ctx.Flag(Severity.Medium, FindingCategory.Injection, $"Module hidden from {label}'s module list: {Path.GetFileName(file)}",
                    $"{file} is mapped into the game as an executable image at 0x{allocation:X}, but the game's module list does not include it. " +
                    "Injectors unlink their DLL from that list to hide it; a library loaded only for its resources can also look like this.", file);
                items++;
            }
            else if (mbi.Type == MEM_PRIVATE && start == allocation &&
                     ReadProcessMemory(h, (IntPtr)start, header, (UIntPtr)header.Length, out var read) && (long)(ulong)read >= 0x40 &&
                     LooksLikePe(header, (int)(ulong)read))
            {
                ctx.Route(Area, "Hand-mapped program code", $"0x{start:X} ({length / 1024} KB)", CheckState.Bad,
                    "A complete program image in private memory, where the Windows loader does not put DLLs.");
                ctx.Flag(Severity.High, FindingCategory.Injection, $"Program code mapped by hand into {label}",
                    $"Private memory at 0x{start:X} ({length / 1024:N0} KB) starts with a Windows program header. The Windows loader does not put " +
                    "a DLL there; manual-mapping injectors do (so the DLL appears in no module list and on no disk path), and so do some packers and copy protections.");
                items++;
            }
        }
        return items;
    }

    internal static bool LooksLikePe(byte[] b, int length)
    {
        if (length < 0x40 || b[0] != 'M' || b[1] != 'Z') return false;
        int pe = BitConverter.ToInt32(b, 0x3C);
        return pe > 0 && pe + 4 <= length && b[pe] == 'P' && b[pe + 1] == 'E' && b[pe + 2] == 0 && b[pe + 3] == 0;
    }

    /// <summary>
    /// Threads whose start address is outside every module (shellcode or a hand-mapped DLL), or exactly at
    /// LoadLibrary (CreateRemoteThread injection). The JVM starts all its threads from inside its own DLLs.
    /// </summary>
    static int Threads(BypassContext ctx, int pid, string label, List<Module> modules)
    {
        var loaders = new Dictionary<long, string>();
        foreach (var (dll, fn) in new[] { ("kernel32.dll", "LoadLibraryA"), ("kernel32.dll", "LoadLibraryW"), ("kernel32.dll", "LoadLibraryExA"),
                     ("kernel32.dll", "LoadLibraryExW"), ("kernelbase.dll", "LoadLibraryA"), ("kernelbase.dll", "LoadLibraryW"),
                     ("kernelbase.dll", "LoadLibraryExA"), ("kernelbase.dll", "LoadLibraryExW"), ("ntdll.dll", "LdrLoadDll") })
        {
            var addr = (long)GetProcAddress(GetModuleHandle(dll), fn);
            if (addr != 0) loaders.TryAdd(addr, $"{dll}!{fn}");
        }

        Process process;
        try { process = Process.GetProcessById(pid); }
        catch (ArgumentException) { return 0; }
        int items = 0, checkedThreads = 0;
        using (process)
        {
            foreach (ProcessThread t in process.Threads)
            {
                using (t)
                {
                    using var th = OpenThread(THREAD_QUERY_INFORMATION, false, t.Id);
                    if (th.IsInvalid || NtQueryInformationThread(th, ThreadQuerySetWin32StartAddress, out var startPtr, IntPtr.Size, out _) != 0) continue;
                    long start = (long)startPtr;
                    if (start == 0) continue;
                    checkedThreads++;
                    if (loaders.TryGetValue(start, out var loader))
                    {
                        ctx.Route(Area, $"Thread {t.Id} starts at {loader}", $"0x{start:X}", CheckState.Bad, "A thread created to load a DLL.");
                        ctx.Flag(Severity.High, FindingCategory.Injection, $"DLL-loading thread injected into {label}",
                            $"Thread {t.Id} in the game was started directly at {loader}. That is how CreateRemoteThread injection loads a DLL " +
                            "into another program; the game never starts its own threads there.");
                        items++;
                    }
                    else if (!modules.Any(m => start >= m.Base && start < m.Base + m.Size))
                    {
                        ctx.Route(Area, $"Thread {t.Id} starts outside any module", $"0x{start:X}", CheckState.Bad, "Code with no file behind it.");
                        ctx.Flag(Severity.High, FindingCategory.Injection, $"Thread running injected code in {label}",
                            $"Thread {t.Id} in the game started at 0x{start:X}, which is not inside any loaded DLL. The JVM starts its threads " +
                            "from its own libraries; a start address in bare memory is injected code (Java's attach mechanism does this only " +
                            "for the moment a tool connects).");
                        items++;
                    }
                }
            }
        }
        ctx.Route(Area, $"{label}: threads", $"{checkedThreads} checked, {items} suspicious", items > 0 ? CheckState.Bad : CheckState.Ok);
        return items;
    }

    static List<Module> Modules(SafeProcessHandle h)
    {
        var list = new List<Module>();
        var handles = new IntPtr[4096];
        if (!EnumProcessModulesEx(h, handles, handles.Length * IntPtr.Size, out int needed, LIST_MODULES_ALL)) return list;
        var name = new char[1024];
        for (int i = 0; i < Math.Min(handles.Length, needed / IntPtr.Size); i++)
        {
            int n = GetModuleFileNameEx(h, handles[i], name, name.Length);
            if (n <= 0 || !GetModuleInformation(h, handles[i], out var info, Marshal.SizeOf<MODULEINFO>())) continue;
            list.Add(new Module(new string(name, 0, n), (long)info.lpBaseOfDll, info.SizeOfImage));
        }
        return list;
    }

    // ---- handles held on the game and on the evidence services -------------------------------------

    /// <summary>
    /// Every open handle in the system that points at the game or at a process keeping execution
    /// evidence in memory, with the access it grants. Windows hides kernel object addresses from
    /// non-administrators, so this needs elevation.
    /// </summary>
    static int Handles(BypassContext ctx, List<int> gamePids)
    {
        var targets = new Dictionary<int, string>();
        foreach (var pid in gamePids) targets[pid] = $"the game (pid {pid})";
        foreach (var p in Process.GetProcessesByName("explorer")) using (p) targets.TryAdd(p.Id, "explorer.exe");
        foreach (var svc in new[] { "DPS", "PcaSvc", "SysMain", "EventLog" })
            if (WinApi.QueryService(svc).Pid is > 0 and var spid) targets.TryAdd(spid, $"the {svc} service");

        // Our own handle to each target lets us find the target's kernel object address in the table.
        var own = new Dictionary<long, (int Pid, SafeProcessHandle Handle)>();
        try
        {
            foreach (var pid in targets.Keys)
            {
                var hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hp.IsInvalid) { hp.Dispose(); continue; }
                own[(long)hp.DangerousGetHandle()] = (pid, hp);
            }
            if (own.Count == 0) return 0;

            var entries = HandleTable();
            if (entries == null)
            {
                ctx.Route("Handles", "Open handles", "Could not be read", CheckState.Unknown);
                return 0;
            }
            int self = Environment.ProcessId;
            var objects = new Dictionary<long, int>();
            foreach (var e in entries)
                if (e.Pid == self && own.TryGetValue(e.Handle, out var o) && e.Object != 0) objects[e.Object] = o.Pid;
            if (objects.Count == 0)
            {
                ctx.Route("Handles", "Programs with access to the game", "Needs administrator", CheckState.Unknown,
                    "Windows only shows which process a handle points to when running as administrator.");
                return 0;
            }

            var parents = gamePids.ToDictionary(p => p, ParentPid);
            int items = 0;
            var seen = new HashSet<(int, int)>();
            foreach (var e in entries)
            {
                if (!objects.TryGetValue(e.Object, out var target) || e.Pid == self || e.Pid == target || e.Pid <= 4) continue;
                bool game = gamePids.Contains(target);
                bool write = (e.Access & (VM_WRITE | CREATE_THREAD | VM_OPERATION)) != 0;
                bool read = (e.Access & VM_READ) != 0;
                if (!write && !(game && read)) continue;
                if (!seen.Add((e.Pid, target))) continue;

                var holder = ProcessAudit.ImagePath(e.Pid) ?? $"pid {e.Pid} (protected)";
                string access = string.Join(", ", new[] { write && (e.Access & VM_WRITE) != 0 ? "write memory" : null,
                    (e.Access & CREATE_THREAD) != 0 ? "start threads" : null, read ? "read memory" : null }.Where(s => s != null));
                bool windowsProcess = holder.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase);
                bool launcher = game && parents.TryGetValue(target, out var parent) && parent == e.Pid;
                var sig = windowsProcess || !File.Exists(holder) ? SignatureStatus.WindowsFile : FileInspector.Verify(holder);
                string who = sig == SignatureStatus.Signed ? FileInspector.SignerName(holder) ?? "signed" : Display.Signature(sig);
                // Windows itself, the launcher that started the game, and signed software (antivirus, overlays,
                // recorders) open the game all the time; an unsigned program with that access does not.
                // History Parser and Client Parser read the game's memory while they scan; a verified copy's handle is ours, not the player's.
                bool ours = SelfTraces.Classify(holder) == SelfTraces.Match.Yes;
                bool trusted = windowsProcess || launcher || ours || sig == SignatureStatus.Signed;
                ctx.Route("Handles", $"{Path.GetFileName(holder)} → {targets[target]}", access,
                    trusted ? CheckState.Ok : CheckState.Bad,
                    ours ? $"{SelfTraces.Label} (this suite's own memory read: History Parser or Client Parser)." : launcher ? "The launcher that started the game." : $"{holder} · {who}", holder);
                items++;
                if (trusted) continue;
                ctx.Flag(game && write || !game ? Severity.High : Severity.Medium, FindingCategory.Injection,
                    game ? $"Unsigned program can {(write ? "write to" : "read")} the game's memory: {Path.GetFileName(holder)}"
                         : $"Unsigned program can write to {targets[target]}'s memory: {Path.GetFileName(holder)}",
                    $"{holder} (pid {e.Pid}, {who}) holds an open handle to {targets[target]} with access to {access}. " +
                    (game ? "External cheats read and change the game's memory this way."
                          : "Tools that wipe execution traces from memory (\"string cleaners\") need exactly this access."), holder);
            }
            if (items == 0) ctx.Route("Handles", "Programs with access to the game", "Only the game itself", CheckState.Ok);
            return items;
        }
        finally
        {
            foreach (var (_, h) in own.Values) h.Dispose();
        }
    }

    readonly record struct HandleEntry(long Object, int Pid, long Handle, uint Access);

    static List<HandleEntry>? HandleTable()
    {
        int size = 4 * 1024 * 1024;
        for (int attempt = 0; attempt < 8 && size <= 512 * 1024 * 1024; attempt++)
        {
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                uint status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, size, out int needed);
                if (status == STATUS_INFO_LENGTH_MISMATCH) { size = Math.Max(size * 2, needed + 1024 * 1024); continue; }
                if (status != 0) return null;
                // SYSTEM_HANDLE_INFORMATION_EX: count, reserved, then 40-byte entries (x64).
                long count = Marshal.ReadInt64(buf, 0);
                var list = new List<HandleEntry>((int)Math.Min(count, 4_000_000));
                for (long i = 0; i < count; i++)
                {
                    long off = 16 + i * 40;
                    if (off + 40 > size) break;
                    list.Add(new HandleEntry(Marshal.ReadInt64(buf, (int)off), (int)Marshal.ReadInt64(buf, (int)off + 8),
                        Marshal.ReadInt64(buf, (int)off + 16), (uint)Marshal.ReadInt32(buf, (int)off + 24)));
                }
                return list;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return null;
    }

    static int ParentPid(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return 0;
        var buf = new byte[48];
        // PROCESS_BASIC_INFORMATION (x64): InheritedFromUniqueProcessId at offset 40.
        return NtQueryInformationProcess(h, ProcessBasicInformation, buf, buf.Length, out _) == 0 ? (int)BitConverter.ToInt64(buf, 40) : 0;
    }
}
