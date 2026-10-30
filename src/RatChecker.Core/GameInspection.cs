using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using static HistoryParser.Core.Native.NativeMethods;

namespace RatChecker.Core;

/// <summary>
/// Read-only looks at a running game process for the ways any cheat has to act on it, whatever it is called: threads
/// started in code that belongs to no file, game functions patched to jump elsewhere, other programs holding write or
/// thread access to the game, the game's traffic going through a local proxy, click-through windows drawn over the
/// game, and programs that run from a file that no longer exists. Nothing here changes the game or any other process.
/// </summary>
public static class GameInspection
{
    public sealed record Module(string Path, long Base, long Size)
    {
        public string Name => System.IO.Path.GetFileName(Path);
    }

    public static List<Module> Modules(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.Modules.Cast<ProcessModule>().Select(m => new Module(m.FileName ?? "", (long)m.BaseAddress, m.ModuleMemorySize)).ToList();
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException) { return []; }
    }

    static Module? Owner(List<Module> mods, long address) => mods.FirstOrDefault(m => address >= m.Base && address < m.Base + m.Size);

    /// <summary>What lives at an address: a module's name, or a description of private memory.</summary>
    public static string Describe(SafeProcessHandle h, List<Module> mods, long address)
    {
        if (Owner(mods, address) is { } m) return m.Path;
        if (VirtualQueryEx(h, (IntPtr)address, out var mbi, (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != UIntPtr.Zero)
            return mbi.Type == MEM_PRIVATE ? $"code that belongs to no file (private memory at 0x{address:X})" : $"memory not belonging to a loaded DLL (0x{address:X})";
        return $"0x{address:X}";
    }

    // ---- threads ---------------------------------------------------------------------------------------------------

    /// <summary>
    /// Threads whose start address is in no loaded module. Every thread the JVM, the game or a DLL starts begins in a
    /// module (jvm.dll, ucrtbase, the DLL itself); a thread starting in private memory was started in injected code.
    /// </summary>
    public static List<(int Tid, long Start, string Where)> ForeignThreads(int pid, SafeProcessHandle h, List<Module> mods)
    {
        var list = new List<(int, long, string)>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == (IntPtr)(-1)) return list;
        try
        {
            var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            for (bool ok = Thread32First(snap, ref te); ok; ok = Thread32Next(snap, ref te))
            {
                if (te.th32OwnerProcessID != pid) continue;
                IntPtr th = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
                if (th == IntPtr.Zero) continue;
                try
                {
                    if (NtQueryInformationThread(th, ThreadQuerySetWin32StartAddress, out IntPtr start, IntPtr.Size, IntPtr.Zero) != 0 || start == IntPtr.Zero) continue;
                    if (Owner(mods, (long)start) == null) list.Add(((int)te.th32ThreadID, (long)start, Describe(h, mods, (long)start)));
                }
                finally { CloseHandle(th); }
            }
        }
        finally { CloseHandle(snap); }
        return list;
    }

    // ---- hooks -----------------------------------------------------------------------------------------------------

    /// <summary>DLLs whose functions a client hooks to draw over the game, read input or touch network traffic.</summary>
    static bool HookTarget(string name) =>
        name.Equals("opengl32.dll", StringComparison.OrdinalIgnoreCase) || name.Equals("gdi32.dll", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("gdi32full.dll", StringComparison.OrdinalIgnoreCase) || name.Equals("user32.dll", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("ws2_32.dll", StringComparison.OrdinalIgnoreCase) || name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("glfw", StringComparison.OrdinalIgnoreCase) || name.StartsWith("lwjgl", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Exported functions of those DLLs whose first bytes in the game differ from the file on disk and now jump somewhere
    /// else (an inline hook), with where the jump leads. Every export is compared, not a list of favourites.
    /// </summary>
    public static List<(string Module, string Function, long Target, string TargetWhere)> Hooks(SafeProcessHandle h, List<Module> mods, List<string> notes)
    {
        var list = new List<(string, string, long, string)>();
        foreach (var m in mods.Where(m => HookTarget(m.Name) && File.Exists(m.Path)))
        {
            try
            {
                using var pe = new PEReader(File.OpenRead(m.Path));
                var dir = pe.PEHeaders.PEHeader!.ExportTableDirectory;
                if (dir.Size == 0) continue;
                var exp = pe.GetSectionData(dir.RelativeVirtualAddress).GetReader();
                exp.Offset = 24;
                int functions = exp.ReadInt32(), names = exp.ReadInt32();
                int addrRva = exp.ReadInt32(), nameRva = exp.ReadInt32(), ordRva = exp.ReadInt32();
                var funcRvas = new int[functions];
                var fr = pe.GetSectionData(addrRva).GetReader();
                for (int i = 0; i < functions; i++) funcRvas[i] = fr.ReadInt32();
                var nr = pe.GetSectionData(nameRva).GetReader();
                var or = pe.GetSectionData(ordRva).GetReader();
                var buf = new byte[16];
                for (int i = 0; i < names; i++)
                {
                    int nameAt = nr.ReadInt32();
                    int ordinal = or.ReadUInt16();
                    if (ordinal >= functions) continue;
                    int rva = funcRvas[ordinal];
                    if (rva >= dir.RelativeVirtualAddress && rva < dir.RelativeVirtualAddress + dir.Size) continue; // forwarded
                    var code = pe.GetSectionData(rva);
                    if (code.Length < 16) continue;
                    var onDisk = code.GetReader().ReadBytes(16);
                    if (!ReadProcessMemory(h, (IntPtr)(m.Base + rva), buf, (UIntPtr)16, out _)) continue;
                    if (buf.AsSpan().SequenceEqual(onDisk)) continue;
                    long address = m.Base + rva;
                    long? target = JumpTarget(h, buf, address);
                    if (target is not { } t || JumpTarget(h, onDisk, address) == t) continue; // the file itself starts with this jump
                    if (Owner(mods, t) is { } same && same.Path == m.Path) continue;          // a jump inside the same DLL
                    var name = pe.GetSectionData(nameAt).GetReader();
                    var sb = new StringBuilder();
                    for (byte ch; name.RemainingBytes > 0 && (ch = name.ReadByte()) != 0;) sb.Append((char)ch);
                    list.Add((m.Name, sb.ToString(), t, Describe(h, mods, t)));
                }
            }
            catch (Exception e) when (e is BadImageFormatException or IOException or UnauthorizedAccessException or InvalidOperationException) { }
        }
        return list;
    }

    /// <summary>Where a patched function now jumps: jmp rel32, jmp [rip+x], mov rax, imm64 / jmp rax.</summary>
    static long? JumpTarget(SafeProcessHandle h, byte[] b, long address)
    {
        if (b[0] == 0xE9) return address + 5 + BitConverter.ToInt32(b, 1);
        if (b[0] == 0xFF && b[1] == 0x25)
        {
            long slot = address + 6 + BitConverter.ToInt32(b, 2);
            var q = new byte[8];
            return ReadProcessMemory(h, (IntPtr)slot, q, (UIntPtr)8, out _) ? BitConverter.ToInt64(q, 0) : null;
        }
        if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) return BitConverter.ToInt64(b, 2);
        if (b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF && b[12] == 0xE3) return BitConverter.ToInt64(b, 2); // mov r11 / jmp r11
        return null;
    }

    // ---- other programs with access to the game --------------------------------------------------------------------

    const uint PROCESS_CREATE_THREAD = 0x2, PROCESS_VM_OPERATION = 0x8, PROCESS_VM_WRITE = 0x20;

    /// <summary>
    /// Other processes holding a handle to the game with write, memory-operation or thread-creation rights - what an
    /// external cheat or an injector needs. Needs administrator rights on current Windows (handle addresses are hidden
    /// otherwise); returns null when the system did not tell.
    /// </summary>
    public static List<(int Pid, uint Access)>? WriteHandles(int pid)
    {
        using var mine = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (mine.IsInvalid) return null;
        long myHandle = (long)mine.DangerousGetHandle();
        int me = Environment.ProcessId;
        int size = 1 << 22;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 8; attempt++)
            {
                buf = Marshal.AllocHGlobal(size);
                int status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, size, out int needed);
                if (status == 0) break;
                Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                if ((uint)status != 0xC0000004) return null; // STATUS_INFO_LENGTH_MISMATCH
                size = Math.Max(size * 2, needed + (1 << 20));
            }
            if (buf == IntPtr.Zero) return null;
            long count = Marshal.ReadInt64(buf);
            const int Entry = 40, First = 16;
            long target = 0;
            for (long i = 0; i < count; i++)
            {
                IntPtr e = buf + First + (int)(i * Entry);
                if (Marshal.ReadInt64(e, 8) == me && Marshal.ReadInt64(e, 16) == myHandle) { target = Marshal.ReadInt64(e, 0); break; }
            }
            if (target == 0) return null;
            var holders = new Dictionary<int, uint>();
            for (long i = 0; i < count; i++)
            {
                IntPtr e = buf + First + (int)(i * Entry);
                if (Marshal.ReadInt64(e, 0) != target) continue;
                int owner = (int)Marshal.ReadInt64(e, 8);
                uint access = (uint)Marshal.ReadInt32(e, 24);
                if (owner == me || owner == pid || owner == 4) continue;
                if ((access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) == 0) continue;
                holders[owner] = holders.GetValueOrDefault(owner) | access;
            }
            return holders.Select(kv => (kv.Key, kv.Value)).ToList();
        }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
    }

    // ---- network ---------------------------------------------------------------------------------------------------

    /// <summary>The game's connections to a port on this PC that another process listens on: its traffic goes through a local proxy.</summary>
    public static List<(int Port, int ProxyPid)> LocalProxies(int pid)
    {
        var rows = TcpRows();
        var listeners = rows.Where(r => r.State == 2).GroupBy(r => r.LocalPort).ToDictionary(g => g.Key, g => g.First().Pid);
        return rows.Where(r => r.Pid == pid && r.State == 5 && r.RemoteAddr == 0x0100007F && listeners.TryGetValue(r.RemotePort, out int l) && l != pid)
            .Select(r => (r.RemotePort, listeners[r.RemotePort])).Distinct().ToList();
    }

    internal static List<(uint State, uint LocalAddr, int LocalPort, uint RemoteAddr, int RemotePort, int Pid)> TcpRows()
    {
        var list = new List<(uint, uint, int, uint, int, int)>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
        IntPtr buf = Marshal.AllocHGlobal(size + 4096);
        try
        {
            size += 4096;
            if (GetExtendedTcpTable(buf, ref size, false, 2, 5, 0) != 0) return list;
            int n = Marshal.ReadInt32(buf);
            for (int i = 0; i < n; i++)
            {
                IntPtr r = buf + 4 + i * 24;
                static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
                list.Add(((uint)Marshal.ReadInt32(r), (uint)Marshal.ReadInt32(r, 4), Port(Marshal.ReadInt32(r, 8)),
                          (uint)Marshal.ReadInt32(r, 12), Port(Marshal.ReadInt32(r, 16)), Marshal.ReadInt32(r, 20)));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    // ---- windows over the game -------------------------------------------------------------------------------------

    /// <summary>Visible, click-through, always-on-top windows of other programs that cover the game's window - external overlays.</summary>
    public static List<(int Pid, string Title)> Overlays(int pid)
    {
        var list = new List<(int, string)>();
        IntPtr game = IntPtr.Zero;
        try { using var p = Process.GetProcessById(pid); game = p.MainWindowHandle; } catch (Exception e) when (e is ArgumentException or InvalidOperationException) { }
        if (game == IntPtr.Zero || !GetWindowRect(game, out var g)) return list;
        EnumWindows((hwnd, _) =>
        {
            GetWindowThreadProcessId(hwnd, out uint owner);
            if (owner == pid || !IsWindowVisible(hwnd)) return true;
            long ex = (long)GetWindowLongPtr(hwnd, -20);
            const long Layered = 0x80000, Transparent = 0x20, TopMost = 0x8;
            if ((ex & Layered) == 0 || (ex & Transparent) == 0 || (ex & TopMost) == 0) return true;
            if (!GetWindowRect(hwnd, out var r) || r.Right <= g.Left || r.Left >= g.Right || r.Bottom <= g.Top || r.Top >= g.Bottom) return true;
            if (r.Right - r.Left < 50 || r.Bottom - r.Top < 50) return true;
            var sb = new StringBuilder(256);
            GetWindowText(hwnd, sb, sb.Capacity);
            list.Add(((int)owner, sb.ToString()));
            return true;
        }, IntPtr.Zero);
        return list.Distinct().ToList();
    }

    /// <summary>The process that started this one (for the game: its launcher).</summary>
    public static int ParentPid(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return 0;
        var buf = new byte[48];
        // PROCESS_BASIC_INFORMATION (x64): InheritedFromUniqueProcessId at offset 40.
        return NtQueryInformationProcess(h, 0, buf, buf.Length, out _) == 0 ? (int)BitConverter.ToInt64(buf, 40) : 0;
    }

    /// <summary>The executable path of a process, or null.</summary>
    public static string? ImagePath(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return null;
        var sb = new StringBuilder(1024);
        int len = sb.Capacity;
        return QueryFullProcessImageName(h, 0, sb, ref len) ? sb.ToString() : null;
    }

    // ---- native declarations ---------------------------------------------------------------------------------------

    const uint TH32CS_SNAPTHREAD = 0x4, THREAD_QUERY_INFORMATION = 0x40;
    const int ThreadQuerySetWin32StartAddress = 9, SystemExtendedHandleInformation = 64;

    [StructLayout(LayoutKind.Sequential)]
    struct THREADENTRY32 { public uint dwSize, cntUsage, th32ThreadID, th32OwnerProcessID; public int tpBasePri, tpDeltaPri; public uint dwFlags; }

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int Left, Top, Right, Bottom; }

    delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll")] static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll")] static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr thread, int cls, out IntPtr info, int length, IntPtr returnLength);
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buffer, int length, out int returnLength);
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc proc, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr hwnd, int index);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(SafeProcessHandle h, int flags, StringBuilder name, ref int size);
}
