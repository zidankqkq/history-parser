using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Native;

public sealed record ServiceSnapshot(string Name, bool Exists, int? StartType, string State, int Pid, DateTime? ProcessStartUtc)
{
    public bool IsDisabled => StartType == 4;
    public bool IsRunning => State == "Running";
}

/// <summary>Thin, read-only wrappers over Win32 calls.</summary>
public static class WinApi
{
    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Enables SeDebugPrivilege on our own token (admins hold it, but it is off by default).</summary>
    public static bool TryEnableDebugPrivilege()
    {
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) return false;
        using (token)
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid)) return false;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)
                   && Marshal.GetLastWin32Error() == 0;
        }
    }

    /// <summary>Process creation time; works on protected processes too (limited-information access).</summary>
    public static DateTime? GetProcessStartUtc(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return null;
        return GetProcessTimes(h, out long created, out _, out _, out _) ? Util.FileTime.ToUtc(created) : null;
    }

    public static string? GetCommandLine(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return null;
        NtQueryInformationProcess(h, ProcessCommandLineInformation, new byte[16], 16, out int needed);
        if (needed <= 16 || needed > 1 << 20) return null;
        var buf = new byte[needed];
        if (NtQueryInformationProcess(h, ProcessCommandLineInformation, buf, buf.Length, out _) != 0) return null;
        int length = BitConverter.ToUInt16(buf, 0);          // UNICODE_STRING.Length (bytes)
        int offset = IntPtr.Size == 8 ? 16 : 8;              // text follows the header in the same buffer
        return length > 0 && offset + length <= buf.Length ? System.Text.Encoding.Unicode.GetString(buf, offset, length) : null;
    }

    public static ServiceSnapshot QueryService(string name)
    {
        int? startType = null;
        using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}"))
        {
            if (key == null) return new ServiceSnapshot(name, false, null, "Not installed", 0, null);
            if (key.GetValue("Start") is int s) startType = s;
        }

        string state = "Unknown";
        int pid = 0;
        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm != IntPtr.Zero)
        {
            try
            {
                IntPtr svc = OpenService(scm, name, SERVICE_QUERY_STATUS);
                if (svc != IntPtr.Zero)
                {
                    try
                    {
                        var buf = new byte[36]; // SERVICE_STATUS_PROCESS
                        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, buf, buf.Length, out _))
                        {
                            state = BitConverter.ToUInt32(buf, 4) switch
                            {
                                1 => "Stopped", 2 => "Starting", 3 => "Stopping", 4 => "Running",
                                5 => "Resuming", 6 => "Pausing", 7 => "Paused", var x => $"State {x}",
                            };
                            pid = BitConverter.ToInt32(buf, 28);
                        }
                    }
                    finally { CloseServiceHandle(svc); }
                }
            }
            finally { CloseServiceHandle(scm); }
        }
        return new ServiceSnapshot(name, true, startType, state, pid, pid > 0 ? GetProcessStartUtc(pid) : null);
    }

    public static string StartTypeName(int? startType) => startType switch
    {
        0 => "Boot", 1 => "System", 2 => "Automatic", 3 => "Manual", 4 => "Disabled", null => "Unknown",
        var x => $"Start={x}",
    };

    public static DateTime? GetKeyLastWriteUtc(RegistryKey key) =>
        RegQueryInfoKey(key.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out long ft) == 0 ? Util.FileTime.ToUtc(ft) : null;

    public static string SidToName(string sid)
    {
        try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch (Exception e) when (e is IdentityNotMappedException or ArgumentException or SystemException) { return sid; }
    }

    /// <summary>User hives currently loaded under HKEY_USERS (real users, not the _Classes companions).</summary>
    public static IEnumerable<string> LoadedUserSids() =>
        Registry.Users.GetSubKeyNames()
            .Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !s.EndsWith("_Classes", StringComparison.Ordinal));

    /// <summary>One thread from the system's own process list. Waiting (state 5) for Suspended / WrSuspended (5 / 12) is a suspended thread.</summary>
    public sealed record SystemThread(int Tid, long StartAddress, DateTime? CreatedUtc, uint State, uint WaitReason)
    {
        public bool Suspended => State == 5 && WaitReason is 5 or 12;
    }

    /// <summary>
    /// The threads of a process, read from the system process list (SystemProcessInformation) - no handle to the
    /// process or its threads is opened, so it also works for the System process and protected services. Read-only.
    /// </summary>
    public static List<SystemThread> Threads(int pid)
    {
        var list = new List<SystemThread>();
        int size = 1 << 20;
        for (int attempt = 0; attempt < 6; attempt++, size *= 2)
        {
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint status = NtQuerySystemInformation(5, buf, size, out _);
                if (status == 0xC0000004) continue; // STATUS_INFO_LENGTH_MISMATCH: grow and retry
                if (status != 0) return list;
                // SYSTEM_PROCESS_INFORMATION (x64): NextEntryOffset +0, NumberOfThreads +4, UniqueProcessId +0x50;
                // its SYSTEM_THREAD_INFORMATION array (0x50 bytes each) starts at +0x100.
                long offset = 0;
                while (true)
                {
                    IntPtr entry = buf + (nint)offset;
                    int next = Marshal.ReadInt32(entry, 0), count = Marshal.ReadInt32(entry, 4);
                    if ((long)Marshal.ReadIntPtr(entry, 0x50) == pid)
                    {
                        for (int i = 0; i < count && 0x100 + (i + 1) * 0x50 <= size - offset; i++)
                        {
                            IntPtr t = entry + 0x100 + i * 0x50;
                            list.Add(new SystemThread(
                                Tid: (int)(long)Marshal.ReadIntPtr(t, 48),           // ClientId.UniqueThread
                                StartAddress: (long)Marshal.ReadIntPtr(t, 32),
                                CreatedUtc: Util.FileTime.ToUtc(Marshal.ReadInt64(t, 16)),
                                State: (uint)Marshal.ReadInt32(t, 68),
                                WaitReason: (uint)Marshal.ReadInt32(t, 72)));
                        }
                        return list;
                    }
                    if (next == 0) return list;
                    offset += next;
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return list;
    }

    /// <summary>Where a kernel driver (e.g. "bam.sys") sits in memory: from its base to the next driver's base. Needs administrator.</summary>
    public static (long Start, long End)? DriverRange(string fileName)
    {
        var bases = new IntPtr[2048];
        if (!EnumDeviceDrivers(bases, bases.Length * IntPtr.Size, out int needed)) return null;
        var loaded = bases.Take(Math.Min(bases.Length, needed / IntPtr.Size)).Where(b => b != IntPtr.Zero).Select(b => (long)b).Order().ToList();
        var name = new char[260];
        foreach (var b in loaded)
        {
            int n = GetDeviceDriverFileName((IntPtr)b, name, name.Length);
            if (n <= 0 || !new string(name, 0, n).EndsWith("\\" + fileName, StringComparison.OrdinalIgnoreCase)) continue;
            long end = loaded.FirstOrDefault(x => x > b, b + (16 << 20));
            return (b, end);
        }
        return null;
    }
}

public static class BootInfo
{
    public static DateTime StartUtc => DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

    public static string Describe()
    {
        var age = DateTime.UtcNow - StartUtc;
        string ago = age.TotalHours < 48 ? $"{age.TotalHours:0.#} hours ago" : $"{age.TotalDays:0.#} days ago";
        return $"This boot began {StartUtc.ToLocalTime():d MMM, HH:mm}  ·  {ago}";
    }
}
