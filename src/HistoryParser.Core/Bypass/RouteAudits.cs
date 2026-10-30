using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Ways to get code into the kernel before or below Windows' own checks: driver signature enforcement
/// switched off, test signing, a kernel debugger, Secure Boot off, the vulnerable-driver blocklist off,
/// drivers registered to start from odd folders, and drivers Windows itself refused to load.
/// </summary>
public static class BootAudit
{
    const string Area = "Boot";
    const int CI_ENABLED = 0x01, CI_TESTSIGN = 0x02, CI_DEBUGMODE = 0x80, CI_FLIGHTING = 0x200, CI_HVCI = 0x400;

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        CodeIntegrity(ctx);
        KernelDebugger(ctx);
        SecureBoot(ctx);
        DriverBlocklist(ctx);
        return 4 + BootDrivers(ctx, ct) + RejectedDrivers(ctx, ct);
    }

    static void CodeIntegrity(BypassContext ctx)
    {
        var buf = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt32(buf, 0, 8); // SYSTEM_CODEINTEGRITY_INFORMATION.Length
            if (NtQuerySystemInformation(SystemCodeIntegrityInformation, buf, 8, out _) != 0)
            {
                ctx.Route(Area, "Driver signature enforcement", "Could not be read", CheckState.Unknown);
                return;
            }
            int options = Marshal.ReadInt32(buf, 4);
            bool enforced = (options & CI_ENABLED) != 0, testSign = (options & CI_TESTSIGN) != 0, debug = (options & CI_DEBUGMODE) != 0;

            ctx.Route(Area, "Driver signature enforcement", enforced ? "On" : "OFF", enforced ? CheckState.Ok : CheckState.Bad,
                "Windows only loads kernel drivers with a valid signature while this is on.");
            if (!enforced)
                ctx.Flag(Severity.High, FindingCategory.Boot, "Driver signature enforcement is off",
                    "Windows is not checking kernel driver signatures (a boot option such as nointegritychecks, or the F7 \"Disable driver " +
                    "signature enforcement\" startup option). Any unsigned kernel driver — including kernel cheats — can load.");

            ctx.Route(Area, "Test signing mode", testSign ? "ON" : "Off", testSign ? CheckState.Bad : CheckState.Ok,
                "Test signing lets self-signed drivers load. Driver developers use it; ordinary PCs do not need it.");
            if (testSign)
                ctx.Flag(Severity.High, FindingCategory.Boot, "Test signing mode is on",
                    "Windows was started with test signing (bcdedit /set testsigning on), so any self-signed kernel driver can load. " +
                    "Only driver developers normally use this.");

            ctx.Route(Area, "Kernel debugging boot option", debug ? "ON" : "Off", debug ? CheckState.Bad : CheckState.Ok,
                "With kernel debugging on, code integrity is relaxed and the kernel can be patched from outside.");
            if (debug)
                ctx.Flag(Severity.High, FindingCategory.Boot, "Kernel debugging is enabled",
                    "Windows was started with kernel debugging on (bcdedit /debug on). That relaxes code integrity and lets the kernel be " +
                    "changed at run time. Ordinary PCs do not have this on.");

            ctx.Route(Area, "Memory integrity (HVCI)", (options & CI_HVCI) != 0 ? "On" : "Off", CheckState.Ok,
                "Context only: off is the default on many PCs. When on, even signed vulnerable drivers have a much harder time patching the kernel.");
            if ((options & CI_FLIGHTING) != 0)
                ctx.Route(Area, "Windows Insider build", "Yes", CheckState.Ok, "Insider builds allow flight-signed code; context only.");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static void KernelDebugger(BypassContext ctx)
    {
        var buf = Marshal.AllocHGlobal(2);
        try
        {
            if (NtQuerySystemInformation(SystemKernelDebuggerInformation, buf, 2, out _) != 0) return;
            bool enabled = Marshal.ReadByte(buf, 0) != 0, notPresent = Marshal.ReadByte(buf, 1) != 0;
            ctx.Route(Area, "Kernel debugger", enabled ? notPresent ? "Enabled, none attached" : "ATTACHED" : "Off",
                enabled ? CheckState.Bad : CheckState.Ok);
            if (enabled)
                ctx.Flag(Severity.High, FindingCategory.Boot, notPresent ? "Kernel debugger enabled" : "Kernel debugger attached",
                    "A kernel debugger is " + (notPresent ? "enabled" : "connected right now") + ". It can read and change any memory, " +
                    "including the game's, without any program running on this PC.");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static void SecureBoot(BypassContext ctx)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
        if (key?.GetValue("UEFISecureBootEnabled") is not int on)
        {
            ctx.Route(Area, "Secure Boot", "Not available (legacy BIOS boot)", CheckState.Warning,
                "Context only: older PCs and some custom builds boot this way.");
            return;
        }
        ctx.Route(Area, "Secure Boot", on == 1 ? "On" : "Off", on == 1 ? CheckState.Ok : CheckState.Warning,
            "With Secure Boot on, only signed boot loaders run, which blocks bootkits that load cheats before Windows.");
        if (on != 1)
            ctx.Flag(Severity.Low, FindingCategory.Boot, "Secure Boot is off",
                "Many PCs ship with Secure Boot off and Windows 10 does not need it, so this alone means little. With it off, " +
                "a modified boot loader could load code before Windows starts.");
    }

    static void DriverBlocklist(BypassContext ctx)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config");
        if (key?.GetValue("VulnerableDriverBlocklistEnable") is not int value)
        {
            ctx.Route(Area, "Vulnerable driver blocklist", "Windows default", CheckState.Ok);
            return;
        }
        ctx.Route(Area, "Vulnerable driver blocklist", value == 0 ? "Turned off" : "On", value == 0 ? CheckState.Warning : CheckState.Ok,
            "Windows' list of signed-but-abusable drivers (the ones driver mappers use to load cheats).");
        // Windows 11 22H2 and later keep it on by default; older builds may ship with it off.
        if (value == 0)
            ctx.Flag(Environment.OSVersion.Version.Build >= 22621 ? Severity.Medium : Severity.Low, FindingCategory.Boot,
                "Vulnerable driver blocklist turned off",
                "Windows blocks known abusable drivers (like the ones kdmapper uses) unless this is turned off. On Windows 11 22H2 and " +
                "later it is on by default, so someone switched it off.");
    }

    /// <summary>Kernel drivers registered to start with Windows from outside Windows / Program Files.</summary>
    static int BootDrivers(BypassContext ctx, CancellationToken ct)
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services == null) return 0;
        int items = 0;
        foreach (var name in services.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            using var key = services.OpenSubKey(name);
            if (key?.GetValue("Type") is not int type || type is not (1 or 2)) continue;     // kernel / file-system driver
            if (key.GetValue("Start") is not int start || start > 2) continue;              // boot, system or automatic
            var raw = key.GetValue("ImagePath") as string ?? $@"System32\drivers\{name}.sys";
            var path = ProcessAudit.NormalizeDriverPath(raw.Trim('"'));
            if (path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase)) continue;
            var changed = WinApi.GetKeyLastWriteUtc(key);
            bool exists = File.Exists(path);
            ctx.Route(Area, $"Startup driver: {name}", start switch { 0 => "Boot start", 1 => "System start", _ => "Automatic" },
                CheckState.Bad, exists ? "Registered from an unusual folder." : "Registered from an unusual folder; the file is gone now.", path, changed);
            ctx.Flag(Severity.Medium, FindingCategory.Boot, $"Driver set to load at startup from an unusual folder: {name}",
                $"The kernel driver service \"{name}\" loads {path} every time Windows starts" + (exists ? "" : " (the file no longer exists)") +
                ". Drivers normally live in Windows or an installed program's folder.", path, changed);
            items++;
        }
        return items;
    }

    /// <summary>Drivers Windows refused to load (blocklisted, unsigned, or incompatible with memory integrity).</summary>
    static int RejectedDrivers(BypassContext ctx, CancellationToken ct)
    {
        var seen = new Dictionary<string, (DateTime? Time, string Text)>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Events.Read("Microsoft-Windows-CodeIntegrity/Operational",
                     "*[System[(Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]", 500))
        {
            ct.ThrowIfCancellationRequested();
            string text;
            try { text = r.FormatDescription() ?? ""; }
            catch (Exception e) when (e is System.Diagnostics.Eventing.Reader.EventLogException or InvalidOperationException) { continue; }
            var m = Regex.Match(text, @"[^\\\s""]+\.sys\b", RegexOptions.IgnoreCase);
            if (!m.Success || seen.ContainsKey(m.Value)) continue;
            seen[m.Value] = (Events.Utc(r), text.Length > 400 ? text[..400] + "…" : text);
        }
        foreach (var (file, (time, text)) in seen)
        {
            bool abused = ProcessAudit.AbusedDrivers.TryGetValue(file, out var why);
            ctx.Route(Area, $"Driver rejected by Windows: {file}", abused ? why! : "Blocked", abused ? CheckState.Bad : CheckState.Warning, text, timeUtc: time);
            ctx.Flag(abused ? Severity.High : Severity.Low, FindingCategory.Boot, $"Windows refused to load the driver {file}",
                abused
                    ? $"Code Integrity blocked {file} ({why}) at {Util.When.L(time)}. Driver mappers load exactly this kind of driver to get a cheat into the kernel."
                    : $"Code Integrity blocked {file} at {Util.When.L(time)}. Old hardware drivers that memory integrity rejects look like this too; " +
                      $"check what it belongs to. Windows said: {text}",
                timeUtc: time);
        }
        return seen.Count;
    }
}

/// <summary>
/// Hardware and remote routes: programmable USB boards that act as a mouse or keyboard (hardware
/// autoclickers and macros), FPGA / DMA cards that read game memory from outside, a virtual machine,
/// and remote-desktop software.
/// </summary>
public static class HardwareAudit
{
    /// <summary>USB vendor IDs of hobby microcontroller boards; they can pretend to be a mouse or keyboard.</summary>
    static readonly Dictionary<string, (string Name, Severity Severity)> Boards = new(StringComparer.OrdinalIgnoreCase)
    {
        ["2341"] = ("Arduino", Severity.Medium),
        ["2A03"] = ("Arduino (arduino.org)", Severity.Medium),
        ["1B4F"] = ("SparkFun board", Severity.Medium),
        ["16C0"] = ("Teensy / V-USB board", Severity.Medium),
        ["239A"] = ("Adafruit board", Severity.Medium),
        ["303A"] = ("Espressif ESP32 board", Severity.Medium),
        ["2E8A"] = ("Raspberry Pi Pico (RP2040)", Severity.Medium),
        ["16D0"] = ("Digispark / MCS board", Severity.Medium),
        ["1209"] = ("Open-source hardware (pid.codes)", Severity.Low),
        ["1A86"] = ("QinHeng CH340 / CH9329 chip (Arduino clones, KMBox-style boxes)", Severity.Low),
    };

    static readonly Dictionary<string, string> DmaCards = new(StringComparer.OrdinalIgnoreCase)
    {
        ["VEN_10EE"] = "Xilinx FPGA — PCIe DMA cheat cards are built on these",
        ["VEN_10B5&DEV_3380"] = "PLX USB3380 — used by PCILeech DMA hardware",
    };

    static readonly Dictionary<string, string> RemoteTools = new(StringComparer.OrdinalIgnoreCase)
    {
        ["AnyDesk"] = "AnyDesk", ["TeamViewer"] = "TeamViewer", ["TeamViewer_Service"] = "TeamViewer", ["parsecd"] = "Parsec",
        ["rustdesk"] = "RustDesk", ["remoting_host"] = "Chrome Remote Desktop", ["SRService"] = "Splashtop", ["tvnserver"] = "TightVNC",
        ["winvnc"] = "VNC", ["vncserver"] = "RealVNC", ["ScreenConnect.ClientService"] = "ScreenConnect", ["ToDesk"] = "ToDesk",
        ["LogMeIn"] = "LogMeIn", ["Sunshine"] = "Sunshine game streaming",
    };

    public static int Run(BypassContext ctx, CancellationToken ct) => UsbBoards(ctx, ct) + PciCards(ctx) + VirtualMachine(ctx) + Remote(ctx);

    static int UsbBoards(BypassContext ctx, CancellationToken ct)
    {
        using var usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
        if (usb == null) return 0;
        int items = 0;
        foreach (var id in usb.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            var m = Regex.Match(id, @"^VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", RegexOptions.IgnoreCase);
            if (!m.Success || !Boards.TryGetValue(m.Groups[1].Value, out var board) || id.Contains("&MI_", StringComparison.OrdinalIgnoreCase)) continue;
            using var device = usb.OpenSubKey(id);
            if (device == null) continue;
            foreach (var instance in device.GetSubKeyNames())
            {
                using var inst = device.OpenSubKey(instance);
                if (inst == null) continue;
                string desc = Describe(inst.GetValue("FriendlyName") as string ?? inst.GetValue("DeviceDesc") as string ?? board.Name);
                var changed = WinApi.GetKeyLastWriteUtc(inst);
                string vidPid = $"{m.Groups[1].Value}:{m.Groups[2].Value}".ToUpperInvariant();
                ctx.Route("Hardware", $"{board.Name} ({vidPid})", desc, board.Severity >= Severity.Medium ? CheckState.Bad : CheckState.Warning,
                    "Has been connected to this PC (time = last change of its device entry).", instance, changed);
                ctx.Flag(board.Severity, FindingCategory.Hardware, $"Programmable USB board connected: {desc}",
                    $"A {board.Name} (USB {vidPid}) has been connected to this PC (device entry last changed {Util.When.L(changed)}). Boards like this can " +
                    "pretend to be a mouse or keyboard and click or move for the player — a hardware autoclicker or macro that no program " +
                    "on the PC shows. Electronics hobbyists use them too. Clone boxes can also fake another vendor's ID, so absence proves nothing.",
                    timeUtc: changed);
                items++;
            }
        }
        if (items == 0) ctx.Route("Hardware", "Programmable USB boards", "None seen", CheckState.Ok, "No Arduino-style board has been recorded on this PC.");
        return items;
    }

    static int PciCards(BypassContext ctx)
    {
        using var pci = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
        if (pci == null) return 0;
        int items = 0;
        foreach (var id in pci.GetSubKeyNames())
        {
            var match = DmaCards.FirstOrDefault(d => id.StartsWith(d.Key, StringComparison.OrdinalIgnoreCase));
            if (match.Key == null) continue;
            using var device = pci.OpenSubKey(id);
            var first = device?.GetSubKeyNames().FirstOrDefault();
            using var inst = first != null ? device!.OpenSubKey(first) : null;
            string desc = Describe(inst?.GetValue("DeviceDesc") as string ?? id);
            var changed = inst != null ? WinApi.GetKeyLastWriteUtc(inst) : null;
            ctx.Route("Hardware", $"PCIe device {id.Split('&').Take(2).Aggregate((a, b) => a + "&" + b)}", desc, CheckState.Bad, match.Value, timeUtc: changed);
            ctx.Flag(Severity.High, FindingCategory.Hardware, $"FPGA / DMA-capable card installed: {desc}",
                $"{match.Value}. A DMA card reads and writes the game's memory over PCIe from a second PC, so nothing shows on this one. " +
                "FPGA developers use these boards too. Most cheat cards flash firmware that pretends to be another device, so absence proves nothing.",
                timeUtc: changed);
            items++;
        }
        if (items == 0) ctx.Route("Hardware", "FPGA / DMA cards", "None seen", CheckState.Ok,
            "No known FPGA or DMA bridge has been recorded. Cards with spoofed firmware would not show here.");
        return items;
    }

    static int VirtualMachine(BypassContext ctx)
    {
        using var bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
        string maker = bios?.GetValue("SystemManufacturer") as string ?? "", product = bios?.GetValue("SystemProductName") as string ?? "",
            vendor = bios?.GetValue("BIOSVendor") as string ?? "";
        string all = $"{maker} {product} {vendor}";
        var vm = Regex.Match(all, @"VMware|VirtualBox|innotek|QEMU|KVM|Xen|Parallels|Bochs|BHYVE|Virtual Machine", RegexOptions.IgnoreCase);
        ctx.Route("Hardware", "Machine", $"{maker} {product}".Trim(), vm.Success ? CheckState.Bad : CheckState.Ok,
            vm.Success ? "This Windows is running inside a virtual machine." : "Physical machine.");
        if (vm.Success)
            ctx.Flag(Severity.Medium, FindingCategory.Hardware, "This PC is a virtual machine",
                $"The firmware reports \"{all.Trim()}\" ({vm.Value}). A screenshare inside a virtual machine may not be looking at the PC the " +
                "game really runs on.");
        return 1;
    }

    static int Remote(BypassContext ctx)
    {
        bool rdp = GetSystemMetrics(SM_REMOTESESSION) != 0;
        ctx.Route("Remote access", "Remote Desktop session", rdp ? "Yes" : "No", rdp ? CheckState.Warning : CheckState.Ok);
        if (rdp)
            ctx.Flag(Severity.Low, FindingCategory.Hardware, "The scan is running in a Remote Desktop session",
                "This session is a Remote Desktop connection. Make sure the PC being scanned is the one the game runs on.");
        int items = 1;
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
            using (p)
                if (RemoteTools.TryGetValue(p.ProcessName, out var tool)) running.Add(tool);
        foreach (var tool in running)
        {
            ctx.Route("Remote access", tool, "Running", CheckState.Ok,
                "Screenshare staff often connect with these. If you are not using it, ask what it is connected to.");
            items++;
        }
        return items;
    }

    /// <summary>Device descriptions are stored as "@oem12.inf,%desc%;Arduino Leonardo"; keep the readable part.</summary>
    internal static string Describe(string raw)
    {
        int semi = raw.LastIndexOf(';');
        return (semi >= 0 ? raw[(semi + 1)..] : raw).Trim();
    }
}

/// <summary>
/// Places Windows and Java read on every launch to load extra code: IFEO debuggers and verifier DLLs,
/// AppInit / AppCert DLLs, the Winlogon shell, Java's global option variables, DLLs planted next to
/// java(w).exe, modified Java runtime files, and programs that start with Windows.
/// </summary>
public static class HookAudit
{
    const string IfeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    /// <summary>System DLL names a program loads from its own folder first when a copy is put there.</summary>
    internal static readonly HashSet<string> HijackNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "winmm.dll", "opengl32.dll", "dinput8.dll", "d3d9.dll", "d3d11.dll", "dxgi.dll", "ddraw.dll", "dsound.dll",
        "winhttp.dll", "wininet.dll", "dwmapi.dll", "uxtheme.dll", "hid.dll", "dbghelp.dll", "dbgcore.dll", "xinput1_3.dll",
        "xinput1_4.dll", "xinput9_1_0.dll", "iphlpapi.dll", "userenv.dll", "wtsapi32.dll", "msimg32.dll", "cryptbase.dll",
        "cryptsp.dll", "profapi.dll", "propsys.dll", "secur32.dll", "netapi32.dll", "mswsock.dll", "winspool.drv",
    };

    static readonly string[] JavaVariables = ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"];
    static readonly Regex AgentOption = new(@"-javaagent|-agentpath|-agentlib|-Xbootclasspath|-Djava\.system\.class\.loader|--patch-module",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly string[] ThrowawayFolders = [@"\Temp\", "%TEMP%", "%TMP%", @"\Downloads\", @"\Desktop\"];

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        // Some of these keys are readable by administrators only; one locked key must not hide the rest.
        int Safe(string what, Func<int> check)
        {
            ct.ThrowIfCancellationRequested();
            try { return check(); }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                ctx.Route("Launch hooks", what, "Could not be read", CheckState.Unknown, "Run as administrator to check this.");
                return 0;
            }
        }
        return Safe("Image File Execution Options", () => Ifeo(ctx, IfeoPath)) +
               Safe("Image File Execution Options (32-bit)", () => Ifeo(ctx, @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")) +
               Safe("SilentProcessExit", () => SilentExit(ctx)) +
               Safe("AppInit / AppCert DLLs", () => AppInit(ctx)) +
               Safe("Winlogon", () => Winlogon(ctx)) +
               Safe("Global Java options", () => JavaOptions(ctx)) +
               Safe("Java runtimes", () => JavaFolders(ctx)) +
               Safe("Startup entries", () => Startup(ctx, ct));
    }

    static RegistryKey? TryOpen(RegistryKey root, string path)
    {
        try { return root.OpenSubKey(path); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }

    static int Ifeo(BypassContext ctx, string path)
    {
        using var root = Registry.LocalMachine.OpenSubKey(path);
        if (root == null) return 0;
        {
            int items = 0;
            foreach (var exe in root.GetSubKeyNames())
            {
                using var key = TryOpen(root, exe);
                if (key == null) continue;
                var changed = WinApi.GetKeyLastWriteUtc(key);
                if (key.GetValue("Debugger") is string debugger && debugger.Trim().Length > 0)
                {
                    // Process Explorer / System Informer "Replace Task Manager" sets exactly this.
                    bool taskManagerSwap = exe.Equals("taskmgr.exe", StringComparison.OrdinalIgnoreCase) &&
                                           Regex.IsMatch(debugger, "procexp|ProcessHacker|SystemInformer", RegexOptions.IgnoreCase);
                    bool game = Regex.IsMatch(exe, @"^(javaw?|minecraft.*|.*launcher.*|explorer)\.exe$", RegexOptions.IgnoreCase);
                    var severity = taskManagerSwap ? Severity.Low : game ? Severity.High : Severity.Medium;
                    ctx.Route("Launch hooks", $"Debugger for {exe}", debugger, taskManagerSwap ? CheckState.Warning : CheckState.Bad,
                        taskManagerSwap ? "Set by the \"Replace Task Manager\" option of a process tool." : "Runs instead of the program every time it starts.",
                        timeUtc: changed);
                    ctx.Flag(severity, FindingCategory.Injection, $"Program hijacked at launch: {exe}",
                        $"Every time {exe} starts, Windows runs \"{debugger}\" instead and passes the program to it (Image File Execution " +
                        $"Options \"Debugger\", last changed {Util.When.L(changed)}). That lets something run, wrap or inject into {exe} on every launch." +
                        (taskManagerSwap ? " This one is the \"Replace Task Manager\" option of Process Explorer / System Informer." : ""), timeUtc: changed);
                    items++;
                }
                if (key.GetValue("VerifierDlls") is string verifier && verifier.Trim().Length > 0)
                {
                    ctx.Route("Launch hooks", $"Verifier DLL for {exe}", verifier, CheckState.Bad, "Loaded into the program before its own code runs.", timeUtc: changed);
                    ctx.Flag(Severity.High, FindingCategory.Injection, $"DLL injected into every launch of {exe}",
                        $"Image File Execution Options load \"{verifier}\" into {exe} as an Application Verifier DLL each time it starts " +
                        $"(last changed {Util.When.L(changed)}). Windows loads it before the program's own code — a quiet way to inject a DLL.", timeUtc: changed);
                    items++;
                }
            }
            return items;
        }
    }

    static int SilentExit(BypassContext ctx)
    {
        using var root = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit");
        if (root == null) return 0;
        int items = 0;
        foreach (var exe in root.GetSubKeyNames())
        {
            using var key = root.OpenSubKey(exe);
            if (key?.GetValue("MonitorProcess") is not string monitor || monitor.Trim().Length == 0) continue;
            var changed = WinApi.GetKeyLastWriteUtc(key);
            ctx.Route("Launch hooks", $"Runs when {exe} exits", monitor, CheckState.Bad, timeUtc: changed);
            ctx.Flag(Severity.Medium, FindingCategory.Injection, $"Program runs whenever {exe} exits",
                $"Windows starts \"{monitor}\" every time {exe} closes (SilentProcessExit, last changed {Util.When.L(changed)}). It is used to run " +
                "something automatically — for example a cleaner when the game closes.", timeUtc: changed);
            items++;
        }
        return items;
    }

    static int AppInit(BypassContext ctx)
    {
        int items = 0;
        foreach (var path in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            var dlls = (key?.GetValue("AppInit_DLLs") as string ?? "").Trim();
            bool loaded = key?.GetValue("LoadAppInit_DLLs") is int l && l == 1;
            string view = path.Contains("WOW6432Node") ? "32-bit" : "64-bit";
            ctx.Route("Launch hooks", $"AppInit_DLLs ({view})", dlls.Length == 0 ? "Empty" : dlls,
                dlls.Length == 0 ? CheckState.Ok : loaded ? CheckState.Bad : CheckState.Warning,
                dlls.Length == 0 ? "" : loaded ? "Loaded into every program that uses user32.dll." : "Set, but loading is switched off.");
            if (dlls.Length > 0)
                ctx.Flag(loaded ? Severity.High : Severity.Low, FindingCategory.Injection, $"AppInit DLL {(loaded ? "loaded into every program" : "set but switched off")}",
                    $"AppInit_DLLs ({view}) is \"{dlls}\"" + (loaded
                        ? " and LoadAppInit_DLLs is on, so Windows loads it into nearly every program that starts, the game included."
                        : ". Loading is switched off, so it does nothing right now, but someone or some old software put it there."));
            items++;
        }
        using var cert = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls");
        foreach (var name in cert?.GetValueNames() ?? [])
        {
            var dll = cert!.GetValue(name) as string ?? "";
            ctx.Route("Launch hooks", $"AppCertDlls: {name}", dll, CheckState.Bad, "Loaded into every program started with CreateProcess.");
            ctx.Flag(Severity.High, FindingCategory.Injection, "AppCert DLL registered",
                $"\"{dll}\" is registered in AppCertDlls, so Windows loads it into every program that starts another program.");
            items++;
        }
        return items;
    }

    static int Winlogon(BypassContext ctx)
    {
        int items = 0;
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        var shell = (key?.GetValue("Shell") as string ?? "explorer.exe").Trim();
        var userinit = (key?.GetValue("Userinit") as string ?? "").Trim().TrimEnd(',').Trim();
        bool shellOk = shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
        bool userinitOk = userinit.Length == 0 || Path.GetFileName(userinit).Equals("userinit.exe", StringComparison.OrdinalIgnoreCase);
        ctx.Route("Launch hooks", "Windows shell", shell, shellOk ? CheckState.Ok : CheckState.Bad, "Started at every logon; normally explorer.exe.");
        ctx.Route("Launch hooks", "Userinit", userinit, userinitOk ? CheckState.Ok : CheckState.Bad, "Started at every logon; normally userinit.exe only.");
        if (!shellOk)
            ctx.Flag(Severity.Medium, FindingCategory.Injection, "Windows shell replaced",
                $"Winlogon starts \"{shell}\" at logon instead of explorer.exe.");
        if (!userinitOk)
            ctx.Flag(Severity.Medium, FindingCategory.Injection, "Extra program started at every logon (Userinit)",
                $"Winlogon's Userinit is \"{userinit}\" instead of just userinit.exe, so something else runs at every logon.");
        items += 2;

        foreach (var sid in WinApi.LoadedUserSids())
        {
            using var user = TryOpen(Registry.Users, $@"{sid}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (user?.GetValue("Shell") is not string userShell || userShell.Trim().Length == 0) continue;
            ctx.Route("Launch hooks", $"Windows shell ({WinApi.SidToName(sid)})", userShell, CheckState.Bad);
            ctx.Flag(Severity.Medium, FindingCategory.Injection, "Windows shell replaced for one user",
                $"{WinApi.SidToName(sid)} starts \"{userShell}\" at logon instead of explorer.exe.");
            items++;
        }
        return items;
    }

    /// <summary>Variables every Java program reads at start: a -javaagent there loads into the game with nothing on its command line.</summary>
    static int JavaOptions(BypassContext ctx)
    {
        int items = 0;
        var places = new List<(string Owner, RegistryKey? Key)>
            { ("All users", Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")) };
        foreach (var sid in WinApi.LoadedUserSids())
            places.Add((WinApi.SidToName(sid), TryOpen(Registry.Users, $@"{sid}\Environment")));
        foreach (var (owner, key) in places)
        {
            using (key)
            {
                foreach (var name in JavaVariables)
                {
                    if (key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value || value.Trim().Length == 0) continue;
                    bool agent = AgentOption.IsMatch(value);
                    ctx.Route("Java", $"{name} ({owner})", value, agent ? CheckState.Bad : CheckState.Warning,
                        "Read by every Java program when it starts, including the game.");
                    // Plain settings like -Dfile.encoding=UTF-8 are common; agents and class-path tricks are not.
                    ctx.Flag(agent ? Severity.High : Severity.Low, FindingCategory.Injection,
                        agent ? $"Java agent forced into every Java program ({name})" : $"Java options set for every Java program ({name})",
                        $"{owner}: {name} = \"{value}\". Java reads this at every start, so it applies to the game even though it is not on " +
                        "the launcher's command line." + (agent ? " It loads an agent or changes the class path — a way to inject a client." : ""));
                    items++;
                }
            }
        }
        if (items == 0) ctx.Route("Java", "Global Java options", "None set", CheckState.Ok, string.Join(", ", JavaVariables) + " are not set.");
        return items;
    }

    /// <summary>Every folder a java(w).exe ran from: planted DLLs next to it, and its own files' signatures.</summary>
    static int JavaFolders(BypassContext ctx)
    {
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in ctx.History.Files.Where(f => f.Status == FileStatus.Exists && (f.Name.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase) || f.Name.Equals("java.exe", StringComparison.OrdinalIgnoreCase))))
            if (Path.GetDirectoryName(f.Path) is { } d) dirs.Add(d);
        foreach (var p in Process.GetProcesses())
            using (p)
                if (p.ProcessName is "javaw" or "java" && ProcessAudit.ImagePath(p.Id) is { } path && Path.GetDirectoryName(path) is { } d)
                    dirs.Add(d);

        int items = 0;
        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in SafeFiles(dir, "*.d*"))
            {
                var name = Path.GetFileName(file);
                if (!HijackNames.Contains(name)) continue;
                var sig = FileInspector.Verify(file);
                bool microsoft = sig == SignatureStatus.Signed && (FileInspector.SignerName(file) ?? "").Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
                if (microsoft) continue;
                var written = File.GetLastWriteTimeUtc(file);
                ctx.Route("Java", $"Planted DLL next to Java: {name}", Display.Signature(sig), CheckState.Bad,
                    "Java loads a DLL with this name from its own folder before the real one in System32.", file, written);
                ctx.Flag(Severity.High, FindingCategory.Injection, $"DLL planted next to Java: {name}",
                    $"{file} sits next to java(w).exe. Windows loads a DLL with a system name from the program's own folder first, so this " +
                    "file runs inside the game every time it starts (DLL hijacking). Java does not ship it.", file, written);
                items++;
            }
            // One row per runtime. A broken signature means a file was changed after the vendor signed it;
            // unsigned builds exist, so those are context only.
            var broken = new List<string>();
            string? vendor = null;
            int unsigned = 0, checkedFiles = 0;
            foreach (var core in new[] { "javaw.exe", "java.exe", "java.dll", @"server\jvm.dll", "instrument.dll" })
            {
                var file = Path.Combine(dir, core);
                if (!File.Exists(file)) continue;
                checkedFiles++;
                switch (FileInspector.Verify(file))
                {
                    case SignatureStatus.Invalid:
                        broken.Add(core);
                        ctx.Flag(Severity.High, FindingCategory.Injection, $"Java runtime file modified: {core}",
                            $"{file} carries a signature that no longer matches its contents, so it was changed after the vendor built it. " +
                            "A patched JVM can load a client without any agent or argument.", file);
                        break;
                    case SignatureStatus.Signed: vendor ??= FileInspector.SignerName(file); break;
                    default: unsigned++; break;
                }
            }
            if (checkedFiles == 0) continue;
            ctx.Route("Java", $"Java runtime: {dir}",
                broken.Count > 0 ? $"MODIFIED: {string.Join(", ", broken)}" : vendor != null ? $"Signed by {vendor}" : "Unsigned build",
                broken.Count > 0 ? CheckState.Bad : CheckState.Ok,
                $"{checkedFiles} core files checked" + (unsigned > 0 ? $", {unsigned} unsigned (some Java builds are not signed; context only)." : "."), dir);
            items++;
        }
        if (dirs.Count == 0) ctx.Route("Java", "Java runtimes", "None found", CheckState.Unknown, "No java(w).exe was found in the execution history.");
        return items;
    }

    /// <summary>Run keys and Startup folders: listed, and flagged when they start something from a throwaway folder or a named tool.</summary>
    static int Startup(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        var keys = new List<(string Owner, RegistryKey? Key, string Name)>();
        foreach (var sub in new[] { "Run", "RunOnce" })
        {
            keys.Add(("All users", Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\{sub}"), sub));
            keys.Add(("All users (32-bit)", Registry.LocalMachine.OpenSubKey($@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\{sub}"), sub));
            foreach (var sid in WinApi.LoadedUserSids())
                keys.Add((WinApi.SidToName(sid), TryOpen(Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\{sub}"), sub));
        }
        foreach (var (owner, key, sub) in keys)
        {
            using (key)
            {
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (key.GetValue(name) is not string command) continue;
                    items += StartupEntry(ctx, $"{sub}: {name} ({owner})", command);
                }
            }
        }
        var folders = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\StartUp") };
        folders.AddRange(JavaUsageCollector.UserProfiles().Select(p => Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")));
        foreach (var folder in folders.Where(Directory.Exists))
            foreach (var file in SafeFiles(folder, "*").Where(f => !Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)))
                items += StartupEntry(ctx, $"Startup folder: {Path.GetFileName(file)}", file);
        return items;
    }

    static int StartupEntry(BypassContext ctx, string item, string command)
    {
        bool throwaway = ThrowawayFolders.Any(f => command.Contains(f, StringComparison.OrdinalIgnoreCase));
        // Chromium-based apps pass "/prefetch:N" (a hint to Windows), which is not about the Prefetch folder.
        string? meaning = ctx.Keywords.Classify(Regex.Replace(command, @"[/-]-?prefetch:\d+", "", RegexOptions.IgnoreCase));
        bool script = Util.FileTypes.FromPath(command.Trim('"')) == FileType.Script;
        bool flagged = throwaway || meaning != null;
        ctx.Route("Startup", item, command, flagged ? CheckState.Bad : script ? CheckState.Warning : CheckState.Ok,
            flagged ? "Starts something from a throwaway folder or running a flagged command." : script ? "A script that runs at every logon." : "");
        if (flagged)
            ctx.Flag(Severity.Medium, FindingCategory.Persistence, $"Starts with Windows: {item}",
                $"\"{command}\" runs at every logon" + (meaning != null ? $" and {meaning}" : "") +
                (throwaway ? " from a Temp, Downloads or Desktop folder, where programs rarely start themselves from (installers finishing after a restart sometimes do)" : "") + ".");
        return 1;
    }

    static IEnumerable<string> SafeFiles(string dir, string pattern)
    {
        try { return Directory.GetFiles(dir, pattern); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }
}
