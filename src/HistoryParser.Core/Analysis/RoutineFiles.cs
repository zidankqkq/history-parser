using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Analysis;

/// <summary>
/// Which files may be kept out of the way to keep long lists short - the one rule every program in the suite uses.
/// <para>
/// A file is routine only on what someone hiding a program cannot arrange: it is on disk now; its signature verifies now and
/// the chain ends where it should (Microsoft's own root for Microsoft's files, a root on Windows' own trusted list for the
/// few other publishers named here - never a certificate added to this PC); it has the name it was built with; it is not
/// packed; and it is not a program that runs other code or changes records.
/// </para>
/// <para>
/// Where a file sits, what it is called, what started it and how long it existed are never reasons: whoever runs it chooses
/// all of those. So a file that is gone is never routine (nothing about it can be checked any more), and neither is anything
/// in Temp, in an installer's folder, or in a folder named like Windows' own.
/// </para>
/// Routine files are never dropped: they stay in the results, counted and searchable, behind one switch.
/// </summary>
public static class RoutineFiles
{
    /// <summary>
    /// Programs that run other code, load what they are given, or change settings and records. Their own signature says nothing
    /// about what they ran or changed, so they never count as routine, whoever signed them. Matched against the file's name and
    /// against the name it was built with, so a renamed copy does not slip past.
    /// </summary>
    public static readonly HashSet<string> KeepInView = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "wmic.exe",
        "certutil.exe", "fsutil.exe", "wevtutil.exe", "vssadmin.exe", "attrib.exe", "icacls.exe", "cacls.exe", "takeown.exe", "reg.exe", "regedit.exe", "sc.exe",
        "net.exe", "net1.exe", "auditpol.exe", "bcdedit.exe", "diskpart.exe", "fltmc.exe", "schtasks.exe", "taskkill.exe", "forfiles.exe", "bitsadmin.exe",
        "cipher.exe", "sdelete.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "msiexec.exe", "java.exe", "javaw.exe",
        "javaws.exe", "conhost.exe", "explorer.exe",
        // Microsoft's own programs that inject, load or run what they are given (the LOLBAS project lists these).
        "mavinject.exe", "odbcconf.exe", "pcalua.exe", "msdt.exe", "control.exe", "presentationhost.exe", "ieexec.exe", "msxsl.exe", "cdb.exe", "ntsd.exe",
        "windbg.exe", "dotnet.exe", "csi.exe", "rcsi.exe", "csc.exe", "vbc.exe", "jsc.exe", "ilasm.exe", "hh.exe", "infdefaultinstall.exe", "xwizard.exe",
        "syncappvpublishingserver.exe", "appvlp.exe", "bash.exe", "wsl.exe", "scriptrunner.exe", "tracker.exe", "dfsvc.exe", "msconfig.exe", "at.exe",
        "register-cimprovider.exe", "te.exe", "dnscmd.exe", "wuauclt.exe", "ftp.exe", "rasautou.exe", "verclsid.exe", "dllhost.exe",
        // Windows tools that stop, clear or alter what records a PC keeps: services, logs, the clock, volumes, tracing sessions.
        "taskmgr.exe", "mmc.exe", "perfmon.exe", "resmon.exe", "eventvwr.exe", "logman.exe", "tzutil.exe", "w32tm.exe", "wbadmin.exe", "mountvol.exe",
        "subst.exe", "regedt32.exe", "cleanmgr.exe", "sdbinst.exe", "tskill.exe", "wpr.exe", "tracelog.exe", "label.exe", "format.com", "compact.exe",
        // Terminals and editors that run whatever is typed into them, and the game's own launchers.
        "windowsterminal.exe", "wt.exe", "openconsole.exe", "code.exe", "ssh.exe", "minecraftlauncher.exe", "minecraft.exe", "minecraft.windows.exe",
    };

    /// <summary>
    /// Publishers other than Microsoft whose valid signature lets a file count as routine. Matched exactly against the certificate's
    /// organisation, and only when the chain ends in a root on Windows' own trusted list. A short list on purpose: anyone can buy a
    /// certificate. Java runtimes are here because every Minecraft check is full of them; java.exe and javaw.exe themselves stay in view.
    /// </summary>
    static readonly HashSet<string> KnownPublishers = new(StringComparer.Ordinal)
    {
        "Google LLC", "Mozilla Corporation", "Valve Corp.", "Discord Inc.",
        "NVIDIA Corporation", "Advanced Micro Devices, Inc.", "Advanced Micro Devices Inc.", "Intel Corporation",
        "Oracle America, Inc.", "Azul Systems, Inc.", "Eclipse.org Foundation, Inc.",
    };

    public static bool IsKnownPublisher(string signer) => KnownPublishers.Contains(signer);

    /// <summary>Programs and libraries only. Drivers, scripts, jars and installers are never routine: a signed one can still be used to load or run something else.</summary>
    static readonly HashSet<string> Kinds = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".com", ".cpl", ".ocx", ".scr" };

    /// <summary>Section names the common packers and protectors give a program.</summary>
    static readonly string[] PackerSections = ["UPX", ".vmp", ".themida", ".winlice", ".enigma", ".aspack", ".MPRESS", ".petite", ".nsp"];

    static readonly string WindowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    static readonly string[] ProgramFolders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("ProgramW6432") ?? "",
        }.Where(p => p.Length > 3).Select(p => p.TrimEnd('\\') + "\\").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    /// <summary>Inside the real Windows folder of this PC. A place, so never a reason to trust a file: only a way to say where one is.</summary>
    public static bool InWindowsFolder(string path) => path.StartsWith(WindowsFolder, StringComparison.OrdinalIgnoreCase);

    /// <summary>Inside one of this PC's real Program Files folders (not a folder that is merely named like one).</summary>
    public static bool InProgramFiles(string path) => ProgramFolders.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    static readonly ConcurrentDictionary<string, string> Reasons = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Why the file is routine, if that has been worked out already. Null when it is not, or is not known yet: such files stay in view.</summary>
    public static string? Known(string path) => Reasons.TryGetValue(path, out var reason) && reason.Length > 0 ? reason : null;

    /// <summary>Why the file is routine, or null. Reads the file the first time it is asked about.</summary>
    public static string? Reason(string path) => Reasons.GetOrAdd(path, Work) is { Length: > 0 } reason ? reason : null;

    /// <summary>Forgets what was worked out, so a new scan judges every file as it is then.</summary>
    public static void Forget() => Reasons.Clear();

    /// <summary>Works out many files at once; verifying a signature reads the whole file.</summary>
    public static void Prime(IEnumerable<string> paths, CancellationToken ct = default)
    {
        var todo = paths.Where(p => !Reasons.ContainsKey(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (todo.Count == 0) return;
        Parallel.ForEach(todo, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 12), CancellationToken = ct },
            p => Reason(p));
    }

    static string Work(string path)
    {
        if (path.Length < 4 || path[1] != ':' || path[2] != '\\') return "";
        string extension = Path.GetExtension(path), name = Path.GetFileName(path);
        // A driver is routine only when it is Microsoft's own: another company's signed driver is exactly what is brought
        // along to get into the kernel, so those always stay in view.
        bool driver = extension.Equals(".sys", StringComparison.OrdinalIgnoreCase);
        if (!driver && !Kinds.Contains(extension) || KeepInView.Contains(name)) return "";

        var facts = SignatureTrust.Of(path); // a file that is gone is "not checked", so it never gets past this line
        if (facts.Status != SignatureStatus.Signed) return "";
        bool microsoft = facts.Root == SignerRoot.Microsoft;
        if (driver && !microsoft) return "";
        if (!microsoft && !(facts.Root == SignerRoot.Program && facts.Signer is { } signer && KnownPublishers.Contains(signer))) return "";
        string who = microsoft ? "Microsoft" : facts.Signer!;

        if (BuiltName(path) is { } built)
        {
            // A renamed copy of a program that runs other code is the oldest way round a list of names.
            if (KeepInView.Contains(built) || KeepInView.Contains(Path.ChangeExtension(built, ".exe"))) return "";
            if (!SameName(built, name))
            {
                // Microsoft names many of its files differently from how they were built. That only stands for its libraries, which
                // cannot run by themselves, and for its programs in the Windows folder.
                bool library = extension.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                if (!microsoft || !library && !InWindowsFolder(path)) return "";
                return $"{who} signed it and the signature verifies now. It was built as {built}, which Microsoft does with its own files.";
            }
        }
        if (!microsoft && Packed(path)) return "";
        return $"{who} signed it and the signature verifies now. It has the name it was built with.";
    }

    /// <summary>The name the program was built with (its version details), or null when it carries none.</summary>
    internal static string? BuiltName(string path)
    {
        try
        {
            var built = FileVersionInfo.GetVersionInfo(path).OriginalFilename?.Trim();
            if (string.IsNullOrEmpty(built)) return null;
            return built.EndsWith(".mui", StringComparison.OrdinalIgnoreCase) ? built[..^4] : built;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    /// <summary>"WerMgr" and "wermgr.exe" are the same name; "notepad.exe" and "x.exe" are not.</summary>
    internal static bool SameName(string built, string name) =>
        built.Equals(name, StringComparison.OrdinalIgnoreCase) ||
        Path.GetFileNameWithoutExtension(built).Equals(Path.GetFileNameWithoutExtension(name), StringComparison.OrdinalIgnoreCase) ||
        built.Equals(Path.GetFileNameWithoutExtension(name), StringComparison.OrdinalIgnoreCase);

    static bool Packed(string path)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var pe = new PEReader(file);
            return pe.PEHeaders.SectionHeaders.Any(s => PackerSections.Any(p => s.Name.StartsWith(p, StringComparison.OrdinalIgnoreCase)));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException) { return true; }
    }
}
