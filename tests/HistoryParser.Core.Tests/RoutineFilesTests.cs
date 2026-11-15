using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;
using HistoryParser.Core.Util;
using Xunit.Abstractions;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The rule that decides which files may be kept out of the way. Every case here is one a person hiding a program could try:
/// the file's folder, its name and a certificate's name must never be what makes it routine.
/// Reads real Windows files, so it runs on a real machine (Category=Integration).
/// </summary>
[Trait("Category", "Integration")]
public class RoutineFilesTests(ITestOutputHelper output)
{
    static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    static string Sys(string name) => Path.Combine(System32, name);

    static string TempFolder()
    {
        string dir = Path.Combine(Path.GetTempPath(), "hp-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Windows_own_files_are_verified_as_Microsofts()
    {
        foreach (var name in new[] { "notepad.exe", "kernel32.dll", "cmd.exe", "svchost.exe" })
        {
            var facts = SignatureTrust.Of(Sys(name));
            output.WriteLine($"{name}: {facts}");
            output.WriteLine("  " + SignatureTrust.Diagnose(FileInspector.CatalogFor(Sys(name)) ?? Sys(name)));
            Assert.Equal(SignatureStatus.Signed, facts.Status);
            Assert.Equal(SignerRoot.Microsoft, facts.Root);
        }
    }

    [Fact]
    public void A_Windows_program_in_the_Windows_folder_is_routine_but_one_that_runs_other_code_never_is()
    {
        Assert.NotNull(RoutineFiles.Reason(Sys("svchost.exe")));
        Assert.True(FileTypes.IsWindowsFile(Sys("kernel32.dll")));
        // Their signatures are just as valid; what they ran or changed is what matters.
        foreach (var tool in new[] { "cmd.exe", "rundll32.exe", "fltmc.exe", "wevtutil.exe", "fsutil.exe", "reg.exe", "sc.exe", "mshta.exe" })
        {
            if (!File.Exists(Sys(tool))) continue;
            Assert.Null(RoutineFiles.Reason(Sys(tool)));
            Assert.False(FileTypes.IsWindowsFile(Sys(tool)));
        }
    }

    [Fact]
    public void A_file_that_is_gone_is_never_routine_whatever_its_folder()
    {
        Assert.Null(RoutineFiles.Reason(Sys("this-file-was-deleted.exe")));
        Assert.False(FileTypes.IsWindowsFile(Sys("this-file-was-deleted.dll")));
        Assert.Equal(SignatureStatus.NotChecked, SignatureTrust.Of(Sys("this-file-was-deleted.exe")).Status);
    }

    [Fact]
    public void An_unsigned_program_is_not_routine_wherever_it_is_put()
    {
        string dir = TempFolder();
        try
        {
            // Not a signed program at all, in folders named like the ones a path rule would trust.
            foreach (var folder in new[] { "WindowsApps", "Program Files", @"Windows\System32", "Lib" })
            {
                string path = Path.Combine(dir, folder, "helper.exe");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.Copy(typeof(RoutineFilesTests).Assembly.Location, path);
                Assert.Null(RoutineFiles.Reason(path));
                Assert.False(FileTypes.IsWindowsFile(path));
                Assert.NotEqual(SignatureStatus.Signed, SignatureTrust.Of(path).Status);
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void A_renamed_copy_of_a_Windows_tool_is_not_routine()
    {
        string dir = TempFolder();
        try
        {
            // fltmc.exe unloads the filter Prefetch is built from. Copied under a harmless name it is still fltmc.
            string source = File.Exists(Sys("fltmc.exe")) ? Sys("fltmc.exe") : Sys("cmd.exe");
            string renamed = Path.Combine(dir, "updater.exe");
            File.Copy(source, renamed);
            Assert.True(SignatureTrust.Of(renamed).IsMicrosoft); // the signature is real …
            Assert.Null(RoutineFiles.Reason(renamed));            // … and it changes nothing

            // A Windows program that is not such a tool, under another name outside the Windows folder: also stays in view.
            string notepad = Path.Combine(dir, "x.exe");
            File.Copy(Sys("svchost.exe"), notepad);
            Assert.Null(RoutineFiles.Reason(notepad));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Built_names_compare_the_way_Microsoft_writes_them()
    {
        Assert.True(RoutineFiles.SameName("NOTEPAD.EXE", "notepad.exe"));
        Assert.True(RoutineFiles.SameName("WerMgr", "wermgr.exe"));
        Assert.True(RoutineFiles.SameName("kernel32", "kernel32.dll"));
        Assert.False(RoutineFiles.SameName("fltMC.exe", "updater.exe"));
    }

    [Fact]
    public void Folder_tests_only_hold_for_the_real_folders()
    {
        Assert.True(RoutineFiles.InWindowsFolder(Sys("notepad.exe")));
        Assert.False(RoutineFiles.InWindowsFolder(@"D:\Windows\System32\notepad.exe".Replace("D:", OtherDrive())));
        Assert.False(RoutineFiles.InProgramFiles(@"C:\Users\me\Desktop\Program Files\cheat.dll"));
        Assert.False(RoutineFiles.InWindowsFolder(@"C:\Users\me\AppData\Local\Microsoft\WindowsApps\cheat.exe"));
    }

    [Fact]
    public void A_Store_app_is_verified_through_its_own_package_and_not_by_its_folder()
    {
        // The apps folder cannot be listed without administrator rights, but a package's own folder can be read once its name
        // is known - which the folder of a running Store app (or HP_TEST_PACKAGE, set by hand) gives.
        string apps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps") + "\\";
        var packages = new List<string>();
        if (Environment.GetEnvironmentVariable("HP_TEST_PACKAGE") is { Length: > 0 } named) packages.Add(named);
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.MainModule?.FileName is { } file && file.StartsWith(apps, StringComparison.OrdinalIgnoreCase))
                        packages.Add(apps + file[apps.Length..].Split('\\')[0]);
                }
                catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
            }
        }
        packages = packages.Distinct(StringComparer.OrdinalIgnoreCase).Take(6).ToList();
        output.WriteLine($"{packages.Count} package folder(s) to check");
        foreach (var package in packages)
        {
            if (FileInspector.PackageCatalogFor(Path.Combine(package, "x")) is not { } catalog) { output.WriteLine($"{package}: no catalog"); continue; }
            foreach (var exe in Directory.EnumerateFiles(package, "*.exe", SearchOption.AllDirectories).Take(3))
            {
                var facts = SignatureTrust.Of(exe);
                output.WriteLine($"{exe}: {facts} signer={FileInspector.SignerName(exe)} listed={FileInspector.ListedIn(catalog, exe)}");
                output.WriteLine("  " + SignatureTrust.Diagnose(catalog));
                Assert.Equal(SignatureStatus.Signed, facts.Status);
            }
        }
        // A file that is not in the package's catalog gains nothing from sitting in a folder that has one.
        string dir = TempFolder();
        try
        {
            if (packages.Select(p => Path.Combine(p, "AppxMetadata", "CodeIntegrity.cat")).FirstOrDefault(File.Exists) is not { } real) return;
            Directory.CreateDirectory(Path.Combine(dir, "AppxMetadata"));
            File.Copy(real, Path.Combine(dir, "AppxMetadata", "CodeIntegrity.cat"));
            string planted = Path.Combine(dir, "helper.exe");
            File.Copy(typeof(RoutineFilesTests).Assembly.Location, planted);
            Assert.NotEqual(SignatureStatus.Signed, SignatureTrust.Of(planted).Status);
            Assert.Null(RoutineFiles.Reason(planted));
        }
        finally { Directory.Delete(dir, true); }
    }

    static string OtherDrive() => Environment.GetFolderPath(Environment.SpecialFolder.Windows).StartsWith("D", StringComparison.OrdinalIgnoreCase) ? "E:" : "D:";

    [Fact]
    public void Other_publishers_are_vouched_for_by_Windows_trusted_roots_not_by_their_name()
    {
        // A build server's image decides which programs and which list of roots are there; this is a check of a real PC.
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        // Whatever signed third-party programs this PC has: none may read as Microsoft, and none as "added to this PC".
        var candidates = new[]
        {
            @"C:\Program Files\Git\cmd\git.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            @"C:\Program Files\Mozilla Firefox\firefox.exe", @"C:\Program Files (x86)\Steam\steam.exe",
            @"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe", @"C:\Program Files\7-Zip\7z.exe",
        }.Where(File.Exists).ToList();
        foreach (var path in candidates)
        {
            var facts = SignatureTrust.Of(path);
            output.WriteLine($"{path}: {facts} routine={RoutineFiles.Reason(path) ?? "no"}");
            output.WriteLine("  " + SignatureTrust.Diagnose(path));
            Assert.NotEqual(SignerRoot.Microsoft, facts.Root);
            if (facts.Status == SignatureStatus.Signed) Assert.NotEqual(SignerRoot.Local, facts.Root);
        }
        var runtime = SignatureTrust.Of(typeof(object).Assembly.Location);
        output.WriteLine($".NET runtime: {runtime}");
        Assert.True(runtime.IsMicrosoft);
    }
}
