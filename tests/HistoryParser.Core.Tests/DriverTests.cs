using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Tests;

/// <summary>
/// Drivers and scripts in the file lists: the kernel's names for its modules become paths a file record can be built on, the
/// change journal is read for .sys and .py files, and only Microsoft's own drivers may be folded out of the way.
/// </summary>
public class DriverTests
{
    static string Same(string path) => path;

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\ntfs.sys", @"C:\WINDOWS\System32\drivers\ntfs.sys")]
    [InlineData(@"\??\C:\Users\me\AppData\Local\Temp\x.sys", @"C:\Users\me\AppData\Local\Temp\x.sys")]
    [InlineData(@"\Windows\system32\ntoskrnl.exe", @"C:\Windows\system32\ntoskrnl.exe")]
    public void A_kernel_module_name_becomes_a_path(string kernelName, string expected) =>
        Assert.Equal(expected, LoadedDriverCollector.ToPath(kernelName, @"C:\WINDOWS", "C:", Same));

    [Fact]
    public void A_device_path_goes_through_the_volume_map() =>
        Assert.Equal(@"D:\tools\x.sys",
            LoadedDriverCollector.ToPath(@"\Device\HarddiskVolume7\tools\x.sys", @"C:\WINDOWS", "C:", _ => @"D:\tools\x.sys"));

    [Theory]
    [InlineData("driver.sys", true)]
    [InlineData("tool.py", true)]
    [InlineData("tool.pyw", true)]
    [InlineData("run.bat", true)]
    [InlineData("macro.ahk", true)]
    [InlineData("notes.txt", false)]
    [InlineData("bundle.js", false)]
    public void The_change_journal_is_read_for_drivers_and_scripts(string name, bool followed) =>
        Assert.Equal(followed, FileTypes.IsInteresting(name));

    [Fact, Trait("Category", "Integration")]
    public void Windows_own_driver_is_routine()
    {
        string ntfs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "ntfs.sys");
        Assert.NotNull(RoutineFiles.Reason(ntfs));
    }

    [Fact, Trait("Category", "Integration")]
    public void A_driver_that_is_not_Microsofts_is_never_routine()
    {
        // Another company's signed driver is exactly what is brought along to get into the kernel, so those stay in view:
        // every .sys on this PC that is routine must be one Microsoft signed.
        string drivers = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
        foreach (var file in Directory.EnumerateFiles(drivers, "*.sys").Take(60))
            if (RoutineFiles.Reason(file) != null)
                Assert.Equal(SignerRoot.Microsoft, SignatureTrust.Of(file).Root);
    }
}
