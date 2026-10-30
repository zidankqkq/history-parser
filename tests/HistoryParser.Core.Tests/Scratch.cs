namespace HistoryParser.Core.Tests;

/// <summary>
/// Files the tests need on disk. They live next to the test binaries and are overwritten on the next run, never deleted:
/// a fake .exe/.dll written to Temp and deleted again is exactly what a cheat cleaning up looks like, and Log Parser
/// rightly reported the test suite's leftovers on the developer's PC as "program deleted right before the scan".
/// </summary>
static class Scratch
{
    static readonly string Root = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "test-scratch")).FullName;

    /// <summary>A path in its own subfolder (so a file can carry a fixed name such as HistoryParser.exe), with the given contents.</summary>
    public static string File(string folder, string name, byte[] contents)
    {
        var dir = Directory.CreateDirectory(Path.Combine(Root, folder)).FullName;
        var path = Path.Combine(dir, name);
        System.IO.File.WriteAllBytes(path, contents);
        return path;
    }
}
