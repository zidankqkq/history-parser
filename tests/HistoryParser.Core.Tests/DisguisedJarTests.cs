using System.IO.Compression;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Tests;

public class DisguisedJarTests
{
    static byte[] Jar(params string[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var e in entries)
                using (var s = zip.CreateEntry(e).Open()) s.Write("x"u8);
        return ms.ToArray();
    }

    static readonly byte[] PngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52];

    [Fact]
    public void A_jar_renamed_to_png_is_still_a_java_archive()
    {
        var path = Scratch.File("disguised", "cape.png", Jar("META-INF/MANIFEST.MF", "a/b/Module.class"));
        Assert.True(FileTypes.IsJavaArchive(path));
        Assert.True(FileTypes.LooksHarmless(path));
        Assert.False(FileTypes.IsJavaContainerName(path));
    }

    [Fact]
    public void A_picture_with_a_jar_appended_is_caught_too()
    {
        // Java reads a jar from its end, so this runs with "java -jar"; it also opens as a picture.
        var path = Scratch.File("polyglot", "skin.png", [.. PngHeader, .. Jar("Main.class")]);
        Assert.True(FileTypes.IsJavaArchive(path));
    }

    [Fact]
    public void A_resource_pack_or_a_real_picture_is_not()
    {
        Assert.False(FileTypes.IsJavaArchive(Scratch.File("pack", "pack.png", Jar("assets/minecraft/textures/a.png", "pack.mcmeta"))));
        Assert.False(FileTypes.IsJavaArchive(Scratch.File("picture", "real.png", [.. PngHeader, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])));
    }

    [Theory]
    [InlineData("javaw.exe", @"javaw -Xmx2G -jar C:\Users\a\Pictures\cape.png", @"C:\Users\a\Pictures\cape.png")]
    [InlineData("java.exe", "\"C:\\jre\\bin\\java.exe\" -jar \"C:\\Users\\a\\My Files\\notes.txt\" nogui", @"C:\Users\a\My Files\notes.txt")]
    [InlineData("javaw.exe", @"javaw -jar C:\games\client.jar", null)]
    [InlineData("javaw.exe", @"javaw -cp lib\a.jar net.minecraft.client.main.Main", null)]
    [InlineData("cmd.exe", @"cmd /c java -jar x.png", null)]
    public void Jar_arguments_named_like_something_else(string program, string commandLine, string? expected) =>
        Assert.Equal(expected, Bypass.ArgumentAudit.DisguisedJarArgument(program, commandLine));

    static byte[] RealClass() =>
        // The smallest valid class file header is enough for the reader to count it as code.
        [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 5, 7, 0, 2, 1, 0, 1, (byte)'A', 7, 0, 4, 1, 0, 16, .. "java/lang/Object"u8, 0, 33, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0];

    static byte[] JarWithClass()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            using (var s = zip.CreateEntry("A.class").Open()) s.Write(RealClass());
        return ms.ToArray();
    }

    [Fact]
    public void Program_Checker_names_a_jar_called_png()
    {
        var r = RatChecker.Core.RatScanner.Scan("cape.png", JarWithClass());
        Assert.Contains(r.Signs, s => s.Title == "Java archive under another name");
        var normal = RatChecker.Core.RatScanner.Scan("client.jar", JarWithClass());
        Assert.DoesNotContain(normal.Signs, s => s.Title == "Java archive under another name");
    }

    [Theory]
    [InlineData(@"C:\mods\old.zip")]
    [InlineData(@"C:\mods\x.litemod")]
    [InlineData(@"C:\x\client.jar")]
    public void Normal_java_code_names_are_not_disguises(string path) => Assert.True(FileTypes.IsJavaContainerName(path));
}
