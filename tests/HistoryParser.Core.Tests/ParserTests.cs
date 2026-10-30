using System.Text;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Tests;

public class PrefetchParserTests
{
    static readonly DateTime Run1 = new(2026, 10, 20, 18, 30, 0, DateTimeKind.Utc);
    static readonly DateTime Run2 = new(2026, 10, 19, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>Builds a minimal version-30 prefetch file (the 0x130 layout: run count at 208).</summary>
    internal static byte[] BuildV30(string exe, int runCount, DateTime[] runs, string[] files, uint serial = 0xA1B2C3D4)
    {
        var d = new byte[4096];
        void U32(int o, uint v) => BitConverter.GetBytes(v).CopyTo(d, o);
        void I64(int o, long v) => BitConverter.GetBytes(v).CopyTo(d, o);

        U32(0, 30);
        Encoding.ASCII.GetBytes("SCCA").CopyTo(d, 4);
        Encoding.Unicode.GetBytes(exe).CopyTo(d, 16);
        U32(76, 0xDEADBEEF);
        U32(84, 0x130);
        for (int i = 0; i < runs.Length; i++) I64(128 + i * 8, runs[i].ToFileTimeUtc());
        U32(208, (uint)runCount);

        var names = Encoding.Unicode.GetBytes(string.Join("\0", files) + "\0");
        U32(100, 1024);
        U32(104, (uint)names.Length);
        names.CopyTo(d, 1024);

        int vol = 3072;
        var device = Encoding.Unicode.GetBytes(@"\VOLUME{01d2a3b4c5d6e7f8-a1b2c3d4}");
        U32(108, (uint)vol);
        U32(112, 1);
        U32(vol, 96);                       // device path offset (relative to volume block)
        U32(vol + 4, (uint)(device.Length / 2));
        I64(vol + 8, Run2.ToFileTimeUtc());
        U32(vol + 16, serial);
        device.CopyTo(d, vol + 96);
        return d;
    }

    [Fact]
    public void Parses_version_30_run_times_count_and_files()
    {
        var raw = BuildV30("JAVAW.EXE", 42, [Run1, Run2],
            [@"\VOLUME{01d2a3b4c5d6e7f8-a1b2c3d4}\PROGRAM FILES\JAVA\BIN\JAVAW.EXE", @"\VOLUME{01d2a3b4c5d6e7f8-a1b2c3d4}\USERS\BOB\CHEAT.JAR"]);
        var pf = PrefetchParser.Parse(raw);

        Assert.Equal(30, pf.Version);
        Assert.Equal("JAVAW.EXE", pf.ExecutableName);
        Assert.Equal(42, pf.RunCount);
        Assert.Equal([Run1, Run2], pf.RunTimesUtc);
        Assert.Contains(pf.FileNames, f => f.EndsWith("CHEAT.JAR"));
        Assert.Equal(0xA1B2C3D4u, Assert.Single(pf.Volumes).Serial);
    }

    [Fact]
    public void Run_times_come_back_newest_first_and_skip_empty_slots()
    {
        var pf = PrefetchParser.Parse(BuildV30("A.EXE", 2, [Run2, Run1], []));
        Assert.Equal([Run1, Run2], pf.RunTimesUtc);
    }

    [Fact]
    public void Decompresses_mam_files_with_the_windows_codec()
    {
        var plain = BuildV30("CMD.EXE", 3, [Run1], [@"\VOLUME{0-a1b2c3d4}\WINDOWS\SYSTEM32\CMD.EXE"]);
        var mam = PrefetchParser.Compress(plain);
        Assert.True(PrefetchParser.IsMam(mam));

        var pf = PrefetchParser.Parse(mam);
        Assert.Equal("CMD.EXE", pf.ExecutableName);
        Assert.Equal(3, pf.RunCount);
    }

    [Fact]
    public void Truncated_or_garbage_input_is_a_format_error_not_a_crash()
    {
        var raw = BuildV30("A.EXE", 1, [Run1], ["X"]);
        Assert.Throws<FormatException>(() => PrefetchParser.Parse(raw[..50]));
        Assert.Throws<FormatException>(() => PrefetchParser.Parse(new byte[300]));
        var bad = (byte[])raw.Clone();
        BitConverter.GetBytes(int.MaxValue).CopyTo(bad, 100); // filename offset points far outside the file
        Assert.Throws<FormatException>(() => PrefetchParser.Parse(bad));
    }

    [Fact]
    public void Executable_path_is_resolved_from_the_loaded_file_list()
    {
        var pf = PrefetchParser.Parse(BuildV30("JAVAW.EXE", 1, [Run1],
            [@"\VOLUME{0-a1b2c3d4}\WINDOWS\SYSTEM32\NTDLL.DLL", @"\VOLUME{0-a1b2c3d4}\JDK\BIN\JAVAW.EXE"]));
        var paths = new PathNormalizer([], new Dictionary<uint, string> { [0xA1B2C3D4] = "D:" }, new Dictionary<Guid, string>());
        Assert.Equal(@"D:\JDK\BIN\JAVAW.EXE", PrefetchCollector.ResolveExecutablePath(pf, paths));
    }
}

public class PathNormalizerTests
{
    readonly PathNormalizer _p = new(
        [new KeyValuePair<string, string>(@"\Device\HarddiskVolume3", "C:"), new(@"\Device\HarddiskVolume12", "E:")],
        new Dictionary<uint, string> { [0x1A2B3C4D] = "C:" },
        new Dictionary<Guid, string> { [new Guid("6D809377-6AF0-444B-8957-A3773F02200E")] = @"C:\Program Files" });

    [Theory]
    [InlineData(@"\Device\HarddiskVolume3\Users\x\a.exe", @"C:\Users\x\a.exe")]
    [InlineData(@"\Device\HarddiskVolume12\b.jar", @"E:\b.jar")]
    [InlineData(@"\Device\HarddiskVolume1\c.exe", @"\Device\HarddiskVolume1\c.exe")] // unknown volume: left as is
    [InlineData(@"\VOLUME{01d7aaaaaaaaaaaa-1a2b3c4d}\WINDOWS\X.DLL", @"C:\WINDOWS\X.DLL")]
    [InlineData(@"{6D809377-6AF0-444B-8957-A3773F02200E}\Tool\t.exe", @"C:\Program Files\Tool\t.exe")]
    [InlineData(@"\\?\C:\x.exe", @"C:\x.exe")]
    [InlineData(@"\??\C:\x.exe", @"C:\x.exe")]
    [InlineData("C:/fwd/slash.exe", @"C:\fwd\slash.exe")]
    public void Normalizes(string raw, string expected) => Assert.Equal(expected, _p.Normalize(raw));

    [Fact]
    public void Volume3_does_not_capture_volume30()
    {
        var p = new PathNormalizer([new KeyValuePair<string, string>(@"\Device\HarddiskVolume3", "C:")],
            new Dictionary<uint, string>(), new Dictionary<Guid, string>());
        Assert.Equal(@"\Device\HarddiskVolume30\x.exe", p.Normalize(@"\Device\HarddiskVolume30\x.exe"));
    }
}

public class SmallParserTests
{
    [Fact]
    public void ShimCache_windows10_entries()
    {
        var t = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(0x34u);
        w.Write(new byte[0x30]);
        foreach (var path in new[] { @"C:\a\one.exe", @"C:\b\two.exe" })
        {
            var p = Encoding.Unicode.GetBytes(path);
            w.Write(Encoding.ASCII.GetBytes("10ts"));
            w.Write(0u);
            w.Write((uint)(2 + p.Length + 8 + 4));
            w.Write((ushort)p.Length);
            w.Write(p);
            w.Write(t.ToFileTimeUtc());
            w.Write(0u);
        }
        var entries = ShimCacheParser.Parse(ms.ToArray());
        Assert.Equal(2, entries.Count);
        Assert.Equal(@"C:\b\two.exe", entries[1].Path);
        Assert.Equal(t, entries[0].LastModifiedUtc);
    }

    [Fact]
    public void RecycleBin_version2()
    {
        var t = new DateTime(2026, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        var path = @"C:\Users\bob\Desktop\vape.jar";
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(2L); w.Write(12345L); w.Write(t.ToFileTimeUtc()); w.Write(path.Length + 1);
        w.Write(Encoding.Unicode.GetBytes(path + "\0"));
        var e = RecycleBinParser.Parse(ms.ToArray());
        Assert.Equal(path, e.OriginalPath);
        Assert.Equal(12345, e.Size);
        Assert.Equal(t, e.DeletedUtc);
    }

    [Fact]
    public void UserAssist_rot13_name_and_fields()
    {
        var t = new DateTime(2026, 3, 3, 3, 3, 3, DateTimeKind.Utc);
        var data = new byte[72];
        BitConverter.GetBytes(7u).CopyTo(data, 4);
        BitConverter.GetBytes(t.ToFileTimeUtc()).CopyTo(data, 60);
        var e = UserAssistParser.Parse(Rot13.Decode(@"C:\Games\cheat.exe"), data)!;
        Assert.Equal(@"C:\Games\cheat.exe", e.Path);
        Assert.Equal(7, e.RunCount);
        Assert.Equal(t, e.LastRunUtc);
    }

    [Fact]
    public void Pca_launch_dictionary_is_utc()
    {
        var entries = PcaParser.ParseLaunchDic("C:\\a b\\x.exe|2026-10-20 18:05:01.123\r\ngarbage\r\nC:\\y.exe|not a date\r\n");
        var e = Assert.Single(entries);
        Assert.Equal(@"C:\a b\x.exe", e.Path);
        Assert.Equal(new DateTime(2026, 10, 20, 18, 5, 1, 123, DateTimeKind.Utc), e.TimeUtc);
        Assert.Equal(DateTimeKind.Utc, e.TimeUtc.Kind);
    }

    [Fact]
    public void Pca_general_db_finds_time_and_path_in_any_column()
    {
        var e = Assert.Single(PcaParser.ParseGeneralDb("2026-10-20 18:05:01.000|2|%USERPROFILE%\\dl\\x.exe|Desc|Vendor|1.0|id|0\n"));
        Assert.Equal(@"%USERPROFILE%\dl\x.exe", e.Path);
    }

    [Fact]
    public void Dps_strings()
    {
        Assert.Equal(("javaw.exe", "2026/10/20:18:22:13"), DpsStringParser.Match("xx!!javaw.exe!2026/10/20:18:22:13!1a2b!"));
        Assert.Null(DpsStringParser.Match("!!javaw.exe!yesterday!"));
    }

    [Fact]
    public void Text_decoding_detects_utf16_without_bom()
    {
        Assert.Equal("C:\\x.exe|t", TextDecoding.Decode(Encoding.Unicode.GetBytes("C:\\x.exe|t")));
        Assert.Equal("héllo", TextDecoding.Decode(Encoding.UTF8.GetBytes("héllo")));
    }
}

public class UsnTests
{
    static byte[] Record(ulong frn, ulong parent, long usn, DateTime t, UsnReason reason, uint attrs, string name)
    {
        var n = Encoding.Unicode.GetBytes(name);
        int len = (60 + n.Length + 7) & ~7;
        var r = new byte[len];
        BitConverter.GetBytes((uint)len).CopyTo(r, 0);
        BitConverter.GetBytes((ushort)2).CopyTo(r, 4);
        BitConverter.GetBytes(frn).CopyTo(r, 8);
        BitConverter.GetBytes(parent).CopyTo(r, 16);
        BitConverter.GetBytes(usn).CopyTo(r, 24);
        BitConverter.GetBytes(t.ToFileTimeUtc()).CopyTo(r, 32);
        BitConverter.GetBytes((uint)reason).CopyTo(r, 40);
        BitConverter.GetBytes(attrs).CopyTo(r, 52);
        BitConverter.GetBytes((ushort)n.Length).CopyTo(r, 56);
        BitConverter.GetBytes((ushort)60).CopyTo(r, 58);
        n.CopyTo(r, 60);
        return r;
    }

    [Fact]
    public void Parses_v2_records_after_the_header()
    {
        var t = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
        var buffer = new byte[8].Concat(Record(10, 5, 100, t, UsnReason.FileDelete | UsnReason.Close, 0x20, "vape.jar"))
            .Concat(Record(11, 5, 200, t, UsnReason.FileCreate, 0x10, "folder")).ToArray();
        var seen = new List<(string, UsnReason, bool)>();
        int n = UsnParser.ParseBuffer(buffer, (in UsnRecord r) => seen.Add((r.Name.ToString(), r.Reason, r.IsDirectory)));
        Assert.Equal(2, n);
        Assert.Equal(("vape.jar", UsnReason.FileDelete | UsnReason.Close, false), seen[0]);
        Assert.True(seen[1].Item3);
    }

    [Fact]
    public void Stops_on_a_corrupt_record_length()
    {
        var buffer = new byte[8].Concat(new byte[] { 3, 0, 0, 0 }).Concat(new byte[100]).ToArray();
        Assert.Equal(0, UsnParser.ParseBuffer(buffer, (in UsnRecord _) => { }));
    }

    [Fact]
    public void Clock_order_tracker_reports_backward_jumps_only()
    {
        var tracker = new ClockOrderTracker(TimeSpan.FromMinutes(2));
        var t0 = new DateTime(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);
        tracker.Observe(t0);
        tracker.Observe(t0.AddSeconds(-30));   // jitter: ignored
        tracker.Observe(t0.AddHours(5));       // forward (sleep): ignored
        tracker.Observe(t0.AddHours(2));       // back 3 h: reported
        tracker.Observe(t0.AddHours(2.1));
        var (before, after) = Assert.Single(tracker.Rollbacks);
        Assert.Equal(t0.AddHours(5), before);
        Assert.Equal(t0.AddHours(2), after);
    }
}

public class StringExtractorTests
{
    [Fact]
    public void Finds_ascii_and_utf16_paths_and_dps_markers()
    {
        var data = new byte[64]
            .Concat(Encoding.ASCII.GetBytes(@"C:\Users\x\Desktop\vape.jar")).Concat(new byte[5])
            .Concat(Encoding.Unicode.GetBytes(@"D:\tools\inject.dll")).Concat(new byte[6])
            .Concat(Encoding.Unicode.GetBytes("!!javaw.exe!2026/10/20:18:22:13!1!")).Concat(new byte[4])
            .Concat(Encoding.ASCII.GetBytes("no extension here at all")).ToArray();
        var found = new List<string>();
        StringExtractor.Extract(data, 8, found.Add);
        Assert.Contains(@"C:\Users\x\Desktop\vape.jar", found);
        Assert.Contains(@"D:\tools\inject.dll", found);
        Assert.Contains(found, s => s.StartsWith("!!javaw.exe!2026"));
        Assert.DoesNotContain(found, s => s.Contains("no extension"));
        Assert.Equal(found.Count, found.Distinct().Count());
    }

    [Fact]
    public void Json_escaped_paths_are_unescaped() =>
        Assert.Equal(@"C:\Program Files\x.exe", ProcessMemoryCollector.CleanPath(@"C:\\Program Files\\x.exe"));
}
