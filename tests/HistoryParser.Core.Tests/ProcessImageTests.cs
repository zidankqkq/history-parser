using HistoryParser.Core.Bypass;
using HistoryParser.Core.Models;
using Xunit.Abstractions;
using static HistoryParser.Core.Bypass.ProcessImageAudit;

namespace HistoryParser.Core.Tests;

/// <summary>
/// Process hollowing: a running program whose memory is not the file the records name. The judging is tested on made-up
/// processes (no process is ever hollowed here); the reading is tested on this test process itself.
/// </summary>
public class ProcessImageTests(ITestOutputHelper output)
{
    static readonly DateTime Started = new(2026, 11, 12, 18, 0, 0, DateTimeKind.Utc);

    static PeImage Image(uint stamp = 0x65000000, uint entry = 0x1400, bool managed = false, params PeSection[] sections) =>
        new(0x8664, stamp, entry, 0x20000, managed, (0, 0),
            sections.Length > 0 ? sections : [new PeSection(".text", 0x1000, 0x8000, 0x400, 0x8000, 0x60000020), new PeSection(".data", 0xA000, 0x1000, 0x8400, 0x200, 0xC0000040)]);

    static Seen Normal() => new()
    {
        Pid = 4242, Name = "svchost", StartedAs = @"\Device\HarddiskVolume3\Windows\System32\svchost.exe", Path = @"C:\Windows\System32\svchost.exe",
        StartedUtc = Started, ImageBase = 0x7FF6_1234_0000, BackedByImage = true, Mapped = @"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
        Memory = Image(), Disk = Image(), MicrosoftFile = true,
    };

    static Judgement? Judge(Seen p, bool journalCovers = true, bool pathChanged = false) => ProcessImageAudit.Judge(p, _ => journalCovers, _ => pathChanged);

    [Fact]
    public void A_program_that_is_its_file_is_not_reported() => Assert.Null(Judge(Normal()));

    [Fact]
    public void Private_memory_where_the_program_should_be_is_a_hollowed_process()
    {
        var found = Judge(Normal() with { BackedByImage = false, Mapped = null, Memory = null, Disk = null });
        Assert.Equal(Severity.High, found!.Severity);
        Assert.StartsWith("Hollowed process: svchost (PID 4242)", found.Title);
    }

    [Fact]
    public void An_image_that_is_not_the_file_mapped_there_is_reported()
    {
        // Overwritten in place: the file says one build, the memory another.
        var found = Judge(Normal() with { Memory = Image(stamp: 0x66112233) });
        Assert.Equal(Severity.High, found!.Severity);
        Assert.Contains("is not its file", found.Title);

        // A different section layout is a different program.
        var other = Judge(Normal() with { Memory = Image(sections: [new PeSection("UPX0", 0x1000, 0x9000, 0, 0, 0xE0000080)]) });
        Assert.Equal(Severity.High, other!.Severity);
    }

    [Fact]
    public void A_packed_program_that_rewrites_itself_is_not_called_hollowed()
    {
        // Its own file says it: code that is writable and empty on disk.
        var packed = Image(sections: [new PeSection("UPX0", 0x1000, 0x9000, 0, 0, 0xE0000080), new PeSection("UPX1", 0xA000, 0x4000, 0x400, 0x4000, 0xE0000040)]);
        var found = Judge(Normal() with { MicrosoftFile = false, Disk = packed, Memory = packed with { EntryPoint = 0x9999 }, ReplacedCode = 4096 });
        Assert.True(found == null || found.Severity <= Severity.Low);
    }

    [Fact]
    public void A_dot_net_program_whose_header_Windows_adjusted_is_not_reported()
    {
        // Windows changes the entry point and size fields when it loads a .NET program; the build time and sections stay.
        var disk = Image(managed: true);
        Assert.Null(Judge(Normal() with { Disk = disk, Memory = disk with { EntryPoint = 0, SizeOfImage = 0x24000, Machine = 0x14C } }));
    }

    [Fact]
    public void Replaced_code_is_high_in_a_Microsoft_program_and_a_lead_in_any_other()
    {
        var replaced = Normal() with { ReplacedCode = 8192, ReplacedIn = "section \".text\"" };
        Assert.Equal(Severity.High, Judge(replaced)!.Severity);
        Assert.Equal(Severity.Medium, Judge(replaced with { MicrosoftFile = false })!.Severity);
        // A hook is a few bytes; less than two whole blocks is never reported.
        Assert.Null(Judge(Normal() with { ReplacedCode = 64 }));
    }

    [Fact]
    public void A_program_updated_while_running_is_told_apart_from_a_swapped_image()
    {
        var renamed = Normal() with
        {
            Name = "chrome", MicrosoftFile = false, StartedAs = @"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe",
            Mapped = @"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\old_chrome.exe", OtherFile = true, PathFileExists = true,
        };
        // The new version at the old path was written after the process started: an update.
        Assert.Null(Judge(renamed with { PathFileCreatedUtc = Started.AddHours(2), PathFileWrittenUtc = Started.AddDays(-3) }));
        // Its dates are old (an installer keeps them), but the journal shows the path being replaced since: still an update.
        Assert.Null(Judge(renamed with { PathFileCreatedUtc = Started.AddDays(-9), PathFileWrittenUtc = Started.AddDays(-9) }, pathChanged: true));
        // The old path is empty now: the program was renamed or removed while running.
        Assert.Null(Judge(renamed with { PathFileExists = false }));

        // The file it was started from is still there, untouched since before it started - yet it runs another file's image.
        var swapped = renamed with
        {
            Name = "svchost", StartedAs = @"\Device\HarddiskVolume3\Windows\System32\svchost.exe", Mapped = @"\Device\HarddiskVolume3\Users\x\AppData\Local\Temp\a.tmp",
            PathFileCreatedUtc = Started.AddDays(-200), PathFileWrittenUtc = Started.AddDays(-200),
        };
        Assert.Equal(Severity.High, Judge(swapped)!.Severity);
        // Without a journal that reaches back that far it is a lead, not a certainty.
        Assert.Equal(Severity.Medium, Judge(swapped, journalCovers: false)!.Severity);
    }

    [Fact]
    public void A_wiped_header_is_reported()
    {
        Assert.Equal(Severity.High, Judge(Normal() with { Memory = null })!.Severity);
        Assert.Equal(Severity.Medium, Judge(Normal() with { Memory = null, MicrosoftFile = false })!.Severity);
    }

    // ---- comparing code ---------------------------------------------------------------------------

    static byte[] Code(int length, int seed)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    [Fact]
    public void Identical_code_and_loader_changes_are_not_replaced_code()
    {
        var disk = Code(64 * 1024, 1);
        Assert.Equal(0, ReplacedCode(disk, disk).Bytes);

        // Loading at another address rewrites addresses inside the code: here every pointer of a table, 4 bytes in 8.
        var relocated = (byte[])disk.Clone();
        for (int i = 0; i + 8 <= 4096; i += 8)
            for (int b = 2; b < 6; b++) relocated[i + b] ^= 0x5A;
        Assert.Equal(0, ReplacedCode(disk, relocated).Bytes);

        // A hook: a jump written over the start of a function.
        var hooked = (byte[])disk.Clone();
        for (int i = 0; i < 14; i++) hooked[5000 + i] ^= 0xFF;
        Assert.Equal(0, ReplacedCode(disk, hooked).Bytes);
    }

    [Fact]
    public void Code_written_over_code_is_found_and_the_import_table_is_left_out()
    {
        var disk = Code(64 * 1024, 2);
        var memory = (byte[])disk.Clone();
        Code(1024, 3).CopyTo(memory, 8192);
        var (bytes, first) = ReplacedCode(disk, memory);
        Assert.InRange(bytes, 900, 1024);
        Assert.Equal(8192, first);

        // The same change inside the range the loader fills in itself is not code.
        Assert.Equal(0, ReplacedCode(disk, memory, (8192, 8192 + 1024)).Bytes);
        // A whole image of other code.
        Assert.True(ReplacedCode(disk, Code(64 * 1024, 4)).Bytes > 60 * 1024);
    }

    [Fact]
    public void Entropy_tells_compiled_code_from_encrypted_data()
    {
        Assert.True(Entropy(Code(1 << 16, 5)) > 7.9);
        // Real code: this test assembly's own bytes.
        var real = File.ReadAllBytes(typeof(ProcessImageTests).Assembly.Location);
        output.WriteLine($"entropy of a real program: {Entropy(real):0.00}");
        Assert.True(Entropy(real) < 7.2);
        Assert.Equal(0, Entropy(new byte[4096]));
    }

    [Fact]
    public void A_header_is_read_from_a_real_program()
    {
        var bytes = File.ReadAllBytes(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll")).AsSpan(0, 0x1000);
        var image = ParseHeader(bytes);
        Assert.NotNull(image);
        Assert.Contains(image!.Sections, s => s.Name == ".text" && s.Executable && !s.Writable);
        Assert.False(image.ChangesItself);
        Assert.Null(ParseHeader(new byte[0x1000]));
        Assert.Empty(HeaderDifferences(image, image));
    }

    // ---- a real process ---------------------------------------------------------------------------

    [Fact]
    [Trait("Category", "Integration")]
    public void This_test_process_reads_as_the_file_it_was_started_from()
    {
        var seen = Look(Environment.ProcessId);
        Assert.NotNull(seen);
        output.WriteLine($"{seen!.Name}: started as {seen.StartedAs}, mapped {seen.Mapped}, replaced {seen.ReplacedCode}");
        Assert.True(seen.BackedByImage);
        Assert.NotNull(seen.Memory);
        Assert.NotNull(seen.Disk);
        Assert.Equal(seen.StartedAs, seen.Mapped, ignoreCase: true);
        Assert.Null(Judge(seen));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public void No_program_running_on_this_PC_reads_as_hollowed()
    {
        // A build server runs whatever its image carries; this is a check of a real PC.
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        int looked = 0, closed = 0;
        var reported = new List<string>();
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id is 0 or 4) continue;
                var seen = Look(process.Id);
                if (seen == null) { closed++; continue; }
                if (seen.NoImage) continue;
                looked++;
                if (Judge(seen, journalCovers: false) is { } found) reported.Add($"{found.Severity}: {found.Title} — {found.Detail}");
            }
        }
        output.WriteLine($"{looked} compared, {closed} could not be opened");
        foreach (var line in reported) output.WriteLine(line);
        Assert.True(looked > 5);
        Assert.DoesNotContain(reported, r => r.StartsWith("High", StringComparison.Ordinal));
    }
}
