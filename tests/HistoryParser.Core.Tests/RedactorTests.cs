using HistoryParser.Core.Export;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

public class RedactorTests
{
    static readonly DateTime Now = new(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);

    static ScanResult Sample()
    {
        var file = new FileRecord { Path = @"C:\Users\Bob\Desktop\vape.jar", Name = "vape.jar", Status = FileStatus.Deleted,
            StatusDetail = "Deleted by BOB-PC" };
        file.Evidence.Add(new Evidence { Source = EvidenceSource.Bam, Kind = EvidenceKind.Execution, Path = file.Path, Detail = @"Last execution for BOB-PC\Bob" });
        file.Findings.Add(new Finding { Severity = Severity.Medium, Category = FindingCategory.TimelineInconsistency, Title = "Ran, then deleted", Detail = @"C:\Users\Bob\Desktop\vape.jar ran then was deleted", Path = file.Path });

        return new ScanResult
        {
            Machine = new MachineInfo { ComputerName = "BOB-PC", UserName = @"BOB-PC\Bob" },
            StartedUtc = Now, FinishedUtc = Now,
            Files = [file],
            Findings = file.Findings.ToList(),
            Checks = [new IntegrityCheck("Memory", "explorer", CheckState.Ok, @"read C:\Users\Bob\x")],
            Sources = [],
            ClockChanges = [],
            MemoryHits = [new MemoryHit { Process = "explorer.exe", Pid = 1, Path = @"C:\Users\Bob\cheat.exe", Raw = "secret blob" }],
            Timeline =
            [
                file.Evidence[0],
                new Evidence { Source = EvidenceSource.ShellHistory, Kind = EvidenceKind.Presence, Path = "[Typed] my bank site", Detail = "Run box" },
                new Evidence { Source = EvidenceSource.Prefetch, Kind = EvidenceKind.Execution, Path = @"C:\Users\Public\tool.exe", Detail = "bobby's tool" },
            ],
            Commands =
            [
                new CommandEntry { Group = "PowerShell", Source = "history", Command = @"cd C:\Users\Bob\Documents\taxes", User = "Bob" },
                new CommandEntry { Group = "PowerShell", Source = "history", Command = @"fsutil usn deletejournal /d c: # run by Bob", User = "Bob",
                    Suspicion = "deletes the USN journal" },
            ],
        };
    }

    [Fact]
    public void Masks_the_computer_and_user_names_everywhere()
    {
        var r = Redactor.Redact(Sample());
        Assert.True(r.PrivateDetailsHidden);
        Assert.Equal("<pc>", r.Machine.ComputerName);
        Assert.Equal("<user>", r.Machine.UserName);
        var f = Assert.Single(r.Files);
        Assert.Equal(@"C:\Users\<user>\Desktop\vape.jar", f.Path);
        Assert.Equal("Deleted by <pc>", f.StatusDetail);
        Assert.Equal(@"Last execution for <pc>\<user>", f.Evidence[0].Detail);
        Assert.Equal(@"C:\Users\<user>\Desktop\vape.jar ran then was deleted", r.Findings[0].Detail);
        Assert.Equal(@"read C:\Users\<user>\x", r.Checks[0].Detail);

        var everything = System.Text.Json.JsonSerializer.Serialize(r);
        Assert.DoesNotContain("Bob\\", everything);
        Assert.DoesNotContain("BOB-PC", everything);
    }

    [Fact]
    public void Leaves_shared_profiles_and_longer_words_alone()
    {
        var r = Redactor.Redact(Sample());
        var tool = Assert.Single(r.Timeline, e => e.Path.EndsWith("tool.exe"));
        Assert.Equal(@"C:\Users\Public\tool.exe", tool.Path);
        Assert.Equal("bobby's tool", tool.Detail); // "bob" inside "bobby" is not the user name
    }

    [Fact]
    public void Removes_personal_history_but_keeps_flagged_commands()
    {
        var r = Redactor.Redact(Sample());
        var cmd = Assert.Single(r.Commands);
        Assert.Equal("deletes the USN journal", cmd.Suspicion);
        Assert.Equal("fsutil usn deletejournal /d c: # run by <user>", cmd.Command);
        Assert.Equal("<user>", cmd.User);
        Assert.DoesNotContain(r.Timeline, e => e.Source == EvidenceSource.ShellHistory);
        Assert.Equal("", Assert.Single(r.MemoryHits).Raw);
        Assert.Equal(@"C:\Users\<user>\cheat.exe", r.MemoryHits[0].Path);
    }

    [Fact]
    public void Redacted_report_round_trips_through_json()
    {
        var path = Path.GetTempFileName();
        try
        {
            JsonExporter.Write(Redactor.Redact(Sample()), path);
            var back = JsonExporter.Read(path);
            Assert.True(back.PrivateDetailsHidden);
            Assert.Equal(@"C:\Users\<user>\Desktop\vape.jar", back.Files[0].Path);
        }
        finally { File.Delete(path); }
    }
}
