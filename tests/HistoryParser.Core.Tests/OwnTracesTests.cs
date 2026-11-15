using HistoryParser.Core.Models;

namespace HistoryParser.Core.Tests;

/// <summary>What the check itself leaves is told apart only by proof, never by a name or a folder.</summary>
public class OwnTracesTests
{
    const string Pf = @"C:\Windows\Prefetch\HISTORYPARSER.EXE-1A2B3C4D.pf";

    static FileRecord Program(string path, bool verified, string pf)
    {
        var r = new FileRecord { Path = path, Name = Path.GetFileName(path), Type = FileType.Exe, IsThisTool = verified };
        r.Evidence.Add(new Evidence { Source = EvidenceSource.Prefetch, Kind = EvidenceKind.Execution, Path = path, Origin = Path.GetFileName(pf) });
        return r;
    }

    static FileRecord PrefetchFile(string path)
    {
        var r = new FileRecord { Path = path, Name = Path.GetFileName(path), Type = FileType.Other, Status = FileStatus.Deleted };
        r.Findings.Add(new Finding { Severity = Severity.Medium, Category = FindingCategory.AntiForensics, Title = "Prefetch file changed", Detail = "", Path = path });
        return r;
    }

    [Fact]
    public void The_prefetch_file_of_a_verified_copy_is_ours()
    {
        var pf = PrefetchFile(Pf);
        Analysis.SelfTraces.Mark([Program(@"C:\Users\a\Downloads\HistoryParser.exe", verified: true, Pf), pf], []);
        Assert.True(pf.IsThisTool);
        Assert.Equal(Severity.Info, pf.Findings[0].Severity);
    }

    [Fact]
    public void A_prefetch_file_named_like_ours_is_not_ours()
    {
        // The program it belongs to isn't verified: a copy named like ours, or gone.
        var pf = PrefetchFile(Pf);
        Analysis.SelfTraces.Mark([Program(@"C:\Users\a\Downloads\gone\HistoryParser.exe", verified: false, Pf), pf], []);
        Assert.False(pf.IsThisTool);
        Assert.Equal(Severity.Medium, pf.Findings[0].Severity);

        // Nothing ties this one to any program at all.
        var lone = PrefetchFile(Pf);
        Analysis.SelfTraces.Mark([lone], []);
        Assert.False(lone.IsThisTool);
    }

    [Fact]
    public void A_gone_file_in_a_runtime_folder_like_ours_is_noted_but_keeps_its_severity()
    {
        string path = @"C:\Users\a\AppData\Local\Temp\.net\HistoryParser\5554\wpfgfx_cor3.dll";
        var r = new FileRecord { Path = path, Name = "wpfgfx_cor3.dll", Type = FileType.Dll, Status = FileStatus.Deleted };
        r.Findings.Add(new Finding { Severity = Severity.Low, Category = FindingCategory.Deletion, Title = "Loaded, then deleted", Detail = "", Path = path });
        Analysis.SelfTraces.Mark([r], []);
        Assert.False(r.IsThisTool);
        Assert.Equal(Severity.Low, r.Findings[0].Severity);
        Assert.Contains("cannot be confirmed", r.StatusDetail);
    }
}
