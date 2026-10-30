using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Domains the PC looked up recently (the DNS Client's cache): a cheat's site, its licence server or a download host
/// shows here even after the browser history and the downloaded file are deleted. Shown with the memory strings; only
/// names matching a keyword become a finding.
/// </summary>
public sealed class DnsCacheCollector : ICollector
{
    public const string Label = "DNS cache";

    public string Name => "DNS cache";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        // Without administrator rights Windows answers with an empty cache rather than an error: never report that as "nothing looked up".
        if (DnsCache.Read() is not { } entries || (entries.Count == 0 && !WinApi.IsElevated()))
        {
            ctx.Check("Memory", Label, CheckState.Unknown, "The DNS cache could not be read (Windows only gives it to administrators).");
            return 0;
        }
        int pid = WinApi.QueryService("Dnscache").Pid;
        foreach (var e in entries)
        {
            ct.ThrowIfCancellationRequested();
            ctx.MemoryHits.Add(new MemoryHit { Process = Label, Pid = pid, Path = e.Name, Raw = $"{e.Type} record" });
        }
        ctx.Check("Memory", Label, CheckState.Ok, $"{entries.Count:N0} domains looked up recently are still cached.");
        return entries.Count;
    }
}
