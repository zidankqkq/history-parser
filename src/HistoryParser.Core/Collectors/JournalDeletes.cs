using System.Globalization;
using HistoryParser.Core.Bypass;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Who deleted a change journal, from the requests Windows logs (Ntfs/Operational 501: the process, the drive and the
/// id of the journal the request named).
/// <para>
/// The event's own text says "a process has deleted a USN journal", but it is not proof of a deletion. It is logged for
/// every such request, and a program can send one only to be told when a journal is deleted: the search indexer does
/// that about once a day. On a real PC ten weeks of the log held dozens of these, every one naming the journal that was
/// still there. So an event counts only when both of these hold:
/// </para>
/// <list type="bullet">
/// <item>the journal it names is no longer the drive's (a journal's id is the time it was created, so ids also give the order);</item>
/// <item>it is the last request that named that journal, and the journal that came next was created within minutes of it.</item>
/// </list>
/// The process name is whatever Windows logged, cut to 14 characters; it identifies nothing by itself.
/// </summary>
internal static class JournalDeletes
{
    public const string Log = "Microsoft-Windows-Ntfs/Operational";

    /// <summary>How long after the request the next journal may appear and still be the result of it.</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    public sealed record Request(DateTime TimeUtc, string Process, string Volume, ulong JournalId);

    /// <param name="DeletedCreatedUtc">When the deleted journal had been created (its id).</param>
    /// <param name="NextJournalId">The journal that replaced it; null when the drive has none now.</param>
    /// <param name="NextCreatedUtc">When that one was created.</param>
    public sealed record Deletion(Request Request, DateTime? DeletedCreatedUtc, ulong? NextJournalId, DateTime? NextCreatedUtc);

    /// <summary>Every request in the log; empty when the log is missing, switched off or cannot be read.</summary>
    public static List<Request> Read()
    {
        var list = new List<Request>();
        foreach (var r in Events.Read(Log, "*[System[EventID=501]]", 5000))
            if (Parse(Events.Data(r), Events.Utc(r)) is { } request) list.Add(request);
        return list;
    }

    public static Request? Parse(IReadOnlyDictionary<string, string> data, DateTime? timeUtc)
    {
        if (timeUtc is not { } t) return null;
        var id = (data.GetValueOrDefault("JournalId") ?? "").Trim();
        if (id.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) id = id[2..];
        if (!ulong.TryParse(id, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong journal) || journal == 0) return null;
        var volume = (data.GetValueOrDefault("VolumeName") ?? "").Trim().TrimEnd('\\');
        if (volume.Length == 0) return null;
        return new Request(t, (data.GetValueOrDefault("ProcessName") ?? "").Trim(), volume, journal);
    }

    /// <summary>
    /// The deletions the log shows for one drive, oldest first. <paramref name="currentJournalId"/> is the journal the
    /// drive has now, or null when it has none.
    /// </summary>
    public static List<Deletion> Deletions(IEnumerable<Request> requests, string volume, ulong? currentJournalId)
    {
        var mine = requests.Where(r => r.Volume.Equals(volume, StringComparison.OrdinalIgnoreCase)).ToList();
        var ids = mine.Select(r => r.JournalId).Concat(currentJournalId is { } c ? [c] : []).Distinct().Order().ToList();
        var result = new List<Deletion>();
        for (int i = 0; i < ids.Count; i++)
        {
            ulong id = ids[i];
            if (id == currentJournalId) continue;
            var last = mine.Where(r => r.JournalId == id).MaxBy(r => r.TimeUtc)!;
            var created = FileTime.ToUtc((long)id);
            if (i + 1 < ids.Count)
            {
                // A later journal is known: the request deleted this one only if that journal followed it closely.
                var next = FileTime.ToUtc((long)ids[i + 1]);
                if (next is not { } n || n < last.TimeUtc.AddSeconds(-5) || n - last.TimeUtc > Window) continue;
                result.Add(new Deletion(last, created, ids[i + 1], next));
            }
            // No later journal at all: the drive has none now, and this is the last request that named the last one.
            else result.Add(new Deletion(last, created, null, null));
        }
        return result;
    }

    /// <summary>"fsutil.exe" as logged, or a plain word when Windows logged no name.</summary>
    public static string Who(Request r) => r.Process.Length > 0 ? r.Process : "an unnamed process";
}
