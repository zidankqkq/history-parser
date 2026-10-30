using System.Text.RegularExpressions;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Export;

/// <summary>
/// Makes a copy of a scan that is safer to share: the computer name and Windows user names are
/// masked everywhere, unflagged command history and typed text (Run box, address bar, Explorer
/// search) are removed, and raw memory text is dropped. Files, findings, deletions and
/// timestamps are kept because they are the evidence.
/// </summary>
public static class Redactor
{
    public const string UserMask = "<user>";
    public const string PcMask = "<pc>";

    static readonly Regex UserFolder = new(@"(?i)(\b[A-Z]:\\Users\\)([^\\/:*?""<>|\r\n]+)", RegexOptions.Compiled);
    static readonly HashSet<string> SharedProfiles = new(StringComparer.OrdinalIgnoreCase)
        { "Public", "Default", "Default User", "All Users", UserMask };

    /// <summary>Returns a function that masks the computer name and every user name found in the scan.</summary>
    public static Func<string?, string> CreateCleaner(ScanResult r)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddUser(string? account)
        {
            if (string.IsNullOrWhiteSpace(account)) return;
            var name = account.Contains('\\') ? account[(account.LastIndexOf('\\') + 1)..] : account;
            if (name.Length >= 2 && !SharedProfiles.Contains(name)) names.Add(name);
        }
        void FromPath(string? text)
        {
            if (string.IsNullOrEmpty(text)) return;
            foreach (Match m in UserFolder.Matches(text)) AddUser(m.Groups[2].Value);
        }

        AddUser(r.Machine.UserName);
        foreach (var f in r.Files) FromPath(f.Path);
        foreach (var e in r.Timeline) FromPath(e.Path);
        foreach (var c in r.Commands) AddUser(c.User);

        string pc = r.Machine.ComputerName;
        // Longest first so "zidan.smith" is replaced before "zidan".
        var ordered = names.OrderByDescending(n => n.Length).ToList();
        var nameRegex = ordered.Count == 0 ? null : new Regex(
            @"(?i)(?<![A-Za-z0-9])(" + string.Join("|", ordered.Select(Regex.Escape)) + @")(?![A-Za-z0-9])");
        var pcRegex = pc.Length >= 2 ? new Regex(@"(?i)(?<![A-Za-z0-9])" + Regex.Escape(pc) + @"(?![A-Za-z0-9])") : null;

        return text =>
        {
            if (string.IsNullOrEmpty(text)) return text ?? "";
            var s = UserFolder.Replace(text, m => SharedProfiles.Contains(m.Groups[2].Value) ? m.Value : m.Groups[1].Value + UserMask);
            if (pcRegex != null) s = pcRegex.Replace(s, PcMask);
            if (nameRegex != null) s = nameRegex.Replace(s, UserMask);
            return s;
        };
    }

    /// <summary>Typed text that is personal rather than evidence (Run box, address bar, search box).</summary>
    public static bool IsTypedHistory(Evidence e) => e.Source == EvidenceSource.ShellHistory;

    public static ScanResult Redact(ScanResult r)
    {
        var clean = CreateCleaner(r);

        Evidence E(Evidence e) => e with
        {
            Path = clean(e.Path),
            Detail = clean(e.Detail),
            Origin = e.Origin == null ? null : clean(e.Origin),
            RelatedPath = e.RelatedPath == null ? null : clean(e.RelatedPath),
        };
        Finding F(Finding f) => f with
        {
            Title = clean(f.Title),
            Detail = clean(f.Detail),
            Path = f.Path == null ? null : clean(f.Path),
        };

        var files = r.Files.Select(f =>
        {
            var copy = new FileRecord
            {
                Path = clean(f.Path), Name = clean(f.Name), Type = f.Type, IsWindowsFile = f.IsWindowsFile,
                LastExecutionUtc = f.LastExecutionUtc, LastActivityUtc = f.LastActivityUtc, RunCount = f.RunCount,
                WasExecutedDirectly = f.WasExecutedDirectly, WasLoaded = f.WasLoaded, Status = f.Status,
                StatusDetail = clean(f.StatusDetail), DeletedUtc = f.DeletedUtc, Size = f.Size, Sha256 = f.Sha256,
                Signature = f.Signature, Signer = f.Signer,
            };
            copy.Evidence.AddRange(f.Evidence.Where(e => !IsTypedHistory(e)).Select(E));
            copy.Findings.AddRange(f.Findings.Select(F));
            return copy;
        }).ToList();

        return new ScanResult
        {
            Machine = r.Machine with { ComputerName = PcMask, UserName = UserMask },
            StartedUtc = r.StartedUtc,
            FinishedUtc = r.FinishedUtc,
            Files = files,
            Findings = r.Findings.Select(F).ToList(),
            Checks = r.Checks.Select(c => c with { Name = clean(c.Name), Detail = clean(c.Detail) }).ToList(),
            Sources = r.Sources.Select(s => s with { Message = clean(s.Message) }).ToList(),
            ClockChanges = r.ClockChanges.Select(c => c with { Detail = clean(c.Detail) }).ToList(),
            // Looked-up domains are browsing history, not execution evidence: a redacted export leaves them out.
            MemoryHits = r.MemoryHits.Where(h => h.Process != Collectors.DnsCacheCollector.Label)
                .Select(h => h with { Path = clean(h.Path), Raw = "" }).ToList(),
            Timeline = r.Timeline.Where(e => !IsTypedHistory(e)).Select(E).ToList(),
            // Only flagged commands are kept: they are evidence; the rest is personal history.
            Commands = r.Commands.Where(c => c.Suspicion != null).Select(c => c with
            {
                Command = clean(c.Command), Source = clean(c.Source), Detail = clean(c.Detail),
                User = string.IsNullOrEmpty(c.User) ? "" : UserMask,
            }).ToList(),
            // Folder history is personal and no longer judged by name, so a redacted export leaves it out.
            Folders = [],
            PrivateDetailsHidden = true,
            Window = r.Window,
            SinceUtc = r.SinceUtc,
        };
    }
}
