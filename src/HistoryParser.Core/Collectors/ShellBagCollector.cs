using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// ShellBags: every folder each signed-in user opened in Explorer or an Open / Save dialog, which Windows keeps to
/// remember how the folder was shown — including folders deleted since, USB drives, and archives (a .zip, a modpack)
/// browsed like folders. Read from the loaded user hives (UsrClass.dat and NTUSER.DAT BagMRU).
///
/// Dates: a folder's record is rewritten whenever it, or a folder inside it, is opened, so that time is a moment it
/// was in use. Only the most recently opened folder inside each parent gets its own exact "opened" time.
/// </summary>
public sealed class ShellBagCollector : ICollector
{
    public string Name => "ShellBags (folders opened)";

    /// <summary>Enough for any real Explorer history; stops a crafted, endless tree.</summary>
    const int MaxNodes = 50_000, MaxDepth = 64;

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var sid in WinApi.LoadedUserSids())
        {
            ct.ThrowIfCancellationRequested();
            string user = WinApi.SidToName(sid);
            var known = new KnownFolders(sid);
            var visits = new List<FolderVisit>();
            foreach (var (hive, path, label) in new[]
            {
                (sid + "_Classes", @"Local Settings\Software\Microsoft\Windows\Shell\BagMRU", "UsrClass BagMRU"),
                (sid, @"Software\Microsoft\Windows\Shell\BagMRU", "NTUSER BagMRU"),
            })
            {
                using var key = Registry.Users.OpenSubKey(hive + "\\" + path);
                if (key == null) continue;
                int budget = MaxNodes;
                if (Load(key, label, ref budget, 0) is { } root) visits.AddRange(Walk(root, known.Resolve, known.Desktop, user));
            }
            foreach (var visit in Merge(visits))
            {
                ctx.Folders.Add(Judge(ctx, visit));
                items++;
            }
        }
        return items;
    }

    /// <summary>
    /// The same folder can be recorded more than once (reached from the Desktop and from This PC, or in both hives):
    /// one row each, with the latest times.
    /// </summary>
    internal static IEnumerable<FolderVisit> Merge(IEnumerable<FolderVisit> visits) =>
        visits.GroupBy(v => v.Path, StringComparer.OrdinalIgnoreCase).Select(g => g.Aggregate((a, b) => a with
        {
            OpenedUtc = Later(a.OpenedUtc, b.OpenedUtc),
            RecordUpdatedUtc = Later(a.RecordUpdatedUtc, b.RecordUpdatedUtc),
            FolderModifiedUtc = Later(a.FolderModifiedUtc, b.FolderModifiedUtc),
            Source = a.Source == b.Source ? a.Source : a.Source + "; " + b.Source,
        }));

    static DateTime? Later(DateTime? a, DateTime? b) => a == null ? b : b == null ? a : a > b ? a : b;

    // ---- the tree ---------------------------------------------------------------------------

    internal sealed record BagNode(string Key, DateTime? WrittenUtc, IReadOnlyList<int> Mru, IReadOnlyList<BagChild> Children);
    internal sealed record BagChild(int Slot, byte[] Item, BagNode? Node);

    static BagNode? Load(RegistryKey key, string label, ref int budget, int depth)
    {
        if (--budget < 0 || depth > MaxDepth) return null;
        var mru = new List<int>();
        if (key.GetValue("MRUListEx") is byte[] m)
            for (int i = 0; i + 4 <= m.Length && BitConverter.ToInt32(m, i) is var slot and >= 0; i += 4) mru.Add(slot);
        var children = new List<BagChild>();
        foreach (var name in key.GetValueNames())
        {
            if (!int.TryParse(name, out int slot) || slot < 0 || key.GetValue(name) is not byte[] item) continue;
            BagNode? node = null;
            using (var sub = key.OpenSubKey(name))
                if (sub != null) node = Load(sub, label + "\\" + name, ref budget, depth + 1);
            children.Add(new BagChild(slot, item, node));
        }
        return new BagNode(label, WinApi.GetKeyLastWriteUtc(key), mru, children);
    }

    /// <summary>
    /// Every folder, archive and archive entry in the tree with its full path. A path Explorer only kept the end of
    /// (under a special folder such as Quick access) starts with "…\". The top level is the Desktop.
    /// </summary>
    internal static IEnumerable<FolderVisit> Walk(BagNode root, Func<Guid, string?> knownFolder, string? desktop, string user)
    {
        var stack = new Stack<(BagNode Node, string? Path, bool InArchive, int Depth)>();
        stack.Push((root, desktop, false, 0));
        while (stack.Count > 0)
        {
            var (node, parent, parentInArchive, depth) = stack.Pop();
            foreach (var child in node.Children)
            {
                var item = ShellItems.Parse(child.Item);
                string? path = item.Kind switch
                {
                    ShellItemKind.Root => item.KnownFolder is { } g ? knownFolder(g) : null,
                    ShellItemKind.Drive => item.Name,
                    ShellItemKind.Special => null,
                    _ => Join(parent, item.Name),
                };
                // A file entry here is an archive Explorer opened like a folder; everything under it is inside it.
                bool inArchive = parentInArchive || item.Kind is ShellItemKind.File or ShellItemKind.ArchiveEntry;
                if (item.Kind is ShellItemKind.Folder or ShellItemKind.File or ShellItemKind.ArchiveEntry && path != null)
                {
                    yield return new FolderVisit
                    {
                        Path = path, User = user,
                        OpenedUtc = node.Mru.Count > 0 && node.Mru[0] == child.Slot ? node.WrittenUtc : null,
                        RecordUpdatedUtc = child.Node?.WrittenUtc,
                        FolderModifiedUtc = item.Modified is { } t ? FatToUtc(t) : null,
                        What = parentInArchive || item.Kind == ShellItemKind.ArchiveEntry ? "Inside archive"
                            : item.Kind == ShellItemKind.File ? "Archive" : "Folder",
                        Source = child.Node?.Key ?? $"{node.Key}\\{child.Slot}",
                    };
                }
                if (child.Node != null && depth < MaxDepth) stack.Push((child.Node, path, inArchive, depth + 1));
            }
        }
    }

    static string Join(string? parent, string name) => parent switch
    {
        null => "…\\" + name,
        "" => name,
        _ when parent.EndsWith('\\') => parent + name,
        _ => parent + "\\" + name,
    };

    // ---- judging ----------------------------------------------------------------------------

    // Folders opened are listed as plain history; History Parser no longer matches their names.
    static FolderVisit Judge(ScanContext ctx, FolderVisit v) => v with { Exists = Exists(v) };

    /// <summary>
    /// Null when it cannot be checked: a partial path, a network share (never touched), a drive that is not
    /// present now (a USB stick), or a folder inside an archive.
    /// </summary>
    static bool? Exists(FolderVisit v)
    {
        if (v.What == "Inside archive" || v.Path.StartsWith('…') || v.Path.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        try
        {
            if (Path.GetPathRoot(v.Path) is not { Length: > 0 } root || !Directory.Exists(root)) return null;
            return v.What == "Archive" ? File.Exists(v.Path) : Directory.Exists(v.Path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    /// <summary>
    /// Shell items keep the folder's time as a FAT date and time in UTC (checked on a real PC: 71 of the folders
    /// unchanged since matched their modified time as UTC, none as local time).
    /// </summary>
    internal static DateTime FatToUtc(DateTime fat) => DateTime.SpecifyKind(fat, DateTimeKind.Utc);

    // ---- known folders ----------------------------------------------------------------------

    /// <summary>Where a user's Desktop, Downloads … really are (they can be moved, e.g. into OneDrive).</summary>
    sealed class KnownFolders
    {
        readonly string _sid;
        readonly string? _profile;

        public KnownFolders(string sid)
        {
            _sid = sid;
            using var p = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
            _profile = p?.GetValue("ProfileImagePath") as string;
            Desktop = ShellFolder("Desktop");
        }

        public string? Desktop { get; }

        // Explorer's namespace items for the user's folders, and the registry value that says where each one is.
        static readonly Dictionary<Guid, string> Folders = new()
        {
            [new("B4BFCC3A-DB2C-424C-B029-7FE99A87C641")] = "Desktop",
            [new("D3162B92-9365-467A-956B-92703ACA08AF")] = "Personal",
            [new("FDD39AD0-238F-46AF-ADB4-6C85480369C7")] = "Personal",
            [new("088E3905-0323-4B02-9826-5D99428E115F")] = "{374DE290-123F-4565-9164-39C4925E467B}",
            [new("374DE290-123F-4565-9164-39C4925E467B")] = "{374DE290-123F-4565-9164-39C4925E467B}",
            [new("24AD3AD4-A569-4530-98E1-AB02F9417AA8")] = "My Pictures",
            [new("33E28130-4E1E-4676-835A-98395C3BC3BB")] = "My Pictures",
            [new("3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE")] = "My Music",
            [new("4BD8D571-6D19-48D3-BE97-422220080E43")] = "My Music",
            [new("F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A")] = "My Video",
            [new("18989B1D-99B5-455B-841C-AB7C74E4DDFC")] = "My Video",
        };
        static readonly Guid ThisPc = new("20D04FE0-3AEA-1069-A2D8-08002B30309D");
        static readonly Guid UserFolder = new("59031A47-3F72-44A7-89C5-5595FE6B30EE");
        static readonly Guid OneDrive = new("018D5C66-4533-4307-9B53-224DE2ED1FE6");

        /// <summary>"" for This PC (its children are drives), a folder path, or null for anything that is not a folder on disk.</summary>
        public string? Resolve(Guid g)
        {
            if (g == ThisPc) return "";
            if (g == UserFolder) return _profile;
            if (g == OneDrive)
            {
                using var env = Registry.Users.OpenSubKey($@"{_sid}\Environment");
                return env?.GetValue("OneDrive") as string ?? (_profile == null ? null : Path.Combine(_profile, "OneDrive"));
            }
            return Folders.TryGetValue(g, out var value) ? ShellFolder(value) : null;
        }

        string? ShellFolder(string value)
        {
            using var key = Registry.Users.OpenSubKey($@"{_sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
            if (key?.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string raw) return null;
            // %USERPROFILE% is that user's profile, not the profile of whoever runs the scan.
            if (_profile != null) raw = raw.Replace("%USERPROFILE%", _profile, StringComparison.OrdinalIgnoreCase);
            return Environment.ExpandEnvironmentVariables(raw).TrimEnd('\\');
        }
    }
}
