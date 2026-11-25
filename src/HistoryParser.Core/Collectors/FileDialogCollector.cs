using System.Text;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Files picked in Open / Save dialogs. Windows keeps the last twenty per file type for every user
/// (ComDlg32\OpenSavePidlMRU\dll, \exe, \jar ...), so the library chosen in an injector's "select file" box, or the jar
/// handed to a launcher, is still listed after the file itself is gone. LastVisitedPidlMRU beside it keeps which program
/// showed a dialog and the folder it was last in.
/// <para>
/// Dates: a list is rewritten each time a file is picked, so its key's write time is when its newest entry was picked.
/// The other entries keep their order only.
/// </para>
/// </summary>
public sealed class FileDialogCollector : ICollector
{
    public string Name => "File dialogs";

    const string ComDlg = @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var sid in WinApi.LoadedUserSids())
        {
            ct.ThrowIfCancellationRequested();
            string user = WinApi.SidToName(sid);
            var known = new ShellBagCollector.KnownFolders(sid);

            var picks = new List<FileDialogHistory.Pick>();
            using (var lists = Registry.Users.OpenSubKey($@"{sid}\{ComDlg}\OpenSavePidlMRU"))
                if (lists != null)
                    foreach (var name in lists.GetSubKeyNames())
                    {
                        using var list = lists.OpenSubKey(name);
                        if (list == null) continue;
                        var (values, mru, ordered) = Load(list);
                        picks.AddRange(FileDialogHistory.List(name, values, mru, ordered ? WinApi.GetKeyLastWriteUtc(list) : null, known.Resolve));
                    }

            foreach (var p in FileDialogHistory.Merge(picks))
            {
                if (FileTypes.FromPath(p.Path) == FileType.Other && !FileDialogHistory.IsArchive(p.Path)) continue;
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.FileDialog, Kind = EvidenceKind.Presence,
                    // A path Windows kept only the end of joins its file by name, like a journal record in a deleted folder.
                    Path = p.Complete ? ctx.Paths.Normalize(p.Path) : @"?\" + Path.GetFileName(p.Path),
                    TimeUtc = p.PickedUtc, Origin = user, Detail = FileDialogHistory.Describe(p, user),
                });
                items++;
            }

            using var visited = Registry.Users.OpenSubKey($@"{sid}\{ComDlg}\LastVisitedPidlMRU");
            if (visited == null) continue;
            var (programs, order, programsOrdered) = Load(visited);
            var written = programsOrdered ? WinApi.GetKeyLastWriteUtc(visited) : null;
            for (int i = 0; i < order.Count; i++)
            {
                if (!programs.TryGetValue(order[i], out var value) || FileDialogHistory.LastVisited(value, known.Resolve) is not { } v) continue;
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.FileDialog, Kind = EvidenceKind.Presence, Path = $"[File dialog] {v.Program}",
                    TimeUtc = i == 0 ? written : null, Origin = user,
                    Detail = $"{v.Program} showed an Open/Save dialog for {user}" + (v.Folder != null ? $"; last folder {v.Folder}" : "") +
                             (i == 0 ? "" : $" (#{i + 1} of {order.Count}; only the newest is dated)"),
                });
                items++;
            }
        }
        return items;
    }

    /// <summary>
    /// A list key's numbered values and the order Windows keeps them in, newest first. Entries the order does not name
    /// (left behind, or the order is damaged) are still listed, after the ones it does. <c>Ordered</c> is false when there
    /// is no order at all: then nothing says which entry is the newest, so none can be dated.
    /// </summary>
    static (Dictionary<int, byte[]> Values, List<int> Mru, bool Ordered) Load(RegistryKey key)
    {
        var values = new Dictionary<int, byte[]>();
        foreach (var name in key.GetValueNames())
            if (int.TryParse(name, out int slot) && slot >= 0 && key.GetValue(name) is byte[] data) values[slot] = data;
        return (values, Order(key.GetValue("MRUListEx") as byte[], values.Keys, out bool ordered), ordered);
    }

    internal static List<int> Order(byte[]? mruListEx, IEnumerable<int> slots, out bool ordered)
    {
        var mru = new List<int>();
        if (mruListEx != null)
            for (int i = 0; i + 4 <= mruListEx.Length && BitConverter.ToInt32(mruListEx, i) is var slot and >= 0; i += 4)
                if (!mru.Contains(slot)) mru.Add(slot);
        ordered = mru.Count > 0;
        mru.AddRange(slots.Where(s => !mru.Contains(s)).Order());
        return mru;
    }
}

/// <summary>Reads the item lists the file dialogs store. No registry access of its own, so it can be tested on plain bytes.</summary>
public static class FileDialogHistory
{
    /// <param name="Path">Full path; starts with "…\" when Windows kept only the end of it.</param>
    /// <param name="List">The list it is in: a file type ("dll") or "*" for the list of every type.</param>
    /// <param name="Position">0 for the newest pick of its list.</param>
    /// <param name="PickedUtc">When it was picked; only the newest pick of a list has one.</param>
    /// <param name="FileModifiedUtc">The file's own modified time as it was when picked.</param>
    public sealed record Pick(string Path, string List, int Position, int Count, DateTime? PickedUtc, DateTime? FileModifiedUtc)
    {
        public bool Complete => !Path.StartsWith('…');
    }

    static readonly string[] Archives = [".zip", ".rar", ".7z"];
    public static bool IsArchive(string path) => Archives.Any(a => path.EndsWith(a, StringComparison.OrdinalIgnoreCase));

    /// <summary>The items of an item list: each starts with its own size, and a size of zero ends the list.</summary>
    public static List<byte[]> Items(ReadOnlySpan<byte> list)
    {
        var items = new List<byte[]>();
        int pos = 0;
        while (pos + 2 <= list.Length && items.Count < 64)
        {
            int size = BitConverter.ToUInt16(list[pos..]);
            if (size < 3 || pos + size > list.Length) break;
            items.Add(list.Slice(pos, size).ToArray());
            pos += size;
        }
        return items;
    }

    /// <summary>
    /// The path an item list leads to and its last item, or null when it leads to nothing on disk (a phone, a control
    /// panel page). A list that starts somewhere Windows does not spell out gives a path beginning "…\".
    /// <para>
    /// A file picked from search results or a library view is stored differently: no chain of folders, only items made of
    /// property sets, the last of which carries the file's full path as text. Seen in a real PC's lists; that path is used.
    /// </para>
    /// </summary>
    public static (string Path, ShellItem Last)? PathOf(IReadOnlyList<byte[]> items, Func<Guid, string?> knownFolder)
    {
        string? path = null;
        ShellItem? last = null;
        bool named = false;
        foreach (var bytes in items)
        {
            var item = ShellItems.Parse(bytes);
            switch (item.Kind)
            {
                case ShellItemKind.Root: path = item.KnownFolder is { } g ? knownFolder(g) : null; named = false; break;
                case ShellItemKind.Drive: path = item.Name; named = true; break;
                case ShellItemKind.Folder or ShellItemKind.File: path = ShellBagCollector.Join(path, item.Name); named = true; break;
                default: path = null; named = false; break;
            }
            last = item;
        }
        if (last != null && named && path != null) return (path, last);
        if (items.Count > 0 && EmbeddedPath(items[^1]) is { } embedded) return (embedded, new ShellItem(ShellItemKind.File, Path.GetFileName(embedded)));
        return null;
    }

    const string NotInPaths = "<>\"|?*";

    /// <summary>A full path ("C:\folder\file.ext") stored as text inside an item, ended by a zero; null when there is none.</summary>
    internal static string? EmbeddedPath(ReadOnlySpan<byte> item)
    {
        for (int i = 0; i + 8 <= item.Length; i++)
        {
            if (!char.IsAsciiLetter((char)item[i]) || item[i + 1] != 0 || item[i + 2] != ':' || item[i + 3] != 0 || item[i + 4] != '\\' || item[i + 5] != 0) continue;
            // The drive letter must start the text, not end a word before a colon.
            if (i >= 2 && item[i - 1] == 0 && char.IsAsciiLetterOrDigit((char)item[i - 2])) continue;
            int end = i;
            bool clean = true;
            while (end + 1 < item.Length && (item[end] != 0 || item[end + 1] != 0))
            {
                char c = (char)BitConverter.ToUInt16(item[end..]);
                if (c < 0x20 || c == 0xFFFF || NotInPaths.Contains(c) || (c == ':' && end != i + 2)) { clean = false; break; }
                end += 2;
            }
            if (clean && end + 1 < item.Length && end - i <= 2 * 520)
            {
                string text = Encoding.Unicode.GetString(item[i..end]);
                if (!text.EndsWith('\\') && Path.GetExtension(text).Length > 1) return text;
            }
            i = Math.Max(i, end - 1);
        }
        return null;
    }

    /// <summary>One list's entries as picks, newest first. Entries that are not files (a folder picked in a "select folder" box) are left out.</summary>
    public static IEnumerable<Pick> List(string name, IReadOnlyDictionary<int, byte[]> values, IReadOnlyList<int> mru, DateTime? writtenUtc,
        Func<Guid, string?> knownFolder)
    {
        for (int i = 0; i < mru.Count; i++)
        {
            if (!values.TryGetValue(mru[i], out var value) || PathOf(Items(value), knownFolder) is not { } found) continue;
            if (found.Last.Kind != ShellItemKind.File) continue;
            yield return new Pick(found.Path, name, i, mru.Count, i == 0 ? writtenUtc : null,
                found.Last.Modified is { } m ? ShellBagCollector.FatToUtc(m) : null);
        }
    }

    /// <summary>
    /// A file is in its own type's list and in the list of every type: one row for it, with the time when either list dates
    /// it and the place in its own type's list.
    /// </summary>
    public static IEnumerable<Pick> Merge(IEnumerable<Pick> picks) =>
        picks.GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase).Select(g =>
        {
            var own = g.Where(p => p.List != "*").OrderBy(p => p.Position).FirstOrDefault() ?? g.OrderBy(p => p.Position).First();
            return own with { PickedUtc = g.Max(p => p.PickedUtc), FileModifiedUtc = own.FileModifiedUtc ?? g.Max(p => p.FileModifiedUtc) };
        });

    public static string Describe(Pick p, string user) =>
        $"Picked in an Open/Save dialog by {user}: " + (p.Position == 0 ? "newest" : $"#{p.Position + 1}") + $" of {p.Count} in the " +
        (p.List == "*" ? "list of all file types" : $".{p.List} list") +
        (p.PickedUtc == null ? " (only the newest pick of a list is dated)" : "") +
        (p.FileModifiedUtc is { } m ? $"; the file was dated {When.L(m)} then" : "");

    /// <summary>A LastVisitedPidlMRU value: the program's file name as text, then the item list of the folder its dialog was last in.</summary>
    public static (string Program, string? Folder)? LastVisited(byte[] value, Func<Guid, string?> knownFolder)
    {
        int end = 0;
        while (end + 1 < value.Length && (value[end] != 0 || value[end + 1] != 0)) end += 2;
        if (end == 0 || end + 1 >= value.Length) return null;
        string program = Encoding.Unicode.GetString(value, 0, end);
        if (program.Any(c => c < 0x20) || program.Length > 260) return null;
        var items = Items(value.AsSpan(end + 2));
        string? folder = null;
        if (items.Count > 0)
        {
            // A known folder by itself (Downloads) has no named item after it; PathOf wants one, so it is resolved here.
            folder = PathOf(items, knownFolder)?.Path;
            if (folder == null && items.Count == 1 && ShellItems.Parse(items[0]) is { Kind: ShellItemKind.Root, KnownFolder: { } g })
                folder = knownFolder(g) is { Length: > 0 } f ? f : null;
        }
        return (program, folder);
    }
}
