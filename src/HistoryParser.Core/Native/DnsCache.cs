using System.Runtime.InteropServices;

namespace HistoryParser.Core.Native;

/// <summary>
/// The names Windows' DNS Client has looked up recently and still holds (what "ipconfig /displaydns" shows). Entries
/// live until their record expires or the cache is flushed, so this is recent activity only. Read-only.
/// </summary>
public static class DnsCache
{
    public sealed record Entry(string Name, string Type);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    static extern bool DnsGetCacheDataTable(out IntPtr table);

    /// <summary>Every cached name once (lower case), with the record types held for it. Null when the cache cannot be read (needs administrator on current Windows).</summary>
    public static List<Entry>? Read()
    {
        var types = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        try
        {
            if (!DnsGetCacheDataTable(out var p)) return null;
            // DNS_CACHE_ENTRY (x64): pNext +0, pszName +8, wType +16, wDataLength +18, dwFlags +20.
            // The list is not freed: dnsapi documents no matching free call, and one small leak per scan is harmless.
            for (int guard = 0; p != IntPtr.Zero && guard < 100_000; guard++)
            {
                var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 8));
                ushort type = (ushort)Marshal.ReadInt16(p, 16);
                if (!string.IsNullOrWhiteSpace(name))
                {
                    var key = name.Trim().TrimEnd('.').ToLowerInvariant();
                    if (!types.TryGetValue(key, out var set)) types[key] = set = new SortedSet<string>(StringComparer.Ordinal);
                    set.Add(TypeName(type));
                }
                p = Marshal.ReadIntPtr(p, 0);
            }
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return null; }
        return types.OrderBy(t => t.Key, StringComparer.Ordinal).Select(t => new Entry(t.Key, string.Join(", ", t.Value))).ToList();
    }

    static string TypeName(ushort type) => type switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 65 => "HTTPS",
        var t => $"type {t}",
    };
}
