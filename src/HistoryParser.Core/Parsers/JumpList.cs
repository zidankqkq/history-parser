using System.Text;

namespace HistoryParser.Core.Parsers;

/// <summary>One file or program in a Jump List: what was opened, when last, and how often.</summary>
public sealed record JumpListEntry(string Path, DateTime? LastOpenedUtc, int? OpenCount, bool Pinned, ShellLinkInfo? Link);

/// <summary>
/// Windows Jump Lists (Recent\AutomaticDestinations\*.automaticDestinations-ms): a compound file per application with
/// one shell link per opened item and a "DestList" stream holding each item's last-opened time and open count. They
/// survive clearing the Recent folder, so a full Jump List next to an empty Recent folder means cleaning. Read-only.
/// </summary>
public static class JumpList
{
    public static List<JumpListEntry> Parse(byte[] file)
    {
        var streams = CompoundFile.Streams(file);
        var links = new Dictionary<int, ShellLinkInfo>();
        foreach (var (name, data) in streams)
            if (int.TryParse(name, System.Globalization.NumberStyles.HexNumber, null, out int id) && ShellLink.Parse(data) is { } info)
                links[id] = info;
        var list = new List<JumpListEntry>();
        if (streams.TryGetValue("DestList", out var dest))
            foreach (var (id, path, time, count, pinned) in DestList(dest))
                list.Add(new JumpListEntry(links.TryGetValue(id, out var l) ? l.TargetPath : path, time, count, pinned, links.GetValueOrDefault(id)));
        else
            list.AddRange(links.Values.Select(l => new JumpListEntry(l.TargetPath, null, null, false, l)));
        return list;
    }

    /// <summary>
    /// The DestList stream: a 32-byte header (version, entry count), then one entry per item. Windows 10/11 (version 3+)
    /// entries carry the entry number at 0x58, the last access time at 0x64, the pin state at 0x6C, the access count at
    /// 0x74 and the path's length and text at 0x80, followed by 4 trailing bytes; Windows 7/8 entries (version 1) end
    /// after the path, with the path at 0x72 and no count.
    /// </summary>
    internal static List<(int Id, string Path, DateTime? LastUtc, int? Count, bool Pinned)> DestList(byte[] d)
    {
        var list = new List<(int, string, DateTime?, int?, bool)>();
        if (d.Length < 32) return list;
        int version = BitConverter.ToInt32(d, 0), entries = BitConverter.ToInt32(d, 4);
        bool modern = version >= 3;
        int pathAt = modern ? 0x80 : 0x70;
        int p = 32;
        for (int i = 0; i < entries && p + pathAt + 2 <= d.Length; i++)
        {
            int id = BitConverter.ToInt32(d, p + 0x58);
            long ft = BitConverter.ToInt64(d, p + 0x64);
            bool pinned = BitConverter.ToInt32(d, p + 0x6C) >= 0;
            int? count = modern ? BitConverter.ToInt32(d, p + 0x74) : null;
            int chars = BitConverter.ToUInt16(d, p + pathAt);
            if (chars <= 0 || p + pathAt + 2 + chars * 2 > d.Length) break;
            string path = Encoding.Unicode.GetString(d, p + pathAt + 2, chars * 2);
            DateTime? time = ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(ft) : null;
            list.Add((id, path, time, count, pinned));
            p += pathAt + 2 + chars * 2 + (modern ? 4 : 0);
        }
        return list;
    }
}

/// <summary>A minimal read-only reader for Microsoft compound files (OLE / CFB): every stream by name.</summary>
public static class CompoundFile
{
    const uint EndOfChain = 0xFFFFFFFE, Free = 0xFFFFFFFF;

    public static Dictionary<string, byte[]> Streams(byte[] f)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        if (f.Length < 512 || BitConverter.ToUInt64(f, 0) != 0xE11AB1A1E011CFD0) throw new InvalidDataException("Not a compound file.");
        int sectorSize = 1 << BitConverter.ToUInt16(f, 0x1E), miniSize = 1 << BitConverter.ToUInt16(f, 0x20);
        uint firstDir = BitConverter.ToUInt32(f, 0x30), cutoff = BitConverter.ToUInt32(f, 0x38);
        uint firstMiniFat = BitConverter.ToUInt32(f, 0x3C), firstDifat = BitConverter.ToUInt32(f, 0x44);
        int fatSectors = BitConverter.ToInt32(f, 0x2C);
        int Offset(uint sector) => (int)((sector + 1) * (long)sectorSize);

        // The FAT's own sectors: 109 listed in the header, the rest in a chain of DIFAT sectors.
        var fatList = new List<uint>();
        for (int i = 0; i < 109 && fatList.Count < fatSectors; i++) fatList.Add(BitConverter.ToUInt32(f, 0x4C + i * 4));
        for (uint s = firstDifat; s != EndOfChain && s != Free && fatList.Count < fatSectors && Offset(s) + sectorSize <= f.Length;)
        {
            int at = Offset(s);
            for (int i = 0; i < sectorSize / 4 - 1 && fatList.Count < fatSectors; i++) fatList.Add(BitConverter.ToUInt32(f, at + i * 4));
            s = BitConverter.ToUInt32(f, at + sectorSize - 4);
        }
        var fat = new List<uint>();
        foreach (var s in fatList)
        {
            if (s == Free || Offset(s) + sectorSize > f.Length) break;
            for (int i = 0; i < sectorSize / 4; i++) fat.Add(BitConverter.ToUInt32(f, Offset(s) + i * 4));
        }

        byte[] Chain(uint start, long size)
        {
            using var ms = new MemoryStream();
            var seen = new HashSet<uint>();
            for (uint s = start; s != EndOfChain && s < fat.Count && seen.Add(s) && ms.Length < size;)
            {
                int at = Offset(s);
                if (at + sectorSize > f.Length) break;
                ms.Write(f, at, sectorSize);
                s = fat[(int)s];
            }
            var data = ms.ToArray();
            return data.Length > size ? data[..(int)size] : data;
        }

        var dir = Chain(firstDir, long.MaxValue);
        var miniFat = new List<uint>();
        if (firstMiniFat != EndOfChain)
        {
            var mf = Chain(firstMiniFat, long.MaxValue);
            for (int i = 0; i + 4 <= mf.Length; i += 4) miniFat.Add(BitConverter.ToUInt32(mf, i));
        }
        byte[] miniStream = [];
        for (int e = 0; e + 128 <= dir.Length; e += 128)
        {
            int nameLen = BitConverter.ToUInt16(dir, e + 0x40);
            byte type = dir[e + 0x42];
            if (type == 0 || nameLen < 2 || nameLen > 64) continue;
            string name = Encoding.Unicode.GetString(dir, e, nameLen - 2);
            uint start = BitConverter.ToUInt32(dir, e + 0x74);
            long size = BitConverter.ToUInt32(dir, e + 0x78);
            if (type == 5) { miniStream = Chain(start, size); continue; } // root entry: the mini stream
            if (type != 2 || size > 64 * 1024 * 1024) continue;
            if (size < cutoff)
            {
                // Small streams live in the mini stream, chained through the mini FAT.
                using var ms = new MemoryStream();
                var seen = new HashSet<uint>();
                for (uint s = start; s != EndOfChain && s < miniFat.Count && seen.Add(s) && ms.Length < size;)
                {
                    long at = (long)s * miniSize;
                    if (at + miniSize > miniStream.Length) break;
                    ms.Write(miniStream, (int)at, miniSize);
                    s = miniFat[(int)s];
                }
                var data = ms.ToArray();
                result[name] = data.Length > size ? data[..(int)size] : data;
            }
            else result[name] = Chain(start, size);
        }
        return result;
    }
}
