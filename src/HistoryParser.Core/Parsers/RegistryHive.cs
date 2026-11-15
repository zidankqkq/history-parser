using System.Text;

namespace HistoryParser.Core.Parsers;

/// <summary>
/// Minimal read-only parser for a registry hive file ("regf"), enough to walk keys and read string /
/// integer values. Used for Amcache.hve, which Windows keeps locked and never mounts where other
/// programs can see it. Cell offsets are relative to the first hive bin at 0x1000.
/// </summary>
public sealed class RegistryHive
{
    const int BinsStart = 0x1000;
    readonly byte[] _data;

    public RegistryHive(byte[] data)
    {
        if (data.Length < BinsStart + 0x20 || Encoding.ASCII.GetString(data, 0, 4) != "regf")
            throw new InvalidDataException("Not a registry hive.");
        _data = data;
        Root = ReadKey(BitConverter.ToInt32(data, 0x24)) ?? throw new InvalidDataException("Hive has no root key.");
    }

    public Key Root { get; }

    /// <summary>Subkey links seen so far that led to something other than a key, so a damaged hive can say so instead of looking emptier than it is.</summary>
    public int BrokenLinks { get; private set; }

    public sealed record Key(RegistryHive Hive, int Offset, string Name, DateTime? LastWriteUtc, int SubkeyList, int SubkeyCount, int ValueList, int ValueCount)
    {
        public IEnumerable<Key> Subkeys() => Hive.Subkeys(this);
        public Key? Subkey(string name) => Subkeys().FirstOrDefault(k => k.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        public Key? Path(string path) => path.Split('\\').Aggregate((Key?)this, (k, part) => k?.Subkey(part));
        public Dictionary<string, object> Values() => Hive.Values(this);
    }

    /// <summary>Start of a cell's data (after its 4-byte size), or -1 when outside the file.</summary>
    int Cell(int offset)
    {
        long pos = (long)BinsStart + offset + 4;
        return offset < 0 || pos + 4 > _data.Length ? -1 : (int)pos;
    }

    Key? ReadKey(int offset)
    {
        int p = Cell(offset);
        if (p < 0 || p + 0x4C > _data.Length || _data[p] != 'n' || _data[p + 1] != 'k') return null;
        ushort flags = BitConverter.ToUInt16(_data, p + 2);
        long ft = BitConverter.ToInt64(_data, p + 4);
        int nameLength = BitConverter.ToUInt16(_data, p + 0x48);
        if (p + 0x4C + nameLength > _data.Length) return null;
        string name = (flags & 0x20) != 0
            ? Encoding.Latin1.GetString(_data, p + 0x4C, nameLength)
            : Encoding.Unicode.GetString(_data, p + 0x4C, nameLength);
        return new Key(this, offset, name, Util.FileTime.ToUtc(ft),
            BitConverter.ToInt32(_data, p + 0x1C), BitConverter.ToInt32(_data, p + 0x14),
            BitConverter.ToInt32(_data, p + 0x28), BitConverter.ToInt32(_data, p + 0x24));
    }

    IEnumerable<Key> Subkeys(Key key)
    {
        if (key.SubkeyCount <= 0) yield break;
        var seen = new HashSet<int>();
        foreach (var offset in ListOffsets(key.SubkeyList, 0))
        {
            if (!seen.Add(offset)) continue;
            if (ReadKey(offset) is { } k) yield return k;
            else BrokenLinks++;
        }
    }

    /// <summary>Key offsets from an lf / lh / li / ri subkey list.</summary>
    IEnumerable<int> ListOffsets(int listOffset, int depth)
    {
        int p = Cell(listOffset);
        if (p < 0 || p + 4 > _data.Length || depth > 4) yield break;
        string sig = Encoding.ASCII.GetString(_data, p, 2);
        int count = BitConverter.ToUInt16(_data, p + 2);
        int stride = sig is "lf" or "lh" ? 8 : 4;
        for (int i = 0; i < count; i++)
        {
            int at = p + 4 + i * stride;
            if (at + 4 > _data.Length) yield break;
            int child = BitConverter.ToInt32(_data, at);
            if (sig == "ri")
            {
                foreach (var o in ListOffsets(child, depth + 1)) yield return o;
            }
            else if (sig is "lf" or "lh" or "li") yield return child;
        }
    }

    Dictionary<string, object> Values(Key key)
    {
        var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        int list = Cell(key.ValueList);
        if (list < 0 || key.ValueCount <= 0) return result;
        for (int i = 0; i < key.ValueCount && list + i * 4 + 4 <= _data.Length; i++)
        {
            int p = Cell(BitConverter.ToInt32(_data, list + i * 4));
            if (p < 0 || p + 0x14 > _data.Length || _data[p] != 'v' || _data[p + 1] != 'k') continue;
            int nameLength = BitConverter.ToUInt16(_data, p + 2);
            uint size = BitConverter.ToUInt32(_data, p + 4);
            int dataOffset = BitConverter.ToInt32(_data, p + 8);
            int type = BitConverter.ToInt32(_data, p + 0x0C);
            bool asciiName = (BitConverter.ToUInt16(_data, p + 0x10) & 1) != 0;
            if (p + 0x14 + nameLength > _data.Length) continue;
            string name = asciiName ? Encoding.Latin1.GetString(_data, p + 0x14, nameLength) : Encoding.Unicode.GetString(_data, p + 0x14, nameLength);

            bool inline = (size & 0x80000000) != 0;
            int length = (int)(size & 0x7FFFFFFF);
            byte[] bytes;
            if (inline) bytes = BitConverter.GetBytes(dataOffset)[..Math.Min(length, 4)];
            else
            {
                int d = Cell(dataOffset);
                if (d < 0) continue;
                if (length > 16344 && d + 8 <= _data.Length && _data[d] == 'd' && _data[d + 1] == 'b')
                {
                    if (ReadBigData(d, length) is not { } big) continue;
                    bytes = big;
                }
                else
                {
                    if (d + length > _data.Length) continue;
                    bytes = _data.AsSpan(d, length).ToArray();
                }
            }
            object? value = type switch
            {
                1 or 2 => Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
                4 when bytes.Length >= 4 => BitConverter.ToUInt32(bytes, 0),
                11 when bytes.Length >= 8 => BitConverter.ToUInt64(bytes, 0),
                _ => bytes,
            };
            result[name] = value;
        }
        return result;
    }

    /// <summary>A value over 16344 bytes: "db" header, segment count +2, segment list cell +4; each segment holds at most 16344 bytes.</summary>
    byte[]? ReadBigData(int db, int length)
    {
        int segments = BitConverter.ToUInt16(_data, db + 2);
        int list = Cell(BitConverter.ToInt32(_data, db + 4));
        if (list < 0 || list + segments * 4 > _data.Length) return null;
        var bytes = new byte[length];
        int done = 0;
        for (int i = 0; i < segments && done < length; i++)
        {
            int segment = Cell(BitConverter.ToInt32(_data, list + i * 4));
            if (segment < 0) return null;
            int take = Math.Min(16344, length - done);
            if (segment + take > _data.Length) return null;
            _data.AsSpan(segment, take).CopyTo(bytes.AsSpan(done));
            done += take;
        }
        return done == length ? bytes : null;
    }
}
