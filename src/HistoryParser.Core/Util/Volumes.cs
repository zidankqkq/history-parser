using HistoryParser.Core.Native;

namespace HistoryParser.Core.Util;

/// <summary>
/// One volume Windows has mounted: the device name the kernel uses for it (\Device\HarddiskVolume7), its permanent
/// name (\\?\Volume{...}), and the drive letters and folders it can be reached at - none for a volume kept without a
/// drive letter, which Explorer does not show.
/// </summary>
public sealed record VolumeInfo(string Device, string GuidPath, IReadOnlyList<string> MountPaths);

public static class Volumes
{
    /// <summary>Every volume present now. Needs no special rights. Empty when Windows would not list them.</summary>
    public static List<VolumeInfo> List()
    {
        var list = new List<VolumeInfo>();
        var name = new char[260];
        IntPtr find = NativeMethods.FindFirstVolumeW(name, (uint)name.Length);
        if (find == new IntPtr(-1)) return list;
        try
        {
            do
            {
                string volume = new string(name).Split('\0')[0]; // \\?\Volume{guid}\
                if (!IsVolumePath(volume) || !volume.EndsWith('\\')) continue;
                var target = new char[1024];
                uint n = NativeMethods.QueryDosDevice(volume[4..^1], target, (uint)target.Length);
                if (n == 0) continue;
                string device = new string(target, 0, (int)n).Split('\0')[0];
                if (device.Length > 0) list.Add(new VolumeInfo(device, volume.TrimEnd('\\'), MountPaths(volume)));
            } while (NativeMethods.FindNextVolumeW(find, name, (uint)name.Length));
        }
        finally { NativeMethods.FindVolumeClose(find); }
        return list;
    }

    static List<string> MountPaths(string volume)
    {
        var buffer = new char[8192];
        if (!NativeMethods.GetVolumePathNamesForVolumeNameW(volume, buffer, (uint)buffer.Length, out uint length)) return [];
        return new string(buffer, 0, (int)Math.Min(length, (uint)buffer.Length)).Split('\0', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// <summary>A path given by a volume's permanent name: how a file on a volume with no drive letter and no folder is written.</summary>
    public static bool IsVolumePath(string path) =>
        path.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) && path.IndexOf('}') is > 11 and var close &&
        (path.Length == close + 1 || path[close + 1] == '\\');
}
