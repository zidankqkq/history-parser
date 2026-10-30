using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Util;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Every USB storage device ever connected (Windows keeps them even when unplugged), with first
/// install, last arrival and last removal times, the drive letter it got, and the connect/disconnect
/// history from the Partition/Diagnostic log.
/// </summary>
public static class UsbAudit
{
    static DEVPROPKEY FriendlyName = new("a45c254e-df1c-4efd-8020-67d146a850e0", 14);
    static DEVPROPKEY DeviceDesc = new("a45c254e-df1c-4efd-8020-67d146a850e0", 2);
    static DEVPROPKEY Service = new("a45c254e-df1c-4efd-8020-67d146a850e0", 6);
    static DEVPROPKEY FirstInstall = new("83da6326-97a6-4088-9453-a1923f573b29", 101);
    static DEVPROPKEY LastArrival = new("83da6326-97a6-4088-9453-a1923f573b29", 102);
    static DEVPROPKEY LastRemoval = new("83da6326-97a6-4088-9453-a1923f573b29", 103);

    const uint DEVPROP_TYPE_STRING = 0x12, DEVPROP_TYPE_FILETIME = 0x10;

    sealed record Node(string InstanceId, string Name, string Service, DateTime? First, DateTime? Arrival, DateTime? Removal);

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        var letters = DriveLettersBySerial();
        var present = new HashSet<string>(Enumerate("USB", DIGCF_ALLCLASSES | DIGCF_PRESENT).Select(n => n.InstanceId)
            .Concat(Enumerate("USBSTOR", DIGCF_ALLCLASSES | DIGCF_PRESENT).Select(n => n.InstanceId)), StringComparer.OrdinalIgnoreCase);

        // USBSTOR\Disk&Ven_X&Prod_Y\SERIAL&0 carries the friendly model name; its parent USB\VID_..\SERIAL carries the
        // storage service. Merge both by serial number.
        var storage = Enumerate("USBSTOR", DIGCF_ALLCLASSES).ToList();
        var usbParents = Enumerate("USB", DIGCF_ALLCLASSES)
            .Where(n => n.Service.Equals("USBSTOR", StringComparison.OrdinalIgnoreCase) || n.Service.Equals("UASPStor", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var devices = new Dictionary<string, UsbDevice>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in storage.Concat(usbParents))
        {
            ct.ThrowIfCancellationRequested();
            string serial = SerialOf(n.InstanceId);
            string key = serial.Length > 0 ? serial : n.InstanceId;
            devices.TryGetValue(key, out var existing);
            bool isStor = n.InstanceId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase);
            devices[key] = new UsbDevice
            {
                Name = isStor || existing == null ? (n.Name.Length > 0 ? n.Name : existing?.Name ?? "USB storage device") : existing.Name,
                Serial = serial,
                Kind = n.Service.Equals("UASPStor", StringComparison.OrdinalIgnoreCase) || existing?.Kind == "USB drive (UAS)" ? "USB drive (UAS)" : "USB storage",
                DriveLetter = letters.GetValueOrDefault(serial, existing?.DriveLetter ?? ""),
                FirstConnectedUtc = Min(existing?.FirstConnectedUtc, n.First),
                LastConnectedUtc = Max(existing?.LastConnectedUtc, n.Arrival),
                LastRemovedUtc = Max(existing?.LastRemovedUtc, n.Removal),
                ConnectedNow = (existing?.ConnectedNow ?? false) || present.Contains(n.InstanceId),
                InstanceId = isStor ? n.InstanceId : existing?.InstanceId ?? n.InstanceId,
            };
        }

        foreach (var d in devices.Values)
        {
            ctx.UsbDevices.Add(d);
            if (d.LastRemovedUtc is { } removed && !d.ConnectedNow && ctx.NowUtc - removed < TimeSpan.FromHours(1))
                ctx.Flag(Severity.Medium, FindingCategory.Usb, "USB drive removed just before the scan",
                    $"\"{d.Name}\" (serial {d.Serial}) was unplugged at {Util.When.L(removed)}, {(ctx.NowUtc - removed).TotalMinutes:0} min before the scan. " +
                    "Cheats can be run from a USB stick and removed before a screenshare.", timeUtc: removed);
            else if (d.LastConnectedUtc is { } arrived && ctx.NowUtc - arrived < TimeSpan.FromHours(24))
                ctx.Flag(Severity.Low, FindingCategory.Usb, "USB drive connected in the last 24 hours",
                    $"\"{d.Name}\" (serial {d.Serial}) was last connected {Util.When.L(arrived)}{(d.ConnectedNow ? " and is still plugged in" : "")}.", timeUtc: arrived);
        }

        int events = ConnectionHistory(ctx);
        return devices.Count + events;
    }

    /// <summary>Partition/Diagnostic 1006 is logged on every connect (and with capacity 0 on removal).</summary>
    static int ConnectionHistory(BypassContext ctx)
    {
        int items = 0;
        foreach (var r in Events.Read("Microsoft-Windows-Partition/Diagnostic", "*[System[EventID=1006]]", 3000))
        {
            var d = Events.Data(r);
            if (ParsePartitionEvent(d) is not { } e) continue;
            ctx.UsbEvents.Add(e with { TimeUtc = Events.Utc(r) });
            items++;
        }
        return items;
    }

    /// <summary>Turns a Partition/Diagnostic 1006 event into a USB connect/disconnect row (null for internal disks).</summary>
    public static UsbEvent? ParsePartitionEvent(IReadOnlyDictionary<string, string> data)
    {
        if (data.GetValueOrDefault("BusType") != "7") return null; // 7 = USB
        string model = Clean(data.GetValueOrDefault("Model"));
        string maker = Clean(data.GetValueOrDefault("Manufacturer"));
        string name = string.Join(" ", new[] { maker, model }.Where(s => s.Length > 0));
        long.TryParse(data.GetValueOrDefault("Capacity"), out long capacity);
        return new UsbEvent
        {
            Device = name.Length > 0 ? name : "USB drive",
            Serial = Clean(data.GetValueOrDefault("SerialNumber")),
            Action = capacity > 0 ? "Connected" : "Disconnected",
            Detail = capacity > 0 ? $"{capacity / 1_000_000_000.0:0.#} GB" : "",
        };
    }

    static string Clean(string? s) => (s ?? "").Trim().TrimEnd('.') is var c && c.Equals("NULL", StringComparison.OrdinalIgnoreCase) ? "" : c;

    /// <summary>Last part of an instance ID: USBSTOR\Disk&amp;Ven_X\4C5300012&amp;0 → 4C5300012.</summary>
    public static string SerialOf(string instanceId)
    {
        int slash = instanceId.LastIndexOf('\\');
        var last = slash >= 0 ? instanceId[(slash + 1)..] : instanceId;
        int amp = last.LastIndexOf('&');
        // Serial numbers Windows makes up itself contain '&' in the second position (e.g. 7&2a1b3c&0).
        if (amp > 0 && last.Length - amp <= 3) last = last[..amp];
        return last;
    }

    /// <summary>HKLM\SYSTEM\MountedDevices: \DosDevices\E: → "_??_USBSTOR#Disk&amp;…#SERIAL&amp;0#{guid}".</summary>
    static Dictionary<string, string> DriveLettersBySerial()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices");
        if (key == null) return map;
        foreach (var name in key.GetValueNames().Where(n => n.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase)))
        {
            if (key.GetValue(name) is not byte[] data || data.Length < 16) continue;
            var text = Encoding.Unicode.GetString(data);
            if (ParseMountedDevice(text) is { } serial) map[serial] = name[@"\DosDevices\".Length..];
        }
        return map;
    }

    public static string? ParseMountedDevice(string text)
    {
        int i = text.IndexOf("USBSTOR#", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        var parts = text[i..].Split('#');
        return parts.Length >= 3 ? SerialOf(parts[2]) : null;
    }

    static DateTime? Min(DateTime? a, DateTime? b) => a is null ? b : b is null ? a : a < b ? a : b;
    static DateTime? Max(DateTime? a, DateTime? b) => a is null ? b : b is null ? a : a > b ? a : b;

    static IEnumerable<Node> Enumerate(string enumerator, uint flags)
    {
        IntPtr set = SetupDiGetClassDevs(IntPtr.Zero, enumerator, IntPtr.Zero, flags);
        if (set == IntPtr.Zero || set == new IntPtr(-1)) yield break;
        try
        {
            var data = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(set, i, ref data); i++)
            {
                var id = new char[512];
                if (!SetupDiGetDeviceInstanceId(set, ref data, id, id.Length, out int len)) continue;
                string instance = new string(id, 0, Math.Max(0, len - 1)).TrimEnd('\0');
                string name = String(set, ref data, FriendlyName) ?? String(set, ref data, DeviceDesc) ?? "";
                yield return new Node(instance, name, String(set, ref data, Service) ?? "",
                    Time(set, ref data, FirstInstall), Time(set, ref data, LastArrival), Time(set, ref data, LastRemoval));
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }

    static string? String(IntPtr set, ref SP_DEVINFO_DATA data, DEVPROPKEY key)
    {
        var buffer = new byte[1024];
        return SetupDiGetDevicePropertyW(set, ref data, ref key, out uint type, buffer, buffer.Length, out int size, 0) &&
               type == DEVPROP_TYPE_STRING && size >= 2
            ? Encoding.Unicode.GetString(buffer, 0, size).TrimEnd('\0')
            : null;
    }

    static DateTime? Time(IntPtr set, ref SP_DEVINFO_DATA data, DEVPROPKEY key)
    {
        var buffer = new byte[8];
        return SetupDiGetDevicePropertyW(set, ref data, ref key, out uint type, buffer, buffer.Length, out _, 0) &&
               type == DEVPROP_TYPE_FILETIME
            ? FileTime.ToUtc(BitConverter.ToInt64(buffer, 0))
            : null;
    }
}
