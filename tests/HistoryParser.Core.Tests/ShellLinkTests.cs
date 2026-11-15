using System.Text;
using HistoryParser.Core.Parsers;
using Xunit;

namespace HistoryParser.Core.Tests;

public class ShellLinkTests
{
    const uint IdList = 0x1, LinkInfo = 0x2, Relative = 0x8, WorkingDir = 0x10, Arguments = 0x20, Unicode = 0x80;

    static List<byte> Header(uint flags)
    {
        var b = new byte[0x4C];
        BitConverter.GetBytes(0x4C).CopyTo(b, 0);
        BitConverter.GetBytes(flags).CopyTo(b, 0x14);
        return [.. b];
    }

    static byte[] Hex(string hex) => Convert.FromHexString(hex);

    static void AddIdList(List<byte> b, params byte[][] items)
    {
        b.AddRange(BitConverter.GetBytes((ushort)(items.Sum(i => i.Length) + 2)));
        foreach (var item in items) b.AddRange(item);
        b.AddRange(new byte[2]);
    }

    static void AddString(List<byte> b, string text)
    {
        b.AddRange(BitConverter.GetBytes((ushort)text.Length));
        b.AddRange(Encoding.Unicode.GetBytes(text));
    }

    // Both taken from real shortcuts in a Recent folder.
    const string InternetRoot = "14001f6880531c87a0426910a2ea08002b30309d";
    const string ControlPanelRoot = "14001f706806ee260aa0d7449371beb064c98683";
    const string ControlPanelItem = "0c0001008421de3900000000";

    static byte[] UriItem(string address)
    {
        var text = Encoding.Unicode.GetBytes(address);
        var item = new List<byte> { 0, 0, 0x61, 0x80, 0, 0, 0, 0 };
        item.AddRange(text);
        item.AddRange(new byte[6]);
        item[0] = (byte)item.Count;
        item[1] = (byte)(item.Count >> 8);
        return [.. item];
    }

    [Fact]
    public void A_shortcut_to_an_address_gives_the_address()
    {
        var b = Header(IdList | Unicode);
        AddIdList(b, Hex(InternetRoot), UriItem("http://www.msftconnecttest.com/redirect"));
        Assert.Equal("http://www.msftconnecttest.com/redirect", ShellLink.Parse([.. b])!.TargetPath);
    }

    [Fact]
    public void A_control_panel_item_is_a_sound_link_with_no_target()
    {
        var b = Header(IdList | Unicode);
        AddIdList(b, Hex(ControlPanelRoot), Hex(ControlPanelItem));
        byte[] link = [.. b];
        Assert.Null(ShellLink.Parse(link));
        Assert.True(ShellLink.IsLink(link));
    }

    [Fact]
    public void Something_else_is_not_a_link() => Assert.False(ShellLink.IsLink(new byte[0x4C]));

    [Fact]
    public void A_network_target_is_read_when_there_is_no_local_path()
    {
        var net = new List<byte>();
        net.AddRange(BitConverter.GetBytes(0x14 + 15));       // size
        net.AddRange(BitConverter.GetBytes(0));               // flags
        net.AddRange(BitConverter.GetBytes(0x14));            // net name offset
        net.AddRange(BitConverter.GetBytes(0));               // device name offset
        net.AddRange(BitConverter.GetBytes(0));               // provider
        net.AddRange(Encoding.ASCII.GetBytes(@"\\srv\share"));
        net.AddRange(new byte[4]);

        const int header = 0x1C;
        byte[] suffix = Encoding.ASCII.GetBytes("run.exe\0");
        int size = header + net.Count + suffix.Length;
        var info = new byte[size];
        BitConverter.GetBytes(size).CopyTo(info, 0);
        BitConverter.GetBytes(header).CopyTo(info, 4);
        BitConverter.GetBytes(2).CopyTo(info, 8);                  // network only
        BitConverter.GetBytes(header).CopyTo(info, 0x14);          // network block offset
        BitConverter.GetBytes(header + net.Count).CopyTo(info, 0x18); // suffix offset
        net.CopyTo(info, header);
        suffix.CopyTo(info, header + net.Count);

        var b = Header(LinkInfo | Unicode);
        b.AddRange(info);
        Assert.Equal(@"\\srv\share\run.exe", ShellLink.Parse([.. b])!.TargetPath);
    }

    [Fact]
    public void A_path_written_with_variables_is_read_from_the_environment_block()
    {
        var b = Header(Arguments | Unicode);
        AddString(b, "-jar x.jar");
        var block = new byte[0x314];
        BitConverter.GetBytes(0x314).CopyTo(block, 0);
        BitConverter.GetBytes(0xA0000001).CopyTo(block, 4);
        Encoding.Unicode.GetBytes(@"%TEMP%\javaw.exe").CopyTo(block, 268);
        b.AddRange(block);
        b.AddRange(new byte[4]);

        var link = ShellLink.Parse([.. b])!;
        Assert.Equal(@"%TEMP%\javaw.exe", link.TargetPath);
        Assert.Equal(@"%TEMP%\javaw.exe", link.EnvironmentTarget);
        Assert.Equal("-jar x.jar", link.Arguments);
    }

    [Fact]
    public void A_relative_path_is_placed_in_the_working_folder()
    {
        var b = Header(Relative | WorkingDir | Unicode);
        AddString(b, @"..\tools\run.exe");
        AddString(b, @"C:\Users\a\Desktop");
        Assert.Equal(@"C:\Users\a\tools\run.exe", ShellLink.Parse([.. b])!.TargetPath);
    }

    [Fact]
    public void Damage_never_throws()
    {
        var b = Header(IdList | Relative | Arguments | Unicode);
        AddIdList(b, Hex(InternetRoot), UriItem("http://example.com/"));
        AddString(b, "rel");
        AddString(b, "args");
        byte[] link = [.. b];
        for (int length = 0; length <= link.Length; length++) ShellLink.Parse(link[..length]);

        var random = new Random(1);
        for (int i = 0; i < 20000; i++)
        {
            var copy = (byte[])link.Clone();
            for (int hit = 0; hit < 3; hit++) copy[random.Next(0x14, copy.Length)] = (byte)random.Next(256);
            ShellLink.Parse(copy);
        }
    }
}
