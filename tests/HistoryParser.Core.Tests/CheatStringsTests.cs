using System.Text;
using RatChecker.Core;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The Cheat String Finder's memory logic. Verified against two real, clean running games (0 strings reported for both);
/// these tests pin down the rules that made that possible, and that an injected client is still found.
/// </summary>
public class CheatStringsTests
{
    /// <summary>A HotSpot Symbol: 4 bytes of hash/refcount, a 2-byte little-endian length, then the name.</summary>
    static byte[] Symbol(string name) => [0x11, 0x22, 0x33, 0x44, (byte)name.Length, (byte)(name.Length >> 8), .. Encoding.ASCII.GetBytes(name)];

    [Fact]
    public void Class_names_are_taken_only_from_records_with_their_own_length()
    {
        byte[] memory =
        [
            .. Symbol("net/fakeclient/hacks/KillauraHack"),
            .. "XY"u8,                                        // stray printable bytes right after a name
            .. Symbol("Lnet/fakeclient/module/Module;"),      // a type descriptor
            0, 0, .. "a/lang/Obj3"u8, 0,                      // a fragment: the bytes in front are not its length
            .. Symbol("assets/minecraft/textures/block"),     // a resource path, not a class
        ];
        var names = new HashSet<string>();
        CheatStrings.CollectClassNames(memory, names);
        Assert.Equal(["net/fakeclient/hacks/KillauraHack", "net/fakeclient/module/Module"], names.Order());
    }

    [Theory]
    [InlineData("Lcom/x/y/Z", "com/x/y/Z")]
    [InlineData("[Lcom/x/y/Z", "com/x/y/Z")]
    [InlineData("ILnet/fake/hacks/Fly", "net/fake/hacks/Fly")]
    [InlineData("INF/versions/9/module", null)]   // from META-INF
    [InlineData("BONUS_SPEED/asm/m", null)]
    [InlineData("assets/minecraft/lang/en_us", null)]
    public void Descriptors_are_unwrapped_and_lookalikes_rejected(string raw, string? expected) =>
        Assert.Equal(expected, CheatStrings.NormalizeClassName(raw));

    [Fact]
    public void Only_clustered_code_from_unknown_packages_is_unexplained()
    {
        var clean = new HashSet<string> { "com/legit/mod/Main", "com/legit/mod/util/Helper" };
        var memory = new[]
        {
            "com/legit/mod/MainX",                          // a legit name with a stray byte: its package is clean
            "net/fakeclient/hacks/Aura", "net/fakeclient/hacks/Reach", "net/fakeclient/hacks/Velocity",
            "net/lonely/thing/Fragment",                    // a single name in an unknown package
            "wiki/w/Attack_Speed_Enrichment", "wiki/w/Fly_Swatter", "wiki/w/Berberis_Fuel",   // wiki titles
            "essence/boots/1/13705", "essence/boots/2/13706", "essence/boots/3/13707",       // item IDs
            "java/lang/String", "org/spongepowered/asm/synthetic/args/Args$1",               // runtime / generated
        };
        Assert.Equal(["net/fakeclient/hacks/Aura", "net/fakeclient/hacks/Reach", "net/fakeclient/hacks/Velocity"],
            CheatStrings.Unexplained(memory, clean).Order());
    }

    [Fact]
    public void Two_real_class_names_are_enough_but_two_random_ones_are_not()
    {
        // Seen in a game with a native client injected: the client looking up version-specific game classes.
        var memory = new[] { "net/minecraft_26_1_2/SharedConstants", "net/minecraft_26_1_2/WorldVersion", "kq/zz/Xcx", "kq/zz/v3H7" };
        Assert.Equal(["net/minecraft_26_1_2/SharedConstants", "net/minecraft_26_1_2/WorldVersion"],
            CheatStrings.Unexplained(memory, []).Order());
    }

    [Fact]
    public void Hosts_of_plain_web_requests_are_collected_except_the_games_own()
    {
        var memory = Encoding.ASCII.GetBytes(
            "POST /font/Arial_3_128_2.png HTTP/1.1\r\nHost: DoomsdayClient.xyz\r\nCookie: x\r\n\r\n" +
            "GET /x HTTP/1.1\r\nHost: api.minecraftservices.com\r\n" +
            "GET /x HTTP/1.1\r\nHost: sessionserver.mojang.com\r\n" +
            "GET /pack.zip HTTP/1.1\r\nHost: 51.77.1.2\r\n" +         // an IP: could be a server's resource pack
            "\r\nHost: cut-off.exam");                               // no line end: not a whole header
        var hosts = new HashSet<string>();
        CheatStrings.CollectHosts(memory, hosts);
        Assert.Equal(["doomsdayclient.xyz"], hosts);
    }

    [Fact]
    public void Strings_inside_longer_clean_strings_are_unsafe_to_search()
    {
        // A Contains search for net/java/g would also hit Minecraft 1.8's net/java/games/input library.
        var clean = new HashSet<string> { "net/java/games/input/Controller", "Killaura enabled for legit reasons" };
        var hits = CheatStrings.ContainedIn(["net/java/games", "Killaura", "net/fakeclient/hacks/Aura"], clean, default);
        Assert.Equal(["Killaura", "net/java/games"], hits.Order());
    }

    [Fact]
    public void Only_readable_text_counts()
    {
        Assert.True(CheatStrings.Readable("Killaura enabled"));
        Assert.False(CheatStrings.Readable("FkG!,,��,p�^"));  // binary data read as text
        Assert.False(CheatStrings.Readable("0123456789abcdef0123"));       // hash
        Assert.False(CheatStrings.Readable("short"));
    }
}
