using System.Net;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Tests;

// Reads the live Windows DNS cache - depends on the DNS Client service caching a real lookup, which a headless CI
// runner does not reliably do. Runs on a real machine; excluded from CI (Category=Integration).
[Trait("Category", "Integration")]
public class DnsCacheTests
{
    [Fact]
    public void A_name_just_looked_up_is_in_the_cache()
    {
        // A headless CI runner does not reliably populate the Windows DNS Client cache from a lookup; run on a real machine.
        if (Environment.GetEnvironmentVariable("CI") == "true") return;
        // Current Windows only hands the cache to administrators (ipconfig /displaydns says the same).
        if (!WinApi.IsElevated()) return;
        try { Dns.GetHostAddresses("example.com"); }
        catch (System.Net.Sockets.SocketException) { return; } // no network: nothing was cached, nothing to prove
        var cache = DnsCache.Read();
        Assert.NotNull(cache);
        var entry = Assert.Single(cache, e => e.Name == "example.com");
        Assert.Contains("A", entry.Type.Split(", "));
        Assert.All(cache, e => Assert.Equal(e.Name.ToLowerInvariant(), e.Name));
    }
}
