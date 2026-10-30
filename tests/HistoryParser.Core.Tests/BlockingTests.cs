using HistoryParser.Core.Analysis;
using HistoryParser.Core.Bypass;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The decisions behind Log Parser's "Tool blocking &amp; logging settings" checks and History Parser's new path checks:
/// the tricks from bypass guides are caught, and what ordinary PCs have (ad-block hosts files, sandbox firewall rules,
/// conda's cmd AutoRun, normal console colours) is not.
/// </summary>
public class BlockingTests
{
    [Fact]
    public void Hosts_redirects_of_tool_sites_are_found_but_adblock_entries_are_not()
    {
        var (entries, blocked) = BlockingAudit.ParseHosts(
        [
            "# Copyright (c) Microsoft",
            "127.0.0.1 localhost",
            "0.0.0.0 ads.doubleclick.net  # ad blocker",
            "0.0.0.0 www.virustotal.com virustotal.com",
            "127.0.0.1 download.anydesk.com",
        ]);
        Assert.Equal(5, entries.Count);
        Assert.Equal(["www.virustotal.com", "virustotal.com", "download.anydesk.com"], blocked.Select(b => b.Host));
    }

    [Fact]
    public void Firewall_blocks_count_only_when_aimed_at_tools()
    {
        // A sandbox's block-everything rule (seen on a clean PC) is an outbound block, but not aimed at a tool.
        Assert.Null(BlockingAudit.ToolBlockRule("v2.33|Action=Block|Active=TRUE|Dir=Out|RA4=0.0.0.0-126.255.255.255|Name=sandbox_block_outbound|", out bool sandbox));
        Assert.True(sandbox);
        Assert.NotNull(BlockingAudit.ToolBlockRule(@"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\Program Files (x86)\AnyDesk\AnyDesk.exe|Name=x|", out _));
        Assert.Null(BlockingAudit.ToolBlockRule(@"v2.33|Action=Block|Active=FALSE|Dir=Out|App=C:\Tools\SystemInformer.exe|Name=x|", out bool inactive));
        Assert.False(inactive);
        Assert.Null(BlockingAudit.ToolBlockRule(@"v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\Tools\SystemInformer.exe|Name=x|", out _));
        Assert.Null(BlockingAudit.ToolBlockRule(@"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\Games\game.exe|Name=@FirewallAPI.dll,-1|", out _));
    }

    [Fact]
    public void Invisible_console_text_and_destructive_autoruns()
    {
        Assert.True(BlockingAudit.InvisibleText(0x00));   // black on black
        Assert.True(BlockingAudit.InvisibleText(0x77));   // grey on grey
        Assert.False(BlockingAudit.InvisibleText(0x07));  // Windows default
        Assert.False(BlockingAudit.InvisibleText(0x56));  // PowerShell default

        Assert.True(BlockingAudit.IsDestructive("taskkill /f /im SystemInformer.exe"));
        Assert.True(BlockingAudit.IsDestructive("del /q C:\\Windows\\Prefetch\\*.pf"));
        Assert.False(BlockingAudit.IsDestructive("\"C:\\Users\\x\\miniconda3\\condabin\\conda_hook.bat\""));
        Assert.False(BlockingAudit.IsDestructive("\"C:\\Program Files\\clink\\clink.bat\" inject --autorun"));
    }

    [Fact]
    public void Loopback_share_paths_are_recognised()
    {
        Assert.Matches(TamperAnalysis.Loopback, @"\\localhost\C$\Users\x\Desktop\client.exe");
        Assert.Matches(TamperAnalysis.Loopback, @"\\127.0.0.1\c$\cheat.exe");
        Assert.Matches(TamperAnalysis.Loopback, @"\Device\Mup\localhost\C$\x.exe");
        Assert.Matches(TamperAnalysis.Loopback, @"\\?\UNC\localhost\C$\x.exe");
        Assert.DoesNotMatch(TamperAnalysis.Loopback, @"\\fileserver\share\tool.exe");
        Assert.DoesNotMatch(TamperAnalysis.Loopback, @"C:\localhost\x.exe");
    }
}
