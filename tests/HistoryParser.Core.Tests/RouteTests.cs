using System.Text;
using HistoryParser.Core.Bypass;

namespace HistoryParser.Core.Tests;

public class RouteTests
{
    static byte[] PeHeader(int peOffset = 0x80)
    {
        var b = new byte[0x400];
        b[0] = (byte)'M'; b[1] = (byte)'Z';
        BitConverter.GetBytes(peOffset).CopyTo(b, 0x3C);
        b[peOffset] = (byte)'P'; b[peOffset + 1] = (byte)'E';
        return b;
    }

    [Fact]
    public void Pe_header_in_memory_is_recognised() => Assert.True(GameProcessAudit.LooksLikePe(PeHeader(), 0x400));

    [Fact]
    public void Mz_without_pe_signature_is_not_a_program()
    {
        var b = PeHeader();
        b[0x80] = 0;
        Assert.False(GameProcessAudit.LooksLikePe(b, 0x400));
    }

    [Fact]
    public void Pe_offset_past_the_read_bytes_is_rejected() => Assert.False(GameProcessAudit.LooksLikePe(PeHeader(0x300), 0x200));

    [Fact]
    public void Jit_code_is_not_a_program() => Assert.False(GameProcessAudit.LooksLikePe([0x48, 0x89, 0x5C, 0x24, .. new byte[0x3FC]], 0x400));

    [Fact]
    public void Jvmti_agent_exports_are_found_in_the_file()
    {
        var path = Scratch.File("agent", "agent.dll", [.. "MZ junk "u8, .. Encoding.ASCII.GetBytes("Agent_OnAttach\0Agent_OnLoad\0"), .. "more"u8]);
        Assert.Equal("Agent_OnAttach, Agent_OnLoad", GameProcessAudit.AgentExports(path));
    }

    [Fact]
    public void Ordinary_library_has_no_agent_exports()
    {
        // The name inside a longer identifier (no terminating zero) is not an export.
        var path = Scratch.File("lib", "library.dll", [.. "MZ "u8, .. Encoding.ASCII.GetBytes("call_Agent_OnLoadHelper\0")]);
        Assert.Null(GameProcessAudit.AgentExports(path));
    }

    [Theory]
    [InlineData("@oem42.inf,%leonardo.name%;Arduino Leonardo", "Arduino Leonardo")]
    [InlineData("USB Serial Device", "USB Serial Device")]
    public void Device_descriptions_keep_the_readable_part(string raw, string expected) =>
        Assert.Equal(expected, HardwareAudit.Describe(raw));

    [Theory]
    [InlineData("version.dll")]
    [InlineData("WINMM.DLL")]
    [InlineData("dinput8.dll")]
    public void System_dll_names_are_hijack_candidates(string name) => Assert.Contains(name, HookAudit.HijackNames);

    [Fact]
    public void Java_runtime_dlls_are_not_hijack_candidates()
    {
        Assert.DoesNotContain("jvm.dll", HookAudit.HijackNames);
        Assert.DoesNotContain("java.dll", HookAudit.HijackNames);
    }
}
