using HistoryParser.Core.Models;
using RatChecker.Core;

namespace HistoryParser.Core.Tests;

/// <summary>
/// The Program Checker's cheat rules, one per naming scheme. Real files were checked too: Wurst (26.1.2) and the Doomsday
/// loader are flagged; Fabric API and Meow Client Fucker are not.
/// </summary>
public class CheatScannerTests
{
    static RatFileReport Check(Action<RatContent> build)
    {
        var c = new RatContent { Kind = "Java mod / jar" };
        build(c);
        var report = new RatFileReport { Path = "test.jar" };
        CheatScanner.Evaluate(c, report.Signs);
        return report;
    }

    static JavaClass Class(string name, string[] refs, string[]? names = null, string[]? writes = null, string super = "java/lang/Object") =>
        new(name, super, name + ".class", new HashSet<string>(refs), new HashSet<string>(names ?? []))
        { Writes = new HashSet<string>(writes ?? []) };

    /// <summary>A cheat client's skeleton: a switchable base class and a few feature modules on it.</summary>
    static void Modules(RatContent c, params JavaClass[] features)
    {
        c.Classes.Add(Class("a/b/Module", [], names: ["onEnable", "onDisable", "toggle"]));
        foreach (var n in new[] { "Fly", "Speed", "Sprint", "Step", "Timer" }) c.Classes.Add(Class("a/b/m/" + n, [], super: "a/b/Module"));
        foreach (var f in features) c.Classes.Add(f with { Super = "a/b/Module" });
    }

    [Fact]
    public void Trigger_bot_module_in_mojang_names()
    {
        var r = Check(c => Modules(c, Class("a/b/m/Trigger",
            ["net/minecraft/client/Minecraft.hitResult", "net/minecraft/client/multiplayer/MultiPlayerGameMode.attack"])));
        Assert.Equal(CheatVerdict.Cheat, r.CheatVerdict);
        Assert.Contains(r.Signs, s => s.Title == "Trigger bot code" && s.Severity == Severity.High);
    }

    [Fact]
    public void The_same_code_outside_a_module_is_only_check_by_hand()
    {
        // Content mods do this for game effects (an elixir that turns the player, a "hold to attack" tweak).
        var r = Check(c => c.Classes.Add(Class("a/b/ElixirHandler",
            ["net/minecraft/client/Minecraft.hitResult", "net/minecraft/client/multiplayer/MultiPlayerGameMode.attack"])));
        Assert.Equal(CheatVerdict.Possible, r.CheatVerdict);
    }

    [Fact]
    public void Kill_aura_module_in_fabric_intermediary_names()
    {
        var r = Check(c => Modules(c, Class("a/b/m/Aura",
            ["net/minecraft/class_638.method_18112", "net/minecraft/class_636.method_2918"])));
        Assert.Contains(r.Signs, s => s.Title == "Kill aura code" && s.Severity == Severity.High);
    }

    [Fact]
    public void Aim_assist_module_in_forge_1_8_9_names_by_assigning_rotation()
    {
        var r = Check(c => Modules(c, Class("a/b/m/Aim",
            ["net/minecraft/client/multiplayer/WorldClient.field_72996_f"], writes: ["net/minecraft/client/entity/EntityPlayerSP.field_70177_z"])));
        Assert.Contains(r.Signs, s => s.Title == "Aim assist code" && s.Severity == Severity.High);
    }

    [Fact]
    public void An_arrow_turning_itself_is_not_aim_code()
    {
        // 1.12 mods' projectiles and boats assign their own rotation (the same SRG field, reached through their own type).
        var r = Check(c => Modules(c, Class("a/b/m/Arrow",
            ["net/minecraft/world/World.field_72996_f"], writes: ["a/b/m/Arrow.field_70177_z", "net/minecraft/entity/Entity.field_70177_z"])));
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void Reading_rotation_is_not_turning_the_player()
    {
        // A minimap reads the entity list and the player's yaw; only assigning the yaw is aim code.
        var r = Check(c => c.Classes.Add(Class("a/b/Minimap",
            ["net/minecraft/client/multiplayer/WorldClient.field_72996_f", "net/minecraft/client/entity/EntityPlayerSP.field_70177_z"])));
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void Autoclicker_module_presses_the_attack_key()
    {
        var r = Check(c => Modules(c, Class("a/b/m/Clicker",
            ["net/minecraft/class_315.field_1886", "net/minecraft/class_304.method_1420"])));
        Assert.Contains(r.Signs, s => s.Title == "Autoclicker code" && s.Severity == Severity.High);
    }

    [Fact]
    public void A_mixin_into_the_game_does_not_do_what_it_names()
    {
        // A camera mod's mixin into Minecraft names startAttack and hitResult because it is mixed into that class.
        var r = Check(c => Modules(c, Class("a/b/mixin/MinecraftMixin",
            ["org/spongepowered/asm/mixin/Mixin", "net/minecraft/class_310.method_1536", "net/minecraft/class_310.field_1765"])));
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void A_mixin_into_the_attack_code_is_not_an_attack()
    {
        // Fabric API's attack events: a mixin into MultiPlayerGameMode refers to attack without attacking.
        var r = Check(c => c.Classes.Add(Class("net/fabricmc/fabric/mixin/MultiPlayerGameModeMixin",
            ["org/spongepowered/asm/mixin/Mixin", "net/minecraft/client/multiplayer/MultiPlayerGameMode.attack"])));
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void An_anticheat_plugin_named_after_cheats_is_not_a_cheat()
    {
        // Server anticheats name their checks after cheats but never touch the client's code.
        var r = Check(c =>
        {
            c.Classes.Add(Class("ac/checks/combat/KillAuraA", ["org/bukkit/entity/Player", "org/bukkit/event/entity/EntityDamageByEntityEvent"]));
            c.Classes.Add(Class("ac/checks/combat/ReachB", ["org/bukkit/entity/Player"]));
            c.Strings.Add(("KillAura", "ac/checks/combat/KillAuraA.class"));
        });
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    static void VelocityPacketsReach(RatContent c)
    {
        Modules(c);
        c.Classes.Add(Class("a/b/mixin/PacketMixin", ["org/spongepowered/asm/mixin/Mixin"], names: ["handleSetEntityMotion"]));
        c.Classes.Add(Class("a/b/NoFall", ["net/minecraft/network/protocol/game/ServerboundMovePlayerPacket$StatusOnly.<init>"]));
        c.Classes.Add(Class("a/b/mixin/ReachMixin", ["org/spongepowered/asm/mixin/Mixin"], names: ["entityInteractionRange"]));
    }

    [Fact]
    public void Hooks_without_any_action_are_check_by_hand()
    {
        // Legitimate PvP clients hook knockback and reach for their displays; a cheat also acts.
        var r = Check(VelocityPacketsReach);
        Assert.Equal(CheatVerdict.Possible, r.CheatVerdict);
    }

    [Fact]
    public void Hooks_together_with_an_action_are_a_cheat()
    {
        var r = Check(c => { VelocityPacketsReach(c); c.Classes.Add(Class("a/b/Fight", ["net/minecraft/client/multiplayer/MultiPlayerGameMode.attack"])); });
        Assert.Contains(r.Signs, s => s.Title == "Several cheat features" && s.Severity == Severity.High);
    }

    [Fact]
    public void One_reach_change_alone_is_only_check_by_hand()
    {
        var r = Check(c => c.Classes.Add(Class("a/b/mixin/ScaleMixin", ["org/spongepowered/asm/mixin/Mixin"], names: ["entityInteractionRange"])));
        Assert.Equal(CheatVerdict.Possible, r.CheatVerdict);
    }

    [Fact]
    public void A_mixin_that_only_calls_reach_does_not_change_it()
    {
        // Cobblemon's ender pearl mixin reads the reach; only injecting into the method changes it.
        var r = Check(c => c.Classes.Add(Class("a/b/mixin/PearlMixin",
            ["org/spongepowered/asm/mixin/Mixin", "net/minecraft/world/entity/player/Player.entityInteractionRange"], names: ["entityInteractionRange"])));
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void Agent_that_defines_classes_from_encrypted_data_is_a_loader()
    {
        var r = Check(c =>
        {
            c.Manifest["Premain-Class"] = "net.java.ag";
            c.AddRef("net/java/m.defineClass", "net/java/m.class");
            c.Encrypted.Add(("net/java/a", 214_490, "net/java/a"));
        });
        Assert.Contains(r.Signs, s => s.Title == "Injects hidden code into the game" && s.Severity == Severity.High);
    }

    [Fact]
    public void Native_injector_aimed_at_the_game()
    {
        var r = Check(c =>
        {
            c.Kind = "Windows program";
            foreach (var s in new[] { "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "javaw.exe" }) c.Strings.Add((s, "x.exe"));
        });
        Assert.Contains(r.Signs, s => s.Title == "Injects code into the game" && s.Severity == Severity.High);
    }

    static void Agent(RatContent c)
    {
        c.Kind = "Zip archive";
        c.Manifest["Agent-Class"] = "x.loader.Main";
        c.Classes.Add(Class("x/loader/Main", ["java/lang/instrument/Instrumentation", "java/lang/instrument/Instrumentation.retransformClasses"], names: ["agentmain"]) with { Where = "bin/loader.jar → x/loader/Main.class" });
    }

    [Fact]
    public void An_injectable_client_whose_actions_cannot_be_read_is_check_by_hand()
    {
        // Legitimate PvP clients enter as agents and are built from modules too; without seeing the code act, it's a lead.
        var r = Check(c => { Agent(c); Modules(c); });
        Assert.Equal(CheatVerdict.Possible, r.CheatVerdict);
    }

    [Fact]
    public void An_injectable_client_that_attacks_is_a_cheat()
    {
        var r = Check(c => { Agent(c); Modules(c, Class("a/b/m/Aura", ["net/minecraft/client/multiplayer/WorldClient.loadedEntityList", "net/minecraft/client/multiplayer/PlayerControllerMP.attackEntity"])); });
        Assert.Contains(r.Signs, s => s.Title == "Rewrites the game's code while it runs" && s.Severity == Severity.High);
    }

    [Fact]
    public void A_build_tool_agent_bundled_inside_a_mod_does_not_count()
    {
        // Lombok's agent, shipped by a careless mod inside a nested jar.
        var r = Check(c =>
        {
            c.Classes.Add(Class("lombok/launch/Agent", ["java/lang/instrument/Instrumentation", "java/lang/instrument/Instrumentation.addTransformer"], names: ["agentmain"])
                with { Where = "META-INF/jars/lombok.jar → lombok/launch/Agent.class" });
        });
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void A_content_mod_with_combat_code_in_modules_is_only_check_by_hand()
    {
        var r = Check(c =>
        {
            Modules(c, Class("a/b/m/Trigger", ["net/minecraft/client/Minecraft.hitResult", "net/minecraft/client/multiplayer/MultiPlayerGameMode.attack"]));
            foreach (var n in new[] { "Ruby", "Sapphire", "Golem" }) c.Classes.Add(Class("a/b/content/" + n, [], super: n == "Golem" ? "net/minecraft/world/entity/Mob" : "net/minecraft/world/item/Item"));
        });
        Assert.Equal(CheatVerdict.Possible, r.CheatVerdict);
    }

    [Fact]
    public void A_standalone_client_in_mcp_names()
    {
        var r = Check(c => Modules(c, Class("a/b/m/Aura",
            ["net/minecraft/client/multiplayer/WorldClient.loadedEntityList", "net/minecraft/client/multiplayer/PlayerControllerMP.attackEntity"])));
        Assert.Contains(r.Signs, s => s.Title == "Kill aura code" && s.Severity == Severity.High);
    }

    [Fact]
    public void Programs_locked_behind_a_password_are_reported()
    {
        var r = Check(c => { c.Kind = "Zip archive"; c.Locked.Add(("Client/loader.exe", "Client/loader.exe")); c.Locked.Add(("Client/readme.txt", "Client/readme.txt")); });
        Assert.Contains(r.Signs, s => s.Title == "Programs locked behind a password" && s.Evidence == "loader.exe");
    }

    [Theory]
    [InlineData("a/b/IlIlIl", true)]
    [InlineData("a/b/xq", true)]
    [InlineData("a/b/abc", true)]
    [InlineData("net/wurstclient/hacks/KillauraHack", false)]
    [InlineData("com/example/ConfigScreen$1", false)]
    public void Scrambled_class_names(string cls, bool scrambled) => Assert.Equal(scrambled, CheatScanner.ScrambledName(cls));

    [Theory]
    [InlineData("8rK;Zq&e\\ >i?eY", true)]
    [InlineData("Kill Aura enabled", false)]
    [InlineData("textures/gui/icon.png", false)]
    [InlineData("com.example.Main", false)]
    [InlineData("aGVsbG8gd29ybGQ=", false)]
    public void Encrypted_texts(string text, bool random) => Assert.Equal(random, CheatScanner.RandomText(text));

    [Fact]
    public void A_module_reaching_the_game_through_its_own_reflection_layer()
    {
        // How injected and multi-version clients are built: a wrapper resolves KeyBinding.onTick by its runtime name and
        // keeps the Method in a field; the module only reads that field - on a random timer.
        var r = Check(c =>
        {
            Agent(c);
            c.Classes.Add(Class("x/mapping/KeyBinding", ["java/lang/Class.getDeclaredMethod", "java/lang/reflect/Method.invoke"])
                with { Texts = ["net.minecraft.client.settings.KeyBinding", "func_74507_a"], FieldTexts = new() { ["x/mapping/KeyBinding.onTick"] = "func_74507_a" } });
            c.Classes.Add(Class("x/util/Rand", ["java/util/Random", "java/util/Random.nextFloat"]));
            Modules(c, Class("a/b/m/Clicker", ["x/mapping/KeyBinding", "x/mapping/KeyBinding.onTick", "x/util/Rand", "x/util/Rand.next"]));
        });
        Assert.Contains(r.Signs, s => s.Title == "Autoclicker code" && s.Severity == Severity.High);
    }

    [Fact]
    public void A_key_remap_without_random_timing_is_not_a_clicker()
    {
        // A farming mod mirroring the player's own key: presses a key from code, but neither the attack key nor on a timer.
        var r = Check(c => Modules(c, Class("a/b/m/Remap", ["net/minecraft/client/KeyMapping.setDown"])));
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void Programs_inside_an_archive_are_judged_one_by_one()
    {
        var r = Check(c =>
        {
            c.Kind = "Zip archive";
            c.Entries.Add(("launcher.exe", [(byte)'M', (byte)'Z'], "launcher.exe"));
            c.Entries.Add(("readme.txt", [], "readme.txt"));
            foreach (var s in new[] { "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "GLFW30" }) c.Strings.Add((s, "launcher.exe"));
            c.Strings.Add(("OpenProcess VirtualAllocEx", "readme.txt"));
        });
        Assert.Contains(r.Signs, s => s.Title == "Injects code into the game: launcher.exe" && s.Severity == Severity.High);
    }

    [Fact]
    public void A_java_library_in_a_dll_is_not_a_client()
    {
        // FFmpeg's avformat imports JNI_GetCreatedJavaVMs for Android; nothing else in it points at a game client.
        var r = Check(c => { c.Kind = "Windows program"; c.Strings.Add(("JNI_GetCreatedJavaVMs", "avformat.dll")); });
        Assert.Equal(CheatVerdict.None, r.CheatVerdict);
    }

    [Fact]
    public void Browser_key_indicator_needs_the_whole_word()
    {
        Assert.True(RatScanner.ContainsWord("{\"os_crypt\":{\"encrypted_key\":\"x\"}}", "encrypted_key"));
        Assert.False(RatScanner.ContainsWord("CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM", "encrypted_key"));
    }
}
