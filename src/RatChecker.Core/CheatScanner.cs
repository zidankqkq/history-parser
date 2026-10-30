using HistoryParser.Core.Models;

namespace RatChecker.Core;

/// <summary>
/// Decides whether a file is a cheat by what a cheat client cannot avoid, not by what it is called: how its code gets
/// into the game, whether it is built from switchable feature modules, what it makes the player do, and whether it
/// hides. Java code is judged class by class from its constant pool and bytecode (game methods called, fields
/// assigned, mixin targets); programs and scripts by what they import. Server plugins never touch the client classes,
/// so anticheat check names cannot trigger anything.
///
/// Mods name the game's methods in one of three ways, and every name below was checked against real files:
/// Mojang's names (26.x and NeoForge) against the 26.1.2 game jar; Fabric's intermediary names (Fabric up to 1.21.11,
/// stable across versions) by matching the Fabric-remapped 1.21.11 game jar to the 26.1.2 jar member by member; and
/// Forge 1.8.9's SRG names against Lunar Client's 1.8 MCP-to-SRG mapping file. Vanilla 1.8.9's obfuscated names (what
/// clients injected into the unmodded game call) were matched from the official 1.8.9 jar to a complete MCP-named copy of
/// the game and confirmed from the code itself (the field set right after a known text, the method that holds one).
/// </summary>
public static class CheatScanner
{
    /// <summary>
    /// One game API in its namings: full owner.member refs (Mojang, and MCP for standalone 1.8.9 clients built from MCP
    /// source - MCP names verified against Lunar's lunar2searge.tsrg), and member names that are unique on their own
    /// (Fabric intermediary, Forge SRG).
    /// </summary>
    sealed record Api(string[] Mojang, string[] Members, string[]? Mcp = null, string[]? Notch = null)
    {
        public bool Calls(Facts f) => Mojang.Any(f.Refs.Contains) || Members.Any(f.Members.Contains) || Mcp != null && Mcp.Any(f.Refs.Contains) || Notch != null && Notch.Any(f.Refs.Contains);
        public bool Assigns(Facts f) => Mojang.Any(f.Writes.Contains) || Members.Any(f.WrittenMembers.Contains) || Mcp != null && Mcp.Any(f.Writes.Contains) || Notch != null && Notch.Any(f.Writes.Contains);
        /// <summary>
        /// A mixin that injects into the method: its name is in the class only as an annotation value
        /// (@Inject(method = "handleSetEntityMotion")). A mixin that merely calls the method has it as a member reference.
        /// </summary>
        public bool Hooks(Facts f) => f.IsMixin && Mojang.Concat(Mcp ?? []).Select(m => m[(m.LastIndexOf('.') + 1)..]).Concat(Members)
            .Any(n => f.Names.Contains(n) && !f.Members.Contains(n));
    }

    const string Mc = "net/minecraft/client/Minecraft.";
    const string Pc = "net/minecraft/client/multiplayer/PlayerControllerMP.";

    static readonly Api Attack = new(
        ["net/minecraft/client/multiplayer/MultiPlayerGameMode.attack", "net/minecraft/network/protocol/game/ServerboundAttackPacket.<init>"],
        ["method_2918", "method_34206", "func_78764_a"],    // MultiPlayerGameMode.attack / attack packet / PlayerControllerMP.attackEntity
        [Pc + "attackEntity"],
        ["bda.a (Lwn;Lpk;)V"]);

    static readonly Api Crosshair = new(
        [Mc + "hitResult", Mc + "crosshairPickEntity"],
        ["field_1765", "field_1692", "field_71476_x", "field_147125_j"],  // hitResult, crosshairPickEntity / objectMouseOver, pointedEntity
        [Mc + "objectMouseOver", Mc + "pointedEntity"],
        ["ave.s Lauh;", "ave.i Lpk;"]);

    static readonly Api EntityList = new(
        ["net/minecraft/client/multiplayer/ClientLevel.entitiesForRendering"],
        ["method_18112", "field_72996_f", "field_73010_i", "func_72839_b"],  // loadedEntityList, playerEntities, getEntitiesWithinAABBExcludingEntity
        ["net/minecraft/client/multiplayer/WorldClient.loadedEntityList", "net/minecraft/world/World.loadedEntityList",
         "net/minecraft/client/multiplayer/WorldClient.playerEntities", "net/minecraft/world/World.playerEntities",
         "net/minecraft/client/multiplayer/WorldClient.getEntitiesWithinAABBExcludingEntity", "net/minecraft/world/World.getEntitiesWithinAABBExcludingEntity"],
        ["adm.f Ljava/util/List;", "bdb.f Ljava/util/List;", "adm.j Ljava/util/List;", "bdb.j Ljava/util/List;",
         "adm.b (Lpk;Laug;)Ljava/util/List;", "bdb.b (Lpk;Laug;)Ljava/util/List;"]);

    // Turning the *player*: the call or field is reached through the player's type (mc.player.setYRot). An arrow, boat or
    // boss turning itself goes through its own type, which is ordinary entity code.
    static readonly Api TurnPlayer = new(
        ["net/minecraft/client/player/LocalPlayer.setYRot", "net/minecraft/client/player/LocalPlayer.setXRot",
         "net/minecraft/world/entity/player/Player.setYRot", "net/minecraft/world/entity/player/Player.setXRot",
         "net/minecraft/class_746.method_36456", "net/minecraft/class_746.method_36457",     // LocalPlayer (intermediary)
         "net/minecraft/class_1657.method_36456", "net/minecraft/class_1657.method_36457"], // Player
        []);
    static readonly Api Rotation = new(                                                        // 1.8.9 rotationYaw / rotationPitch, assigned directly
        ["net/minecraft/client/entity/EntityPlayerSP.field_70177_z", "net/minecraft/client/entity/EntityPlayerSP.field_70125_A",
         "net/minecraft/entity/player/EntityPlayer.field_70177_z", "net/minecraft/entity/player/EntityPlayer.field_70125_A"],
        [],
        ["net/minecraft/client/entity/EntityPlayerSP.rotationYaw", "net/minecraft/client/entity/EntityPlayerSP.rotationPitch",
         "net/minecraft/entity/player/EntityPlayer.rotationYaw", "net/minecraft/entity/player/EntityPlayer.rotationPitch"],
        ["bew.y F", "bew.z F", "bet.y F", "bet.z F", "wn.y F", "wn.z F"]);

    static readonly Api StartAttack = new([Mc + "startAttack"], ["method_1536", "func_147116_af"], [Mc + "clickMouse"], ["ave.aw ()V"]); // the game's own left click
    static readonly Api AttackKey = new(["net/minecraft/client/Options.keyAttack"], ["field_1886", "field_74312_F"],
        ["net/minecraft/client/settings/GameSettings.keyBindAttack"], ["avh.ai Lavb;"]);
    static readonly Api PressKey = new(["net/minecraft/client/KeyMapping.click", "net/minecraft/client/KeyMapping.setDown"],
        ["method_1420", "method_23481", "func_74507_a", "func_74510_a"], // KeyMapping.click / setDown / KeyBinding.onTick / setKeyBindState
        ["net/minecraft/client/settings/KeyBinding.onTick", "net/minecraft/client/settings/KeyBinding.setKeyBindState"], ["avb.a (I)V", "avb.a (IZ)V"]);
    static readonly Api KeyPressed = new([], ["field_74513_e"], ["net/minecraft/client/settings/KeyBinding.pressed"], ["avb.h Z"]); // assigned directly

    static readonly Api MovePacket = new(
        ["net/minecraft/network/protocol/game/ServerboundMovePlayerPacket$Pos.<init>", "net/minecraft/network/protocol/game/ServerboundMovePlayerPacket$PosRot.<init>",
         "net/minecraft/network/protocol/game/ServerboundMovePlayerPacket$Rot.<init>", "net/minecraft/network/protocol/game/ServerboundMovePlayerPacket$StatusOnly.<init>",
         "net/minecraft/class_2828$class_2829.<init>", "net/minecraft/class_2828$class_2830.<init>", "net/minecraft/class_2828$class_2831.<init>",
         "net/minecraft/class_2828$class_5911.<init>",
         "net/minecraft/network/play/client/C03PacketPlayer.<init>", "net/minecraft/network/play/client/C03PacketPlayer$C04PacketPlayerPosition.<init>",
         "net/minecraft/network/play/client/C03PacketPlayer$C05PacketPlayerLook.<init>", "net/minecraft/network/play/client/C03PacketPlayer$C06PacketPlayerPosLook.<init>"],
        [], null,
        ["ip.<init> (Z)V", "ip$a.<init> (DDDZ)V", "ip$c.<init> (FFZ)V", "ip$b.<init> (DDDFFZ)V"]);

    static readonly Api Knockback = new(
        ["net/minecraft/client/multiplayer/ClientPacketListener.handleSetEntityMotion", "net/minecraft/client/multiplayer/ClientPacketListener.handleExplosion"],
        ["method_11132", "method_11124", "method_6005", "func_147244_a", "func_147283_a", "func_70653_a"], // + LivingEntity.knockback / knockBack
        ["net/minecraft/client/network/NetHandlerPlayClient.handleEntityVelocity", "net/minecraft/client/network/NetHandlerPlayClient.handleExplosion"]);

    static readonly Api Reach = new(
        ["net/minecraft/world/entity/player/Player.entityInteractionRange", "net/minecraft/world/entity/player/Player.blockInteractionRange"],
        ["method_55755", "method_55754", "func_78757_d", "func_78473_a"], // + PlayerControllerMP.getBlockReachDistance, EntityRenderer.getMouseOver
        [Pc + "getBlockReachDistance", "net/minecraft/client/renderer/EntityRenderer.getMouseOver"]);

    /// <summary>What one class does, in a form the rules can ask about.</summary>
    sealed class Facts
    {
        public required JavaClass Class { get; init; }
        public required HashSet<string> Refs { get; init; }
        public required HashSet<string> Members { get; init; }
        public required HashSet<string> Writes { get; init; }
        public required HashSet<string> WrittenMembers { get; init; }
        public required HashSet<string> Names { get; init; }
        /// <summary>Game fields (SRG / intermediary) assigned through reflection.</summary>
        public required HashSet<string> ReflectedWrites { get; init; }
        public bool IsMixin { get; init; }
    }

    /// <summary>A game member's runtime name that is unique on its own: Forge SRG and Fabric intermediary.</summary>
    static readonly System.Text.RegularExpressions.Regex GameMember = new(@"^(func_\d+_[a-zA-Z]+_?|field_\d+_[a-zA-Z]+_?|method_\d+|field_\d+)$",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    static readonly string[] Reflection =
    [
        "java/lang/Class.getDeclaredMethod", "java/lang/Class.getMethod", "java/lang/Class.getDeclaredField", "java/lang/Class.getField",
        "java/lang/reflect/Method.invoke", "java/lang/invoke/MethodHandles$Lookup.findVirtual", "java/lang/invoke/MethodHandles$Lookup.findStatic",
        "java/lang/invoke/MethodHandles$Lookup.findGetter", "java/lang/invoke/MethodHandles$Lookup.findSetter", "java/lang/invoke/MethodHandles$Lookup.unreflect",
    ];

    /// <summary>
    /// What one class touches in the game, however it reaches it: direct calls; game member names it hands to reflection
    /// (getDeclaredMethod("func_74507_a")); and fields of the client's own mapping layer that were set from such a name and
    /// that this class reads - a module calling Mappings.KeyBinding.onTick.invoke(...) uses KeyBinding.onTick.
    /// </summary>
    static Facts Read(JavaClass k, Dictionary<string, string> fieldTexts)
    {
        static string Member(string r) => r[(r.LastIndexOf('.') + 1)..];
        var members = k.Refs.Where(r => r.Contains('.')).Select(Member).ToHashSet(StringComparer.Ordinal);
        var refs = new HashSet<string>(k.Refs, StringComparer.Ordinal);
        var reflected = new HashSet<string>(StringComparer.Ordinal);
        if (Reflection.Any(k.Refs.Contains))
        {
            foreach (var t in k.Texts.Where(t => GameMember.IsMatch(t))) reflected.Add(t);
            // Readable names (Mojang / MCP) count when the class also names the owning class: "net.minecraft.client.Minecraft" + "clickMouse".
            foreach (var full in ReadableApis)
            {
                int dot = full.LastIndexOf('.');
                string owner = full[..dot], member = full[(dot + 1)..];
                if (k.Texts.Contains(member) && (k.Texts.Contains(owner.Replace('/', '.')) || k.Texts.Contains(owner))) refs.Add(full);
            }
        }
        foreach (var r in k.Refs)
            if (fieldTexts.TryGetValue(r, out var t) && GameMember.IsMatch(t)) reflected.Add(t);
        members.UnionWith(reflected);
        bool setsFields = k.Refs.Any(r => r.StartsWith("java/lang/reflect/Field.set", StringComparison.Ordinal)) ||
                          k.Refs.Contains("java/lang/invoke/MethodHandles$Lookup.findSetter");
        return new Facts
        {
            Class = k,
            Refs = refs,
            Members = members,
            Writes = k.Writes,
            WrittenMembers = k.Writes.Select(Member).ToHashSet(StringComparer.Ordinal),
            ReflectedWrites = setsFields ? reflected.Where(t => t.StartsWith("field_", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal) : [],
            Names = new HashSet<string>(k.Names, StringComparer.Ordinal),
            IsMixin = k.Refs.Contains("org/spongepowered/asm/mixin/Mixin"),
        };
    }

    /// <summary>Every readable owner.member API the rules use, for spotting them as reflection texts.</summary>
    static readonly string[] ReadableApis = new[] { Attack, Crosshair, EntityList, TurnPlayer, Rotation, StartAttack, AttackKey, PressKey, KeyPressed, MovePacket, Knockback, Reach }
        .SelectMany(a => a.Mojang.Concat(a.Mcp ?? [])).Where(r => !r.Contains("<init>") && !r.Contains("field_") && !r.Contains("class_")).Distinct().ToArray();

    /// <summary>The player's rotation fields, assigned through reflection (Field.setFloat on a mapped field): owner can't be read, the client's own player is meant.</summary>
    static readonly string[] RotationFields = ["field_70177_z", "field_70125_A"];

    static readonly string[] RandomApis = ["java/util/Random", "java/util/concurrent/ThreadLocalRandom", "java/lang/Math.random", "java/security/SecureRandom"];


    // ---- what a client author cannot avoid ------------------------------------------------------------------------
    //
    // A cheat client, however it is written, (1) has to get its code into the game, (2) is built from switchable feature
    // modules, (3) has to make the player do things the player didn't do, and (4) usually hides. A legitimate mod enters
    // through the mod loader, adds content or changes visuals, and has nothing to hide. Each part below is judged on its
    // own; the verdict comes from how they combine, so no single habit of one client decides anything.

    /// <summary>Everything the rules know about the whole file.</summary>
    sealed class FileFacts
    {
        public required List<Facts> Classes { get; init; }
        public required HashSet<string> Modules { get; init; }
        public bool ContentMod { get; init; }
        public string? Hiding { get; init; }
        public List<(string Title, string Why, string Evidence)> Entry { get; } = new();
        public bool Injects => Entry.Count > 0;
    }

    public static void Evaluate(RatContent c, List<RatSign> signs)
    {
        // One sign per behaviour, listing every class that shows it.
        var found = new Dictionary<string, (Severity Severity, RatCategory Category, string Why, List<string> Evidence, string Where)>();
        void Sign(Severity s, RatCategory cat, string title, string why, string evidence, string where)
        {
            if (found.TryGetValue(title, out var f)) { if (!f.Evidence.Contains(evidence)) f.Evidence.Add(evidence); }
            else found[title] = (s, cat, why, [evidence], where);
        }
        static string Short(string cls) => cls.Replace('/', '.');

        // Fields of the file's own mapping layer and the game names they were set from.
        var fieldTexts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var k in c.Classes) foreach (var (field, text) in k.FieldTexts) fieldTexts.TryAdd(field, text);
        var classes = c.Classes.Select(k => Read(k, fieldTexts)).ToList();
        bool isGame = c.Classes.Any(k => k.Name == "net/minecraft/client/main/Main");
        var byName =classes.GroupBy(f => f.Class.Name).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        // Random timing: in the class, or in one of the file's own helpers it uses (a Random/Timer utility class).
        bool Randomised(Facts f) => RandomApis.Any(r => f.Refs.Any(x => x.StartsWith(r, StringComparison.Ordinal))) ||
            f.Refs.Where(r => !r.Contains('.') && byName.ContainsKey(r) && r != f.Class.Name)
                  .Any(r => RandomApis.Any(api => byName[r].Refs.Any(x => x.StartsWith(api, StringComparison.Ordinal))));
        var hiding = Hiding(c, classes);
        var file = new FileFacts
        {
            Classes = classes,
            ContentMod = IsContentMod(c),
            Hiding = hiding,
            Modules = Modules(c, classes, byShapeToo: hiding != null || EntrySigns(c).Count > 0, Sign),
        };
        file.Entry.AddRange(EntrySigns(c));

        // ---- (3) what it makes the player do, class by class ----
        bool InModule(string cls) => file.Modules.Contains(cls) || cls.Contains('$') && file.Modules.Contains(cls[..cls.IndexOf('$')]);
        void Action(Facts f, RatCategory cat, string title, string why)
        {
            // Inside a switchable module of a mod that adds no game content, this is cheat code. Elsewhere it is usually a
            // game effect of a content mod (an elixir that jerks the player's view, a "hold to attack" tweak) - check by hand.
            bool cheat = InModule(f.Class.Name) && !file.ContentMod;
            Sign(cheat ? Severity.High : Severity.Medium, cat, title + (cheat ? "" : " (check by hand)"),
                why + (cheat ? " It is one of the mod's switchable feature modules - the way cheat clients are built."
                             : file.ContentMod ? " The mod also adds game content (items, blocks or entities), so this may be one of its game effects."
                                               : " It is not part of a switchable feature module, so it may be a legitimate tweak."),
                Short(f.Class.Name), f.Class.Where);
        }

        foreach (var f in classes)
        {
            // The game's own classes contain the real attack code: Minecraft's packages, and - in a jar that is the game itself
            // (it holds the game's entry point) - its obfuscated classes, which have no package (ave, bda).
            if (f.Class.Name.StartsWith("net/minecraft/", StringComparison.Ordinal) || f.Class.Name.StartsWith("com/mojang/", StringComparison.Ordinal) ||
                isGame && !f.Class.Name.Contains('/')) continue;
            if (f.Refs.Contains("java/awt/Robot.mousePress"))
                Sign(Severity.High, RatCategory.CheatClicker, "Clicks the mouse by itself",
                    "Uses java.awt.Robot to press mouse buttons - an autoclicker. A game mod has no other reason to fake mouse input.",
                    Short(f.Class.Name), f.Class.Where);
            if (f.IsMixin)
            {
                // A mixin names the methods of the class it is mixed into without doing what they do; it only counts for what it hooks.
                if (Knockback.Hooks(f))
                    Sign(Severity.Medium, RatCategory.CheatCombat, "Changes how knockback is handled",
                        "A mixin into the code that applies knockback from hits and explosions. Velocity / anti-knockback cheats cancel or shrink it there.",
                        Short(f.Class.Name), f.Class.Where);
                if (Reach.Hooks(f))
                    Sign(Severity.Medium, RatCategory.CheatCombat, "Changes attack or block reach",
                        "A mixin into the methods that decide how far the player can hit or reach. Reach cheats change them; a few legitimate mods that resize players do too.",
                        Short(f.Class.Name), f.Class.Where);
                continue;
            }
            // Pressing the game's attack key from code, or pressing keys from code on a random timer (a humanised clicker,
            // whichever key it presses - a key remap mirrors the player's key and never randomises).
            bool presses = PressKey.Calls(f) || KeyPressed.Assigns(f);
            bool attacks = Attack.Calls(f), click = StartAttack.Calls(f) || presses && (AttackKey.Calls(f) || Randomised(f));
            if (Crosshair.Calls(f) && (attacks || click))
                Action(f, RatCategory.CheatCombat, "Trigger bot code",
                    "This class reads what the crosshair is pointing at and attacks it by itself - what a trigger bot does; the game only attacks when the player clicks.");
            if (EntityList.Calls(f) && attacks)
                Action(f, RatCategory.CheatCombat, "Kill aura code",
                    "This class goes through the loaded entities and attacks them by itself - what a kill aura does.");
            if (EntityList.Calls(f) && (TurnPlayer.Calls(f) || Rotation.Assigns(f) || f.ReflectedWrites.Overlaps(RotationFields)))
                Action(f, RatCategory.CheatCombat, "Aim assist code",
                    "This class goes through the loaded entities and turns the player's aim - what an aim assist / aimbot does; camera mods move the camera, not the player's aim.");
            if (click)
                Action(f, RatCategory.CheatClicker, "Autoclicker code",
                    "This class presses the attack button from code - what an autoclicker does.");
            if (attacks)
                Sign(Severity.Medium, RatCategory.CheatCombat, "Attacks from its own code",
                    "This class makes the player attack an entity. In the normal game only a mouse click does that.",
                    Short(f.Class.Name), f.Class.Where);
            if (MovePacket.Calls(f))
                Sign(Severity.Medium, RatCategory.CheatMovement, "Sends its own movement packets",
                    "This class builds the packets that tell the server where the player is and whether they are on the ground. Fly, no-fall, blink and similar cheats work this way; the game sends these itself.",
                    Short(f.Class.Name), f.Class.Where);
        }
        var refmapText = c.Strings.Where(s => s.Where.EndsWith("refmap.json", StringComparison.OrdinalIgnoreCase)).Select(s => s.Text).ToList();
        foreach (var (api, title, why) in new[]
        {
            (Knockback, "Changes how knockback is handled", "Its mixins target the code that applies knockback from hits and explosions. Velocity / anti-knockback cheats cancel or shrink it there."),
            (Reach, "Changes attack or block reach", "Its mixins target the methods that decide how far the player can hit or reach. Reach cheats change them; a few legitimate mods that resize players do too."),
        })
            if (api.Members.Where(m => refmapText.Any(t => t.Contains(m, StringComparison.Ordinal))).ToList() is { Count: > 0 } hits)
                Sign(Severity.Medium, RatCategory.CheatCombat, title, why, string.Join(", ", hits), "mixin refmap");

        // What decides it: a cheat has to *act* - attack, aim, click or fight for the player. Getting in as an agent, hiding
        // its code and being built from modules are what legitimate PvP clients and loaders do as well, so they only make a
        // file worth a look until its code is seen acting.
        var kinds = found.Where(kv => kv.Value.Category is RatCategory.CheatCombat or RatCategory.CheatMovement or RatCategory.CheatClicker && kv.Value.Severity >= Severity.Medium)
            .Select(kv => kv.Key.Replace(" (check by hand)", "")).Distinct().ToList();
        var actions = kinds.Where(k => k is "Trigger bot code" or "Kill aura code" or "Aim assist code" or "Autoclicker code" or "Attacks from its own code").ToList();
        bool acts = actions.Count > 0 && !file.ContentMod;

        // ---- (1) how it gets into the game ----
        foreach (var (title, why, evidence) in file.Entry)
        {
            bool client = file.Modules.Count > 0 || file.Hiding != null;
            bool attaches = title.StartsWith("Injects", StringComparison.Ordinal);
            Sign(acts ? Severity.High : client || attaches ? Severity.Medium : Severity.Low, RatCategory.CheatLoader, title,
                why + (acts ? " Its code also makes the player act on its own - an injectable cheat."
                     : client ? $" It is also {(file.Modules.Count > 0 ? "built from switchable feature modules" : "hiding its own code")}, like injectable clients; legitimate PvP clients are built the same way, so check what it does."
                     : " On its own this is also what launchers, mod loaders and profilers do."),
                evidence, "whole file");
        }

        // ---- (4) hiding: context, and it turns an action into a verdict ----
        if (file.Hiding != null)
            Sign(Severity.Low, RatCategory.CheatStructure, "Hides its own code",
                "Its class names or texts are scrambled so nobody can read what it does. Paid mods and legitimate PvP clients do this too; cheats almost always do.",
                file.Hiding, "whole file");

        if (kinds.Count >= 3 && acts)
            Sign(Severity.High, RatCategory.CheatCombat, "Several cheat features",
                "Each of these alone has rare legitimate uses; together, in a mod that adds no game content, they are a cheat client's feature list.",
                string.Join(" + ", kinds), "whole file");
        else if (acts && (file.Hiding != null || file.Injects))
            Sign(Severity.High, RatCategory.CheatCombat, "Cheat features in hidden or injected code",
                "Code that makes the player act on its own, in a file that " + (file.Injects ? "injects itself into the game" : "scrambles its own code") +
                ". Legitimate mods have no reason to do either.", string.Join(" + ", actions), "whole file");

        Loader(c, Sign);
        Native(c, Sign);
        Locked(c, Sign);

        foreach (var (title, f) in found)
        {
            var evidence = f.Evidence.Count == 1 ? f.Evidence[0]
                : $"{f.Evidence.Count} classes: {string.Join(", ", f.Evidence.Take(12))}{(f.Evidence.Count > 12 ? " …" : "")}";
            signs.Add(new RatSign(f.Severity, f.Category, title, f.Why, evidence, f.Evidence.Count == 1 ? f.Where : "several classes"));
        }
    }

    // ---- (1) entry ---------------------------------------------------------------------------------------------------

    /// <summary>Ways into a running game that the mod loader never needs.</summary>
    static List<(string Title, string Why, string Evidence)> EntrySigns(RatContent c)
    {
        var list = new List<(string, string, string)>();
        // Only the file's own code: a build tool bundled inside a mod (Lombok's agent) says nothing about the mod.
        var own = c.Classes.Where(k => !Bundled(c, k) && !LibraryPrefix.IsMatch(k.Name)).ToList();
        bool Ref(string r) => own.Any(k => k.Refs.Contains(r));
        if (Ref("com/sun/tools/attach/VirtualMachine.attach") && own.Any(k => k.Refs.Any(r => r.StartsWith("com/sun/tools/attach/VirtualMachine.loadAgent", StringComparison.Ordinal))))
            list.Add(("Injects itself into a running game",
                "It attaches to another running Java program and loads code into it (VirtualMachine.attach + loadAgent) - how injectable clients get into an already running game.",
                "VirtualMachine.attach + loadAgent"));
        bool agent = c.Manifest.Keys.Any(k => k is "Agent-Class" or "Launcher-Agent-Class" or "Premain-Class") ||
                     own.Any(k => k.Names.Contains("agentmain") && k.Refs.Contains("java/lang/instrument/Instrumentation"));
        var rewrites = new[] { "addTransformer", "retransformClasses", "redefineClasses" }
            .Where(m => Ref("java/lang/instrument/Instrumentation." + m)).ToList();
        if (agent && rewrites.Count > 0)
            list.Add(("Rewrites the game's code while it runs",
                "It is a Java agent that changes classes that are already loaded (" + string.Join(", ", rewrites) + ") - how injected clients patch the game without a mod loader.",
                string.Join(" | ", c.Manifest.Where(kv => kv.Key.Contains("Agent") || kv.Key.Contains("Premain")).Select(kv => $"{kv.Key}: {kv.Value}").DefaultIfEmpty("agentmain"))));
        return list;
    }

    // ---- (2) structure -------------------------------------------------------------------------------------------

    /// <summary>
    /// Cheat clients are built from many small "modules" that share a base class which is switched on and off. Found by
    /// the base's method names when they are readable, and - in hidden or injected code, where names are scrambled - by
    /// its shape: a base of the mod's own with an on/off flag (boolean field) and a key (int field), extended by at least
    /// 8 classes. Returns every module class. The structure alone is only context: utility mods are built the same way.
    /// </summary>
    static HashSet<string> Modules(RatContent c, List<Facts> facts, bool byShapeToo, Action<Severity, RatCategory, string, string, string, string> sign)
    {
        var toggles = new[] { "onEnable", "onDisable", "toggle", "setEnabled", "isEnabled", "setToggled", "isToggled", "onToggle" };
        var bySuper = c.Classes.Where(k => k.Super != null).ToLookup(k => k.Super!);
        var modules = new HashSet<string>(StringComparer.Ordinal);
        // The same class can appear twice (a library bundled in a nested jar), so names are not unique.
        foreach (var b in facts.GroupBy(f => f.Class.Name).Select(g => g.First()))
        {
            bool named = toggles.Count(b.Names.Contains) >= 2;
            bool shaped = byShapeToo && b.Class.FieldTypes.Contains("Z") && b.Class.FieldTypes.Contains("I") &&
                          b.Class.Super is "java/lang/Object" && !b.IsMixin;
            if (!named && !shaped) continue;
            var subs = bySuper[b.Class.Name].Select(k => k.Name).ToList();
            subs.AddRange(subs.SelectMany(s => bySuper[s].Select(k => k.Name)).ToList()); // an intermediate base (CombatModule : Module)
            if (subs.Count < (named ? 5 : 8)) continue;
            modules.UnionWith(subs);
            sign(Severity.Low, RatCategory.CheatStructure, "Built from switchable modules",
                $"{subs.Count} classes extend one base class that can be switched on and off{(named ? "" : " (recognised by its shape - its names are scrambled)")}. Cheat clients are built this way, one class per feature; so are some utility mods.",
                $"{b.Class.Name.Replace('/', '.')}: {string.Join(", ", subs.Take(8).Select(k => k[(k.LastIndexOf('/') + 1)..]))}{(subs.Count > 8 ? " …" : "")}",
                b.Class.Where);
        }
        return modules;
    }

    /// <summary>
    /// A content mod adds things to the game - items, blocks, entities - which a cheat never needs. Supers checked in all
    /// three namings: Mojang and MCP packages, and Fabric's intermediary ids (verified: Entity 1297, LivingEntity 1309,
    /// Mob 1308, Monster 1588, Projectile 1676, ThrowableProjectile 1682, Item 1792, Block 2248, BlockEntity 2586).
    /// </summary>
    static bool IsContentMod(RatContent c)
    {
        var own = c.Classes.Select(k => k.Name).ToHashSet(StringComparer.Ordinal);
        var content = new HashSet<string>(StringComparer.Ordinal);
        bool Game(string s) =>
            s.StartsWith("net/minecraft/world/item/", StringComparison.Ordinal) || s.StartsWith("net/minecraft/world/level/block/", StringComparison.Ordinal) ||
            s.StartsWith("net/minecraft/world/entity/", StringComparison.Ordinal) && !s.StartsWith("net/minecraft/world/entity/player/", StringComparison.Ordinal) ||
            s.StartsWith("net/minecraft/item/", StringComparison.Ordinal) || s.StartsWith("net/minecraft/block/", StringComparison.Ordinal) ||
            s.StartsWith("net/minecraft/tileentity/", StringComparison.Ordinal) ||
            s.StartsWith("net/minecraft/entity/", StringComparison.Ordinal) && !s.StartsWith("net/minecraft/entity/player/", StringComparison.Ordinal) ||
            s is "net/minecraft/class_1297" or "net/minecraft/class_1309" or "net/minecraft/class_1308" or "net/minecraft/class_1588" or "net/minecraft/class_1676"
              or "net/minecraft/class_1682" or "net/minecraft/class_1792" or "net/minecraft/class_2248" or "net/minecraft/class_2586";
        // Two passes pick up the mod's own intermediate bases (ModItem : Item, then RubyItem : ModItem).
        for (int pass = 0; pass < 2; pass++)
            foreach (var k in c.Classes)
                // A standalone client carries the whole game; the game's own items and mobs are not the file adding content.
                if (k.Super != null && !k.Name.StartsWith("net/minecraft/", StringComparison.Ordinal) && !k.Refs.Contains("org/spongepowered/asm/mixin/Mixin") &&
                    (Game(k.Super) || own.Contains(k.Super) && content.Contains(k.Super)))
                    content.Add(k.Name);
        return content.Count >= 3;
    }

    // ---- (4) hiding ----------------------------------------------------------------------------------------------

    /// <summary>Scrambled class names or encrypted texts across the mod's own code, or null when its code reads normally.</summary>
    static string? Hiding(RatContent c, List<Facts> facts)
    {
        // The mod's own classes: libraries it bundles (shaded into com/google, kotlin, …) are not judged.
        var own = facts.Where(f => !f.Class.Name.StartsWith("net/minecraft/", StringComparison.Ordinal) && !LibraryPrefix.IsMatch(f.Class.Name) && !Bundled(c, f.Class)).ToList();
        var parts = new List<string>();
        if (own.Count >= 20)
        {
            int scrambled = own.Count(f => ScrambledName(f.Class.Name));
            if (scrambled >= own.Count * 0.6) parts.Add($"{scrambled * 100 / own.Count}% of its {own.Count} classes have scrambled names");
        }
        var literals = c.Strings.Where(s => s.Where.EndsWith(".class", StringComparison.OrdinalIgnoreCase) && s.Text.Length >= 8)
            .Select(s => s.Text).Distinct().ToList();
        if (literals.Count >= 30)
        {
            int random = literals.Count(RandomText);
            if (random >= literals.Count * 0.5) parts.Add($"{random * 100 / literals.Count}% of its {literals.Count} texts are encrypted");
        }
        return parts.Count > 0 ? string.Join("; ", parts) : null;
    }

    static readonly System.Text.RegularExpressions.Regex LibraryPrefix = new(
        @"^(com/google|org/apache|org/objectweb|kotlin|kotlinx|org/jetbrains|io/netty|it/unimi|org/slf4j|com/fasterxml|org/json|okhttp3|okio|com/sun|javax|org/lwjgl|imgui|org/yaml|com/github|org/intellij|org/checkerframework|lombok|org/spongepowered|net/bytebuddy|com/llamalad7|net/fabricmc|cpw/mods|net/minecraftforge)/",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// A class from a jar bundled inside the file (Fabric's jar-in-jar libraries). For a plain zip, the jars it carries are
    /// the file's own content, so one level of nesting still counts as its own code.
    /// </summary>
    static bool Bundled(RatContent c, JavaClass k)
    {
        int depth = 0;
        for (int i = k.Where.IndexOf(" → ", StringComparison.Ordinal); i >= 0; i = k.Where.IndexOf(" → ", i + 1, StringComparison.Ordinal)) depth++;
        return depth > (c.Kind == "Zip archive" ? 1 : 0);
    }

    /// <summary>
    /// A class name an obfuscator made: one or two letters, characters no programmer types, or a long run drawn from a
    /// handful of look-alike letters (IlIl1lI, IOCIHHIRIROCOIRO) - a real name has a programmer's mix of letters.
    /// </summary>
    internal static bool ScrambledName(string cls)
    {
        var simple = cls[(cls.LastIndexOf('/') + 1)..];
        int dollar = simple.IndexOf('$');
        if (dollar > 0) simple = simple[..dollar];
        if (simple.Length <= 2 || simple.Any(ch => ch > 0x7E || char.IsControl(ch)) ||
            System.Text.RegularExpressions.Regex.IsMatch(simple, @"^[A-Za-z]{1,2}\d*$|^[a-z]{3}$")) return true;
        // Look-alike alphabets: few distinct letters, all upper case or I/l/1 confusion, repeated over a long name.
        return simple.Length >= 6 && simple.Distinct().Count() <= 6 && (simple.All(char.IsUpper) || simple.All(ch => ch is 'I' or 'l' or '1' or 'i' or 'L' or '|'));
    }

    /// <summary>Encrypted text: no spaces, a mix of letters, digits and symbols, and none of the shapes real texts have.</summary>
    internal static bool RandomText(string s)
    {
        if (s.Contains("://") || s.Count(ch => ch == '/') >= 2) return false;
        // Spaces are fine in encrypted text; a real word ("Kill Aura enabled") is not.
        if (s.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(w => System.Text.RegularExpressions.Regex.IsMatch(w, @"^[A-Za-z]{3,}[.,!?:]?$"))) return false;
        if (System.Text.RegularExpressions.Regex.IsMatch(s, @"^[A-Za-z_$][\w$.]*$|^[0-9a-fA-F]+$|^[A-Za-z0-9+/]+=*$|^[\w.-]+\.(json|png|txt|class|properties)$")) return false;
        int kinds = (s.Any(char.IsUpper) ? 1 : 0) + (s.Any(char.IsLower) ? 1 : 0) + (s.Any(char.IsDigit) ? 1 : 0) + (s.Any(ch => !char.IsLetterOrDigit(ch)) ? 1 : 0);
        return kinds >= 3 || s.Any(ch => ch > 0x7E || char.IsControl(ch));
    }

    /// <summary>A jar that defines classes from encrypted data inside it.</summary>
    static void Loader(RatContent c, Action<Severity, RatCategory, string, string, string, string> sign)
    {
        // Certificate stores are encrypted-looking by nature (a Java cacerts file, keystores).
        var parts = c.Encrypted.Where(e => !Path.GetFileName(e.Name).Equals("cacerts", StringComparison.OrdinalIgnoreCase) &&
                                           !e.Name.EndsWith("store", StringComparison.OrdinalIgnoreCase)).ToList();
        long hidden = parts.Sum(e => (long)e.Size);
        if (hidden < 64 * 1024) return;
        // A class loader subclass calls defineClass on itself (net/java/m.defineClass), so the owner can be anything.
        bool defines = c.Refs.Keys.Any(r => r.EndsWith(".defineClass", StringComparison.Ordinal) || r.EndsWith(".defineHiddenClass", StringComparison.Ordinal) ||
                                            r == "java/lang/instrument/Instrumentation.redefineClasses");
        if (!defines) return;
        bool agent = c.Manifest.Keys.Any(k => k is "Agent-Class" or "Launcher-Agent-Class" or "Premain-Class") ||
                     c.Refs.ContainsKey("java/lang/instrument/Instrumentation");
        var what = $"{parts.Count} encrypted part(s), {hidden / 1024:N0} KB: {string.Join(", ", parts.Take(6).Select(e => e.Name))}";
        if (agent)
            sign(Severity.High, RatCategory.CheatLoader, "Injects hidden code into the game",
                "It can attach to a running game as a Java agent and turns encrypted data inside the jar into code. That is how injectable clients hide their real code from anyone who opens the file.",
                what, "whole file");
        else
            sign(Severity.Medium, RatCategory.CheatLoader, "Loads encrypted code",
                "It turns encrypted data inside the jar into code at runtime, so its real code can't be read from the file. Cheat loaders and some paid mods do this.",
                what, "whole file");
    }

    // ---- programs, DLLs and scripts --------------------------------------------------------------------------------

    static readonly System.Text.RegularExpressions.Regex Word = new(@"[A-Za-z_][A-Za-z0-9_]{2,40}", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>Windows programs, DLLs and the scripts wrapped inside them: what they call says what they do.</summary>
    /// <summary>
    /// Every program in the file is judged on its own: the file itself when it is a program or script, and each program
    /// or script carried inside an archive (a zip with a launcher.exe that injects a runtime.dll).
    /// </summary>
    static void Native(RatContent c, Action<Severity, RatCategory, string, string, string, string> sign)
    {
        if (c.Kind is ".NET program" or "Windows program" or "Script / text")
        {
            NativeUnit(c.Strings, c.Refs.Keys, "", sign);
            return;
        }
        var units = c.Entries.Where(e => e.Head.Length > 1 && e.Head[0] == 'M' && e.Head[1] == 'Z' ||
                                         Path.GetExtension(e.Name).ToLowerInvariant() is ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".ahk" or ".py")
                             .Select(e => e.Where).Distinct().ToList();
        foreach (var unit in units)
        {
            bool Mine(string where) => where == unit || where.StartsWith(unit + " → ", StringComparison.Ordinal);
            NativeUnit(c.Strings.Where(s => Mine(s.Where)).ToList(), c.Refs.Where(r => Mine(r.Value)).Select(r => r.Key), unit, sign);
        }
    }

    static void NativeUnit(IReadOnlyCollection<(string Text, string Where)> strings, IEnumerable<string> refs, string unit,
        Action<Severity, RatCategory, string, string, string, string> outer)
    {
        // Signs from a program inside an archive say which program; one sign per program.
        void sign(Severity s, RatCategory cat, string title, string why, string evidence, string where) =>
            outer(s, cat, unit.Length == 0 ? title : $"{title}: {Path.GetFileName(unit.Split(" → ")[^1])}", why, evidence, unit.Length == 0 ? where : unit);
        // Every identifier: native imports, P/Invoke declarations in a wrapped script, .NET member names.
        var words = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (text, _) in strings)
            if (text.Length <= 4000) foreach (System.Text.RegularExpressions.Match m in Word.Matches(text)) words.Add(m.Value);
        foreach (var r in refs) words.Add(r[(r.LastIndexOf('.') + 1)..]);
        bool Has(params string[] any) => any.Any(words.Contains);
        bool targetsGame = strings.Any(s => s.Text.Contains("javaw", StringComparison.OrdinalIgnoreCase) || s.Text.Contains("LWJGL", StringComparison.Ordinal) ||
                                            s.Text.Contains("GLFW30", StringComparison.Ordinal) || s.Text.Contains("Minecraft", StringComparison.OrdinalIgnoreCase));

        if (Has("OpenProcess") && Has("VirtualAllocEx") && Has("WriteProcessMemory") && Has("CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC"))
            sign(targetsGame ? Severity.High : Severity.Medium, RatCategory.CheatInjector,
                targetsGame ? "Injects code into the game" : "Injects code into other programs",
                "It opens another process, writes into its memory and starts a thread there - the standard way to inject a DLL." +
                (targetsGame ? " It also names the game (javaw / Minecraft / its window class)." : ""),
                "OpenProcess + VirtualAllocEx + WriteProcessMemory + remote thread", "imports");

        // A JVMTI agent: a DLL the JVM loads into the game - at start (Agent_OnLoad) or into the running game (Agent_OnAttach).
        if (Has("Agent_OnAttach") && Has("GetEnv", "JNI_GetCreatedJavaVMs", "jvmtiEnv", "RetransformClasses", "SetEventNotificationMode"))
            sign(Severity.Medium, RatCategory.CheatInjector, "Native Java agent that attaches to a running game",
                "It exports Agent_OnAttach, so it can be loaded into a Java program that is already running and use the JVM's tool interface to inspect or change its code. The JDK's own agents and profilers do this; nothing a normal player runs does.",
                "Agent_OnAttach", "exports");

        // Looking up the Java machine already running in the process is what a DLL client does to control the game from
        // inside - but also what general libraries built with Java support do (FFmpeg's Android code). It counts together
        // with what a client then needs: hooking the frame drawing or functions, reading keys, or naming the game.
        bool drawsOver = Has("wglSwapBuffers", "SwapBuffers", "glfwSwapBuffers");
        bool hooks = Has("MH_CreateHook", "DetourAttach", "DetourTransactionBegin");
        if (Has("JNI_GetCreatedJavaVMs"))
        {
            bool client = drawsOver || hooks || Has("GetAsyncKeyState") || targetsGame;
            sign(client ? Severity.High : Severity.Low, RatCategory.CheatInjector,
                "Attaches to a running Java game",
                "It looks up the Java machine already running in the process it is loaded into - what a DLL client does to control Minecraft from inside." +
                (drawsOver ? " It also hooks the game's frame drawing, which is how such clients draw their menu over the game."
                 : hooks ? " It also carries a function-hooking library."
                 : client ? " It also reads keys or names the game." : " Nothing else here points at a game client, so this is context only."),
                "JNI_GetCreatedJavaVMs", "imports");
        }

        // Fake input in any language: Win32 calls, AutoHotkey commands, Python input libraries.
        bool fakesClicks = Has("SendInput", "mouse_event") ||
                           Has("PostMessage", "PostMessageA", "PostMessageW", "SendMessage", "SendMessageA", "SendMessageW") && Has("WM_LBUTTONDOWN", "WM_RBUTTONDOWN") ||
                           Has("MouseClick", "ControlClick") || Has("Click") && Has("LButton", "RButton") ||
                           Has("pyautogui", "pynput", "pydirectinput") && Has("click", "press");
        bool watchesKeys = Has("GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
                               "is_pressed", "on_press", "on_click", "Hotkey", "KeyWait");
        bool aboutClicks = strings.Any(s => System.Text.RegularExpressions.Regex.IsMatch(s.Text, @"(?i)\bcps\b|auto ?click|clicker|jitter|butterfly|clicks? per second"));
        if (fakesClicks && watchesKeys && (targetsGame || aboutClicks))
            sign(Severity.High, RatCategory.CheatClicker, "Autoclicker",
                "It watches the keyboard / mouse buttons and sends fake clicks" + (targetsGame ? ", and it targets the game." : ", and it talks about clicks per second / clicking."),
                "fake clicks (SendInput / mouse_event / posted button messages) + key polling", "imports");
    }

    /// <summary>Password-locked archive entries: nothing inside can be checked, which is the point when malware or cheats do it.</summary>
    static void Locked(RatContent c, Action<Severity, RatCategory, string, string, string, string> sign)
    {
        var programs = c.Locked.Where(l => Path.GetExtension(l.Name).ToLowerInvariant() is ".exe" or ".dll" or ".jar" or ".sys" or ".bat" or ".ps1" or ".scr").ToList();
        if (programs.Count == 0) return;
        sign(Severity.Medium, RatCategory.CheatLoader, "Programs locked behind a password",
            $"{programs.Count} program(s) in this archive are password-protected, so their code can't be checked by this tool or by antivirus. Cheat and malware downloads do this to avoid detection. Extract them with the password and check the files themselves.",
            string.Join(", ", programs.Take(15).Select(p => Path.GetFileName(p.Name))) + (programs.Count > 15 ? " …" : ""), "password-protected entries");
    }

    public static bool IsCheat(RatCategory c) => c is RatCategory.CheatCombat or RatCategory.CheatMovement or RatCategory.CheatClicker
        or RatCategory.CheatInjector or RatCategory.CheatLoader or RatCategory.CheatStructure;

    /// <summary>A signed program from a real publisher (an anticheat, a macro tool, a debugger) is not treated as a cheat for injecting or clicking.</summary>
    public static void TrustSigned(List<RatSign> signs)
    {
        for (int i = 0; i < signs.Count; i++)
            if (signs[i].Category is RatCategory.CheatInjector or RatCategory.CheatClicker && signs[i].Severity > Severity.Low)
                signs[i] = signs[i] with { Severity = Severity.Low, Why = signs[i].Why + " The file is validly signed by its publisher, so this is listed as context only." };
    }
}
