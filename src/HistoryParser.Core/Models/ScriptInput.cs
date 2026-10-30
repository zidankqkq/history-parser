using System.Text.RegularExpressions;

namespace HistoryParser.Core.Models;

/// <summary>
/// A script that fakes mouse clicks or key presses while watching the keyboard: a clicker / macro that needs no file
/// on disk (pasted into PowerShell, or run from memory). Judged on what the script calls, never on its name.
///
/// Only a function that is declared or called counts, never one that is merely named: detection scripts, notes and
/// screenshare tools list these names as plain strings ('SendInput','mouse_event',...), and that is not a clicker.
/// </summary>
public static class ScriptInput
{
    public sealed record Verdict(bool High, string Title, string Why, int Index, int Length);

    /// <summary>
    /// The ways a script really uses a Windows function: declared for P/Invoke (extern ... name(, EntryPoint = "name",
    /// DefinePInvokeMethod('name'), looked up for a function pointer (GetProcAddress(..., 'name')), or called ([T]::name( / .name().
    /// </summary>
    static Regex Used(string names) => new(
        $@"\bextern\b[^;(){{}}]*?\b(?:{names})\s*\(|(?:::|\.)\s*(?:{names})\s*\(|EntryPoint\s*=\s*""(?:{names})""|" +
        $@"DefinePInvokeMethod\s*\(\s*['""](?:{names})['""]|GetProcAddress\s*\([^)]*?['""](?:{names})['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Making input: the Windows calls that inject it, or a window message that presses a mouse button.
    static readonly Regex FakeMouse = Used("mouse_event|SendInput");
    static readonly Regex MouseMessage = new(@"\b(Post|Send)Message[AW]?\s*\([^)\r\n]{0,200}?(0x0*20[1-4]\b|WM_[LR]BUTTON(DOWN|UP))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex FakeKeys = new(Used("keybd_event") + @"|\bSendKeys\]?::Send(Wait)?\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    // Watching the user: is a key / mouse button held, or a hook / hotkey on input.
    static readonly Regex Watch = Used("GetAsyncKeyState|GetKeyState|GetKeyboardState|SetWindowsHookEx[AW]?|RegisterHotKey");
    static readonly Regex RandomDelay = new(@"\bGet-Random\b|\[System\.Random\]|\bNew-Object\s+(System\.)?Random\b|\bRandom\]::new\b|\.Next(Double)?\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Null unless the script both makes input and watches for it (a clicker / macro).</summary>
    public static Verdict? Judge(string script)
    {
        if (script.Length < 20) return null;
        var mouse = FakeMouse.Match(script);
        if (!mouse.Success) mouse = MouseMessage.Match(script);
        var keys = mouse.Success ? Match.Empty : FakeKeys.Match(script);
        var make = mouse.Success ? mouse : keys;
        if (!make.Success || !Watch.IsMatch(script)) return null;
        bool random = RandomDelay.IsMatch(script);
        string what = mouse.Success ? "clicks the mouse" : "presses keys";
        return new Verdict(
            High: mouse.Success,
            Title: mouse.Success ? "Script autoclicker (no file)" : "Script key macro (no file)",
            Why: $"The script sets up Windows' input functions and {what} by itself ({make.Value.Trim()}) while checking which keys or " +
                 "buttons are held - how an autoclicker or macro works." +
                 (random ? " It also uses random numbers, which clickers use to vary the delay so it looks human." : "") +
                 " Run inside PowerShell, it leaves no program file behind.",
            Index: make.Index, Length: make.Length);
    }
}
