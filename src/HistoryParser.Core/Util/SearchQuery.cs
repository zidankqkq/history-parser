namespace HistoryParser.Core.Util;

/// <summary>
/// What is typed in a search box, read as words: every word must be in the row, and a word that starts with "!" must not
/// be. Quotes keep words together ("program files", !"program files"). Case is ignored.
/// <para>
/// The mark for "must not" is "!" and not "-": a "-" starts the arguments people search for here (-javaagent, -enc).
/// </para>
/// </summary>
public sealed class SearchQuery
{
    public static readonly SearchQuery Empty = new([], []);

    readonly string[] _wanted, _unwanted;

    SearchQuery(string[] wanted, string[] unwanted) => (_wanted, _unwanted) = (wanted, unwanted);

    /// <summary>Nothing typed: every row matches.</summary>
    public bool IsEmpty => _wanted.Length == 0 && _unwanted.Length == 0;

    /// <summary>
    /// Something is being looked for, as opposed to only being taken away. Lists that keep rows out of the way show them to
    /// a search that looks for something; a search that only takes rows away has no reason to bring them back.
    /// </summary>
    public bool Seeks => _wanted.Length > 0;

    public static SearchQuery Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return Empty;
        var wanted = new List<string>();
        var unwanted = new List<string>();
        int i = 0;
        while (i < text.Length)
        {
            if (char.IsWhiteSpace(text[i])) { i++; continue; }
            bool not = text[i] == '!';
            if (not) i++;
            string word;
            if (i < text.Length && text[i] == '"')
            {
                int close = text.IndexOf('"', i + 1);
                if (close < 0) close = text.Length;
                word = text[(i + 1)..close];
                i = Math.Min(close + 1, text.Length);
            }
            else
            {
                int start = i;
                while (i < text.Length && !char.IsWhiteSpace(text[i])) i++;
                word = text[start..i];
            }
            word = word.Trim();
            if (word.Length == 0) continue; // a lone "!" or empty quotes ask for nothing
            (not ? unwanted : wanted).Add(word.ToLowerInvariant());
        }
        return wanted.Count == 0 && unwanted.Count == 0 ? Empty : new SearchQuery(wanted.ToArray(), unwanted.ToArray());
    }

    /// <summary>Whether a row's text matches, whatever its case.</summary>
    public bool Matches(string text) => IsEmpty || MatchesLower(text.ToLowerInvariant());

    /// <summary>The same for text already in lower case (rows keep theirs ready, so a long list filters quickly).</summary>
    public bool MatchesLower(string lowerText)
    {
        foreach (var word in _wanted)
            if (!lowerText.Contains(word, StringComparison.Ordinal)) return false;
        foreach (var word in _unwanted)
            if (lowerText.Contains(word, StringComparison.Ordinal)) return false;
        return true;
    }
}
