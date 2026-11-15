using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HistoryParser.Core.Models;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Analysis;

/// <summary>Size, SHA-256 and Authenticode status for files that still exist. Offline only.</summary>
public static class FileInspector
{
    const long MaxHashBytes = 256L * 1024 * 1024;

    public static bool ShouldInspect(FileRecord r)
    {
        if (r.Status != FileStatus.Exists || r.IsWindowsFile) return false;
        if (r.Type is FileType.Exe or FileType.Jar or FileType.Script) return true;
        // DLLs: only ones outside the real Program Files folders, where injected/cheat modules usually live. A folder
        // that is merely named "Program Files" somewhere else does not count.
        return r.Type == FileType.Dll && !RoutineFiles.InProgramFiles(r.Path);
    }

    public static void Inspect(FileRecord r)
    {
        try
        {
            var fi = new FileInfo(r.Path);
            r.Size = fi.Length;
            if (fi.Length <= MaxHashBytes)
            {
                using var fs = new FileStream(r.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                r.Sha256 = Convert.ToHexString(SHA256.HashData(fs));
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }

        if (r.Type is FileType.Exe or FileType.Dll)
        {
            var facts = SignatureTrust.Of(r.Path);
            r.Signature = Verify(r.Path);
            if (r.Signature is SignatureStatus.Signed or SignatureStatus.Invalid or SignatureStatus.Untrusted) r.Signer = SignerName(r.Path);
            LocalRoot(r, facts);
        }
        else
        {
            r.Signature = SignatureStatus.NotApplicable;
        }
    }

    /// <summary>
    /// A signature that Windows accepts only because of a root certificate someone added to this PC. Anyone with administrator
    /// rights can do that and then sign a program under any name; a real publisher's certificate never needs it.
    /// </summary>
    static void LocalRoot(FileRecord r, SignatureFacts facts)
    {
        if (facts.Status != SignatureStatus.Signed || facts.Root != SignerRoot.Local) return;
        bool imitates = facts.Signer is { } s && (s.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) || RoutineFiles.IsKnownPublisher(s));
        r.Signer = $"{facts.Signer ?? "unknown"} (certificate added to this PC)";
        r.Findings.Add(new Finding
        {
            Severity = imitates ? Severity.High : Severity.Low, Category = FindingCategory.AntiForensics,
            Title = imitates ? $"Signed as \"{facts.Signer}\" with a certificate added to this PC" : "Signed with a certificate only this PC trusts",
            Detail = $"{r.Name} carries a signature naming \"{facts.Signer}\", and Windows accepts it only because a root certificate was added to " +
                     "this PC's trusted list. That root is not Microsoft's and not on the list of roots Windows itself trusts. " +
                     (imitates ? "The real publisher's certificate never needs that, so this is a program made to look signed by them."
                               : "Developers and some companies sign their own tools this way; it also makes any program look signed."),
            Path = r.Path, TimeUtc = r.LastExecutionUtc,
        });
    }

    /// <summary>Signed means Windows accepts the signature now - inside the file, or through a catalog that is itself validly signed.</summary>
    public static SignatureStatus Verify(string path)
    {
        var facts = SignatureTrust.Of(path);
        // A signature vouched for only by a root certificate someone added to this PC is not a trusted signature: every
        // program in the suite that asks "is it signed" would otherwise take a self-made certificate as a publisher's.
        if (facts.Status == SignatureStatus.Signed && facts.Root == SignerRoot.Local) return SignatureStatus.Untrusted;
        // A file that is not there (or cannot be opened) used to read as an untrusted signature; keep that for callers that only ask "is it signed".
        return facts.Status == SignatureStatus.NotChecked ? SignatureStatus.Untrusted : facts.Status;
    }

    /// <summary>WinVerifyTrust's own result for the signature inside the file: 0 = valid.</summary>
    internal static uint VerifyRaw(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path,
        };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return unchecked((uint)result);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    /// <summary>
    /// Who signed it. A file signed through a catalog is named after whoever signed that catalog; only Microsoft's own
    /// catalogs read as <see cref="CatalogSigner"/>.
    /// </summary>
    public static string? SignerName(string path)
    {
        var facts = SignatureTrust.Of(path);
        if (!facts.ByCatalog) return facts.Signer;
        if (facts.Package) return $"{facts.Signer ?? "Unknown signer"} (app package)";
        return facts.Root == SignerRoot.Microsoft ? CatalogSigner : $"{facts.Signer ?? "Unknown signer"} (catalog-signed)";
    }

    public const string CatalogSigner = "Microsoft Windows (catalog-signed)";

    /// <summary>
    /// Whether the file's hash is listed in one of the security catalogs installed on this PC — how Windows
    /// signs most of its own files (wmplayer.exe, notepad.exe …) without a signature inside them. A catalog can be
    /// added by anyone with administrator rights, so being listed is not enough: see <see cref="SignatureTrust"/>.
    /// </summary>
    public static bool InWindowsCatalog(string path) => CatalogFor(path) != null;

    /// <summary>
    /// The catalog an app package carries for its own files (Store apps: Paint, Terminal, the Minecraft launcher), found by
    /// walking up from the file. Such programs have no signature inside them and are not in Windows' catalog store.
    /// </summary>
    internal static string? PackageCatalogFor(string path)
    {
        var dir = Path.GetDirectoryName(path);
        for (int up = 0; up < 8 && dir is { Length: > 3 }; up++, dir = Path.GetDirectoryName(dir))
        {
            string catalog = Path.Combine(dir, "AppxMetadata", "CodeIntegrity.cat");
            if (File.Exists(catalog)) return catalog;
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="path"/> is listed in <paramref name="catalog"/> with the contents it has now, and the catalog is
    /// validly signed. Checked by Windows against the file's own hash: the folder the file sits in plays no part.
    /// </summary>
    internal static bool ListedIn(string catalog, string path)
    {
        foreach (var algorithm in Algorithms)
        {
            IntPtr admin = CatalogSession(algorithm);
            if (admin == IntPtr.Zero) continue;
            IntPtr pHash = IntPtr.Zero, pInfo = IntPtr.Zero;
            try
            {
                using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (CatalogHash(admin, file) is not { } hash) continue;
                uint size = (uint)hash.Length;
                pHash = Marshal.AllocHGlobal((int)size);
                Marshal.Copy(hash, 0, pHash, (int)size);
                var info = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(), pcwszCatalogFilePath = catalog, pcwszMemberTag = Convert.ToHexString(hash),
                    pcwszMemberFilePath = path, pbCalculatedFileHash = pHash, cbCalculatedFileHash = size, hCatAdmin = admin,
                };
                pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                Marshal.StructureToPtr(info, pInfo, false);
                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = WTD_UI_NONE, fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_CATALOG, pFile = pInfo, dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                };
                var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                if (result == 0) return true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
            finally
            {
                if (pInfo != IntPtr.Zero) { Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pInfo); Marshal.FreeHGlobal(pInfo); }
                if (pHash != IntPtr.Zero) Marshal.FreeHGlobal(pHash);
            }
        }
        return false;
    }

    /// <summary>The catalog file that lists this file's hash, or null.</summary>
    internal static string? CatalogFor(string path)
    {
        foreach (var algorithm in Algorithms)
        {
            IntPtr admin = CatalogSession(algorithm);
            if (admin == IntPtr.Zero) continue;
            try
            {
                using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (CatalogHash(admin, file) is not { } hash) continue;
                var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, (uint)hash.Length, 0, IntPtr.Zero);
                if (catalog == IntPtr.Zero) continue;
                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (CryptCATCatalogInfoFromContext(catalog, ref info, 0) && !string.IsNullOrEmpty(info.wszCatalogFile)) return info.wszCatalogFile;
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        }
        return null;
    }

    /// <summary>The hashes catalogs list files under: SHA-256, then SHA-1 (null) for older catalogs.</summary>
    static readonly string?[] Algorithms = ["SHA256", null];

    // One session with Windows' catalog database per thread and hash, kept for the life of the thread. Opening a session
    // costs far more than the one lookup it used to be opened for, and a scan looks up thousands of files. A session is
    // only ever used by the thread that opened it.
    [ThreadStatic] static IntPtr _sha256Session;
    [ThreadStatic] static IntPtr _sha1Session;

    static IntPtr CatalogSession(string? algorithm)
    {
        ref IntPtr session = ref algorithm == null ? ref _sha1Session : ref _sha256Session;
        if (session == IntPtr.Zero && !CryptCATAdminAcquireContext2(out session, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) session = IntPtr.Zero;
        return session;
    }

    /// <summary>The file's hash the way a catalog lists it (Windows works it out, skipping the parts a signature may change), or null.</summary>
    static byte[]? CatalogHash(IntPtr session, Microsoft.Win32.SafeHandles.SafeFileHandle file)
    {
        var hash = new byte[64]; // room for any hash a catalog uses, so the file is read once
        uint size = (uint)hash.Length;
        if (!CryptCATAdminCalcHashFromFileHandle2(session, file, ref size, hash, 0) || size == 0 || size > hash.Length) return null;
        return hash.AsSpan(0, (int)size).ToArray();
    }
}
