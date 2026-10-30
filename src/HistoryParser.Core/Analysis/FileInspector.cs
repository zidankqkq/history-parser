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
        // DLLs: only ones outside Program Files, where injected/cheat modules usually live.
        return r.Type == FileType.Dll && !r.Path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase);
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
            r.Signature = Verify(r.Path);
            if (r.Signature is SignatureStatus.Signed or SignatureStatus.Invalid or SignatureStatus.Untrusted) r.Signer = SignerName(r.Path);
        }
        else
        {
            r.Signature = SignatureStatus.NotApplicable;
        }
    }

    public static SignatureStatus Verify(string path)
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
            return unchecked((uint)result) switch
            {
                0 => SignatureStatus.Signed,
                // No signature inside the file: Windows signs most of its own files through catalogs instead.
                0x800B0100 or 0x800B0003 or 0x800B0001 => InWindowsCatalog(path) ? SignatureStatus.Signed : SignatureStatus.Unsigned,
                0x80096010 => SignatureStatus.Invalid,   // TRUST_E_BAD_DIGEST: contents no longer match the signature
                _ => SignatureStatus.Untrusted,          // expired, unknown root, revoked, distrusted …
            };
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    internal static string? SignerName(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            // The organisation (O=) names the company; the short name can be a product, e.g. ".NET" for Microsoft.
            var org = System.Text.RegularExpressions.Regex.Match(cert.Subject, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
            return org.Success ? org.Groups[1].Value.Trim().Trim('"') : cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (CryptographicException) { return InWindowsCatalog(path) ? CatalogSigner : null; }
    }

    public const string CatalogSigner = "Microsoft Windows (catalog-signed)";

    /// <summary>
    /// Whether the file's hash is listed in one of the security catalogs installed on this PC — how Windows
    /// signs most of its own files (wmplayer.exe, notepad.exe …) without a signature inside them.
    /// Only administrators and Windows itself can install catalogs.
    /// </summary>
    public static bool InWindowsCatalog(string path)
    {
        foreach (var algorithm in new[] { "SHA256", null }) // null = SHA-1, used by older catalogs
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
            try
            {
                using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, null, 0);
                if (size == 0 || size > 256) continue;
                var hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, hash, 0)) continue;
                var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                if (catalog == IntPtr.Zero) continue;
                CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                return true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }
        return false;
    }
}
