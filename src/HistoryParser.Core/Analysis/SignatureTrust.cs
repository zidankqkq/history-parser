using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Analysis;

/// <summary>
/// Who vouches for a signature. Microsoft = the chain ends in Microsoft's own root (checked by Windows' own policy, not by
/// a name). Program = it ends in a root on the list of trusted roots Microsoft signs and Windows downloads. Local = it ends
/// in a root that is trusted only because someone added it to this PC. Unknown = it could not be worked out.
/// </summary>
public enum SignerRoot { None, Microsoft, Program, Local, Unknown }

public sealed record SignatureFacts(SignatureStatus Status, string? Signer, SignerRoot Root, bool ByCatalog)
{
    /// <summary>Signed, valid, and the signer is Microsoft itself.</summary>
    public bool IsMicrosoft => Status == SignatureStatus.Signed && Root == SignerRoot.Microsoft;

    /// <summary>Signed through the catalog of the app package the file belongs to (a Store app), not one of Windows' own catalogs.</summary>
    public bool Package { get; init; }
}

/// <summary>
/// One answer per file to "is it signed, by whom, and who vouches for that". The name on a certificate proves nothing by
/// itself: anyone with administrator rights can add their own root certificate and sign a program as "Microsoft Corporation",
/// and Windows will call that signature valid. So nothing in the suite trusts a signer by name - only by where its chain ends.
/// Offline: nothing is downloaded and no revocation list is fetched.
/// </summary>
public static class SignatureTrust
{
    static readonly ConcurrentDictionary<string, SignatureFacts> Files = new(StringComparer.OrdinalIgnoreCase);
    static readonly ConcurrentDictionary<string, (string? Signer, SignerRoot Root)> Signers = new(StringComparer.Ordinal);
    static readonly ConcurrentDictionary<string, SignatureFacts> Catalogs = new(StringComparer.OrdinalIgnoreCase);

    static readonly SignatureFacts Missing = new(SignatureStatus.NotChecked, null, SignerRoot.None, false);
    static readonly SignatureFacts NotSigned = new(SignatureStatus.Unsigned, null, SignerRoot.None, false);

    /// <summary>Reads the file. Remembered per file as it is now (path, size and modified time), so a replaced file is checked again.</summary>
    public static SignatureFacts Of(string path)
    {
        string key;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return Missing;
            key = $"{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return Missing; }
        return Files.GetOrAdd(key, _ => Check(path));
    }

    static SignatureFacts Check(string path)
    {
        try
        {
            switch (FileInspector.VerifyRaw(path))
            {
                case 0:
                    var (signer, root) = Signer(path);
                    return new SignatureFacts(SignatureStatus.Signed, signer, root, false);
                // No signature inside the file: Windows signs most of its own files through catalogs instead.
                case 0x800B0100 or 0x800B0003 or 0x800B0001:
                    if (FileInspector.CatalogFor(path) is { } catalog) return Catalogs.GetOrAdd(catalog, Catalog);
                    // An app package signs its files through a catalog of its own. The file's hash has to be in it.
                    if (FileInspector.PackageCatalogFor(path) is { } package && FileInspector.ListedIn(package, path))
                        return Catalogs.GetOrAdd(package, Catalog) with { Package = true };
                    return NotSigned;
                case 0x80096010: // TRUST_E_BAD_DIGEST: contents no longer match the signature
                    return new SignatureFacts(SignatureStatus.Invalid, Signer(path).Signer, SignerRoot.None, false);
                default:         // expired, unknown root, revoked, distrusted …
                    return new SignatureFacts(SignatureStatus.Untrusted, Signer(path).Signer, SignerRoot.None, false);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
        {
            return new SignatureFacts(SignatureStatus.NotChecked, null, SignerRoot.Unknown, false);
        }
    }

    /// <summary>A catalog only counts when the catalog file itself is validly signed: anyone with administrator rights can add a catalog.</summary>
    static SignatureFacts Catalog(string catalogFile)
    {
        if (FileInspector.VerifyRaw(catalogFile) != 0) return NotSigned;
        var (signer, root) = Signer(catalogFile);
        return new SignatureFacts(SignatureStatus.Signed, signer, root, true);
    }

    static (string? Signer, SignerRoot Root) Signer(string signedFile)
    {
        X509Certificate2 leaf;
        try
        {
#pragma warning disable SYSLIB0057 // the loader that replaces this cannot read the certificate out of a signed program
            leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
        }
        catch (CryptographicException) { return (null, SignerRoot.Unknown); }
        using (leaf)
        {
            if (Signers.TryGetValue(leaf.Thumbprint, out var known)) return known;
            var worked = (Organisation(leaf), RootOf(leaf, signedFile));
            // Remembered per certificate only once its chain was followed to the end. A file that does not carry the
            // certificates in between leaves the root unknown, and that must not stand for the signer's other files.
            if (worked.Item2 != SignerRoot.Unknown) Signers[leaf.Thumbprint] = worked;
            return worked;
        }
    }

    /// <summary>The organisation (O=) names the company; the short name can be a product, e.g. ".NET" for Microsoft.</summary>
    static string Organisation(X509Certificate2 cert)
    {
        var org = System.Text.RegularExpressions.Regex.Match(cert.Subject, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
        return org.Success ? org.Groups[1].Value.Trim().Trim('"') : cert.GetNameInfo(X509NameType.SimpleName, false);
    }

    static SignerRoot RootOf(X509Certificate2 leaf, string signedFile)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        // A signing certificate expires long before the programs it signed stop being used; Windows already judged the
        // (timestamped) signature. Here only where the chain ends matters.
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        var extra = new X509Certificate2Collection();
        try
        {
#pragma warning disable SYSLIB0057 // the certificates between signer and root travel inside the signature
            extra.Import(signedFile);
#pragma warning restore SYSLIB0057
            chain.ChainPolicy.ExtraStore.AddRange(extra);
        }
        catch (CryptographicException) { }
        try
        {
            chain.Build(leaf);
            if (chain.ChainElements.Count == 0) return SignerRoot.Unknown;
            if (chain.ChainStatus.Any(s => (s.Status & (X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.UntrustedRoot)) != 0))
                return SignerRoot.Unknown;
            if (EndsInMicrosoftRoot(chain.ChainContext))
                // Microsoft also signs for others under its own roots: other companies' drivers (hardware compatibility,
                // attestation) and other publishers' Store apps. That says the file went through Microsoft's programme, not
                // that Microsoft made it - so "Microsoft" needs Microsoft named as the organisation on a Microsoft chain.
                return IsThirdPartyAttested(leaf) || !leaf.Subject.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
                    ? SignerRoot.Program : SignerRoot.Microsoft;
            return ProgramRoots.Contains(chain.ChainElements[^1].Certificate.Thumbprint) switch
            {
                true => SignerRoot.Program,
                false => SignerRoot.Local,
                null => SignerRoot.Unknown,
            };
        }
        catch (CryptographicException) { return SignerRoot.Unknown; }
        finally
        {
            foreach (var c in extra) c.Dispose();
        }
    }

    /// <summary>How the answer for one signed file (or catalog) was reached, for checking this class against a real PC.</summary>
    internal static string Diagnose(string signedFile)
    {
        var text = new System.Text.StringBuilder($"verify=0x{FileInspector.VerifyRaw(signedFile):X8} catalog={FileInspector.CatalogFor(signedFile) ?? "none"} programRoots={ProgramRoots.Count} {ProgramRoots.Note}");
        try
        {
#pragma warning disable SYSLIB0057
            using var leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
            var extra = new X509Certificate2Collection();
            try { extra.Import(signedFile); } catch (CryptographicException e) { text.Append($" import-failed={e.Message}"); }
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            chain.ChainPolicy.ExtraStore.AddRange(extra);
            bool built = chain.Build(leaf);
            text.Append($" extra={extra.Count} built={built} status=[{string.Join(",", chain.ChainStatus.Select(s => s.Status))}] microsoftRoot={EndsInMicrosoftRoot(chain.ChainContext)}");
            foreach (var element in chain.ChainElements) text.Append($"\n    {element.Certificate.Subject} [{element.Certificate.Thumbprint}]");
        }
        catch (CryptographicException e) { text.Append($" no-certificate={e.Message}"); }
        return text.ToString();
    }

    /// <summary>Windows' own test for "this chain ends in a Microsoft root" (product and application roots; never test roots).</summary>
    static bool EndsInMicrosoftRoot(IntPtr chainContext)
    {
        if (chainContext == IntPtr.Zero) return false;
        // Asked twice: without the flag Windows accepts its product roots (what Windows itself is signed with), with it the
        // application root (what Microsoft's other products are signed with). Each call accepts only its own kind.
        foreach (uint flags in new[] { 0u, MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG })
        {
            var para = new CERT_CHAIN_POLICY_PARA { cbSize = (uint)Marshal.SizeOf<CERT_CHAIN_POLICY_PARA>(), dwFlags = flags };
            var status = new CERT_CHAIN_POLICY_STATUS { cbSize = (uint)Marshal.SizeOf<CERT_CHAIN_POLICY_STATUS>() };
            if (CertVerifyCertificateChainPolicy((IntPtr)CERT_CHAIN_POLICY_MICROSOFT_ROOT, chainContext, ref para, ref status) && status.dwError == 0) return true;
        }
        return false;
    }

    static bool IsThirdPartyAttested(X509Certificate2 leaf)
    {
        if (leaf.Subject.Contains("Hardware Compatibility", StringComparison.OrdinalIgnoreCase) ||
            leaf.Subject.Contains("Third Party", StringComparison.OrdinalIgnoreCase) ||
            leaf.Issuer.Contains("Third Party", StringComparison.OrdinalIgnoreCase)) return true;
        // 1.3.6.1.4.1.311.10.3.5 = hardware compatibility (WHQL), .5.1 = attestation-signed driver.
        return leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>())
            .Any(o => o.Value is "1.3.6.1.4.1.311.10.3.5" or "1.3.6.1.4.1.311.10.3.5.1");
    }

    /// <summary>
    /// The roots Windows trusts because Microsoft's root programme lists them, read from the list Windows keeps in the
    /// registry. The list is signed by Microsoft and that signature is checked here, so adding a root to this PC (or
    /// editing the stored list) does not put it on this list.
    /// </summary>
    static class ProgramRoots
    {
        static readonly Lazy<HashSet<string>?> Thumbprints = new(Load);

        /// <summary>Null when the list is not on this PC or could not be verified.</summary>
        public static bool? Contains(string thumbprint) => Thumbprints.Value?.Contains(thumbprint);

        public static int Count => Thumbprints.Value?.Count ?? -1;

        /// <summary>Why the list could not be used, when it could not.</summary>
        public static string Note { get; private set; } = "";

        static HashSet<string>? Load()
        {
            byte[]? encoded;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate");
                encoded = key?.GetValue("EncodedCtl") as byte[];
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { Note = "registry unreadable"; return null; }
            if (encoded == null || encoded.Length < 1024) { Note = "no list stored on this PC"; return null; }

            IntPtr ctl = CertCreateCTLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, encoded, encoded.Length);
            if (ctl == IntPtr.Zero) { Note = $"list could not be parsed (error {Marshal.GetLastWin32Error()})"; return null; }
            try
            {
                // CTL_CONTEXT (x64): pCtlInfo +24, hCertStore +32, hCryptMsg +40.
                IntPtr info = Marshal.ReadIntPtr(ctl, 24), message = Marshal.ReadIntPtr(ctl, 40);
                if (info == IntPtr.Zero || message == IntPtr.Zero) { Note = "list has no content"; return null; }
                if (!SignedByMicrosoft(message, encoded)) { Note = "list is not validly signed by Microsoft: " + Note; return null; }
                // CTL_INFO (x64): cCTLEntry +96, rgCTLEntry +104; CTL_ENTRY is 32 bytes: SubjectIdentifier { cbData +0, pbData +8 }.
                int count = Marshal.ReadInt32(info, 96);
                IntPtr entries = Marshal.ReadIntPtr(info, 104);
                if (count is < 20 or > 20_000 || entries == IntPtr.Zero) { Note = $"list has {count} entries"; return null; }
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < count; i++)
                {
                    IntPtr entry = entries + i * 32;
                    int length = Marshal.ReadInt32(entry, 0);
                    IntPtr data = Marshal.ReadIntPtr(entry, 8);
                    if (length != 20 || data == IntPtr.Zero) continue; // the list names each root by its SHA-1
                    var hash = new byte[20];
                    Marshal.Copy(data, hash, 0, 20);
                    set.Add(Convert.ToHexString(hash));
                }
                return set.Count >= 20 ? set : null;
            }
            finally { CertFreeCTLContext(ctl); }
        }

        static bool SignedByMicrosoft(IntPtr message, byte[] encoded)
        {
            if (!CryptMsgGetAndVerifySigner(message, 0, IntPtr.Zero, 0, out var signerContext, IntPtr.Zero) || signerContext == IntPtr.Zero)
            {
                Note = $"signature does not verify (error 0x{Marshal.GetLastWin32Error():X})";
                return false;
            }
            try
            {
                using var signer = new X509Certificate2(signerContext);
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                // The certificate between the list's signer and Microsoft's root travels inside the list itself.
                var carried = new X509Certificate2Collection();
                try
                {
#pragma warning disable SYSLIB0057
                    carried.Import(encoded);
#pragma warning restore SYSLIB0057
                    chain.ChainPolicy.ExtraStore.AddRange(carried);
                }
                catch (CryptographicException) { }
                chain.Build(signer);
                bool ok = chain.ChainElements.Count > 1 &&
                          !chain.ChainStatus.Any(s => (s.Status & (X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.UntrustedRoot)) != 0) &&
                          EndsInMicrosoftRoot(chain.ChainContext);
                if (!ok) Note = $"signer {signer.Subject} chain [{string.Join(" > ", chain.ChainElements.Select(e => e.Certificate.GetNameInfo(X509NameType.SimpleName, false)))}] status [{string.Join(",", chain.ChainStatus.Select(s => s.Status))}]";
                return ok;
            }
            catch (CryptographicException e) { Note = e.Message; return false; }
            finally { CertFreeCertificateContext(signerContext); }
        }
    }
}
