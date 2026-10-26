using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;
using X509Location = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Kisib
{
    // "root not trusted (not your block)": Windows needed a root it doesn't have and couldn't download it.
    // kisib asks Windows Update for Microsoft's current root list (certutil -generateSSTFromWU, which checks it
    // against Microsoft's signed authroot.stl) and puts just that root into Trusted Root — what Windows itself
    // would have downloaded. Only roots on Microsoft's list; a root you blocked stays blocked.
    internal sealed partial class ExplorerForm
    {
        private bool fetchingRoots;

        // The name of the root a refusal was missing: the top of the logged chain if it is a root, else its issuer.
        internal string MissingRootName(Denial d)
        {
            CertificateRecord top = d.ChainSha1.Count == 0 || snapshot == null ? null : snapshot.BySha1(d.ChainSha1[d.ChainSha1.Count - 1]);
            if (top != null) return top.Subject == top.Issuer ? top.SubjectShortName : top.IssuerShortName;
            return d.ChainNames.Count > 0 && d.ChainNames[d.ChainNames.Count - 1].Length > 0 ? d.ChainNames[d.ChainNames.Count - 1] : "the missing root";
        }

        internal void FetchRoot(Denial d)
        {
            List<string> sha1s = new List<string>(d.ChainSha1);
            CertificateRecord top = sha1s.Count == 0 || snapshot == null ? null : snapshot.BySha1(sha1s[sha1s.Count - 1]);
            string issuerDn = top != null && top.Subject != top.Issuer ? top.Issuer : null, issuerKey = top == null ? null : top.AuthorityKeyId;
            if (sha1s.Count == 0)
            {
                Say("Windows didn't log the chain for " + d.Subject + ", so kisib can't tell which root is missing. Repair > What this PC uses lists the roots behind recent refusals.");
                return;
            }
            FetchFromMicrosoft(delegate(CertificateRecord c)
            {
                return sha1s.Contains(c.Sha1, StringComparer.OrdinalIgnoreCase) || (issuerDn != null && c.Subject == issuerDn && (issuerKey == null || c.SubjectKeyId == issuerKey));
            }, MissingRootName(d));
        }

        internal void FetchFromMicrosoft(Func<CertificateRecord, bool> wanted, string label)
        {
            if (fetchingRoots) { Say("Already getting roots from Microsoft; one moment."); return; }
            fetchingRoots = true;
            Say("Getting " + label + " from Microsoft's root list (certutil asks Windows Update, up to a minute)...");
            bool elevated = Elevation.IsElevated;
            Thread worker = new Thread(delegate()
            {
                List<byte[]> found = new List<byte[]>();
                string error = null, folder = null;
                try
                {
                    folder = PrivateFolder(elevated);
                    string sst = Path.Combine(folder, "roots.sst");
                    error = MicrosoftList.Generate(sst);
                    if (error == null)
                    {
                        X509Certificate2Collection roots = new X509Certificate2Collection();
                        roots.Import(sst);
                        foreach (X509Certificate2 x in roots)
                        {
                            CertificateRecord c = CertificateRecord.FromDer(x.RawData);
                            if (c != null && c.Subject == c.Issuer && wanted(c)) found.Add(x.RawData);
                        }
                    }
                }
                catch (Exception ex) { error = ex.GetType().Name + ": " + ex.Message; }
                finally { try { if (folder != null) Directory.Delete(folder, true); } catch (Exception) { } }
                Post(delegate { fetchingRoots = false; FinishFetch(found, error, label, elevated); });
            });
            worker.IsBackground = true; worker.Name = "kisib root from Microsoft"; worker.Start();
        }

        private void FinishFetch(List<byte[]> found, string error, string label, bool elevated)
        {
            if (error != null)
            {
                string first = error.Split('\r', '\n').FirstOrDefault(l => l.Trim().Length > 0) ?? error;
                Say("Couldn't get Microsoft's root list: " + first + (RootAutoUpdateOff() ? " Windows' automatic root download is switched off on this PC too (policy DisableRootAutoUpdate)." : " A VPN or firewall blocking certutil can cause this."));
                return;
            }
            if (found.Count == 0) { Say("Microsoft's list doesn't have " + label + " as a trusted root, so kisib won't add it."); return; }
            List<string> added = new List<string>(), problems = new List<string>();
            foreach (byte[] der in found)
            {
                CertificateRecord c = CertificateRecord.FromDer(der);
                CertificateRecord onPc = snapshot == null ? null : snapshot.BySha1(c.Sha1);
                if (onPc != null && snapshot.IsBlocked(onPc)) { problems.Add(c.SubjectShortName + " is blocked by you, so it stays out (Allow or Unblock it first)"); continue; }
                try
                {
                    if (elevated)
                    {
                        using (OwnStore root = OwnStore.Open("Root", X509Location.LocalMachine, true)) root.Add(der);
                        BlockEngine.Note("trust-from-microsoft", X509Location.LocalMachine, c.Sha256, c.Sha1, c.SubjectShortName, "root from Microsoft's list (certutil -generateSSTFromWU)");
                    }
                    else
                    {
                        // This user only. Windows shows its own "install this root?" question here.
                        using (X509Store store = new X509Store(StoreName.Root, X509Location.CurrentUser)) { store.Open(OpenFlags.ReadWrite); store.Add(new X509Certificate2(der)); }
                        BlockEngine.Note("trust-from-microsoft", X509Location.CurrentUser, c.Sha256, c.Sha1, c.SubjectShortName, "root from Microsoft's list (certutil -generateSSTFromWU)");
                    }
                    added.Add(c.SubjectShortName);
                }
                catch (Exception ex) { problems.Add(c.SubjectShortName + ": " + ex.Message); }
            }
            Say((added.Count > 0 ? "Put into Trusted Root (" + (elevated ? "whole PC" : "this user; run kisib as administrator for services like lsass") + "): " + String.Join(", ", added.ToArray()) + ". Try it again now." : "Nothing was added.") +
                (problems.Count > 0 ? " " + String.Join("; ", problems.ToArray()) + "." : ""));
            if (added.Count > 0) StartScan();
        }

        // A folder only administrators can write, so nothing can swap the list between certutil and kisib.
        private static string PrivateFolder(bool elevated)
        {
            string path = Path.Combine(Path.GetTempPath(), "kisib-roots-" + Guid.NewGuid().ToString("N"));
            if (!elevated) { Directory.CreateDirectory(path); return path; }
            DirectorySecurity rules = new DirectorySecurity();
            rules.SetAccessRuleProtection(true, false);
            InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            rules.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            rules.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(path, rules);
            return path;
        }

        // Windows can be told never to download roots on its own; then every missing root stays missing.
        internal static bool RootAutoUpdateOff()
        {
            foreach (string key in new string[] { @"SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot", @"SOFTWARE\Microsoft\SystemCertificates\AuthRoot" })
            {
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(key))
                    {
                        object v = k == null ? null : k.GetValue("DisableRootAutoUpdate");
                        if (v is int && (int)v != 0) return true;
                    }
                }
                catch (Exception) { }
            }
            return false;
        }
    }
}
