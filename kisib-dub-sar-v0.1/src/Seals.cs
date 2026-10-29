using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Kisib
{
    // Standard seals carried inside kisib.dub-sar.exe: the roots Windows ships with (Microsoft's "required trusted root
    // certificates" list) and the roots needed to get online (microsoft.com, Windows Update, the big certificate companies).
    // Repair puts these back without downloading anything. Each one is used only if its SHA-256 matches the pin below;
    // sources for every seal are in data\standard-seals.csv.
    internal sealed class Seal
    {
        internal string Name, Set, Purpose, Sha256, Sha1;
        internal byte[] Der;
        internal CertificateRecord Record;
        internal bool IsMicrosoft
        {
            get
            {
                string s = Record == null ? "" : Record.Subject ?? "";
                return s.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("O=MSFT", StringComparison.Ordinal) >= 0;
            }
        }
    }

    internal static class Seals
    {
        // SHA-256 of the certificate, which set it belongs to, and what it is for in plain words.
        private static readonly string[,] Pins =
        {
            { "F38406E540D7A9D90CB4A9479299640FFB6DF9E224ECC7A01C0D9558D8DAD77D", "windows", "older Windows files and drivers (signatures)" },
            { "885DE64C340E3EA70658F01E1145F957FCDA27AABEEA1AB9FAA9FDB0102D4077", "windows", "older Windows files and drivers (signatures)" },
            { "DF545BF919A2439C36983B54CDFC903DFA4F37D3996D8D84B4C31EEC6F3C163E", "windows", "Windows files, drivers and time stamps (signatures)" },
            { "847DF6A78497943F27FC72EB93F9A637320A02B561D0A91B09E87A7807ED7C61", "windows", "Windows Update, Defender, drivers, Microsoft Store" },
            { "6EF914723F089D2ADAFF98D470A3651CCF1768E559FBDCC0FAAA640AA12E5753", "windows", "old time stamps on signed files" },
            { "4898B1749717A594A2030F47C83C272BD14BAE3DCEB2EAE382174EF2EC1C75C9", "windows", "old signed programs" },
            { "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308", "windows", "old time stamps on signed files" },
            { "6B6C1E01F590F5AFC5FCF85CD0B9396884048659FC2C6D1170D68B045216C3FD", "windows", "old time stamps on signed files" },
            { "8A5E4881D42F7475E8EC3726FCD5E51884AA04DAA9FA7ADAC8CD26452CF885D4", "windows", "signed programs (Symantec for Microsoft)" },
            { "CACA93B9D23D2B6FA76E8B8471931E0DF3EC6F63AF3CDBB936C41954A1872326", "windows", "newer Windows files and drivers (ECC signatures)" },
            { "3FD4BE8BAAD2F26E1BDE06C7584BB720DD1A972D111F5A4999BC44B08FB4960D", "windows", "newer time stamps (ECC)" },
            { "65AF95F4BE86847344634282F941B2E605063EF0C8542F014CA088D182109E4F", "windows", "time stamps on signed files" },
            { "C741F70F4B2A8D88BF2E71C14122EF53EF10EBA0CFA5E64CFA20F418853073E0", "microsoft", "Microsoft websites and services (TLS)" },
            { "358DF39D764AF9E1B766E9C972DF352EE15CFAC227AF6AD1D70E8E4A6EDCBA02", "microsoft", "Microsoft websites and services (TLS, ECC)" },
            { "5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270", "microsoft", "programs signed through Microsoft's signing service (Trusted Signing)" },
            { "CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F", "online", "microsoft.com, Office, Microsoft sign-in, Defender cloud, most big sites" },
            { "4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161", "online", "many websites (DigiCert)" },
            { "31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0", "online", "Microsoft Azure and many websites (DigiCert ECC)" },
            { "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6", "online", "Let's Encrypt websites (codeberg, IVPN, most small sites)" },
            { "69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470", "online", "Let's Encrypt websites (ECC)" },
            { "E793C9B02FD8AA13E21C31228ACCB08119643B749C898964B1746D46C3D4CBD2", "online", "Sectigo websites, Steam" },
            { "EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99", "online", "GlobalSign websites, Google" },
            { "CBB522D7B7F127AD6A0113865BDF1CD4102E7D0759AF635A7CF4720DC963C53B", "online", "GlobalSign websites" },
            { "D947432ABDE7B7FA90FC2E6B59101B1280E0E1C7E4E40FA3C6887FFF57A7F4CF", "online", "Google websites" },
            { "8D25CD97229DBF70356BDA4EB3CC734031E24CF00FAFCFD32DC76EB5841C7EA8", "online", "Google websites" },
            { "34D8A73EE208D9BCDB0D956520934B4E40E69482596E8B6F73C8426B010A6F48", "online", "Google websites" },
            { "349DFA4058C5E263123B398AE795573C4E1313C83FE68F93556CD5E8031B3C7D", "online", "Google websites" },
            { "3E9099B5015E8F486C00BCEA9D111EE721FABA355A89BCF1DF69561E3DC6325C", "windows", "signed programs and time stamps (DigiCert, older)" },
            { "9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF", "windows", "signed programs and installers (Apple, Symantec code signing)" },
            { "2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C", "windows", "time stamps on signed installers (Symantec, Apple)" },
            { "552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988", "windows", "signed programs and installers (Apple, Defender, DigiCert code signing)" },
        };

        private static List<Seal> all;
        internal static string LoadError;

        internal static List<Seal> All
        {
            get
            {
                if (all != null) return all;
                List<Seal> list = new List<Seal>();
                try
                {
                    string text;
                    using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Kisib.seals.pem"))
                    {
                        if (s == null) { LoadError = "the seals are missing from this build"; return all = list; }
                        using (StreamReader r = new StreamReader(s, Encoding.ASCII)) text = r.ReadToEnd();
                    }
                    Dictionary<string, int> pin = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < Pins.GetLength(0); i++) pin[Pins[i, 0]] = i;
                    int at = 0;
                    while (true)
                    {
                        int start = text.IndexOf("-----BEGIN CERTIFICATE-----", at, StringComparison.Ordinal);
                        if (start < 0) break;
                        int end = text.IndexOf("-----END CERTIFICATE-----", start, StringComparison.Ordinal);
                        if (end < 0) break;
                        at = end + 25;
                        byte[] der;
                        try { der = Convert.FromBase64String(text.Substring(start + 27, end - start - 27)); } catch (FormatException) { continue; }
                        string sha256;
                        using (SHA256 h = SHA256.Create()) sha256 = CertificateRecord.Hex(h.ComputeHash(der));
                        int k;
                        if (!pin.TryGetValue(sha256, out k)) continue;   // not pinned: never used
                        try
                        {
                            CertificateRecord rec = CertificateRecord.FromDer(der);
                            list.Add(new Seal { Name = rec.SubjectShortName, Set = Pins[k, 1], Purpose = Pins[k, 2], Sha256 = sha256, Sha1 = rec.Sha1, Der = der, Record = rec });
                        }
                        catch (Exception ex) { LoadError = (LoadError == null ? "" : LoadError + "; ") + ex.Message; }
                    }
                    if (list.Count != Pins.GetLength(0)) LoadError = list.Count + " of " + Pins.GetLength(0) + " seals matched their pins";
                }
                catch (Exception ex) { LoadError = ex.Message; }
                return all = list;
            }
        }

        internal static Seal ByName(string name)
        { return All.FirstOrDefault(s => String.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase) || (s.Record != null && String.Equals(s.Record.SubjectCn, name, StringComparison.OrdinalIgnoreCase))); }

        internal static Seal BySha1(string sha1)
        { return All.FirstOrDefault(s => String.Equals(s.Sha1, sha1, StringComparison.OrdinalIgnoreCase)); }
    }
}
