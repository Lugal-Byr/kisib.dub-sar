using System;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kisib
{
    [DataContract] internal sealed class ApplicationSignature
    {
        [DataMember] internal string ApplicationKey;
        [DataMember] internal string Executable;
        [DataMember] internal string ObservedUtc;
        [DataMember] internal string FileSha256;
        [DataMember] internal long FileBytes;
        [DataMember] internal string ModifiedUtc;
        [DataMember] internal string SignerSha256;
        [DataMember] internal string SignerSubject;
        [DataMember] internal string SignerIssuer;
        [DataMember] internal string Error;
        [DataMember] internal string Verification = "Not evaluated; embedded signer metadata only";
        internal CertificateRecord Certificate;
        internal static ApplicationSignature Read(ApplicationRecord app)
        {
            ApplicationSignature result = new ApplicationSignature { ApplicationKey = app.Key, Executable = app.Executable, ObservedUtc = DateTime.UtcNow.ToString("o") };
            try
            {
                ApplicationRecord live = ApplicationRecord.Find((uint)app.ProcessId);
                if (live == null || live.Key != app.Key || live.Executable == null || !String.Equals(live.Executable, app.Executable, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Process lifetime/path cannot be confirmed; embedded signer was not read.");
                using (FileStream file = new FileStream(app.Executable, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (SHA256 hash = SHA256.Create())
                {
                    result.FileBytes = file.Length; result.ModifiedUtc = File.GetLastWriteTimeUtc(app.Executable).ToString("o");
                    result.FileSha256 = CertificateRecord.Hex(hash.ComputeHash(file));
                    using (X509Certificate signer = X509Certificate.CreateFromSignedFile(app.Executable))
                    {
                        result.Certificate = CertificateRecord.FromDer(signer.GetRawCertData());
                        result.SignerSha256 = result.Certificate.Sha256; result.SignerSubject = result.Certificate.Subject; result.SignerIssuer = result.Certificate.Issuer;
                        CertificateSignals.Evaluate(new CertificateRecord[] { result.Certificate });
                    }
                }
            }
            catch (Exception ex) { result.Error = ex.GetType().Name + ": " + ex.Message + "; catalog-only signatures and unsupported files require separate verification."; }
            return result;
        }
        internal string Describe()
        {
            return "Application lifetime: " + ApplicationKey + "\r\nObserved file: " + Executable + "\r\nObserved UTC: " + ObservedUtc +
                "\r\nFile SHA-256: " + FileSha256 + "\r\nBytes: " + FileBytes + " | modified UTC: " + ModifiedUtc +
                "\r\nEmbedded signer Subject: " + (SignerSubject ?? "Unavailable") + "\r\nEmbedded signer Issuer: " + SignerIssuer +
                "\r\nSigner certificate SHA-256: " + SignerSha256 + "\r\nSignature/chain verification: " + Verification +
                "\r\nObservation errors: " + Error + "\r\n\r\nMicrosoft: X509Certificate.CreateFromSignedFile / GetRawCertData [documented]; file-to-process binding and extraction coverage [to test].\r\n" +
                "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.createfromsignedfile";
        }
    }
}
