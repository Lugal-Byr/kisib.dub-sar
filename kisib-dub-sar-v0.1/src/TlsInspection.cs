using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Kisib
{
    [DataContract] internal sealed class TlsChainEvidence
    {
        [DataMember] internal byte[] CertificateDer;
        [DataMember] internal string Status;
    }
    [DataContract] internal sealed class TlsObservation
    {
        [DataMember] internal string Id = Guid.NewGuid().ToString("N");
        [DataMember] internal string StartedUtc, FinishedUtc, Host, Endpoint, Outcome, Error, PolicyErrors, Protocol, CaptureError;
        [DataMember] internal bool CertificateObserved, Authenticated, Encrypted, Signed;
        [DataMember] internal byte[] LeafDer;
        [DataMember] internal TlsChainEvidence[] Chain = new TlsChainEvidence[0];
        [DataMember] internal string CatalogSha256;
        internal CertificateRecord Leaf { get { return LeafDer == null ? null : CertificateRecord.FromDer(LeafDer); } }
        internal string Report(IncidentCatalog catalog, IEnumerable<CertificateRecord> inventory)
        {
            StringBuilder text = new StringBuilder(); text.AppendLine("Manual TLS check [to test]: " + Host + ":443");
            text.AppendLine("Started UTC: " + StartedUtc + " | finished UTC: " + FinishedUtc);
            text.AppendLine("Connected endpoint: " + (Endpoint ?? "not observed")); text.AppendLine("Outcome: " + Outcome);
            text.AppendLine("Application making this connection: kisib.dub-sar. Browser acceptance: unknown [to test].");
            text.AppendLine("Windows SslStream authentication: " + (Authenticated ? "succeeded" : "did not succeed") + "; encrypted=" + Encrypted + "; signed=" + Signed);
            text.AppendLine("SslPolicyErrors: " + (PolicyErrors ?? "not returned") + " | protocol: " + (Protocol ?? "not negotiated"));
            text.AppendLine("Revocation checking requested: true. No reported revocation error is not proof of fresh online revocation data.");
            if (Error != null) text.AppendLine("Connection error: " + Error); if (CaptureError != null) text.AppendLine("Evidence capture error: " + CaptureError);
            CertificateRecord leaf = Leaf;
            if (leaf == null) text.AppendLine("Certificate identity: not observed. A failed connection is not proof a certificate was blocked.");
            else
            {
                text.AppendLine(); text.AppendLine("Presented certificate [to test]: " + leaf.SubjectShortName); text.AppendLine("Subject DN: " + leaf.Subject); text.AppendLine("Issuer DN: " + leaf.Issuer);
                text.AppendLine("Subject C= " + (leaf.SubjectCountry ?? "unknown") + " | issuer C= " + (leaf.IssuerCountry ?? "unknown") + " (certificate claims)");
                text.AppendLine("SHA-1: " + leaf.Sha1); text.AppendLine("SHA-256: " + leaf.Sha256); text.AppendLine("SPKI SHA-256: " + (leaf.SpkiSha256 ?? "unavailable"));
                text.AppendLine("Not-before: " + CertificateRecord.Time(leaf.NotBefore) + " | not-after: " + CertificateRecord.Time(leaf.NotAfter));
                if (catalog != null) text.AppendLine(catalog.HashReport(leaf.Sha256, inventory));
            }
            if (catalog != null)
            {
                CertificateIncident[] context = catalog.NamespaceMatches(Host);
                text.AppendLine("Historical namespace context: " + (context.Length == 0 ? "MISS in this catalog." : "HIT; this does not identify this certificate as unauthorized."));
                foreach (CertificateIncident incident in context) text.AppendLine(incident.Title + " | " + incident.Published + "\r\n" + incident.Source);
            }
            text.AppendLine("Returned chain elements: " + (Chain == null ? 0 : Chain.Length) + "; see Chain for each certificate and its own status.");
            text.AppendLine("Microsoft terms: SslStream.AuthenticateAsClient / RemoteCertificateValidationCallback / X509ChainStatusFlags [documented]. Custom observation and interpretation [to test].");
            text.AppendLine(IncidentSources.Tls); text.AppendLine(IncidentSources.Callback); text.AppendLine(IncidentSources.ChainStatus);
            return text.ToString();
        }
    }
    internal static class TlsInspection
    {
        internal static string NormalizeHost(string value)
        {
            if (value == null || value.Length > 253 || value.Any(c => Char.IsWhiteSpace(c) || Char.IsControl(c))) throw new ArgumentException("Enter a DNS hostname only, such as example.com.");
            string host;
            try
            {
                string name = value.EndsWith(".", StringComparison.Ordinal) ? value.Substring(0, value.Length - 1) : value;
                host = new IdnMapping { UseStd3AsciiRules = true }.GetAscii(name).ToLowerInvariant();
            }
            catch (ArgumentException) { throw new ArgumentException("Enter a complete DNS hostname; URLs, IP addresses, ports and wildcards are not accepted."); }
            IPAddress address;
            if (host.Length == 0 || host.Length > 253 || IPAddress.TryParse(host, out address) || host.IndexOf('.') < 0 ||
                host.Split('.').Any(label => label.Length < 1 || label.Length > 63 || label[0] == '-' || label[label.Length - 1] == '-' ||
                    label.Any(c => c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9')))) throw new ArgumentException("Enter a complete DNS hostname; URLs, IP addresses, ports and wildcards are not accepted.");
            return host;
        }
        internal static string RevocationSummary(X509ChainStatusFlags flags)
        {
            if ((flags & X509ChainStatusFlags.Revoked) != 0) return "Revoked reported for this element";
            if ((flags & (X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation)) != 0) return "Revocation unknown/offline for this element";
            return "No revocation error reported; freshness/source unknown";
        }
        internal static bool Accept(SslPolicyErrors errors, bool captured)
        { return captured && errors == SslPolicyErrors.None; }

        // The callback records the actual peer and actual Windows chain. It never clears policy errors.
        private sealed class Capture
        {
            private readonly object gate = new object(); private bool sealedResult;
            internal readonly TlsObservation Result;
            internal Capture(TlsObservation result) { Result = result; }
            internal bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
            {
                lock (gate)
                {
                    if (sealedResult) return false;
                    Result.PolicyErrors = errors.ToString();
                    try
                    {
                        if (certificate == null) return false;
                        byte[] der = certificate.GetRawCertData();
                        if (der.Length > 256 * 1024) throw new InvalidOperationException("Peer certificate exceeds the evidence size limit.");
                        Result.LeafDer = der; Result.CertificateObserved = true;
                        List<TlsChainEvidence> elements = new List<TlsChainEvidence>();
                        if (chain != null)
                        {
                            if (chain.ChainElements.Count > 64) throw new InvalidOperationException("Returned chain exceeds the evidence size limit.");
                            foreach (X509ChainElement element in chain.ChainElements)
                            {
                                byte[] bytes = element.Certificate.RawData;
                                if (bytes.Length > 256 * 1024) throw new InvalidOperationException("Chain certificate exceeds the evidence size limit.");
                                X509ChainStatusFlags flags = X509ChainStatusFlags.NoError;
                                foreach (X509ChainStatus state in element.ChainElementStatus) flags |= state.Status;
                                elements.Add(new TlsChainEvidence { CertificateDer = bytes, Status = flags + "; " + RevocationSummary(flags) });
                            }
                        }
                        Result.Chain = elements.ToArray();
                        return Accept(errors, true);
                    }
                    catch (Exception ex) { Result.CaptureError = ex.GetType().Name + ": " + ex.Message; return false; }
                }
            }
            internal void Seal() { lock (gate) { sealedResult = true; } }
        }
        private static void Wait(Task operation, CancellationToken cancellation, Stopwatch clock, int timeout)
        {
            cancellation.ThrowIfCancellationRequested(); int remaining = timeout - (int)Math.Min(Int32.MaxValue, clock.ElapsedMilliseconds);
            if (remaining <= 0) throw new TimeoutException("TLS check deadline reached.");
            if (!operation.Wait(remaining, cancellation)) throw new TimeoutException("TLS check deadline reached.");
            cancellation.ThrowIfCancellationRequested();
        }
        internal static TlsObservation Run(string host, CancellationToken cancellation)
        { string normalized = NormalizeHost(host); return RunEndpoint(normalized, normalized, 443, cancellation, 15000); }

        // Separate endpoint only for owned local verification. Product UI always connects to host:443.
        internal static TlsObservation RunEndpoint(string host, string connectHost, int port, CancellationToken cancellation, int timeout)
        {
            host = NormalizeHost(host);
            if (timeout < 50 || timeout > 60000 || port < 1 || port > 65535) throw new ArgumentOutOfRangeException("timeout/port");
            TlsObservation result = new TlsObservation { Host = host, StartedUtc = DateTime.UtcNow.ToString("o"), Outcome = "Not completed" };
            Capture capture = new Capture(result); Stopwatch clock = Stopwatch.StartNew();
            using (TcpClient client = new TcpClient())
            {
                SslStream stream = null;
                try
                {
                    cancellation.ThrowIfCancellationRequested();
                    Task connect = Task.Factory.FromAsync<string, int>(client.BeginConnect, client.EndConnect, connectHost, port, null);
                    Wait(connect, cancellation, clock, timeout);
                    result.Endpoint = client.Client.RemoteEndPoint.ToString();
                    stream = new SslStream(client.GetStream(), false, capture.Validate);
                    Task authenticate = Task.Factory.FromAsync((callback, state) => stream.BeginAuthenticateAsClient(host, new X509CertificateCollection(), SslProtocols.None, true, callback, state), stream.EndAuthenticateAsClient, null);
                    Wait(authenticate, cancellation, clock, timeout);
                    cancellation.ThrowIfCancellationRequested();
                    result.Authenticated = stream.IsAuthenticated; result.Encrypted = stream.IsEncrypted; result.Signed = stream.IsSigned; result.Protocol = stream.SslProtocol.ToString();
                    result.Outcome = result.Authenticated && result.Encrypted && result.Signed ? "Authenticated by Windows for this kisib connection" : "Authentication did not establish encrypted/signed TLS";
                }
                catch (OperationCanceledException) { result.Outcome = "Canceled; no completed authentication verdict"; }
                catch (TimeoutException ex) { result.Outcome = "Timed out; no completed authentication verdict"; result.Error = ex.Message; }
                catch (Exception ex) { result.Outcome = "Authentication/connection failed; inspect the returned evidence"; result.Error = ex.GetType().Name + ": " + ex.Message; }
                finally { capture.Seal(); if (stream != null) stream.Dispose(); client.Close(); result.FinishedUtc = DateTime.UtcNow.ToString("o"); }
            }
            return result;
        }
    }
}
