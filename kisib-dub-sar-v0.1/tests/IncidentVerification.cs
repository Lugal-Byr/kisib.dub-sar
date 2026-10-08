using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Kisib
{
    internal static class IncidentVerification
    {
        private static void Reject(Action action, Action<bool, string> check, string message)
        { bool rejected = false; try { action(); } catch (Exception ex) { if (!(ex is ArgumentException || ex is InvalidOperationException || ex is System.Runtime.Serialization.SerializationException)) throw; rejected = true; } check(rejected, message); }
        internal static void Run(string project, Action<bool, string> check)
        {
            IncidentCatalog catalog = IncidentCatalog.Read(project);
            check(catalog.Incidents.Length == 1 && catalog.Incidents[0].Hashes.Length == 0 && catalog.Sha256.Length == 64, "Primary incident seed does not invent certificate identities");
            check(catalog.NamespaceMatches("google.com.gh").Length == 1 && catalog.NamespaceMatches("GOOGLE.SL.").Length == 1 && catalog.NamespaceMatches("google.as").Length == 1, "Incident context matches exact DNS label suffixes with canonical casing");
            check(catalog.NamespaceMatches("google.gh.example.com").Length == 0 && catalog.NamespaceMatches("google.ghx").Length == 0 && catalog.NamespaceMatches("google.so").Length == 0, "Namespace matches reject lookalikes and do not confuse American Samoa with Somalia");
            check(TlsInspection.NormalizeHost("B\u00dcCHER.example.") == "xn--bcher-kva.example", "TLS hostname normalizes international DNS names for SNI and connection");
            foreach (string invalid in new string[] { "https://example.com", "example.com:443", "*.example.com", "127.0.0.1", "[::1]", "example.com/path", "example.com\r\nother", "-bad.example", "a..example", "example.com..", new string('a', 64) + ".example" })
                Reject(delegate { TlsInspection.NormalizeHost(invalid); }, check, "TLS input rejects " + invalid.Replace('\r', ' ').Replace('\n', ' '));
            string digest = new string('A', 64);
            check(IncidentCatalog.NormalizeHash(String.Join(":", Enumerable.Repeat("aa", 32).ToArray())) == digest && catalog.HashMatches(digest).Length == 0, "Complete certificate hash normalization keeps catalog misses visible");
            Reject(delegate { IncidentCatalog.NormalizeHash(new string('A', 40)); }, check, "SHA-1 is not accepted as certificate SHA-256");
            string miss = catalog.HashReport(digest, new CertificateRecord[0]);
            check(miss.Contains("MISS") && miss.Contains("absence is not a safety verdict") && miss.Contains("Listed hashes: 0"), "No source fingerprint is a bounded catalog miss, not a safe verdict");
            CertificateRecord fixture = CertificateRecord.FromDer(File.ReadAllBytes(Path.Combine(project, "tests", "fixture.cer")));
            IncidentCatalog synthetic = IncidentCatalog.Decode(HistoryArchive.Encode(catalog));
            synthetic.Incidents[0].Hashes = new IncidentHash[] { new IncidentHash { Sha256 = fixture.Sha256, Source = "https://example.test/owned-fixture", Date = "2026-10-07", Tag = "to test" } }; synthetic.Validate();
            string hit = synthetic.HashReport(fixture.Sha256, new CertificateRecord[] { fixture });
            check(synthetic.HashMatches(fixture.Sha256).Length == 1 && hit.Contains("HIT") && hit.Contains("Current inventory matches: 1") && hit.Contains("local enforcement remains separate"), "Exact certificate identity joins sources and inventory without inventing enforcement");
            check(catalog.Describe(catalog.Incidents[0]).Contains("Local browser result: unknown") && catalog.Describe(catalog.Incidents[0]).Contains("Namespace geography is separate"), "Browser vendor reports and registry geography remain separate from local results and certificate claims");
            Reject(delegate { IncidentCatalog.Decode(System.Text.Encoding.UTF8.GetBytes("null")); }, check, "Null incident catalog is unavailable, not a clean result");
            synthetic.Incidents[0].Hashes[0].Sha256 = "not-a-hash"; Reject(synthetic.Validate, check, "Malformed source certificate identity rejected");
            synthetic.Incidents[0].Hashes[0].Sha256 = fixture.Sha256; synthetic.Incidents[0].Source = "file:///C:/Windows/test"; Reject(synthetic.Validate, check, "Incident source refuses file or executable URLs");
            synthetic.Incidents[0].Source = catalog.Incidents[0].Source; synthetic.Incidents[0].Browsers[0].Tag = "verified on this PC"; Reject(synthetic.Validate, check, "Catalog cannot promote a vendor claim to verified local browser evidence");
            synthetic.Incidents[0].Browsers[0].Tag = "documented"; synthetic.Incidents[0].Hashes = Enumerable.Range(0, 10025).Select(n => new IncidentHash { Sha256 = n.ToString("X64"), Source = "https://example.test/synthetic-scale", Date = "2026-10-07", Tag = "to test" }).ToArray();
            IncidentCatalog large = IncidentCatalog.Decode(HistoryArchive.Encode(synthetic));
            check(large.Incidents[0].Hashes.Length == 10025 && large.HashMatches(10024.ToString("X64")).Length == 1, "Incident hash catalog handles 10025 source records without a 10000-item truncation");
            check(TlsInspection.Accept(SslPolicyErrors.None, true) && !TlsInspection.Accept(SslPolicyErrors.None, false) &&
                !TlsInspection.Accept(SslPolicyErrors.RemoteCertificateNameMismatch, true) && !TlsInspection.Accept(SslPolicyErrors.RemoteCertificateChainErrors, true) && !TlsInspection.Accept(SslPolicyErrors.RemoteCertificateNotAvailable, true), "TLS observation callback never bypasses certificate errors or missing evidence");
            check(TlsInspection.RevocationSummary(X509ChainStatusFlags.RevocationStatusUnknown).Contains("unknown") && TlsInspection.RevocationSummary(X509ChainStatusFlags.OfflineRevocation).Contains("unknown") &&
                TlsInspection.RevocationSummary(X509ChainStatusFlags.Revoked).Contains("Revoked") && TlsInspection.RevocationSummary(X509ChainStatusFlags.NoError).Contains("freshness/source unknown"), "Revoked, offline/unknown and no reported revocation error have distinct evidence meanings");
            using (CancellationTokenSource canceled = new CancellationTokenSource())
            { canceled.Cancel(); TlsObservation result = TlsInspection.Run("example.test", canceled.Token); check(result.Outcome.StartsWith("Canceled") && !result.CertificateObserved && !result.Authenticated && result.Endpoint == null, "Cancellation before connect creates no endpoint or certificate verdict"); }
            // Owned loopback peers only; no public Internet or trust-store writes in Test.cmd.
            SilentPeer(false, check); SilentPeer(true, check);
            TlsObservation observed = new TlsObservation { Host = "example.gh", StartedUtc = DateTime.UtcNow.ToString("o"), FinishedUtc = DateTime.UtcNow.ToString("o"), LeafDer = fixture.Der,
                CertificateObserved = true, Outcome = "Owned test observation", CatalogSha256 = catalog.Sha256, Chain = new TlsChainEvidence[] { new TlsChainEvidence { CertificateDer = fixture.Der, Status = "UntrustedRoot; fixture" } } };
            string report = observed.Report(catalog, new CertificateRecord[] { fixture });
            check(report.Contains("Historical namespace context: HIT") && report.Contains("does not identify this certificate as unauthorized") && report.Contains("Browser acceptance: unknown") && report.Contains("SslPolicyErrors: not returned"), "Presented certificate and historical namespace context do not imply unauthorized identity or browser acceptance");
            string directory = Path.Combine(Path.GetTempPath(), "kisib-tls-log-test-" + Guid.NewGuid().ToString("N"));
            try
            {
                using (HistoryArchive journal = new HistoryArchive(directory, false))
                {
                    check(journal.RecordTlsObservation(observed), "Journal durably appends manual TLS observation");
                    check(!Directory.Exists(Path.Combine(directory, "evidence")) && !Directory.Exists(Path.Combine(directory, "certificates")) && journal.JournalFiles().SelectMany(p => journal.Lines(p)).Any(line => line.Contains("manual_tls_observation") && line.Contains(fixture.Sha256)), "Journal-only TLS recording stores hash and outcome without public DER or evidence objects");
                }
                using (HistoryArchive archive = new HistoryArchive(directory, true))
                {
                    check(archive.RecordTlsObservation(observed), "Archive opt-in durably retains TLS evidence");
                    string evidence = Directory.GetFiles(Path.Combine(directory, "evidence"), "*.json").Single();
                    TlsObservation replay = HistoryArchive.Decode<TlsObservation>(File.ReadAllBytes(evidence));
                    check(replay.LeafDer.SequenceEqual(fixture.Der) && replay.Chain.Length == 1 && replay.CatalogSha256 == catalog.Sha256 && replay.Outcome == observed.Outcome, "Archived manual TLS evidence preserves exact peer DER, returned chain, time, catalog identity and result");
                }
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }
        private static void SilentPeer(bool cancel, Action<bool, string> check)
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            using (CancellationTokenSource cancellation = new CancellationTokenSource())
            using (ManualResetEvent release = new ManualResetEvent(false))
            {
                Exception failure = null; Thread server = new Thread(delegate()
                {
                    try { using (TcpClient peer = listener.AcceptTcpClient()) { if (cancel) cancellation.Cancel(); release.WaitOne(3000); } }
                    catch (SocketException) { } catch (ObjectDisposedException) { } catch (Exception ex) { failure = ex; }
                }); server.IsBackground = true; server.Start(); Stopwatch clock = Stopwatch.StartNew();
                TlsObservation observed = TlsInspection.RunEndpoint("example.test", "127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, cancellation.Token, cancel ? 3000 : 250);
                release.Set(); listener.Stop(); if (!server.Join(4000)) throw new TimeoutException("Owned TLS fixture failed to close."); if (failure != null) throw failure;
                check(clock.Elapsed.TotalSeconds < 5 && !observed.Authenticated && !observed.CertificateObserved && observed.Outcome.StartsWith(cancel ? "Canceled" : "Timed out"), cancel ? "TLS cancellation terminates an owned stalled handshake without a certificate verdict" : "TLS deadline terminates an owned stalled handshake without a block verdict");
            }
        }
    }
    // Called only in disposable hosted CI with a temporary private key created and removed there.
    public static class TlsPeerVerification
    {
        public static int Run(X509Certificate2 serverCertificate)
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); Exception serverError = null;
            Thread server = new Thread(delegate()
            {
                try { using (TcpClient peer = listener.AcceptTcpClient()) using (SslStream stream = new SslStream(peer.GetStream(), false)) stream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Tls12, false); }
                catch (AuthenticationException) { } catch (IOException) { } catch (Exception ex) { serverError = ex; }
            }); server.IsBackground = true; server.Start();
            try
            {
                TlsObservation observed = TlsInspection.RunEndpoint("kisib-untrusted.example", "127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, CancellationToken.None, 15000);
                if (observed.Authenticated || !observed.CertificateObserved || observed.Leaf == null || !observed.Leaf.Der.SequenceEqual(serverCertificate.RawData) ||
                    observed.PolicyErrors == null || !observed.PolicyErrors.Contains("RemoteCertificateChainErrors") || observed.Chain.Length == 0) throw new InvalidOperationException("Untrusted TLS peer was not captured and rejected with its actual Windows chain.");
                Console.WriteLine("PASS TLS peer: actual SslStream rejects owned untrusted certificate and retains exact peer DER and chain errors.");
                return 0;
            }
            catch (Exception ex) { Console.WriteLine("FAIL TLS peer: " + ex); return 1; }
            finally { listener.Stop(); if (!server.Join(20000)) throw new TimeoutException("Owned TLS server close deadline."); if (serverError != null) throw new InvalidOperationException("Owned TLS server failed.", serverError); }
        }
    }
}
