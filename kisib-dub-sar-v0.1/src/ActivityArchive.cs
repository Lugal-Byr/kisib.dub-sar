using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace Kisib
{
    internal sealed class ActivityPage
    {
        internal ActivityRecord[] Records;
        internal bool More;
        internal string Coverage;
    }
    internal static class ActivityArchive
    {
        internal static ActivityPage Certificates(HistoryArchive history, string journal, int page)
        {
            if (!history.JournalFiles().Contains(journal, StringComparer.Ordinal) || page < 0) throw new InvalidOperationException("Select a retained activity date and page.");
            List<ActivityRecord> rows = new List<ActivityRecord>(); int skip = checked(page * 500), matched = 0; bool more = false;
            {
                foreach (string line in history.Lines(journal))
                {
                    HistoryEvent entry;
                    try { entry = HistoryArchive.Decode<HistoryEvent>(Encoding.UTF8.GetBytes(line)); }
                    catch (SerializationException) { continue; } // unreadable originals remain visible in the main History log
                    if (entry == null || entry.Action != "application_certificate_activity") continue;
                    if (matched++ < skip) continue;
                    if (rows.Count == 500) { more = true; break; }
                    try
                    {
                        if (entry.EvidenceObject == null || !System.Text.RegularExpressions.Regex.IsMatch(entry.EvidenceObject, "^[A-F0-9]{64}(?:-[A-F0-9]{128})?$"))
                            throw new InvalidOperationException("Invalid retained activity reference.");
                        byte[] bytes = history.ReadObjectBytes(Path.Combine(history.DirectoryPath, "evidence", entry.EvidenceObject + ".json"), HistoryArchive.EvidenceByteLimit);
                        using (SHA256 hash = SHA256.Create()) if (CertificateRecord.Hex(hash.ComputeHash(bytes)) != entry.EvidenceObject.Substring(0, 64)) throw new InvalidOperationException("Retained activity integrity mismatch.");
                        ActivityRecord activity = HistoryArchive.Decode<ActivityRecord>(bytes);
                        if (activity == null) throw new InvalidOperationException("Retained activity schema is incomplete.");
                        activity.ValidateRetained();
                        activity.EvidenceObject = entry.EvidenceObject; rows.Add(activity);
                    }
                    catch (Exception ex) { rows.Add(new ActivityRecord { Id = entry.EventId, Operation = "Retained evidence unavailable", Result = ex.Message, Source = journal,
                        Utc = entry.Utc, EvidenceObject = entry.EvidenceObject, Payload = line, ActorEvidence = "Original journal entry retained; evidence read failed" }); }
                }
            }
            return new ActivityPage { Records = rows.ToArray(), More = more, Coverage = "Archived CAPI2 evidence; 500 records per page, all retained dates. Raw source XML and original attribution remain available." };
        }

        internal static ActivityPage Syscalls(HistoryArchive history, string path, int page)
        {
            string directory = Path.Combine(history.DirectoryPath, "traces");
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(EtwNative.Logfile)) != 448) throw new NotSupportedException("ETL paging requires the verified 64-bit Windows ABI.");
            if (page < 0 || !Directory.GetFiles(directory, "*.etl").Contains(path, StringComparer.Ordinal)) throw new InvalidOperationException("Select a retained original ETL.");
            using (FileStream pinnedFile = history.OpenArchiveRead(path))
            {
            List<ActivityRecord> rows = new List<ActivityRecord>(); int skip = checked(page * 500), matched = 0; bool more = false; uint lost = 0;
            EtwNative.EventCallback callback = delegate(IntPtr pointer)
            {
                if (more) return;
                try
                {
                    EtwNative.Record record = (EtwNative.Record)Marshal.PtrToStructure(pointer, typeof(EtwNative.Record));
                    if (record.Header.ProviderId != EtwNative.PerfInfoGuid || record.Header.Descriptor.Opcode != 51 && record.Header.Descriptor.Opcode != 52) return;
                    if (matched++ < skip) return;
                    if (rows.Count == 500) { more = true; return; }
                    rows.Add(SyscallTrace.DecodeRecord(record, path));
                }
                catch (Exception ex)
                { if (rows.Count < 500) rows.Add(new ActivityRecord { Operation = "ETL decode unavailable", Source = path, Result = ex.Message, Payload = "Original ETL retained", ActorEvidence = "Unparsed retained event" }); }
            };
            EtwNative.BufferCallback buffer = delegate(IntPtr value)
            { lost = unchecked((uint)Marshal.ReadInt32(value, (int)Marshal.OffsetOf(typeof(EtwNative.Logfile), "EventsLost"))); return more ? 0U : 1U; };
            EtwNative.Logfile logfile = new EtwNative.Logfile { LogFileName = path, ProcessTraceMode = 0x10000000, EventRecordCallback = callback, BufferCallback = buffer };
            ulong handle = EtwNative.OpenTraceW(ref logfile);
            if (handle == UInt64.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                uint status = EtwNative.ProcessTrace(new ulong[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);
                if (status != 0 && status != 1223) throw new Win32Exception((int)status);
            }
            finally { EtwNative.CloseTrace(handle); GC.KeepAlive(callback); GC.KeepAlive(buffer); }
            return new ActivityPage { Records = rows.ToArray(), More = more,
                Coverage = "Original ETL page, without live display sampling; source reported events lost=" + lost + "; enter/exit remain separate records. Symbol names unresolved [to test]." };
            }
        }
    }
}
