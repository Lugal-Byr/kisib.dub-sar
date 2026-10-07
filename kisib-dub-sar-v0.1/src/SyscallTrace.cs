using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace Kisib
{
    // Dedicated system logger, never the shared "NT Kernel Logger" session.
    // ETL is the full event archive. Bounded UI delivery does not trim the ETL.
    internal sealed class SyscallTrace : IDisposable
    {
        private readonly object gate = new object();
        private readonly HistoryArchive history;
        private readonly Action<ActivityRecord> publish;
        private readonly EtwNative.EventCallback callback;
        private readonly EtwNative.BufferCallback bufferCallback;
        private IntPtr properties;
        private ulong session, consumer = UInt64.MaxValue;
        private Thread worker;
        private bool disposed, stopping;
        internal string Name { get; private set; }
        internal string Path { get; private set; }
        internal string Status { get; private set; }
        internal long EventsReceived;
        internal long DecodeErrors;
        internal long DisplaySamplesSkipped;
        private long sampleSecond;
        private int samplesThisSecond;
        internal uint EventsLost;
        internal uint BuffersLost;
        internal bool Running { get { lock (gate) return session != 0; } }
        internal SyscallTrace(HistoryArchive history, Action<ActivityRecord> publish)
        {
            this.history = history; this.publish = publish; callback = Event; bufferCallback = Buffer;
            Status = "Syscall capture off";
            AppDomain.CurrentDomain.ProcessExit += ProcessExit;
        }
        internal void Start()
        {
            lock (gate)
            {
                if (disposed || session != 0) return;
                if (worker != null && worker.IsAlive) throw new InvalidOperationException("The previous ETW consumer is still finishing. Retry after its end record appears in History.");
                if (IntPtr.Size != 8) throw new NotSupportedException("Syscall capture requires the 64-bit Windows process; run Start.cmd from 64-bit Windows PowerShell.");
                if (Marshal.SizeOf(typeof(EtwNative.Logfile)) != 448 || Marshal.SizeOf(typeof(EtwNative.Properties)) != 120 ||
                    Marshal.SizeOf(typeof(EtwNative.Record)) != 112) throw new NotSupportedException("ETW structure sizes differ from the supported 64-bit Windows ABI.");
                if (history == null || history.LastError != null) throw new InvalidOperationException("Persistent history must be available before starting syscall capture.");
                string id = Guid.NewGuid().ToString("N");
                Name = "kisib.dub-sar.Syscalls." + id;
                string directory = System.IO.Path.Combine(history.DirectoryPath, "traces"); history.PinArchiveDirectory(directory);
                Path = System.IO.Path.Combine(directory, id + ".etl");
                if (File.Exists(Path) || Directory.Exists(Path)) throw new IOException("A new syscall capture path already exists; start refused.");
                int size = Marshal.SizeOf(typeof(EtwNative.Properties)), total = size + (Name.Length + Path.Length + 2) * 2;
                properties = Marshal.AllocHGlobal(total); Marshal.Copy(new byte[total], 0, properties, total);
                EtwNative.Properties settings = new EtwNative.Properties();
                settings.Wnode.BufferSize = (uint)total; settings.Wnode.Guid = EtwNative.SystemTraceControlGuid;
                settings.Wnode.ClientContext = 1; settings.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID; QPC clock
                settings.BufferSize = 64; settings.MinimumBuffers = (uint)Math.Max(16, Environment.ProcessorCount * 2);
                settings.MaximumBuffers = Math.Max(settings.MinimumBuffers, 128); settings.FlushTimer = 1;
                settings.LogFileMode = 0x02000000 | 0x00000100 | 0x00000001; // SYSTEM_LOGGER | REAL_TIME | FILE_SEQUENTIAL
                settings.EnableFlags = 0x00000080; // EVENT_TRACE_FLAG_SYSTEMCALL only
                settings.MaximumFileSize = 512; // per-session sequential ETL ceiling; never overwrite old traces
                settings.LoggerNameOffset = (uint)size; settings.LogFileNameOffset = (uint)(size + (Name.Length + 1) * 2);
                Marshal.StructureToPtr(settings, properties, false);
                Marshal.Copy((Name + "\0").ToCharArray(), 0, IntPtr.Add(properties, (int)settings.LoggerNameOffset), Name.Length + 1);
                Marshal.Copy((Path + "\0").ToCharArray(), 0, IntPtr.Add(properties, (int)settings.LogFileNameOffset), Path.Length + 1);
                try
                {
                    uint error = EtwNative.StartTraceW(out session, Name, properties);
                    if (error != 0) { session = 0; throw new Win32Exception((int)error, "StartTrace: " + new Win32Exception((int)error).Message + "; kernel capture normally requires an elevated Windows instance."); }
                    EtwNative.Logfile logfile = new EtwNative.Logfile { LoggerName = Name, ProcessTraceMode = 0x00000100 | 0x10000000,
                        EventRecordCallback = callback, BufferCallback = bufferCallback }; // REAL_TIME | EVENT_RECORD; converted FILETIME timestamps
                    consumer = EtwNative.OpenTraceW(ref logfile);
                    if (consumer == UInt64.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
                    EventsReceived = 0; DecodeErrors = 0; DisplaySamplesSkipped = 0; sampleSecond = 0; samplesThisSecond = 0;
                    EventsLost = 0; BuffersLost = 0; stopping = false;
                    Status = "Syscalls live — original ETL retained; 512 MB sequential ceiling";
                    history.Note(null, "syscall_capture_started", Name, Path + "; only system-call enter/exit; raw ETL is primary evidence; Windows execution to test.");
                    ulong opened = consumer; string captureName = Name, capturePath = Path;
                    worker = new Thread(delegate() { Consume(opened, captureName, capturePath); }) { IsBackground = true, Name = "ETW syscall consumer" }; worker.Start();
                }
                catch
                {
                    if (consumer != UInt64.MaxValue) { EtwNative.CloseTrace(consumer); consumer = UInt64.MaxValue; }
                    if (session != 0)
                    {
                        uint cleanup = EtwNative.ControlTraceW(session, Name, properties, 1);
                        if (cleanup != 0 && cleanup != 4201)
                        { Status = "Owned syscall session cleanup failed; use Stop capture. " + new Win32Exception((int)cleanup).Message; throw new Win32Exception((int)cleanup, Status); }
                        session = 0;
                    }
                    Marshal.FreeHGlobal(properties); properties = IntPtr.Zero; throw;
                }
            }
        }
        private void Consume(ulong handle, string captureName, string capturePath)
        {
            uint result = EtwNative.ProcessTrace(new ulong[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);
            lock (gate)
            {
                if (Name == captureName && !stopping) Status = "Syscall consumer ended: " + new Win32Exception((int)result).Message + "; capture may require Stop/restart";
                if (consumer == handle && Name == captureName) { EtwNative.CloseTrace(handle); consumer = UInt64.MaxValue; }
            }
            if (history != null) history.Note(null, "syscall_consumer_ended", captureName, capturePath + "; ProcessTrace status=" + result + "; decode errors=" + Interlocked.Read(ref DecodeErrors));
        }
        private void Event(IntPtr pointer)
        {
            try
            {
                EtwNative.Record record = (EtwNative.Record)Marshal.PtrToStructure(pointer, typeof(EtwNative.Record));
                if (record.Header.ProviderId != EtwNative.PerfInfoGuid || record.Header.Descriptor.Opcode != 51 && record.Header.Descriptor.Opcode != 52) return;
                Interlocked.Increment(ref EventsReceived);
                long second = System.Diagnostics.Stopwatch.GetTimestamp() / System.Diagnostics.Stopwatch.Frequency;
                if (second != sampleSecond) { sampleSecond = second; samplesThisSecond = 0; }
                if (++samplesThisSecond > 500) { Interlocked.Increment(ref DisplaySamplesSkipped); return; } // ETL still records every delivered provider event
                publish(DecodeRecord(record, Path));
            }
            catch { Interlocked.Increment(ref DecodeErrors); } // full event remains in the ETL; counter is surfaced and journaled
        }
        internal static ActivityRecord DecodeRecord(EtwNative.Record record, string tracePath)
        {
                int width = (record.Header.Flags & 0x20) != 0 ? 4 : 8;
                byte[] payload = new byte[record.UserDataLength];
                if (payload.Length > 0)
                { if (record.UserData == IntPtr.Zero) throw new InvalidOperationException("ETW payload pointer is unavailable."); Marshal.Copy(record.UserData, payload, 0, payload.Length); }
                string outcome = Decode(record.Header.Descriptor.Opcode, payload, width);
                return new ActivityRecord { Utc = DateTime.FromFileTimeUtc(record.Header.Timestamp).ToString("o"), Source = "ETW system logger",
                    Provider = record.Header.ProviderId.ToString(), EventId = record.Header.Descriptor.Opcode, ProcessId = record.Header.ProcessId == UInt32.MaxValue ? null : (uint?)record.Header.ProcessId,
                    ThreadId = record.Header.ThreadId == UInt32.MaxValue ? null : (uint?)record.Header.ThreadId, ActivityId = record.Header.ActivityId.ToString(), TracePath = tracePath,
                    Operation = record.Header.Descriptor.Opcode == 51 ? "SysCallEnter" : "SysCallExit", Result = outcome,
                    ActorEvidence = "ETW EVENT_HEADER process/thread; executable identity requires a matching observed process lifetime.",
                    Payload = "Provider=" + record.Header.ProviderId + "; opcode=" + record.Header.Descriptor.Opcode + "; version=" + record.Header.Descriptor.Version +
                        "; flags=0x" + record.Header.Flags.ToString("X4") + "; raw payload=" + CertificateRecord.Hex(payload) + "; original event is retained in ETL." };
        }
        internal static string Decode(byte opcode, byte[] data, int pointerSize)
        {
            if (opcode == 51 && (pointerSize == 4 || pointerSize == 8) && data.Length >= pointerSize)
                return "SysCallAddress=0x" + (pointerSize == 4 ? (ulong)BitConverter.ToUInt32(data, 0) : BitConverter.ToUInt64(data, 0)).ToString(pointerSize == 4 ? "X8" : "X16") + " [schema to test; symbol name unresolved]";
            if (opcode == 52 && data.Length >= 4) return "SysCallNtStatus=0x" + BitConverter.ToUInt32(data, 0).ToString("X8") + " [schema to test]";
            return "Payload unavailable or unsupported; original ETL retained";
        }
        private uint Buffer(IntPtr file)
        { EventsLost = unchecked((uint)Marshal.ReadInt32(file, (int)Marshal.OffsetOf(typeof(EtwNative.Logfile), "EventsLost"))); return 1; }
        internal void Query()
        {
            lock (gate)
            {
                if (session == 0) return;
                uint error = EtwNative.ControlTraceW(session, Name, properties, 0);
                if (error != 0) { Status = "Syscall capture query: " + new Win32Exception((int)error).Message + "; coverage incomplete"; return; }
                EtwNative.Properties current = (EtwNative.Properties)Marshal.PtrToStructure(properties, typeof(EtwNative.Properties));
                EventsLost = current.EventsLost; BuffersLost = current.LogBuffersLost + current.RealTimeBuffersLost;
                if (EventsLost > 0 || BuffersLost > 0) Status = "Syscalls live with gaps — ETW events lost=" + EventsLost + "; buffers lost=" + BuffersLost;
                if (consumer == UInt64.MaxValue) Status = "Syscall live consumer unavailable; inspect retained ETL — ETW events lost=" + EventsLost + "; buffers lost=" + BuffersLost;
                if (File.Exists(Path) && new FileInfo(Path).Length >= 510L * 1024 * 1024) Status = "ETL session ceiling reached/near; Stop and start a new retained capture";
            }
        }
        internal void Stop()
        {
            Thread oldWorker; string tracePath;
            lock (gate)
            {
                if (session == 0) return;
                stopping = true;
                uint error = EtwNative.ControlTraceW(session, Name, properties, 1);
                if (error != 0 && error != 4201) { stopping = false; Status = "Owned syscall session stop failed: " + new Win32Exception((int)error).Message; throw new Win32Exception((int)error); }
                EtwNative.Properties final = (EtwNative.Properties)Marshal.PtrToStructure(properties, typeof(EtwNative.Properties));
                EventsLost = final.EventsLost; BuffersLost = final.LogBuffersLost + final.RealTimeBuffersLost;
                session = 0; oldWorker = worker; tracePath = Path;
                if (consumer != UInt64.MaxValue) { EtwNative.CloseTrace(consumer); consumer = UInt64.MaxValue; }
                Marshal.FreeHGlobal(properties); properties = IntPtr.Zero;
                Status = "Syscall capture stopped; original ETL retained";
            }
            if (oldWorker != null && oldWorker != Thread.CurrentThread) oldWorker.Join(2000);
            string digest = "unavailable"; long bytes = 0;
            try { using (FileStream file = new FileStream(tracePath, FileMode.Open, FileAccess.Read, FileShare.Read)) using (SHA256 hash = SHA256.Create()) { bytes = file.Length; digest = CertificateRecord.Hex(hash.ComputeHash(file)); } }
            catch (Exception ex) { Status += "; final ETL integrity read failed: " + ex.Message; }
            if (history != null) history.Note(null, "syscall_capture_stopped", Name, tracePath + "; bytes=" + bytes + "; SHA-256=" + digest +
                "; received=" + Interlocked.Read(ref EventsReceived) + "; UI samples omitted=" + Interlocked.Read(ref DisplaySamplesSkipped) +
                "; decode errors=" + Interlocked.Read(ref DecodeErrors) + "; ETW events lost=" + EventsLost + "; buffers lost=" + BuffersLost + "; " + Status);
        }
        private void ProcessExit(object sender, EventArgs args) { try { Stop(); } catch { } }
        public void Dispose() { Stop(); disposed = true; AppDomain.CurrentDomain.ProcessExit -= ProcessExit; }
    }

    internal static class EtwNative
    {
        internal static readonly Guid SystemTraceControlGuid = new Guid("9e814aad-3204-11d2-9a82-006008a86939");
        internal static readonly Guid PerfInfoGuid = new Guid("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc");
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void EventCallback(IntPtr record);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate uint BufferCallback(IntPtr logfile);
        [StructLayout(LayoutKind.Sequential)] internal struct Wnode
        { internal uint BufferSize, ProviderId; internal ulong HistoricalContext; internal long Timestamp; internal Guid Guid; internal uint ClientContext, Flags; }
        [StructLayout(LayoutKind.Sequential)] internal struct Properties
        {
            internal Wnode Wnode;
            internal uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags;
            internal int AgeLimit;
            internal uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost;
            internal IntPtr LoggerThreadId; internal uint LogFileNameOffset, LoggerNameOffset;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct Descriptor
        { internal ushort Id; internal byte Version, Channel, Level, Opcode; internal ushort Task; internal ulong Keyword; }
        [StructLayout(LayoutKind.Sequential)] internal struct Header
        { internal ushort Size, HeaderType, Flags, Property; internal uint ThreadId, ProcessId; internal long Timestamp; internal Guid ProviderId; internal Descriptor Descriptor; internal ulong ProcessorTime; internal Guid ActivityId; }
        [StructLayout(LayoutKind.Sequential)] internal struct Record
        { internal Header Header; internal uint BufferContext; internal ushort ExtendedDataCount, UserDataLength; internal IntPtr ExtendedData, UserData, UserContext; }
        [StructLayout(LayoutKind.Sequential)] internal struct LegacyHeader
        { internal ushort Size, FieldTypeFlags; internal uint Version, ThreadId, ProcessId; internal long Timestamp; internal Guid Guid; internal ulong ProcessorTime; }
        [StructLayout(LayoutKind.Sequential)] internal struct LegacyEvent
        { internal LegacyHeader Header; internal uint InstanceId, ParentInstanceId; internal Guid ParentGuid; internal IntPtr MofData; internal uint MofLength, ClientContext; }
        [StructLayout(LayoutKind.Sequential)] internal struct SystemTime
        { internal ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct TimeZone
        {
            internal int Bias; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] internal string StandardName;
            internal SystemTime StandardDate; internal int StandardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] internal string DaylightName;
            internal SystemTime DaylightDate; internal int DaylightBias;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct LogfileHeader
        {
            internal uint BufferSize, Version, ProviderVersion, NumberOfProcessors; internal long EndTime;
            internal uint TimerResolution, MaximumFileSize, LogFileMode, BuffersWritten;
            internal uint StartBuffers, PointerSize, EventsLost, CpuSpeed; internal IntPtr LoggerName, LogFileName;
            internal TimeZone TimeZone; internal long BootTime, PerfFreq, StartTime; internal uint ReservedFlags, BuffersLost;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct Logfile
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string LogFileName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string LoggerName;
            internal long CurrentTime; internal uint BuffersRead, ProcessTraceMode;
            internal LegacyEvent CurrentEvent; internal LogfileHeader LogfileHeader;
            internal BufferCallback BufferCallback; internal uint BufferSize, Filled, EventsLost;
            internal EventCallback EventRecordCallback; internal uint IsKernelTrace; internal IntPtr Context;
        }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] internal static extern uint StartTraceW(out ulong handle, string name, IntPtr properties);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] internal static extern uint ControlTraceW(ulong handle, string name, IntPtr properties, uint control);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)] internal static extern ulong OpenTraceW(ref Logfile logfile);
        [DllImport("advapi32.dll", ExactSpelling = true)] internal static extern uint ProcessTrace([In] ulong[] handles, uint count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll", ExactSpelling = true)] internal static extern uint CloseTrace(ulong handle);
    }
}
