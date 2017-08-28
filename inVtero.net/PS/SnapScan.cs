#if FALSE || NETSTANDARD2_0
using inVtero.net;
using inVtero.net.ConsoleUtils;
using inVtero.net.Hashing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Text;
using static inVtero.net.Misc;

namespace inVtero.net.PS
{
    [Cmdlet(VerbsDiagnostic.Test, "Snapshot")]
    [OutputType(typeof(double))]
    public class SnapScan : Cmdlet
    {
        [Parameter(Position = 0, Mandatory = true, HelpMessage = "The folder to hold the integrity DB, Bitmap, XML MetaData and relocation information"),
            Alias("VF")]
        public string VteroFolder { get; set; }

        [Parameter(Mandatory = true,
        HelpMessage = "The size of the blocks to use for importing to the DB.  The smaller sizes will take many more times larger DB and impact performace some but will be much better at locating fragments of data."),
        ValidateSet("4096", "2048", "1024", "512", "256", "128", "64"), Alias("HS")]
        public int HashSize { get; set; }

        [Parameter(Mandatory = true,
            HelpMessage = "The memory dump to scan from. VMWARE (Workstation/Server) XEN or Microsoft formats supported"),
            Alias("I")]
        public string InputFile { get; set; }

        [Parameter(Mandatory = false,
            HelpMessage = "Force a regenerate ignoring any cached data."),
            Alias("F")]
        public bool Force { get; set; }

        [Parameter(Mandatory = false,
            HelpMessage = "Scan mode to enable"),
            Alias("M"), PSDefaultValue(Help = "GENERIC", Value = "GENERIC"), ValidateSet("GENERIC", "ALL", "FreeBSD", "HyperV", "LinuxS", "NetBSD", "OpenBSD", "VMCS", "Windows")]
        public PTType Mode { get; set; }

        [Parameter(Mandatory = false,
            HelpMessage = "Enable LocalBitmap Scan"),
            Alias("LBit")]
        public bool LocalBitmap { get; set; }

        [Parameter(Mandatory = false,
            HelpMessage = "Enable Cloud Bitmap Scan"),
            Alias("CBit")]
        public bool CloudBitmap { get; set; }


        MetaDB mdb;

        protected override void BeginProcessing()
        {
            var copts = new ConfigOptions();
            copts.IgnoreSaveData = Force;
            copts.FileName = InputFile;
            copts.VersionsToEnable = Mode;
            copts.VerboseOutput = Vtero.VerboseOutput;
            copts.VerboseLevel = Vtero.VerboseLevel;

            mdb = new MetaDB(VteroFolder, HashSize);

            var MemoryDumpSize = new FileInfo(InputFile).Length;
            //# Check StopWatch
            var runTime = Stopwatch.StartNew();
            //# since we are not ignoring SaveData, this just get's our state from
            //# the underlying protobuf, pretty fast
            var vtero = Scan.Scanit(copts);
            var proc_arr = vtero.Processes.ToArray();
            var low_proc = proc_arr[0];
            foreach (var px in proc_arr)
                if (px.CR3Value < low_proc.CR3Value)
                    low_proc = px;
            var proc = low_proc;

            WriteColor(1, ConsoleColor.White, $"Assumed Kernel Proc: {proc}");
            vtero.KernelProc = proc;
            proc.MemAccess = new Mem(vtero.MemAccess);
            if (vtero.KVS == null)
            {
                var kvs = proc.ScanAndLoadModules();
                vtero.KVS = kvs;
            }
            else
                proc.LoadSymbols();
            var kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff;

            WriteColor(1, ConsoleColor.Cyan, $"Kernel version detected {kMinorVer}");
            var logicalList = vtero.CoreWalkProcessList(vtero.KernelProc);

            foreach(var p in vtero.Processes)
                WriteColor(1, ConsoleColor.Cyan, $"{p}");

            try { vtero.HashAllProcs(mdb, LocalBitmap, CloudBitmap); }
            catch (Exception ex) { WriteColor(ConsoleColor.Red, $"Exception in Hash Generation {ex} "); }

            WriteColor(1, ConsoleColor.Cyan, "Done");
        }

        protected override void ProcessRecord()
        {
        }

        protected override void EndProcessing()
        {
            Console.WriteLine("Done");
        }

        protected override void StopProcessing()
        {
            Console.WriteLine("Abort");
        }
    }
}
#endif