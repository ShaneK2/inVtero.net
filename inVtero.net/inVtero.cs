// Copyright(C) 2017 Shane Macaulay smacaulay@gmail.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.If not, see<http://www.gnu.org/licenses/>.

using inVtero.net.Support;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using inVtero.net.Specialties;
using System.Runtime.InteropServices;
using static System.Console;
using ProtoBuf;
using System.Text;
using Reloc;
using System.ComponentModel;
using System.Diagnostics;
using Dia2Sharp;
using static inVtero.net.Misc;

// TODO: MemoryCopy / unsafe version performance testing
// TODO: Use git issues ;)
// TODO: Implement 5 level page table traversal (new intel spec)
using System.Dynamic;
using libyaraNET;

namespace inVtero.net
{
    /// <summary>
    /// Moving things around to support save state
    /// If it turns out that we are to parse the input aggressively, it may make sense to not have to waste time doing the same analysis over again
    /// 
    /// Rooting everything off of a main class helps the structure a bit
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class Vtero
    {
        public static Action ProgressCallback;

        public string MemFile;
        public long FileSize;
        public double GroupThreshold;

        // Preserve detected results to avoid aggressive kernel / symbol scanning loading
        public DetectedProc KernelProc;
        public VirtualScanner KVS;

        public PTType Version { get; set; }

        public static bool VerboseOutput { get; set; }

        public static int VerboseLevel { get; set; }

        /// <summary>
        /// I should really get an errorlevel going
        /// </summary>
        public static bool DiagOutput { get; set; }

        public static bool DisableProgressBar { get { return ProgressBarz.DisableProgressBar; } set { ProgressBarz.DisableProgressBar = value; } }

        // eventually we can get to where we know everything
        // grouped and organized
        public ConcurrentDictionary<EPTP, ConcurrentBag<DetectedProc>> AddressSpace;

        // Every Process detected for a given dump (not yet grouped)
        public ConcurrentBag<DetectedProc> Processes;
        // Each VMCS found
        public ConcurrentDictionary<long, VMCS> VMCSs;

        //WAHBitArray PFNdb;
        public ConcurrentDictionary<int, ConcurrentBag<DetectedProc>> ASGroups;

        public Mem MemAccess { get; set; }

        /// <summary>
        /// Flatten the ConcurrentDictionary/ConcurrentBag to a simple List.
        /// We move the AS info into the proc object itself
        /// </summary>
        public List<DetectedProc> FlattenASGroups
        {
            get {
                var rv = new List<DetectedProc>();

                foreach(var id in ASGroups.Keys)
                    foreach (var proc in ASGroups[id])
                    {
                        proc.ASGroup = id;
                        rv.Add(proc);
                    }

                return rv;
            }
            set
            {
                if (ASGroups == null)
                    ASGroups = new ConcurrentDictionary<int, ConcurrentBag<DetectedProc>>();

                foreach (var proc in value)
                {
                    if (ASGroups[proc.ASGroup] == null)
                        ASGroups[proc.ASGroup] = new ConcurrentBag<DetectedProc>();

                    ASGroups[proc.ASGroup].Add(proc);
                }
            }
        }

        public int Phase;

        [ProtoMember(42)]
        public AMemoryRunDetector MRD;

        /// <summary>
        /// Set OverRidePhase to force a re-run of a stage
        /// </summary>
        public bool OverRidePhase;

        // Scanner is the first pass 
        [ProtoMember(99)]
        Scanner scan;

        public Vtero()
        {

            Processes = new ConcurrentBag<DetectedProc>();
            VMCSs = new ConcurrentDictionary<long, VMCS>();
            GroupThreshold = 0.5;
            Phase = 1;

#if DEBUGX 
            VerboseOutput = true;
            DiagOutput = false;
#endif
            if (IsOutputRedirected)
            {
                WriteLine("disabling progress bar & Verbose due to console redirection.");
                VerboseOutput = DisableProgressBar = true;
            }

            ProgressBarz.pBarColor = ConsoleColor.Yellow;

        }
        

        public Vtero(string MemoryDump) :this()
        {
            MemFile = MemoryDump.ToLower();
            FileSize = new FileInfo(MemFile).Length;
            DeriveMemoryDescriptors();
            scan = new Scanner(MemFile, this);

        }

        public Vtero(string MemoryDump, AMemoryRunDetector MD) : this()
        {
            MemFile = MemoryDump.ToLower();
            FileSize = new FileInfo(MemFile).Length;
            MRD = MD;
            MemAccess = Mem.InitMem(MemFile, MRD);
            scan = new Scanner(MemFile, this);
        }

        /// <summary>
        /// Part of initialization used to carve up / figure out which underlying memory space were looking at
        /// </summary>
        [ProtoAfterDeserialization]
        void DeriveMemoryDescriptors()
        {
            AMemoryRunDetector Detected = null;

            if (MemFile.EndsWith(".dmp"))
            {
                Detected = new CrashDump(MemFile);
                Detected.IsSupportedFormat(this);

            } else if (MemFile.Contains(".vm"))
            {
                Detected = new VMWare(MemFile);
                if (Detected.IsSupportedFormat(this))
                    MemFile = Detected.MemFile;
            }

            // try XEN!
            if(Detected == null)
            {
                Detected = new XEN(MemFile);
                if (Detected != null)
                    Detected.IsSupportedFormat(this);
            }

            // if the memory run is defined as 0 count then it's implicitly 1
            if (Detected == null || Detected.PhysMemDesc == null || Detected.PhysMemDesc.NumberOfPages < 1)
            {
                Detected = new BasicRunDetector(MemFile);
                if (Detected != null)
                    Detected.IsSupportedFormat(this);
            }

            if (Vtero.VerboseLevel > 1)
                WriteColor(ConsoleColor.Green, $"HW Memory Run: {Detected.PhysMemDesc}" + Environment.NewLine + Environment.NewLine + Environment.NewLine);

            MRD = Detected;
            MemAccess = Mem.InitMem(MemFile, Detected);
        }

        public string CheckpointSaveState(string OverrideName = null, string DirSpec = null)
        {
            if (DirSpec == null)
                DirSpec = Path.GetDirectoryName(MemFile);

            var SerName = $"{Path.Combine(DirSpec, OverrideName == null ? MemFile : OverrideName)}.inVtero.net";

            using (var serOut = File.OpenWrite(SerName))
                Serializer.Serialize<inVtero.net.Vtero>(serOut, this);

            return SerName;
        }

        public Vtero CheckpointRestoreState(string SaveFile)
        {
            Vtero ThisInstance = new Vtero();

            var siz = new FileInfo(SaveFile).Length;
            if (siz == 0)
                return null;

            using (var SerData = File.OpenRead(SaveFile))
                ThisInstance = Serializer.Deserialize<inVtero.net.Vtero>(SerData);

            return ThisInstance;
        }

        public int ProcDetectScan(PTType Modes, int DetectOnly = 0)
        {
            if (Phase >= 1 && OverRidePhase)
                return Processes.Count();

            scan.ScanMode = Modes;

            var rv = scan.Analyze(DetectOnly);

            foreach (var p in scan.DetectedProcesses.Values)
                Processes.Add(p);

            Phase = 2;

            return rv;
        }

        public int VMCSScan()
        {
            if (Phase >= 2 && OverRidePhase)
                return VMCSs.Count();


            scan.ScanMode = PTType.VMCS;

            //scan.VMCSScanSet = (from dp in Processes
            //                    group dp by dp.CR3Value into CR3Masters
            //                    select new KeyValuePair<long, DetectedProc>(CR3Masters.Key, CR3Masters.First())).AsParallel();

            scan.ScanForVMCSset = Processes.GroupBy(p => p.CR3Value).Select(pg => pg.First()).ToArray();

            var rv = scan.Analyze();

            foreach (var vm in scan.HVLayer)
                if(!VMCSs.ContainsKey(vm.EPTP))
                    VMCSs.TryAdd(vm.EPTP, vm);

            rv = VMCSs.Count();
            Phase = 3;

            return rv;
        }

        public DetectedProc GetKernelRangeFromGroup(int GroupID)
        {
            //var mem = new Mem(MemFile, null, DetectedDesc) { OverrideBufferLoadInput = true };
            DetectedProc Proc = null;
            foreach (var Procz in ASGroups[GroupID])
            {
                Proc = Procz;

                if (Proc.PT == null)
                    PageTable.AddProcess(Proc, MemAccess, true);

                if (Proc.PT.EntriesParsed < 512)
                    continue;
                else
                    break;
            }

            if (Proc.PT.EntriesParsed < 512)
            {
                WriteLine("did not figure out a page table properly, bailing out");
                return null;
            }
            return Proc;
        }

        public CODEVIEW_HEADER ExtractCVDebug(DetectedProc dp, MemSection sec)
        {
            return dp.ExtractCVDebug(sec);
        }

        // These parallel function's almost always are I/O bound and slwoer 
        public Tuple<long, string, string>[][] HashAllProcs()
        {
            ConcurrentBag<Tuple<long, string, string>[]> rv = new ConcurrentBag<Tuple<long, string, string>[]>();

            KernelProc.InitSymbolsForVad();

            Parallel.ForEach<DetectedProc>(Processes, proc =>
            {
                var doKernel = (proc.CR3Value == KernelProc.CR3Value);
                proc.KernelSection = KernelProc.KernelSection;
                proc.CopySymbolsForVad(KernelProc);

                using (proc.MemAccess = new Mem(MemAccess))
                {
                    //var procHashSet = proc.HashGenBlocks(doKernel);
                    //rv.Add(procHashSet);
                }
            });

            return rv.ToArray();
        }

        public ScanResult[] YaraAll(string RulesFile, bool IncludeData = false, bool KernelSpace = false)
        {
            ConcurrentBag<ScanResult> rv = new ConcurrentBag<ScanResult>(); 

            Parallel.ForEach<DetectedProc>(Processes, proc =>
            {
                var doKernel = (proc.CR3Value == KernelProc.CR3Value);

                using (proc.MemAccess = new Mem(MemAccess))
                {
                    var prv = proc.YaraScan(RulesFile, IncludeData, false);
                    foreach (var r in prv)
                        rv.Add(r);

                    if (Vtero.VerboseLevel > 0)
                        WriteColor(ConsoleColor.Cyan, $"Done yara on proc {proc}, {prv.Count} signature matches.");
                }
            });

            return rv.ToArray();
        }


        /// <summary>
        /// Prefer symbol loading.
        /// </summary>
        /// <param name="dp"></param>
        /// <param name="ext"></param>
        /// <param name="cv_data"></param>
        /// <param name="SymbolCache"></param>
        /// <returns></returns>
        public bool GetKernelDebuggerData(DetectedProc dp, Extract ext, CODEVIEW_HEADER cv_data, string SymbolCache)
        {
            DebugHelp.SYMBOL_INFO symInfo = new DebugHelp.SYMBOL_INFO();
            bool rv = false;

            // Locate and extract some data points

            symInfo.SizeOfStruct = 0x58;
            symInfo.MaxNameLen = 1024;
            rv = DebugHelp.SymFromName(dp.ID.GetHashCode(), "KdpDataBlockEncoded", ref symInfo);
            if(!rv)
            {
                WriteLine($"Symbol Find : {new Win32Exception(Marshal.GetLastWin32Error()).Message }.");
                return rv;
            }

            KernelProc = dp;

            // at this point we should return true if it's encoded or not
            rv = true;
            return rv;
#if FALSE
            I'm leaving this in for now just to show the use of DecodePointer if needed since it could be uswed in a scenerio where symbols fail


            var KdpDataBlockEncoded = dp.GetByteValue(symInfo.Address);
            // Convention is to use *Address for addresses or the simple name is the value it is assumed to be a pointer

            dp.SymbolStore["KdDebuggerDataBlockAddress"] = GetSymAddress(dp, "KdDebuggerDataBlock");

            if (KdpDataBlockEncoded == 0)
                WriteColor(ConsoleColor.Green, $"Kernel KdDebuggerDataBlock @ {dp.SymbolStore["KdDebuggerDataBlockAddress"]:X16} not encoded.");
            else
            {
#if FALSE_NOT_NEEDED_IF_WE_USE_SYMBOLS
                var KdDebuggerDataBlock = dp.VGetBlockLong(dp.KdDebuggerDataBlockAddress, ref GotData);
                if (!GotData)
                    WriteColor(ConsoleColor.Red, "Unable to read debuggerdatablock array");

                // Windbg tells us the diff for loaded modules is 0x48 and active proc is 0x50
                var EncLoadedModuleList = KdDebuggerDataBlock[9];
                var EncActiveProcessList = KdDebuggerDataBlock[0xA];

                var PsLoadedModuleList = (long) DecodePointer((ulong) dp.KdDebuggerDataBlockAddress, (ulong)dp.KiWaitAlways, (ulong)dp.KiWaitNever,(ulong) EncLoadedModuleList);
                var PsActiveProcessHead = (long) DecodePointer((ulong) dp.KdDebuggerDataBlockAddress, (ulong)dp.KiWaitAlways, (ulong)dp.KiWaitNever, (ulong) EncActiveProcessList);

                WriteColor(ConsoleColor.Cyan, $"Decoded LoadedModuleList {PsLoadedModuleList}, ActiveProcessList {PsActiveProcessHead}");
#endif
            }
            return rv;
#endif
        }


        /// <summary>
        /// Manages SymForKernel  
        /// </summary>
        /// <param name="dp"></param>
        /// <returns></returns>
        public dynamic[] WalkProcList(DetectedProc dp)
        {
            bool GotData = false;
            // TODO: Build out symbol system / auto registration into DLR for DIA2
            // expected kernel hardcoded

            var pdbFile = (from kern in dp.Sections
                           where kern.Value.Name.Contains("ntkrnlmp")
                           select kern.Value.DebugDetails.PDBFullPath).FirstOrDefault();

            if (string.IsNullOrWhiteSpace(pdbFile))
                return null;

            // this is for DIA API SDK... 
            // TODO: Perf analysis of switching over to xStruct... however it's expando objects
            // are a lot slower than using the dictionary
            var SymForKernel = Sym.Initalize(dp.ID.GetHashCode(), pdbFile);
            long[] memRead = null;

            var PsHeadAddr = GetSymValueLong(dp, "PsActiveProcessHead");

            // TODO: update this to be used instead of legacy .Dictionary kludge ;)
            //var rv = SymForKernel.xStructInfo(pdbFile, "_EPROCESS");
            // figure out OFFSET_OF the process LIST_ENTRY
            // MemberInfo returned is Byte Position, Length
            var aplinks = SymForKernel.StructMemberInfo(pdbFile, "_EPROCESS", "ActiveProcessLinks.Flink");
            var offset_of = aplinks.Item1;
            var sym_dtb = SymForKernel.StructMemberInfo(pdbFile, "_EPROCESS", "Pcb.DirectoryTableBase");
            var sym_ImagePathPtr = SymForKernel.StructMemberInfo(pdbFile, "_EPROCESS", "SeAuditProcessCreationInfo.ImageFileName");
            var sym_procID = SymForKernel.StructMemberInfo(pdbFile, "_EPROCESS", "UniqueProcessId");
            var sym_vadRoot = SymForKernel.StructMemberInfo(pdbFile, "_EPROCESS", ".VadRoot");
            var sym_ethr = SymForKernel.StructMemberInfo(pdbFile, "_EPROCESS", "_EPROCESS.ThreadListHead");
            // adjust the first link through 
            //var flink = dp.GetLongValue(PsHeadAddr);

            var typeDefs = from typeDef in SymForKernel.StructInfo
                            where typeDef.Key.StartsWith("_EPROCESS")
                            select typeDef;

            var flink = PsHeadAddr;
            do 
            {
                // walk the offset back to the head of the _EPROCESS
                // this needs to adjsut since we get the entire block here based to the page not offset 
                memRead = dp.GetVirtualLong((flink - offset_of), ref GotData);
                if (!GotData)
                    break;

                var EThrPtr = memRead[sym_ethr.Item1 / 8];
                // memRead is a long array so we have to divide the length by 8
                var EprocCR3 = memRead[sym_dtb.Item1 / 8];
                var ProcessID = memRead[sym_procID.Item1 / 8];
                var VadRootPtr = memRead[sym_vadRoot.Item1 / 8];

                var ImagePath = "";
                var filename = "";

                if (ProcessID != 4)
                {
                    // ImagePath here is a pointer to a struct, get ptr
                    // +0x10 in this unicode string object
                    var ImagePathPtr = memRead[sym_ImagePathPtr.Item1 / 8];
                    var ImagePathArr = dp.GetVirtualByte(ImagePathPtr + 0x10);
                    ImagePath = Encoding.Unicode.GetString(ImagePathArr);
                    var pathTrim = ImagePath.Split('\x0');
                    ImagePath = pathTrim[0];
                    if (ImagePath.Contains(Path.DirectorySeparatorChar))
                        filename = ImagePath.Split(Path.DirectorySeparatorChar).Last();
                    else
                        filename = ImagePath;

                        foreach (char c in Path.GetInvalidFileNameChars())
                            filename = filename.Replace(c, '_');
                }
                else
                    filename = ImagePath = "System";

                dynamic lproc = new ExpandoObject();
                var dproc = (IDictionary<string, object>)lproc;

                var staticDict = new Dictionary<string, object>();
                lproc.Dictionary = staticDict;

                foreach (var def in typeDefs)
                {
                    // custom types are not fitted this way
                    // we just recuse into basic types
                    if (def.Value.Item2 > 8)
                        continue;

                    // TODO: expand on this dynamic object stuff
                    var defName = def.Key.Substring("_EPROCESS".Length + 1); //.Replace('.', '_');
                    
                    switch (def.Value.Item2)
                    {
                        case 4:
                            var ival = (int)(memRead[def.Value.Item1 / 8] & 0xffffffffff);
                            dproc.Add(defName, ival);
                            staticDict.Add(defName, ival);
                            break;
                        case 2:
                            var sval = (short)(memRead[def.Value.Item1 / 8] & 0xffffff);
                            dproc.Add(defName, sval);
                            staticDict.Add(defName, sval);
                            break;
                        case 1:
                            var bval = (byte)(memRead[def.Value.Item1 / 8] & 0xff);
                            dproc.Add(defName, bval);
                            staticDict.Add(defName, bval);
                            break;
                        default:
                            var lval = memRead[def.Value.Item1 / 8];
                            dproc.Add(defName, lval);
                            staticDict.Add(defName, lval);
                            break;
                    }
                } 

                lproc.ImagePath = ImagePath;
                lproc.ImageFileName = filename;
                dp.LogicalProcessList.Add(lproc);

                // also bind the specific entry to the hw entry
                foreach (var hw in Processes)
                {
                    if (hw.CR3Value == EprocCR3)
                    {
                        hw.EThreadPtr = EThrPtr;
                        hw.EProc = lproc;
                        hw.VadRootPtr = VadRootPtr;
                        hw.OSPath = ImagePath;
                        hw.OSFileName = filename;
                        hw.ProcessID = ProcessID;
                        break;
                    }
                }

                // move flink to next list entry
                flink = memRead[offset_of / 8];

                // if flink is > 0 we have a problem since it's in the expected "user" range 
                // and we are walking the kernel sooooo... exit  TODO: Report error! ;)
            } while (PsHeadAddr != flink && flink < 0);
            return dp.LogicalProcessList.ToArray();
        }

        /// <summary>
        /// You only need this if you can't get symbols.  
        /// see http://uninformed.org/index.cgi?v=3&a=3&t=sumry by skape & Skywing
        /// </summary>
        /// <param name="BlockAddress"></param>
        /// <param name="Always"></param>
        /// <param name="Never"></param>
        /// <param name="Value"></param>
        /// <returns></returns>
        public static ulong DecodePointer(ulong BlockAddress, ulong Always, ulong Never, ulong Value)
        {
            ulong decoded = 0;

            decoded = Value ^ Never;
            decoded = Misc.RotL(decoded, (int) Never & 0xff);
            decoded = decoded ^ BlockAddress;

            var bytes = BitConverter.GetBytes(decoded);
            Array.Reverse(bytes, 0, 8);
            decoded = BitConverter.ToUInt64(bytes, 0);

            decoded = decoded ^ Always;

            decoded = (BlockAddress & 0xffffffff00000000) | (decoded & 0xffffffff);
            return decoded;
        }

        /// <summary>
        /// TODO: Make better for all types
        /// </summary>
        /// <param name="dp"></param>
        /// <param name="SymName"></param>
        /// <returns>Currently a single byte for the address resolved from the Name</returns>
        public long GetSymValueLong(DetectedProc dp, string SymName)
        {
            long value = 0;

            if (dp.SymbolStore.ContainsKey(SymName))
                return dp.SymbolStore[SymName];

            value = dp.GetLongValue(GetSymAddress(dp, SymName));
            dp.SymbolStore.Add(SymName, value);

            return value;
        }

        public long GetSymAddress(DetectedProc dp, string SymName)
        {
            var AddrName = SymName + "Address";
            if (dp.SymbolStore.ContainsKey(AddrName))
                return dp.SymbolStore[AddrName];

            DebugHelp.SYMBOL_INFO symInfo = new DebugHelp.SYMBOL_INFO();

            symInfo.SizeOfStruct = 0x58;
            symInfo.MaxNameLen = 1024;

            var rv = DebugHelp.SymFromName(dp.ID.GetHashCode(), SymName, ref symInfo);
            if (!rv)
            {
                WriteColor(ConsoleColor.Red, $"GetSymValue: {new Win32Exception(Marshal.GetLastWin32Error()).Message }.");
                return MagicNumbers.BAD_VALUE_READ;
            }

            dp.SymbolStore.Add(AddrName, symInfo.Address);

            return symInfo.Address;
        }

        /// <summary>
        /// We use sympath environment variable
        /// </summary>
        /// <param name="cv_data"></param>
        /// <param name="BaseVA"></param>
        /// <param name="SymPath"></param>
        /// <returns></returns>
        public static Sym TryLoadSymbols(long Handle, CODEVIEW_HEADER cv_data, long BaseVA)
        {
            if (cv_data == null)
                return null;

            ulong KernRange = 0xffff000000000000;

            // sign extend BaseVA for kernel ranges
            if ((BaseVA & 0xf00000000000) != 0)
                BaseVA |= (long)KernRange;

            var sym = Sym.Initalize(Handle, null, DebugHelp.SymOptions.SYMOPT_UNDNAME);

            if(sym == null)
                WriteLine($"Can not initialize symbols for ${Handle}, error:  {new Win32Exception(Marshal.GetLastWin32Error()).Message }");

            var symStatus = true;

            StringBuilder sbx = new StringBuilder(1024);
            
            int three = 0;
            var flags = DebugHelp.SSRVOPT_GUIDPTR;
            symStatus = DebugHelp.SymFindFileInPathW(Handle, null, cv_data.PdbName, ref cv_data.aGuid, cv_data.Age, three, flags, sbx, IntPtr.Zero, IntPtr.Zero);
            // try twice, just in case
            if (!symStatus)
                symStatus = DebugHelp.SymFindFileInPathW(Handle, null, cv_data.PdbName, ref cv_data.aGuid, cv_data.Age, three, flags, sbx, IntPtr.Zero, IntPtr.Zero);

            if (!symStatus)
            {
                WriteColor(ConsoleColor.Yellow, $" Symbol locate returned {symStatus}: {new Win32Exception(Marshal.GetLastWin32Error()).Message }, attempting less precise request.");

                flags = DebugHelp.SSRVOPT_DWORDPTR;
                var refBytes = BitConverter.GetBytes(cv_data.TimeDateStamp);
                GCHandle pinnedArray = GCHandle.Alloc(refBytes, GCHandleType.Pinned);
                IntPtr pointer = pinnedArray.AddrOfPinnedObject();

                symStatus = DebugHelp.SymFindFileInPath(Handle, null, cv_data.PdbName, pointer, cv_data.VSize, three, flags, sbx, IntPtr.Zero, IntPtr.Zero);
                pinnedArray.Free();
                if (!symStatus)
                    WriteColor(ConsoleColor.Red, $" Find Symbols returned value: {symStatus}:[{sbx.ToString()}]");

                sym = null;
            }
            if (symStatus)
            {
                var symLoaded = DebugHelp.SymLoadModuleEx(Handle, IntPtr.Zero, sbx.ToString(), null, BaseVA, cv_data.VSize, IntPtr.Zero, 0);
                if (symLoaded == 0)
                    WriteColor(ConsoleColor.Red, $"Symbols file located @ {sbx.ToString()} yet load Failed: [{new Win32Exception(Marshal.GetLastWin32Error()).Message }]");

                cv_data.PDBFullPath = sbx.ToString();
            }

            return sym;
        }

        public long DumpProc(string Folder, DetectedProc Proc, bool IncludeData = false, bool KernelSpace = true)
        {
            //var entries = PageTable.Flatten(Proc.PT.Root.Entries.SubTables, 4);
            VIRTUAL_ADDRESS VA;
            VA.Address = 0;
            var PageTables = new Dictionary<VIRTUAL_ADDRESS, PFN>();
            int level = 3;
            long entries = 0;
            long ContigSize = -1;

            if (Proc.PT == null)
                PageTable.AddProcess(Proc, MemAccess);

            foreach (var kvp in Proc.TopPageTablePage)
            {
                // were at the top level (4th)
                VA.PML4 = kvp.Key;
                var pfn = new PFN { PTE = kvp.Value, VA = new VIRTUAL_ADDRESS(VA.PML4 << 39) };

                // Top level for page table
                PageTables.Add(VA, pfn);

                foreach (var DirectoryPointerOffset in Proc.PT.ExtractNextLevel(pfn, level))
                {
                    if (DirectoryPointerOffset == null) continue;
                    foreach (var DirectoryOffset in Proc.PT.ExtractNextLevel(DirectoryPointerOffset, level - 1))
                    {
                        if (DirectoryOffset == null) continue;

                        foreach (var TableOffset in Proc.PT.ExtractNextLevel(DirectoryOffset, level - 2))
                        {
                            if (TableOffset == null) continue;

                            entries++;
                            if (IncludeData == TableOffset.PTE.NoExecute)
                                WriteRange(TableOffset.VA, TableOffset, Folder, ref ContigSize, MemAccess);
                            if (!TableOffset.PTE.NoExecute)
                            WriteRange(TableOffset.VA, TableOffset, Folder, ref ContigSize, MemAccess);

                        }
                        entries++;
                        if (IncludeData == DirectoryOffset.PTE.NoExecute)
                            WriteRange(DirectoryOffset.VA, DirectoryOffset, Folder, ref ContigSize, MemAccess);
                        if (!DirectoryOffset.PTE.NoExecute)
                            WriteRange(DirectoryOffset.VA, DirectoryOffset, Folder, ref ContigSize, MemAccess);
                    }
                    entries++;
                }

            }
            return entries;
        }

        // TODO: Move above into DetectedProc class methods

    /// <summary>
    /// Group address spaces into related buckets
    /// 
    /// We will assign an address space ID to each detected proc so we know what process belongs with who
    /// After AS grouping we will know what EPTP belongs to which AS since one of the DP's will have it's CR3 in the VMCS 
    /// 
    /// Yes it's a bit complicated.  
    /// 
    /// The overall procedure however is straight forward in that; 
    /// 
    /// * For every detected process
    ///       Bucket into groups which are the "Address spaces" that initially are 
    ///       
    ///       (a) based on kernel address space similarities 
    ///       and then 
    ///       (b) based on what VMCS value was found pointing to that group
    ///              
    /// This ensures that if we have several hypervisors with a possibly identical kernel grouping (i.e. the PFN's
    /// were used by each kernel were identical), they are disambiguated by the VMCS.  (Which can be validated later)
    /// 
    /// The benefit here is that brute forcing at this stage is fairly expensive and can lead to significant overhead, there does
    /// tend to be some outliers for large systems that need to be looked at more to determine who they belong too.  Nevertheless, it's 
    /// inconsequential if they are grouped with the appropriate AS since even if they are isolated into their own 'AS' this is an artificial 
    /// construct for our book keeping.  The net result is that even if some process is grouped by itself due to some aggressive variation in
    /// kernel PFN' use (lots of dual mapped memory/MDL's or something), it's still able to be dumped and analyzed.
    /// </summary>
    /// <param name="pTypes">Types to scan for, this is of the already detected processes list so it's already filtered really</param>
    public void GroupAS(PTType pTypes = PTType.UNCONFIGURED)
        {
            var PT2Scan = pTypes == PTType.UNCONFIGURED ? PTType.ALL : pTypes;

            //if (Phase >=3 && OverRidePhase)
            //    return;

            // To join an AS group we want to see > 50% correlation which is a lot considering were only interoperating roughly 10-20 values (more like 12)
            var p = from proc in Processes
                    where (((proc.PageTableType & PT2Scan) == proc.PageTableType))
                    orderby proc.CR3Value ascending
                    select proc;

            ASGroups = new ConcurrentDictionary<int, ConcurrentBag<DetectedProc>>();

            // we trim out the known recursive/self entries since they will naturally not be equivalent
            var AlikelyKernelSet = from ptes in p.First().TopPageTablePage
                                   where ptes.Key > (MagicNumbers.KERNEL_PT_INDEX_START_USUALLY - 1) && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

            int totUngrouped = Processes.Count();
            int CurrASID = 1;
            int LastGroupTotal = 0;
            var grouped = new ConcurrentBag<DetectedProc>();

            if(Vtero.DiagOutput)
                WriteColor(ConsoleColor.White, ConsoleColor.Black, $"Scanning for group correlations total processes {totUngrouped}");
            ASGroups[CurrASID] = new ConcurrentBag<DetectedProc>();

            while (true)
            {
                ForegroundColor = ConsoleColor.Yellow;
                Parallel.ForEach(p, (proc) =>
                {
                    var currKern = from ptes in proc.TopPageTablePage
                                   where ptes.Key > (MagicNumbers.KERNEL_PT_INDEX_START_USUALLY-1) && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

                    var interSection = currKern.Intersect(AlikelyKernelSet);
                    var correlated = interSection.Count() * 1.00 / AlikelyKernelSet.Count();

                    // add this detected CR3/process address space to an address space grouping when
                    // the kernel range is above the acceptable threshold, the group does not contain this proc
                    // and this proc is not already joined into another group
                    if (correlated > GroupThreshold && !ASGroups[CurrASID].Contains(proc) && proc.AddressSpaceID == 0)
                    {
                        if (Vtero.DiagOutput)
                            WriteColor(ConsoleColor.Cyan, $"MemberProces: Group {CurrASID} Type [{proc.PageTableType}] GroupCorrelation [{correlated:P3}] PID [{proc.CR3Value:X}]");

                        proc.AddressSpaceID = CurrASID;
                        ASGroups[CurrASID].Add(proc);
                        // global list to quickly scan
                        grouped.Add(proc);
                    }
                });

                ForegroundColor = ConsoleColor.Yellow;

                var totGrouped = (from g in ASGroups.Values
                                  select g).Sum(x => x.Count());
                if (Vtero.DiagOutput)
                    WriteLine($"Finished Group {CurrASID} collected size {ASGroups[CurrASID].Count()}, continuing to group");
                // if there is more work todo, setup an entry for testing
                if (totGrouped < totUngrouped)
                {
                    // if we wind up here 
                    // there has been no forward progress in isolating further groups
                    if(LastGroupTotal == totGrouped)
                    {
                        if (Vtero.DiagOutput)
                            WriteColor(ConsoleColor.Red, $"Terminating with non-grouped process candidates.  GroupThreshold may be too high. {GroupThreshold}");

                        var pz = from px in Processes
                                where px.AddressSpaceID == 0
                                select px;
                        
                        // just add the ungrouped processes as a single each bare metal
                        // unless it has an existing VMCS pointer
                        foreach (var px in pz)
                        {
                            WriteLine(px);
                            CurrASID++;
                            px.AddressSpaceID = CurrASID;
                            ASGroups[CurrASID] = new ConcurrentBag<DetectedProc>() { px };

                            var isCandidate = from pvmcs in scan.HVLayer
                                              where pvmcs.gCR3 == px.CR3Value
                                              select pvmcs;

                            if (isCandidate.Count() > 0)
                            {
                                px.CandidateList = new List<VMCS>(isCandidate);
                                px.vmcs = px.CandidateList.First();
                                if (Vtero.VerboseOutput)
                                    WriteColor( ConsoleColor.White, $"Detected ungrouped {px.CR3Value} as a candidate under {px.CandidateList.Count()} values (first){px.vmcs.EPTP}");
                            }
                        }
                        break;
                    }


                    CurrASID++;
                    ASGroups[CurrASID] = new ConcurrentBag<DetectedProc>();
                    if (Vtero.DiagOutput)
                        WriteColor(ConsoleColor.Cyan, $"grouped count ({totGrouped}) is less than total process count ({totUngrouped}, rescanning...)");
                    LastGroupTotal = totGrouped;
                }
                else
                    break; // we grouped them all!

                /// Isolate next un-grouped PageTable
                var UnGroupedProc = from nextProc in Processes
                                   where !grouped.Contains(nextProc)
                                   select nextProc;

                AlikelyKernelSet = from ptes in UnGroupedProc.First().TopPageTablePage
                                   where ptes.Key > (MagicNumbers.KERNEL_PT_INDEX_START_USUALLY - 1) && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;
            }
            if (Vtero.DiagOutput)
                WriteColor(ConsoleColor.Green, $"Done All process groups.");

            // after grouping link VMCS back to the group who 'discovered' the VMCS in the first place!
            var eptpz = VMCSs.Values.GroupBy(eptz => eptz.EPTP).OrderBy(eptx => eptx.Key).Select(ept => ept.First()).ToArray();

            // find groups dominated by each vmcs
            var VMCSGroup = from aspace in ASGroups.AsEnumerable()
                            from ept in eptpz
                            where aspace.Value.Any(adpSpace => adpSpace == ept.dp)
                            select new { AS = aspace, EPTctx = ept };

            // link the proc back into the eptp 
            foreach (var ctx in VMCSGroup)
                foreach (var dp in ctx.AS.Value)
                {
                    if(dp.CandidateList == null)
                        dp.CandidateList = new List<VMCS>();

                    dp.vmcs = ctx.EPTctx;
                    dp.CandidateList.Add(ctx.EPTctx);
                }

            // resort by CR3
            foreach (var ctx in ASGroups.Values)
            {
                var dpz = from d in ctx
                          orderby d.CR3Value descending
                          select d;

                if (dpz.Count() >= 1)
                {
                    var aspace = dpz.First().AddressSpaceID;
                    ASGroups[aspace] = new ConcurrentBag<DetectedProc>(dpz);
                }
            }

            Phase = 4;
            // were good, all Processes should have a VMCS if applicable and be identifiable by AS ID
        }
        // Everything below here is really useless in current versions
#region Origional Custom CLI support code

        /// <summary>
        /// This routine is fairly expensive, maybe unnecessary as well but it demo's walking the page table + EPT.
        /// You can connect an address space dumper really easily
        /// 
        /// TODO: Remake this.  Instead of just pre-buffering everything.  Ensure the GroupAS detections are appropriate 
        /// and if not, reassign the VMCS/EPTP page to bare metal or a different HVLayer item.
        /// </summary>
        /// <param name="MemSpace">The list of VMCS/EPTP configurations which will alter the page table use</param>
        /// <param name="Procs">Detected procs to query</param>
        /// <param name="pTypes">Type bitmask to interpret</param>
        public Dictionary<int, List<DetectedProc>> ExtrtactAddressSpaces(IOrderedEnumerable<VMCS> MemSpace = null, ConcurrentBag<DetectedProc> Procs = null, PTType pTypes = PTType.UNCONFIGURED)
        {
            Dictionary<int, List<DetectedProc>> rvList = new Dictionary<int, List<DetectedProc>>();

            var PT2Scan = pTypes == PTType.UNCONFIGURED ? (PTType.Windows | PTType.HyperV | PTType.GENERIC) : pTypes; 
            var procList = Procs == null ? Processes : Procs;
            //var memSpace = MemSpace == null ? VMCSs.First() : MemSpace.First();
            
            var memSpace = MemSpace == null ? VMCSs.Values.GroupBy(x => x.EPTP).Select(xg => xg.First()) : MemSpace;
            var ms = from memx in memSpace
                     orderby memx.Offset ascending
                     select memx;

            int gcnt = ASGroups.Count();
            int vmcnt = memSpace.Count();
            var tot = gcnt * vmcnt;
            var curr = 0;
            bool CollectKernelAS = true;

            var CurrColor = ForegroundColor;

            WriteColor(ConsoleColor.White, ConsoleColor.Black, $"assessing {tot} address space combinations");
            ProgressBarz.RenderConsoleProgress(0);

            var VMCSTriage = new Dictionary<VMCS, int>();

            //Parallel.ForEach(memSpace, (space) =>
            //foreach (var space in ms)
            //{
            // we do it this way so that parallelized tasks do not interfere with each other 
            // overall it may blow the cache hit ratio but will tune a single task to see the larger/better cache
            // versus multicore, my suspicion is that multi-core is better
            //using (var memAxs = new Mem(MemFile, null, DetectedDesc))
            var memAxs = MemAccess;
            {

                var sx = 0;

                // assign address space by group
                foreach (var grp in ASGroups)
                {

                    // if the group is configured fully, then we know we were successful
                    // since we null out the list if we fail, so skip to next one
                    //if ((rvList.ContainsKey(grp.Key) && rvList[grp.Key] != null) || grp.Value == null)
                    //    continue;

                    rvList[grp.Key] = new List<DetectedProc>();
                    var orderedGroup = from px in grp.Value
                                        where ((px.PageTableType & PT2Scan) == px.PageTableType) && px.AddressSpaceID == grp.Key
                                        orderby px.CR3Value ascending
                                        select procList;

                    //foreach (var proc in from proc in grp.Value
                    //                     where (((proc.PageTableType & PT2Scan) == proc.PageTableType)) && (proc.AddressSpaceID == grp.Key)
                    //                    orderby proc.CR3Value ascending
                    //                   select proc)
                    //foreach(var proc in orderedGroup.SelectMany(x => x))
                    //Parallel.ForEach(p, (proc) =>
                    if (orderedGroup.Count() < 1)
                        continue;

                    var proc = orderedGroup.First().First();

                    {
                        int i = 0;
                        List<long> tableCounts = new List<long>();
                        if (proc.CandidateList == null || proc.CandidateList.Count < 1)
                        {
                            if (proc.vmcs != null)
                                proc.CandidateList = new List<VMCS>() { proc.vmcs }; // just set the one
                            else
                                proc.CandidateList = new List<VMCS>() { new VMCS() { EPTP = 0 } };

                        }

                        // find the best space for this proc 
                        foreach (var space in proc.CandidateList)
                        {
                            try
                            {
                                // this is killing memory, probably not needed
                                //var proc = px.Clone<DetectedProc>();
                                proc.vmcs = space;
                                if (VerboseOutput)
                                    WriteLine($"Scanning PT from Type [{proc.PageTableType}] PID [{proc.vmcs.EPTP:X}:{proc.CR3Value:X}] ID{proc.AddressSpaceID} Key{grp.Key}");

                                var pt = PageTable.AddProcess(proc, memAxs, CollectKernelAS);
                                CollectKernelAS = false;
                                if (pt != null)
                                {
                                    // If we used group detection correlation a valid EPTP should work for every process    
                                    // so if it's bad we skip the entire evaluation
                                    if (proc.vmcs != null && proc.PT.Root.Count > proc.TopPageTablePage.Count())
                                    {
                                        tableCounts[i++] = proc.PT.Root.Count;
                                        WriteLine($"TableCount for VMCS candidate is {proc.PT.Root.Count}");
                                        if (VerboseOutput)
                                            WriteLine($"{rvList[grp.Key].Count()} of {grp.Value.Count} Virtualized Process PT Entries [{proc.PT.Root.Count}] Type [{proc.PageTableType}] PID [{proc.vmcs.EPTP:X}:{proc.CR3Value:X}]");

                                        // collect process into now joined EPTP<->Proc
                                        rvList[grp.Key].Add(proc);

                                        if (rvList[grp.Key].Count() == grp.Value.Count && VerboseOutput)
                                        {
                                            ForegroundColor = ConsoleColor.Green;
                                            WriteLine($"Validated 100% {grp.Value.Count} of detected group {proc.AddressSpaceID}, continuing with next group.");
                                            ForegroundColor = CurrColor;
                                            break;
                                        }
                                    }
                                    else {
                                        // let's just cancel if we haven't done any decodes
                                        if (rvList[grp.Key].Count() < 1)
                                        {
                                            WriteColor(ConsoleColor.Yellow, $"Canceling evaluation of bad EPTP for this group/Address Space ({grp.Key}) a likely bare metal group");
                                            foreach (var p in Processes)
                                                if (p.vmcs != null && p.vmcs.EPTP == space.EPTP && p.AddressSpaceID == proc.AddressSpaceID)
                                                    p.vmcs = null;

                                            rvList[grp.Key] = null;
                                        }
                                        break;
                                    }

                                    sx++;
                                    curr++;
                                }
                                var progress = Convert.ToInt32(Convert.ToDouble(curr) / Convert.ToDouble(tot) * 100.0);
                                ProgressBarz.RenderConsoleProgress(progress);
                            }
                            catch (ExtendedPageNotFoundException eptpX)
                            {
                                WriteLine($"Bad EPTP selection;{Environment.NewLine}\tEPTP:{eptpX.RequestedEPTP}{Environment.NewLine}\t CR3:{eptpX.RequestedCR3}{Environment.NewLine} Attempting to skip to next proc.");

                                memAxs.DumpPFNIndex();
                            }
                            catch (MemoryRunMismatchException mrun)
                            {
                                WriteLine($"Error in accessing memory for PFN {mrun.PageRunNumber:X12}");

                                memAxs.DumpPFNIndex();
                            }
                            catch (PageNotFoundException pnf)
                            {
                                WriteLine($"Error in selecting page, see {pnf}");

                                memAxs.DumpPFNIndex();
                            }
                            catch (Exception ex)
                            {
                                WriteLine($"Error in memspace extraction: {ex.ToString()}");

                                memAxs.DumpPFNIndex();
                            }
                            WriteLine($"{sx} VMCS dominated process address spaces and were decoded successfully.");
                            //});
                        }
                    }
                }
            }
            //}
            //});

            CollectKernelAS = true;
            // a backup to test a non-VMCS 
            //using (var memAxs = new Mem(MemFile, null, DetectedDesc))
            //var memAxs = Mem.Instance;
            {
                var nonVMCSprocs = from proc in Processes
                                   where (((proc.PageTableType & PT2Scan) == proc.PageTableType))
                                   where proc.vmcs == null
                                   orderby proc.CR3Value ascending
                                   select proc;

                foreach (var pmetal in nonVMCSprocs)
                {
                    // unassigned, give them a unique entry for now, we should rerun the grouping method
                    if(pmetal.AddressSpaceID == 0)
                    {
                        var ASID = ASGroups.Count + 1;
                        pmetal.AddressSpaceID = ASID;
                        ASGroups.TryAdd(ASID, new ConcurrentBag<DetectedProc> { pmetal });
                    }

                    // this is a process on the bare metal
                    var pt = PageTable.AddProcess(pmetal, memAxs, CollectKernelAS);
                    CollectKernelAS = false;
                    WriteLine($"Process {pmetal.CR3Value:X12} Physical walk w/o SLAT yielded {pmetal.PT.Root.Count} entries, bare metal group is {pmetal.AddressSpaceID}");

                    if (rvList.ContainsKey(pmetal.AddressSpaceID) && rvList[pmetal.AddressSpaceID] == null)
                        rvList[pmetal.AddressSpaceID] = new List<DetectedProc>();

                    if (rvList.ContainsKey(pmetal.AddressSpaceID))
                        rvList[pmetal.AddressSpaceID].Add(pmetal);
                    else
                        rvList.Add(pmetal.AddressSpaceID, new List<DetectedProc>());
                }
            }
             return rvList;
        }
#endregion
        public void DumpFailList()
        {
            var totFails = (from f in Processes
                            where f.PT != null
                            from f2 in f.PT.Failed
                            orderby f2.PTE
                            select f2).AsParallel().AsOrdered();

            if (totFails.Distinct().Count() > 0)
            {
                WriteLine($"{Environment.NewLine}Failed Translations list {totFails.Distinct().Count()};");
                var i = 0;

                foreach (var fail in totFails.Distinct())
                    Write($"{fail.PTE:X16}, " + ((((i++) * 18) / WindowWidth > 0) ? Environment.NewLine : string.Empty));

                WriteLine();
            }
            //foreach (var px in Processes)
            //    if (px.pt != null)
            //        WriteLine($"extracted {proc.PageTableType} PTE from process {proc.vmcs.EPTP:X16}:{proc.CR3Value:X16}, high phys address was {proc.PT.HighestFound}");
        }


        // TODO: remove below here old stuff
#region Dumper

        // TODO: Move this to Dumper.cs or just get rid of this stuff since it's all the super old CLI stuff

        /// <summary>
        /// Memory Dump routines
        /// WARNING: THIS IS LEGACY NON-PYTHON COMPAT STUFF
        /// </summary>
        /// <param name="AS_ToDump"></param>
        public void DumpASToFile(IDictionary<int, List<DetectedProc>> AS_ToDump = null)
        {
            var DumpList = AS_ToDump;
            if(DumpList == null)
            {
                DumpList = new Dictionary<int, List <DetectedProc>> ();
                foreach(var g in ASGroups)
                {
                    DumpList[g.Key] = new List<DetectedProc>();

                    var p = from px in g.Value
                            orderby px.CR3Value
                            select px;

                    foreach (var pp in p)
                        DumpList[pp.AddressSpaceID].Add(pp);
                }
            }

            List <KeyValuePair <VIRTUAL_ADDRESS, PFN>> MemRanges = null;
            List<string> DumpedToDisk = new List<string>();
            Stack<PFN> PFNStack = new Stack<PFN>();
            // instance member
            long ContigSize = -1;

            ForegroundColor = ConsoleColor.Gray;

            string LastDumped = string.Empty;
            int cntDumped = 0;
            WriteLine($"{Environment.NewLine} Address spaces resolved.  Dump method starting. {Environment.NewLine}");
            //using (var memAxs = new Mem(MemFile, null, DetectedDesc))
            var memAxs = MemAccess;
            {
                memAxs.OverrideBufferLoadInput = true;

TripleBreak:

                int asID=0;
                foreach(var AS in DumpList)
                if(DumpList[AS.Key] != null && DumpList[AS.Key].Count() > 0)
                    if(DumpList[AS.Key].Count() > 1)
                        WriteColor(ConsoleColor.Green, $"[{AS.Key}] Contains {DumpList[AS.Key].Count()} entries EPTP/Kernels shared {DumpList[AS.Key][0]}");
                    else
                        WriteColor(ConsoleColor.Yellow, $"[{AS.Key}] Contains {DumpList[AS.Key].Count()} entries EPTP/Kernels shared {DumpList[AS.Key][0]}");

                bool validInput = false;
                do
                {
                    ForegroundColor = ConsoleColor.White;
                    Write("Select an address space: ");
                    var ASselect = ReadLine();
                    validInput = int.TryParse(ASselect, out asID);
                    if (!validInput)
                        WriteLine("just enter the number that coincides with the address space you want to investigate.");
                    if (!DumpList.ContainsKey(asID))
                        validInput = false;

                } while (!validInput);

                WriteColor(ConsoleColor.Green, $"Loading address space entries based on {DumpList[asID][0]}");

                var ToDump = DumpList[asID];

                // sort for convince
                ToDump.Sort((x, y) => { if (x.CR3Value < y.CR3Value) return -1; else if (x.CR3Value > y.CR3Value) return 1; else return 0; });

                while (true)
                {
DoubleBreak:
                    // prompt user
                    for (int i = 0; i < ToDump.Count; i++)
                    {
                        var vmcs = ToDump[i].vmcs == null ? 0 : ToDump[i].vmcs.EPTP;

                        if (ToDump[i].PT == null)
                            PageTable.AddProcess(ToDump[i], memAxs, true);

                        WriteColor(ConsoleColor.Magenta, $"{i} VMCS:{vmcs:X} Process:{ToDump[i].CR3Value:X} (top level) {ToDump[i].PT.Root.Count} type {ToDump[i].PageTableType} group {ToDump[i].Group}");
                    }

                    validInput = false;
                    int procId = 0;
                    do
                    {
                        ForegroundColor = ConsoleColor.White;
                        Write("Select a process to dump: ");
                        var selection = ReadLine();
                        validInput = int.TryParse(selection, out procId);
                        if (!validInput)
                            WriteLine("just enter the number 0 or 1 or 2 or ... that coincides with the process you want to investigate.");

                    } while (!validInput);

                    WriteColor(ConsoleColor.Gray, $"Selected process {procId} {ToDump[procId]}");
                    var tdp = ToDump[procId];

                    var saveLoc = Path.Combine(Path.GetDirectoryName(MemFile), Path.GetFileName(MemFile) + ".");
                    var table = tdp.PT.Root.Entries;
                    bool fKeepGoing = true;

                    while (fKeepGoing)
                    {
                        WriteColor(ConsoleColor.Gray, $"{Environment.NewLine}Listing ranges for {tdp}, {table.PFNCount} entries scanned.");

                        int parse = -1, level = 4;
                        PFN next_table = new PFN();
                        Dictionary<VIRTUAL_ADDRESS, PFN> TableEntries;
                        Dictionary<VIRTUAL_ADDRESS, PFN> LastTableEntries = null;
                        do
                        {
                            TableEntries = table.SubTables;
                            // If we have 0 entries, ensure there really are none and we did
                            // not optimize out pre-buffering everything
                            if (TableEntries.Count() == 0)
                                foreach (var pfn in tdp.PT.ExtractNextLevel(table, level, true)) ;

                            if (TableEntries.Count() == 0)
                            {
                                WriteColor(ConsoleColor.Yellow, $"Entry {parse}:{table.VA}{table.PTE} contains no in-memory pages addressable to this process.");

                                if(LastTableEntries != null)
                                    TableEntries = LastTableEntries;
                                if (level < 4)
                                    level++;

                                if (PFNStack.Count() > 0)
                                    table = PFNStack.Pop();
                                else
                                {
                                    table = tdp.PT.Root.Entries;
                                    level = 4;
                                    TableEntries = table.SubTables;
                                }
                            }

                            var dict_keys = TableEntries.Keys.ToArray();
                            for (int r = 0; r < TableEntries.Count(); r++)
                            {
                                var dict_Val = TableEntries[dict_keys[r]];
                                
                                WriteColor((level & 1) == 1 ? ConsoleColor.Cyan : ConsoleColor.Green, $"{r} Virtual: {dict_keys[r]} \t Physical: {dict_Val.PTE}");
                            }

                            ForegroundColor = ConsoleColor.White;
                            Write($"command ({level}): ");
                            var userSelect = ReadLine().ToLower();

                            if (string.IsNullOrWhiteSpace(userSelect))
                                parse = -1;
                            else if(char.IsLetter(userSelect[0]))
                                switch(userSelect)
                                {
                                    case "u":
                                        if (PFNStack.Count() > 0)
                                        {
                                            table = PFNStack.Pop();
                                            level++;
                                        }
                                        else {
                                            WriteColor(ConsoleColor.Yellow, "Can not go any higher");
                                            table = tdp.PT.Root.Entries;
                                            level = 4;
                                        }
                                        continue;
                                    case "l":
                                        PrintLastDumped(DumpedToDisk);
                                        continue;
                                    case "x":
                                        Environment.Exit(0);
                                        break;
                                    case "p":
                                        goto DoubleBreak;
                                    case "s":
                                        goto TripleBreak;
                                    case "h":
                                    case "r":
                                        ReScanNextLevel(tdp);
                                        break;
                                    case "d":
                                        ReScanNextLevel(tdp, true);
                                        break;
                                    case "a":
                                        AddProcessPageTable(tdp, memAxs);
                                        break;
                                    default:
                                        REPLhelp();
                                        continue;
                                } 
                            else
                                int.TryParse(userSelect, out parse);

                            // extract the key that the user index is referring to and reassign table

                            if (parse >= 0)
                            {
                                PFNStack.Push(table);
                                try
                                {
                                    next_table = TableEntries[TableEntries.Keys.ToArray()[parse]];
                                }
                                catch (Exception ex) { WriteColor(ConsoleColor.Red, $"Exception accessing page table, try again... {ex.ToString()}"); continue; }
                                table = next_table;
                            }
                            if (parse < 0)
                                break;

                            level--;
                            LastTableEntries = TableEntries;
                        } while (level > 0);


                        WriteColor(ConsoleColor.Gray, $"Writing out data into the same folder as the input: {Path.GetDirectoryName(MemFile)}");


                        if (parse < 0)
                        {
                            switch (level)
                            {
                                case 4:
                                    MemRanges = TableEntries.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).SelectMany(z => z.Value.SubTables).ToList();
                                    break;
                                case 3:
                                    MemRanges = TableEntries.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).ToList();
                                    break;
                                case 2:
                                    MemRanges = TableEntries.SelectMany(x => x.Value.SubTables).ToList();
                                    break;
                                case 1:
                                default:
                                    MemRanges = TableEntries.ToList();
                                    break;
                            }

                            foreach (var mr in MemRanges)
                            {
                                LastDumped = WriteRange(mr.Key, mr.Value, saveLoc, ref ContigSize, memAxs);
                                DumpedToDisk.Add(LastDumped);
                                cntDumped++;
                            }
                        }
                        else
                        {
                            var a_range = new KeyValuePair<VIRTUAL_ADDRESS, PFN>(next_table.VA, next_table);
                            LastDumped = WriteRange(a_range.Key, a_range.Value, saveLoc, ref ContigSize, memAxs);
                            DumpedToDisk.Add(LastDumped);
                            cntDumped++;
                        }

                        Write($"All done, last written file {LastDumped} of {cntDumped} so far.  KeepGoing? (y)");
                        var answer = ReadKey();
                        if (answer.Key == ConsoleKey.N)
                            fKeepGoing = false;
                    }
                }
            }
        }

        public void AddProcessPageTable(DetectedProc tdp, Mem memAxs)
        {
            PageTable.AddProcess(tdp, memAxs, true);
        }

        // legacy code
        public void ReScanNextLevel(DetectedProc tdp, bool DisplayOutput = false)
        {
            bool validInput, ignoreSlat;
            int levels;
            do
            {
                WriteColor(ConsoleColor.White, "How many levels to process? (1-4)");
                var selection = ReadLine();
                validInput = int.TryParse(selection, out levels);
                if (!validInput)
                    WriteLine("invalid response.");

            } while (!validInput);

            do
            {
                WriteColor(ConsoleColor.White, "Ignore SLAT? (True|False)");
                var selection = ReadLine();
                validInput = bool.TryParse(selection, out ignoreSlat);
                if (!validInput)
                    WriteLine("invalid response.");

            } while (!validInput);

            if (ignoreSlat)
            {
                tdp.vmcs = null;
                tdp.PT.Root.SLAT = 0;
            }

            tdp.PT.FillTable(true, levels);
            if(DisplayOutput)
            {
                var MemRanges = tdp.PT.Root.Entries.SubTables.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).SelectMany(z => z.Value.SubTables).ToList();
                foreach (var mr in MemRanges)
                    WriteColor(ConsoleColor.Cyan, $" {mr.Key} {mr.Value.PTE}");
            }
        }
        
        public void PrintLastDumped(List<string> LastList)
        {
            foreach(var s in LastList)
                WriteColor(ConsoleColor.DarkCyan, ConsoleColor.Gray, $"Dumped {s} {new FileInfo(s).Length}");
        }

        static void REPLhelp()
        {
            WriteLine("Select by index number the region to expand into (e.g. 1 or 5)");
            WriteLine("u \t Go back up a level");
            WriteLine("p \t Select a different process");
            WriteLine("a \t Select a different Address Space");
            WriteLine("x \t quit");
            WriteLine("l \t list files dumped already");
        }


        public static string WriteRange(VIRTUAL_ADDRESS KEY, PFN VALUE, string BaseFileName, ref long ContigSize, Mem PhysMemReader = null, bool SinglePFNStore = false, bool DumpNULL = false)
        {
            /* WAHBitArray is actually really slow! Use my own
            if (SinglePFNStore && SISmap == null)
                SISmap = new WAHBitArray();
            if(SinglePFNStore)
            {
                if (SISmap.Get((int)VALUE.PTE.PFN))
                    return string.Empty;

                SISmap.Set((int)VALUE.PTE.PFN, true);
            }
                */

            bool GoodRead = false;
            bool canAppend = false;
            var saveLoc = BaseFileName + KEY.Address.ToString("X") + ".bin";
            var lastLoc = BaseFileName + (KEY.Address - ContigSize).ToString("X") + ".bin";

            if (File.Exists(lastLoc))
            {
                canAppend = true;
                ContigSize += 0x1000;
                saveLoc = lastLoc;
            }
            else
                ContigSize = 0x1000;

            var bpage = new byte[0x1000];

            if (DiagOutput)
                WriteColor(VALUE.PTE.Valid ? ConsoleColor.Cyan : ConsoleColor.Red,  $"VA: {KEY:X12}  \t PFN: {VALUE.PTE}");

            // if we have invalid (software managed) page table entries
            // the data may be present, or a prototype or actually in swap.
            // for the moment were only going to dump hardware managed data
            // or feel free to patch this up ;)
            if (!VALUE.PTE.Valid)
                return string.Empty;

            if (VALUE.PTE.LargePage)
            {
                using (var lsavefile = File.OpenWrite(saveLoc))
                {
                    // 0x200 * 4kb = 2MB
                    // TODO: Large pages properly?
                    // TODO: PageCache is still broken in some cases... disable for now here
                    for (int i = 0; i < 0x200; i++)
                    {
                        PhysMemReader.GetPageForPhysAddr(VALUE.PTE, ref bpage, ref GoodRead); 
                        VALUE.PTE.PTE += 0x1000;

                        // write out a null page then
                        if (!GoodRead && DumpNULL)
                            bpage = new byte[0x1000];

                        if(GoodRead || (!GoodRead && DumpNULL))
                            lsavefile.Write(bpage, 0, 4096);
                    }
                    return lastLoc;
                }
            }
            else
            {
                PhysMemReader.GetPageForPhysAddr(VALUE.PTE, ref bpage, ref GoodRead); 

                if (bpage != null && GoodRead || (DumpNULL && UnsafeHelp.IsZero(bpage)))
                {
                    using (var savefile = (canAppend ? File.Open(lastLoc, FileMode.Append, FileAccess.Write, FileShare.ReadWrite) : File.OpenWrite(saveLoc)))
                        savefile.Write(bpage, 0, 4096);

                    return lastLoc;
                }
            }
            ContigSize = 0;
            return string.Empty;
        }
#endregion
    }
}
