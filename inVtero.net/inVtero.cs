// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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
        public string MemFile;
        public long FileSize;
        public double GroupThreshold;


        public static bool VerboseOutput { get; set; }

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

        public int Phase;

        public MemoryDescriptor DetectedDesc;

        /// <summary>
        /// Set OverRidePhase to force a re-run of a stage
        /// </summary>
        public bool OverRidePhase;

        [ProtoMember(99)]
        Scanner scan;

        public Vtero()
        {

            Processes = new ConcurrentBag<DetectedProc>();
            VMCSs = new ConcurrentDictionary<long, VMCS>();
            GroupThreshold = 0.5;
            Phase = 1;

#if DEBUG 
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

            scan = new Scanner(MemFile);
            FileSize = new FileInfo(MemFile).Length;

            if (MemFile.EndsWith(".dmp"))
            {
                var dump = new CrashDump(MemFile);
                if (dump.IsSupportedFormat(this))
                    DetectedDesc = dump.PhysMemDesc;

            }
            else if(MemFile.EndsWith(".vmss") || MemFile.EndsWith(".vmsn") || MemFile.EndsWith(".vmem"))
            {
                var dump = new VMWare(MemFile);
                if (dump.IsSupportedFormat())
                {
                    DetectedDesc = dump.PhysMemDesc;

                    MemFile = dump.MemFile;
                }
            }                       
        }

        public Vtero(string MemoryDump, MemoryDescriptor MD) : this(MemoryDump)
        {
            DetectedDesc = MD;
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

            using (var SerData = File.OpenRead(SaveFile))
                ThisInstance = Serializer.Deserialize<inVtero.net.Vtero>(SerData);

            return ThisInstance;
        }

        public IEnumerable<long> ScanValue(bool Is64, ulong Value, int ScanOnlyFor = 0)
        {
            scan.Scan64 = Is64;
            scan.HexScanDword = (uint) Value;
            scan.HexScanUlong = Value;
            scan.ScanMode = PTType.VALUE;

            return scan.BackwardsValueScan(ScanOnlyFor);
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

            scan.VMCSScanSet = Processes.GroupBy(p => p.CR3Value).Select(pg => pg.First()).ToArray();

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
            var mem = new Mem(MemFile, null, DetectedDesc) { OverrideBufferLoadInput = true };
            DetectedProc Proc = null;
            foreach (var Procz in ASGroups[GroupID])
            {
                Proc = Procz;

                if (Proc.PT == null)
                    PageTable.AddProcess(Proc, mem, true, 4);

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

        public ConcurrentDictionary<long, VAScanType> ModuleScan(DetectedProc dp, Mem mem, long Start, long End)
        {
            Mem localMem = null;

            /// TODO: uhhhhh move mem up into DP
            if (mem != null)
                localMem = mem;
            else if (dp.PT != null && dp.PT.mem != null)
                localMem = dp.PT.mem;
            else if (dp.MemAccess != null)
                localMem = dp.MemAccess;
            else {
                localMem = new Mem(MemFile, null, DetectedDesc);
                if (dp.PT == null)
                    PageTable.AddProcess(dp, localMem, true, 4);
            }

            VirtualScanner VS = new VirtualScanner(dp, localMem);

            VS.ScanMode = VAScanType.PE_FAST;

            ConcurrentDictionary<long, VAScanType> rv = new ConcurrentDictionary<long, VAScanType>();

            foreach (var range in dp.PT.EnumerateVA(Start, End))
            {
                VS.Run(range.Key.Address, range.Key.Address + (range.Value.PTE.LargePage ? (1024 * 1024 * 2) : 0x1000));
                foreach (var item in VS.DetectedFragments)
                    rv.TryAdd(item.Key, item.Value);
            }
            return rv;
        }

        /// <summary>
        /// Group address spaces into related buckets
        /// 
        /// We will assign an address space ID to each detected proc so we know what process belongs with who
        /// After AS grouping we will know what EPTP belongs to which AS since one of the DP's will have it's CR3 in the VMCS 
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
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

            int totUngrouped = Processes.Count();
            int CurrASID = 1;
            int LastGroupTotal = 0;
            var grouped = new ConcurrentBag<DetectedProc>();

            WriteLine($"Scanning for group correlations total processes {totUngrouped}");
            ASGroups[CurrASID] = new ConcurrentBag<DetectedProc>();

            while (true)
            {
                ForegroundColor = ConsoleColor.Yellow;
                Parallel.ForEach(p, (proc) =>
                {
                    var currKern = from ptes in proc.TopPageTablePage
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

                    var interSection = currKern.Intersect(AlikelyKernelSet);
                    var correlated = interSection.Count() * 1.00 / AlikelyKernelSet.Count();


                    if (correlated > GroupThreshold && !ASGroups[CurrASID].Contains(proc))
                    {
                        if(ForegroundColor != ConsoleColor.Cyan)
                            ForegroundColor = ConsoleColor.Cyan;

                        WriteLine($"MemberProces: Group {CurrASID} Type [{proc.PageTableType}] GroupCorrelation [{correlated:P3}] PID [{proc.CR3Value:X}]");

                        proc.AddressSpaceID = CurrASID;
                        ASGroups[CurrASID].Add(proc);
                        // global list to quickly scan
                        grouped.Add(proc);
                    }
                });

                ForegroundColor = ConsoleColor.Yellow;

                var totGrouped = (from g in ASGroups.Values
                                  select g).Sum(x => x.Count());

                Console.WriteLine($"Finished Group {CurrASID} collected size {ASGroups[CurrASID].Count()} next group");
                // if there is more work todo, setup an entry for testing
                if (totGrouped < totUngrouped)
                {
                    // if we wind up here 
                    // there has been no forward progress in isolating further groups
                    if(LastGroupTotal == totGrouped)
                    {
                        ForegroundColor = ConsoleColor.Red;
                        WriteLine($"Terminating with non-grouped process candidates.  GroupThreshold may be too high. {GroupThreshold}");
                        var pz = from px in Processes
                                where px.AddressSpaceID == 0
                                select px;
                        
                        // just add the ungrouped processes as a single each bare metal
                        foreach (var px in pz)
                        {
                            WriteLine(px);
                            CurrASID++;
                            px.AddressSpaceID = CurrASID;
                            ASGroups[CurrASID] = new ConcurrentBag<DetectedProc>() { px };
                        }

                        ForegroundColor = ConsoleColor.Yellow;
                        break;
                    }


                    CurrASID++;
                    ASGroups[CurrASID] = new ConcurrentBag<DetectedProc>();
                    WriteLine($"grouped count ({totGrouped}) is less than total process count ({totUngrouped}, rescanning...)");
                    LastGroupTotal = totGrouped;
                }
                else
                    break; // we grouped them all!

                /// Isolate next un-grouped PageTable
                var UnGroupedProc = from nextProc in Processes
                                   where !grouped.Contains(nextProc)
                                   select nextProc;

                AlikelyKernelSet = from ptes in UnGroupedProc.First().TopPageTablePage
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;
            }

            Console.WriteLine($"Done All process groups.");

            // after grouping link VMCS back to the group who 'discovered' the VMCS in the first place!
            var eptpz = VMCSs.Values.GroupBy(eptz => eptz.EPTP).Select(ept => ept.First()).ToArray();

            // find groups dominated by each vmcs
            var VMCSGroup = from aspace in ASGroups.AsEnumerable()
                            from ept in eptpz
                            where aspace.Value.Any(adpSpace => adpSpace == ept.dp)
                            select new { AS = aspace, EPTctx = ept };

            // link the proc back into the eptp
            foreach (var ctx in VMCSGroup)
                foreach (var dp in ctx.AS.Value)
                    dp.vmcs = ctx.EPTctx;

            // resort by CR3
            foreach (var ctx in  ASGroups)
            {
                var dpz = from d in ctx.Value
                          orderby d.CR3Value descending
                          select d;

                ASGroups[ctx.Key] = new ConcurrentBag<DetectedProc>(dpz);
             
            }

            Phase = 4;
            // were good, all Processes should have a VMCS if applicable and be identifiable by AS ID
        }

        /// <summary>
        /// This routine is fairly expensive, maybe unnecessary as well but it demo's walking the page table + EPT.
        /// You can connect an address space dumper really easily
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

            int pcnt = Processes.Count();
            int vmcnt = memSpace.Count();
            var tot = pcnt * vmcnt;
            var curr = 0;
            bool CollectKernelAS = true;

            var CurrColor = ForegroundColor;

            Console.ForegroundColor = ConsoleColor.Yellow;
            WriteLine($"assessing {tot} address space combinations");
            ProgressBarz.RenderConsoleProgress(0);

            var VMCSTriage = new Dictionary<VMCS, int>();

            //Parallel.ForEach(memSpace, (space) =>
            foreach (var space in memSpace)
            {
                // we do it this way so that parallelized tasks do not interfere with each other 
                // overall it may blow the cache hit ratio but will tune a single task to see the larger/better cache
                // versus multicore, my suspicion is that multi-core is better
                using (var memAxs = new Mem(MemFile, null, DetectedDesc))
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
                        foreach(var proc in orderedGroup.SelectMany(x => x))
                        //Parallel.ForEach(p, (proc) =>
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
                                        if(VerboseOutput)
                                            WriteLine($"{rvList[grp.Key].Count()} of {grp.Value.Count} Virtualized Process PT Entries [{proc.PT.Root.Count}] Type [{proc.PageTableType}] PID [{proc.vmcs.EPTP:X}:{proc.CR3Value:X}]");

                                        // collect process into now joined EPTP<->Proc
                                        rvList[grp.Key].Add(proc);

                                        if(rvList[grp.Key].Count() == grp.Value.Count && VerboseOutput)
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
                                            ForegroundColor = ConsoleColor.Red;
                                            WriteLine($"canceling evaluation of bad EPTP for this group/Address Space ({grp.Key})");
                                            foreach (var p in Processes)
                                                if (p.vmcs != null && p.vmcs.EPTP == space.EPTP && p.AddressSpaceID == proc.AddressSpaceID)
                                                    p.vmcs = null;

                                            ForegroundColor = CurrColor;
                                            rvList[grp.Key] = null;
                                        }
                                        break;
                                    }

                                    sx++;
                                    curr++;
                                }
                                var progress = Convert.ToInt32((Convert.ToDouble(curr) / Convert.ToDouble(tot) * 100.0) + 0.5);
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
            //});

            CollectKernelAS = true;
            // a backup to test a non-VMCS 
            using (var memAxs = new Mem(MemFile, null, DetectedDesc))
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

        #region Dumper

        // TODO: Move this to Dumper.cs

        /// <summary>
        /// Memory Dump routines
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
            ContigSize = -1;

            ForegroundColor = ConsoleColor.Gray;

            string LastDumped = string.Empty;
            int cntDumped = 0;
            WriteLine($"{Environment.NewLine} Address spaces resolved.  Dump method starting. {Environment.NewLine}");
            using (var memAxs = new Mem(MemFile, null, DetectedDesc))
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
                        WriteLine("just enter the number 0 or 1 or 2 or ... that coincides with the address space you want to investigate.");

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
                            PageTable.AddProcess(ToDump[i], memAxs, true, 1);

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
                                foreach (var pfn in tdp.PT.ExtractNextLevel(table, true, level)) ;

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
                                LastDumped = WriteRange(mr, saveLoc, memAxs);
                                DumpedToDisk.Add(LastDumped);
                                cntDumped++;
                            }
                        }
                        else
                        {
                            var a_range = new KeyValuePair<VIRTUAL_ADDRESS, PFN>(next_table.VA, next_table);
                            LastDumped = WriteRange(a_range, saveLoc, memAxs);
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

        void AddProcessPageTable(DetectedProc tdp, Mem memAxs)
        {
            PageTable.AddProcess(tdp, memAxs, true);
        }

        void ReScanNextLevel(DetectedProc tdp, bool DisplayOutput = false)
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

        void WriteColor(ConsoleColor ForeGround, string var)
        {
            ForegroundColor = ForeGround;
            WriteLine(var);
        }
        void WriteColor(ConsoleColor ForeGround, ConsoleColor BackGround, string var)
        {
            BackgroundColor = BackGround;
            ForegroundColor = ForeGround;
            WriteLine(var);
        }

        void PrintLastDumped(List<string> LastList)
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


        long ContigSize;

        string WriteRange(KeyValuePair<VIRTUAL_ADDRESS, PFN> pte, string BaseFileName, Mem PhysMemReader)
        {
            bool canAppend = false;
            var saveLoc = BaseFileName + pte.Key.Address.ToString("X") + ".bin";
            var lastLoc = BaseFileName + (pte.Key.Address - ContigSize).ToString("X") + ".bin";

            if (File.Exists(lastLoc))
            {
                canAppend = true;
                ContigSize += 0x1000;
            }
            else
                ContigSize = 0x1000;

            long[] block = new long[0x200]; // 0x200 * 8 = 4k
            byte[] bpage = new byte[0x1000];


            unsafe
            {
                // block may be set to null by the GetPageForPhysAddr call, so we need to remake it every time through...
                block = new long[0x200]; // 0x200 * 8 = 4k
                bpage = new byte[0x1000];

                fixed (void* lp = block, bp = bpage)
                {

                    if (DiagOutput)
                    {
                        if (!pte.Value.PTE.Valid)
                            Console.ForegroundColor = ConsoleColor.Red;
                        else
                            Console.ForegroundColor = ConsoleColor.Cyan;

                        WriteLine($"VA: {pte.Key:X12}  \t PFN: {pte.Value.PTE}");

                    }

                    // if we have invalid (software managed) page table entries
                    // the data may be present, or a prototype or actually in swap.
                    // for the moment were only going to dump hardware managed data
                    // or feel free to patch this up ;)
                    if (!pte.Value.PTE.Valid)
                        return string.Empty;

                    if (pte.Value.PTE.LargePage)
                    {
                        using (var lsavefile = (canAppend ? File.Open(lastLoc, FileMode.Append, FileAccess.Write, FileShare.ReadWrite) : File.OpenWrite(saveLoc)))
                            // 0x200 * 4kb = 2MB
                            // TODO: Large pages properly
                            for (int i = 0; i < 0x200; i++)
                            {
                                try { PhysMemReader.GetPageForPhysAddr(pte.Value.PTE, ref block); } catch (Exception ex) { }
                                pte.Value.PTE.PTE += (i * 0x1000);
                                if (block == null)
                                    break;

                                Buffer.MemoryCopy(lp, bp, 4096, 4096);
                                lsavefile.Write(bpage, 0, 4096);
                            }
                    }
                    else
                    {
                        try { PhysMemReader.GetPageForPhysAddr(pte.Value.PTE, ref block); } catch (Exception ex) { }

                        if (block != null)
                        using (var savefile = (canAppend ? File.Open(lastLoc, FileMode.Append, FileAccess.Write, FileShare.ReadWrite) : File.OpenWrite(saveLoc)))
                            {
                            Buffer.MemoryCopy(lp, bp, 4096, 4096);
                            savefile.Write(bpage, 0, 4096);
                        }
                    }
                }
            }
            return saveLoc;
        }
        #endregion


    }
}
