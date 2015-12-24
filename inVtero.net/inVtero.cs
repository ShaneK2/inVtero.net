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
using ProtoBuf;
using inVtero.net.Specialties;
using static System.Console;

namespace inVtero.net
{
    /// <summary>
    /// Moving things around to support save state
    /// If it turns out that we are to parse the input aggressively, it may make sense to not have to waste time doing the same analysis over again
    /// 
    /// Rooting everything off of a main class helps the structure a bit
    /// </summary>
    [ProtoContract]
    public class Vtero
    {
        [ProtoMember(1)]
        public string MemFile;
        [ProtoMember(2)]
        public long FileSize;


        [ProtoMember(3)]
        public static bool VerboseOutput { get; set; }

        /// <summary>
        /// I should really get an errorlevel going
        /// </summary>
        public static bool DiagOutput { get; set; }

        public static bool DisableProgressBar { get { return ProgressBarz.DisableProgressBar; } set { ProgressBarz.DisableProgressBar = value; } }

        // eventually we can get to where we know everything
        // grouped and organized
        [ProtoMember(4)]
        public ConcurrentDictionary<EPTP, ConcurrentBag<DetectedProc>> AddressSpace;

        // Every Process detected for a given dump (not yet grouped)
        [ProtoMember(5)]
        public ConcurrentBag<DetectedProc> Processes;
        [ProtoMember(6)]
        // Each VMCS found
        public ConcurrentBag<VMCS> VMCSs;
        [ProtoMember(7)]
        // every PFN at the highest layer (not nested) should be the super set
        public ConcurrentBag<PFN> PFNs;

        //WAHBitArray PFNdb;
        [ProtoMember(8)]
        public Dictionary<int, List<DetectedProc>> ASGroups;

        [ProtoMember(9)]
        int Phase;

        [ProtoMember(10)]
        MemoryDescriptor DetectedDesc;

        /// <summary>
        /// Set OverRidePhase to force a re-run of a stage
        /// </summary>
        public bool OverRidePhase;
        Scanner scan;

        public Vtero()
        {
            Processes = new ConcurrentBag<DetectedProc>();
            VMCSs = new ConcurrentBag<VMCS>();
            PFNs = new ConcurrentBag<PFN>();

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

            if (MemFile.EndsWith(".dmp"))
            {
                var dump = new CrashDump(MemFile);
                if (dump.IsSupportedFormat())
                    DetectedDesc = dump.PhysMemDesc;
            }
            else if(MemFile.EndsWith(".vmss") || MemFile.EndsWith(".vmsn"))
            {
                var dump = new VMWare(MemFile);
                if (dump.IsSupportedFormat())
                {
                    DetectedDesc = dump.PhysMemDesc;

                    MemFile = dump.MemFile;
                }
            }

            scan = new Scanner(MemFile);
            FileSize = new FileInfo(MemFile).Length;

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

        public static Vtero CheckpointRestoreState(string SaveFile)
        {
            Vtero ThisInstance = null;

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

            scan.VMCSScanSet = Processes.GroupBy(p => p.CR3Value).Select(pg => pg.First()).ToArray();

            var rv = scan.Analyze();

            foreach (var vm in scan.HVLayer)
                VMCSs.Add(vm);

            Phase = 3;

            return rv;
        }

        /// <summary>
        /// Group address spaces into related buckets
        /// 
        /// We will assign an address space ID to each detected proc so we know what process belongs with who
        /// After AS grouping we will know what EPTP belongs to which AS since one of the DP's will have it's CR3 in the VMCS 
        /// </summary>
        /// <param name="pTypes">Types to scan for, this is of the already detected processs list so it's already filtered really</param>
        public void GroupAS(PTType pTypes = PTType.UNCONFIGURED)
        {
            var PT2Scan = pTypes == PTType.UNCONFIGURED ? PTType.ALL : pTypes;

            if (Phase >=3 && OverRidePhase)
                return;

            // To join an AS group we want to see > 50% corelation which is a lot considering were only interperating roughly 10-20 values (more like 12)
            var p = from proc in Processes
                    where (((proc.PageTableType & PT2Scan) == proc.PageTableType))
                    orderby proc.CR3Value ascending
                    select proc;


            ASGroups = new Dictionary<int, List<DetectedProc>>();

            // we trim out the known recursive/self entries since they will naturally not be equivalent
            var AlikelyKernelSet = from ptes in p.First().TopPageTablePage
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

            int totUngrouped = Processes.Count();
            int CurrASID = 1;

            var grouped = new List<DetectedProc>();

            ASGroups[CurrASID] = new List<DetectedProc>();
            while (true)
            {
                ForegroundColor = ConsoleColor.Yellow;
                WriteLine("Scanning for group correlations");
                ForegroundColor = ConsoleColor.Cyan;
                foreach (var proc in p)
                {
                    var currKern = from ptes in proc.TopPageTablePage
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

                    var interSection = currKern.Intersect(AlikelyKernelSet);
                    var corralated = interSection.Count() * 1.00 / AlikelyKernelSet.Count();


                    if (corralated > 0.50 && !ASGroups[CurrASID].Contains(proc))
                    {
                        WriteLine($"MemberProces: Group {CurrASID} Type [{proc.PageTableType}] GroupCorrelation [{corralated:P3}] PID [{proc.CR3Value:X}]");

                        proc.AddressSpaceID = CurrASID;
                        ASGroups[CurrASID].Add(proc);
                        // global list to quickly scan
                        grouped.Add(proc);
                    }
                }
                ForegroundColor = ConsoleColor.Yellow;

                var totGrouped = (from g in ASGroups.Values
                                  select g).Sum(x => x.Count());

                Console.WriteLine($"Finished Group {CurrASID} collected size {ASGroups[CurrASID].Count()} next group");
                // if there is more work todo, setup an entry for testing
                if (totGrouped < totUngrouped)
                {
                    CurrASID++;
                    ASGroups[CurrASID] = new List<DetectedProc>();
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
            var eptpz = VMCSs.GroupBy(eptz => eptz.EPTP).Select(ept => ept.First()).ToArray();

            // find groups dominated by each vmcs
            var VMCSGroup = from aspace in ASGroups.Values.AsEnumerable()
                            from ept in eptpz
                            where aspace.Any(adpSpace => adpSpace == ept.dp)
                            select new { AS = aspace, EPTctx = ept };

            // link the proc back into the eptp
            foreach (var ctx in VMCSGroup)
                foreach (var dp in ctx.AS)
                    dp.vmcs = ctx.EPTctx;

            Phase = 4;
            // were good, all Processes should have a VMCS if applicable and be identifiable by AS ID
        }

        /// <summary>
        /// This routine is fairly expensive, maybe unnecessary as well but it demo's walking the page table + EPT.
        /// You can connect an address space dumper really easily
        /// </summary>
        /// <param name="MemSpace">The list of VMCS/EPTP configurations which will alter the page table use</param>
        /// <param name="Procs">Detected procs to query</param>
        /// <param name="pTypes">Type bitmas to interpreate</param>
        public void ExtrtactAddressSpaces(IOrderedEnumerable<VMCS> MemSpace = null, ConcurrentBag<DetectedProc> Procs = null, PTType pTypes = PTType.UNCONFIGURED)
        {
            var PT2Scan = pTypes == PTType.UNCONFIGURED ? (PTType.Windows | PTType.HyperV | PTType.GENERIC) : pTypes;
            var procList = Procs == null ? Processes : Procs;
            //var memSpace = MemSpace == null ? VMCSs.First() : MemSpace.First();

            var memSpace = MemSpace == null ? VMCSs.GroupBy(x => x.EPTP).Select(xg => xg.First()) : MemSpace; 
            
            var p = from proc in Processes
                    where (((proc.PageTableType & PT2Scan) == proc.PageTableType))
                    orderby proc.CR3Value ascending
                    select proc;

            int pcnt = Processes.Count();
            int vmcnt = memSpace.Count();
            var tot = pcnt * vmcnt;
            var curr = 0;

            var AlikelyKernelSet = from ptes in p.First().TopPageTablePage
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

            Console.ForegroundColor = ConsoleColor.Yellow;
            WriteLine($"assessing {tot} address spaces");
            ProgressBarz.Progress = 0;

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
                    foreach (var proc in p)
                    //Parallel.ForEach(p, (proc) =>
                    {
                        try
                        {
                            proc.vmcs = space;
                            var pt = PageTable.AddProcess(proc, memAxs, false);
                            if (pt != null && VerboseOutput)
                            {
                                // If we used group detection correlation a valid EPTP should work for every process    

                                if (proc.vmcs != null && proc.PT.RootPageTable.PFNCount > proc.TopPageTablePage.Count())
                                {
                                    WriteLine($"Virtualized Process PT Entries [{proc.PT.RootPageTable.PFNCount}] Type [{proc.PageTableType}] PID [{proc.vmcs.EPTP:X}:{proc.CR3Value:X}]");
                                }
                                else {
                                    WriteLine($"canceling evaluation of bad EPTP for this group");
                                    foreach (var pxc in Processes)
                                        pxc.vmcs = null;
                                    break;
                                }

                                sx++;
                                curr++;
                                var progress = Convert.ToInt32((Convert.ToDouble(curr) / Convert.ToDouble(tot) * 100.0) + 0.5);
                                ProgressBarz.RenderConsoleProgress(progress);
                            }
                        }
                        catch (ExtendedPageNotFoundException eptpX)
                        {
                            WriteLine($"Bad EPTP selection;{Environment.NewLine}\tEPTP:{eptpX.RequestedEPTP}{Environment.NewLine}\t CR3:{eptpX.RequestedCR3}{Environment.NewLine} Attempting to skip to next proc.");

                            memAxs.DumpPFNIndex();
                        }
                        catch (MemoryRunMismatchException mrun)
                        {
                            WriteLine($"Error in accessing memory for PFN {mrun.PageRunNumber:X16}");

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
                        WriteLine($"{sx} VMCS dominated process address spaces and were decoded succsessfully.");
                    //});
                    }
                }
            }
            //});


            using (var memAxs = new Mem(MemFile, null, DetectedDesc))
            {
                var nonVMCSprocs = from px in Processes
                                   where px.vmcs == null
                                   select px;

                foreach (var pmetal in nonVMCSprocs)
                {
                    // this is a process on the bare metal
                    var pt = PageTable.AddProcess(pmetal, memAxs, false);
                     WriteLine($"Process {pmetal.CR3Value:X16} Physical walk w/o SLAT yielded {pmetal.PT.RootPageTable.PFNCount} entries");
                }
            }
        }

        public void DumpFailList()
        {
            var totFails = (from f in Processes
                            where f.PT != null
                            from f2 in f.PT.Failed
                            orderby f2.PTE
                            select f2).AsParallel().AsOrdered();

            WriteLine($"Failed list {totFails.Distinct().Count()};");
            var i = 0;

            foreach (var fail in totFails.Distinct())
                Write($"{fail.PTE:X16}, " + ((((i++) * 18) / WindowWidth > 0) ? Environment.NewLine : string.Empty));

            WriteLine();

            //foreach (var px in Processes)
            //    if (px.pt != null)
            //        WriteLine($"extracted {proc.PageTableType} PTE from process {proc.vmcs.EPTP:X16}:{proc.CR3Value:X16}, high phys address was {proc.PT.HighestFound}");
        }

        public void DumpASToFile()
        {
            
            using (var memAxs = new Mem(MemFile, null, DetectedDesc))
            {
                var tdp = (from p in Processes
                                  where p.AddressSpaceID == 1
                                  orderby p.CR3Value ascending
                                  select p);

                // as a test let's find the process with the most to dump
                var largest = (from p in Processes
                               where p.AddressSpaceID == 1
                               orderby p.PT.RootPageTable.PFNCount descending
                               select p).Take(1).First();


                var pml4 = largest.PT.RootPageTable;

                WriteLine($"Test dumping {largest}, {pml4.PFNCount} entries scanned.");

                var MemRanges = pml4.SubTables.SelectMany(x => x.Value.SubTables);

                WriteLine($"MemRanges = {MemRanges.Count()} available.");
                foreach (var pte in MemRanges)
                    WriteLine($"VA: {pte.Key:X16}  \t PFN: {pte.Value.PTE}");
            }
        }
    }
}
