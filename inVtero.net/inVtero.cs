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
using static System.Console;

namespace inVtero.net
{
    /// <summary>
    /// Moving things around to support save state
    /// If it turns out that we are to parse the input aggressivly, it may make sence to not have to waste time doing the same analysis over again
    /// 
    /// Rooting everything off of a main class helps the structure a bit
    /// </summary>
    public class Vtero
    {
        public string MemFile;
        public long FileSize {  get { if(scan != null) return scan.FileSize; return 0; } }
        public static bool VerboseOutput { get; set; }

        Scanner scan;

        public Vtero()
        {
            Processes = new ConcurrentBag<DetectedProc>();
            VMCSs = new ConcurrentBag<VMCS>();
            PFNs = new ConcurrentBag<PFN>();


            ProgressBarz.pBarColor = ConsoleColor.Yellow;

#if DEBUG 
            VerboseOutput = true;
#endif
        }

        public Vtero(string MemoryDump) :this()
        {
            MemFile = MemoryDump;
            scan = new Scanner(MemFile);
        }

        public int ProcDetectScan(PTType Modes, int DetectOnly = 0)
        {
            scan.ScanMode = Modes;

            var rv = scan.Analyze(DetectOnly);

            foreach (var p in scan.DetectedProcesses.Values)
                Processes.Add(p);

            return rv;
        }

        public int VMCSScan()
        {
            scan.ScanMode = PTType.VMCS;

            //scan.VMCSScanSet = (from dp in Processes
            //                    group dp by dp.CR3Value into CR3Masters
            //                    select new KeyValuePair<long, DetectedProc>(CR3Masters.Key, CR3Masters.First())).AsParallel();

            scan.VMCSScanSet = Processes.GroupBy(p => p.CR3Value).Select(pg => pg.First()).ToArray();
       


            var rv = scan.Analyze();

            foreach (var vm in scan.HVLayer)
                VMCSs.Add(vm);

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


                /// Isolate next ungrouped PageTable
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

            // were good, all Processes should have a VMCS if applicable and be identifiable by AS ID
        }

        /// <summary>
        /// This routine is fairly expensive, maybe unnessisary as well but it demo's walking the page table + EPT.
        /// You can connect an address space dumper really easially
        /// </summary>
        /// <param name="MemSpace">The list of VMCS/EPTP configurations which will alter the page table use</param>
        /// <param name="Procs">Detected procs to query</param>
        /// <param name="pTypes">Type bitmas to interpreate</param>
        public void ExtrtactAddressSpaces(IOrderedEnumerable<VMCS> MemSpace = null, ConcurrentBag<DetectedProc> Procs = null, PTType pTypes = PTType.UNCONFIGURED)
        {
            var PT2Scan = pTypes == PTType.UNCONFIGURED ? (PTType.Windows | PTType.HyperV | PTType.GENERIC) : pTypes;
            var procList = Procs == null ? Processes : Procs;
            //var memSpace = MemSpace == null ? VMCSs.First() : MemSpace.First();

            var memSpace = MemSpace == null ? VMCSs.GroupBy(x => x.EPTP).Select(xg => xg.First()) : MemSpace; //.Where(xw => xw.All(xz => xz.EPTP == 0x1138601E))

            var p = from proc in Processes
                    where (((proc.PageTableType & PT2Scan) == proc.PageTableType))
                    orderby proc.CR3Value ascending
                    select proc;

            int pcnt = Processes.Count();
            int vmcnt = memSpace.Count();
            int tot = pcnt * vmcnt;
            int curr = 0;

            var AlikelyKernelSet = from ptes in p.First().TopPageTablePage
                                   where ptes.Key > 255 && MagicNumbers.Each.All(ppx => ppx != ptes.Key)
                                   select ptes.Value;

            Console.ForegroundColor = ConsoleColor.Yellow;
            WriteLine($"assessing {tot} address spaces");
            ProgressBarz.Progress = 0;
            Parallel.ForEach(memSpace, (space) =>
            //foreach (var space in memSpace)
            {
                using (var memAxs = new Mem(MemFile))
                {
                    var sx = 0;
                    //foreach (var proc in p)
                    Parallel.ForEach(p, (proc) =>
                    { 
                        try
                        {
                            proc.vmcs = space;
                            var pt = PageTable.AddProcess(proc, memAxs);
                            if (pt != null && VerboseOutput)
                            {
                                WriteLine($"PT Entries [{proc.PT.RootPageTable.PFNCount}] Type [{proc.PageTableType}] PID [{proc.vmcs.EPTP:X}:{proc.CR3Value:X}]");

                                sx++;
                                curr++;
                                var progress = Convert.ToInt32((Convert.ToDouble(curr) / Convert.ToDouble(tot) * 100.0) + 0.5);
                                ProgressBarz.RenderConsoleProgress(progress);

                                WriteLine($"CorrectMap: {Mem.cntInAccessor}  NewMap: {Mem.cntOutAccsor}");

                            }
                        }
                        catch (ExtendedPageNotFoundException eptpX)
                        {
                            WriteLine($"Bad EPTP selection;{Environment.NewLine}\tEPTP:{eptpX.RequestedEPTP}{Environment.NewLine}\t CR3:{eptpX.RequestedCR3}{Environment.NewLine} Attempting to skip to next proc.");
                        }
                        catch (MemoryRunMismatchException mrun)
                        {
                            WriteLine($"Error in accessing memory for PFN {mrun.PageRunNumber:X16}");
                        }
                        catch (PageNotFoundException pnf)
                        {
                            WriteLine($"Error in selecting page, see {pnf}");
                        }
                        catch(Exception ex)
                        {
                            WriteLine($"Error in memspace extraction: {ex.ToString()}");
                        }

                        WriteLine($"{sx} VMCS dominated process address spaces and were decoded succsessfully.");


                    });
                    //}
                }
            //}
            });
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
            


            using (var memAxs = new Mem(MemFile))
            {
                var tdp = (from p in Processes
                                  where p.AddressSpaceID == 1 && p.vmcs != null
                                  orderby p.CR3Value ascending
                                  select p);

                Parallel.ForEach(tdp, (x) =>
                {
                    //foreach (var x in tdp)
                    PageTable.AddProcess(x, memAxs);
                    WriteLine($"PID {x.CR3Value:X} cnt:{x.PT.RootPageTable.PFNCount}");
                });

                var largest = (from p in Processes
                               where p.AddressSpaceID == 1 && p.vmcs != null
                               orderby p.PT.RootPageTable.PFNCount ascending
                               select p).Take(1).First();

                PageTable.AddProcess(largest, memAxs);


                var pml4 = largest.PT.RootPageTable;

                WriteLine($"Test dumping {largest}, {pml4.PFNCount} entries scanned.");

                var MemRanges = pml4.SubTables.SelectMany(x => x.Value.SubTables);

                WriteLine($"MemRanges = {MemRanges.Count()} available.");
                foreach (var pte in largest.TopPageTablePage)
                    WriteLine($"VA = {pte.Key:X}  {pte.Value}");
            }
        }

        // eventually we can get to where we know everything
        // grouped and organized
        public ConcurrentDictionary<EPTP, ConcurrentBag<DetectedProc>> AddressSpace;

        // Every Process detecetd for a given dump (not yet grouped)
        public ConcurrentBag<DetectedProc> Processes;

        // Each VMCS found
        public ConcurrentBag<VMCS> VMCSs;

        // every PFN at the highest layer (not nested) should be the super set
        public ConcurrentBag<PFN> PFNs;

        //WAHBitArray PFNdb;

        public Dictionary<int, List<DetectedProc>> ASGroups;

    }
}
