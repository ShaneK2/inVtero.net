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
using System.Runtime.InteropServices;
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
        public ConcurrentDictionary<long, VMCS> VMCSs;

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
            VMCSs = new ConcurrentDictionary<long, VMCS>();

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
            else if(MemFile.EndsWith(".vmss") || MemFile.EndsWith(".vmsn") || MemFile.EndsWith(".vmem"))
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
                if(!VMCSs.ContainsKey(vm.EPTP))
                    VMCSs.TryAdd(vm.EPTP, vm);

            rv = VMCSs.Count();
            Phase = 3;

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

            if (Phase >=3 && OverRidePhase)
                return;

            // To join an AS group we want to see > 50% correlation which is a lot considering were only interoperating roughly 10-20 values (more like 12)
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
                    var correlated = interSection.Count() * 1.00 / AlikelyKernelSet.Count();


                    if (correlated > 0.50 && !ASGroups[CurrASID].Contains(proc))
                    {
                        WriteLine($"MemberProces: Group {CurrASID} Type [{proc.PageTableType}] GroupCorrelation [{correlated:P3}] PID [{proc.CR3Value:X}]");

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
        public List<DetectedProc> ExtrtactAddressSpaces(IOrderedEnumerable<VMCS> MemSpace = null, ConcurrentBag<DetectedProc> Procs = null, PTType pTypes = PTType.UNCONFIGURED)
        {
            List<DetectedProc> rvList = new List<DetectedProc>();

            var PT2Scan = pTypes == PTType.UNCONFIGURED ? (PTType.Windows) : pTypes; //  | PTType.HyperV | PTType.GENERIC
            var procList = Procs == null ? Processes : Procs;
            //var memSpace = MemSpace == null ? VMCSs.First() : MemSpace.First();
            
            var memSpace = MemSpace == null ? VMCSs.Values.GroupBy(x => x.EPTP).Select(xg => xg.First()) : MemSpace;

            int pcnt = Processes.Count();
            int vmcnt = memSpace.Count();
            var tot = pcnt * vmcnt;
            var curr = 0;
            bool CollectKernelAS = true;

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
                    // only collect kernel VA one time
                    CollectKernelAS = true;
                    var sx = 0;
                    foreach (var proc in from proc in Processes
                                       where (((proc.PageTableType & PT2Scan) == proc.PageTableType))
                                       orderby proc.CR3Value ascending
                                       select proc) 
                    //Parallel.ForEach(p, (proc) =>
                    {
                        try
                        {
                            // this is killing memory, probably not needed
                            //var proc = px.Clone<DetectedProc>();
                            proc.vmcs = space;

                            var pt = PageTable.AddProcess(proc, memAxs, CollectKernelAS);
                            CollectKernelAS = false;
                            if (pt != null && VerboseOutput)
                            {
                                // If we used group detection correlation a valid EPTP should work for every process    
                                // so if it's bad we skip the entire evaluation
                                if (proc.vmcs != null && proc.PT.Root.Count > proc.TopPageTablePage.Count())
                                {
                                    WriteLine($"Virtualized Process PT Entries [{proc.PT.Root.Count}] Type [{proc.PageTableType}] PID [{proc.vmcs.EPTP:X}:{proc.CR3Value:X}]");
                                    rvList.Add(proc);
                                }
                                else {
                                    WriteLine($"canceling evaluation of bad EPTP for this group");
                                    foreach (var pxc in Processes)
                                    {
                                        pxc.vmcs = null;
                                        pxc.PT = null;
                                    }
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
                        WriteLine($"{sx} VMCS dominated process address spaces and were decoded successfully.");
                    //});
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

                foreach (var px in nonVMCSprocs)
                {
                    var pmetal = px.Clone<DetectedProc>();

                    // this is a process on the bare metal
                    var pt = PageTable.AddProcess(pmetal, memAxs, CollectKernelAS);
                    CollectKernelAS = false;
                    WriteLine($"Process {pmetal.CR3Value:X16} Physical walk w/o SLAT yielded {pmetal.PT.Root.Count} entries");

                    rvList.Add(pmetal);
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

            WriteLine($"Failed list {totFails.Distinct().Count()};");
            var i = 0;

            foreach (var fail in totFails.Distinct())
                Write($"{fail.PTE:X16}, " + ((((i++) * 18) / WindowWidth > 0) ? Environment.NewLine : string.Empty));

            WriteLine();

            //foreach (var px in Processes)
            //    if (px.pt != null)
            //        WriteLine($"extracted {proc.PageTableType} PTE from process {proc.vmcs.EPTP:X16}:{proc.CR3Value:X16}, high phys address was {proc.PT.HighestFound}");
        }

        public void DumpASToFile(List<DetectedProc> ToDump)
        {
            List<KeyValuePair<VIRTUAL_ADDRESS, PFN>> MemRanges = null;
            Stack<PFN> PFNStack = new Stack<PFN>();
            // instance member
            ContigSize = -1;

            // sort for convince
            ToDump.Sort((x, y) => { if (x.CR3Value < y.CR3Value) return -1; else if (x.CR3Value > y.CR3Value) return 1; else return 0; });

            // prompt user
            for (int i = 0; i < ToDump.Count; i++)
            {
                var vmcs = ToDump[i].vmcs == null ? 0 : ToDump[i].vmcs.EPTP;
                WriteLine($"{i} Hypervisor:{vmcs} Process:{ToDump[i].CR3Value:X} entries {ToDump[i].PT.Root.Count} type {ToDump[i].PageTableType} group {ToDump[i].Group}");
            }
            WriteLine("Select a process to dump: ");
            var selection = ReadLine();
            var procId = int.Parse(selection);
            WriteLine($"Dumping details for process {procId} {ToDump[procId]}");


            var tdp = ToDump[procId];
            PFNStack.Push(tdp.PT.Root.Entries);

            var saveLoc = Path.Combine(Path.GetDirectoryName(MemFile), Path.GetFileName(MemFile) + ".");

            string LastDumped = string.Empty;
            bool fKeepGoing = true;
            int cntDumped = 0;


            using (var memAxs = new Mem(MemFile, null, DetectedDesc))
            {
                var table = tdp.PT.Root.Entries;

                while (fKeepGoing)
                {
                    WriteLine($"{Environment.NewLine}Listing ranges for {tdp}, {table.PFNCount} entries scanned.");

                    //MemRanges = table.SubTables.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).SelectMany(z => z.Value.SubTables).ToList();

                    int parse = -1, level = 4;
                    PFN next_table = new PFN();

                    do
                    {
                        var dict_keys = table.SubTables.Keys.ToArray();

                        for (int r = 0; r < table.SubTables.Count(); r++)
                        {
                            var dict_Val = table.SubTables[dict_keys[r]];

                            WriteLine($"{r} VA: {dict_keys[r]} \t PhysicalAddr: {dict_Val}");
                        }

                        WriteLine("select a range to dump (enter for all, minus '-' go up a level):");
                        var userSelect = ReadLine();
                        if (string.IsNullOrWhiteSpace(userSelect))
                            parse = -1;
                        else if (userSelect.Equals("-"))
                        {
                            if (PFNStack.Count > 0)
                            {
                                level++;
                                table = PFNStack.Pop();
                            }
                            else
                                WriteLine("at the top level now");

                            continue;
                        }
                        else
                            int.TryParse(userSelect, out parse);

                        // extract the key that the user index is referring to and reassign table

                        if (parse >= 0)
                        {
                            PFNStack.Push(table);
                            next_table = table.SubTables[table.SubTables.Keys.ToArray()[parse]];
                            table = next_table;
                        }
                        if (parse < 0)
                            break;

                        level--;

                    } while (level > 0);


                    WriteLine("Writing out data into the same folder as the input");


                    if (parse < 0)
                    {
                        switch (level)
                        {
                            case 4:
                                MemRanges = table.SubTables.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).SelectMany(z => z.Value.SubTables).ToList();
                                break;
                            case 3:
                                MemRanges = table.SubTables.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).ToList();
                                break;
                            case 2:
                                MemRanges = table.SubTables.SelectMany(x => x.Value.SubTables).ToList();
                                break;
                            case 1:
                            default:
                                MemRanges = table.SubTables.ToList();
                                break;
                        }

                        foreach (var mr in MemRanges)
                        {
                            LastDumped = WriteRange(mr, saveLoc, memAxs);
                            cntDumped++;
                        }
                    }
                    else
                    {
                        var a_range = new KeyValuePair<VIRTUAL_ADDRESS, PFN>(next_table.VA, next_table);
                        LastDumped = WriteRange(a_range, saveLoc, memAxs);
                        cntDumped++;
                    }

                    Write($"All done, last written file {LastDumped} of {cntDumped} so far.  KeepGoing? ((y)es (n)o) ");
                    var answer = ReadKey();
                    if (answer.Key != ConsoleKey.Y)
                        fKeepGoing = false;
                }
            }
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

                        WriteLine($"VA: {pte.Key:X16}  \t PFN: {pte.Value.PTE}");

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

    }
}
