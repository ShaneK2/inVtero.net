// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Threading;
using System.Text;

namespace inVtero.net
{
    /// <summary>
    /// inVtero is the primary memory manager for physical to an architechture independent virtual and physical to hypervisor page extraction mechianism
    /// 
    /// Suport status: Win/FreeBSD good, OpenBSD OK & NetBSD YMMV
    ///                 Additional OS using self/recursive page table mappings should be cake
    /// 
    /// TODO: Tweak Windows Mode 1 into * OS generic detection of host tables
    ///       Generic host scan can then use Generic VMCS
    ///       Finish Linux 
    /// 
    /// </summary>
    public class Scanner
    {
        // for diagnostic printf's
        const int MAX_LINE_WIDTH = 120;

#if Serial
        public Dictionary<ulong, DetectedProc> DetctedProcesses;
        public IEnumerable<KeyValuePair<ulong, DetectedProc>> VMCSScanSet;
#else
        // using bag since it has the same collection interface as List
        public ConcurrentDictionary<ulong, DetectedProc> DetectedProcesses;
        public ParallelQuery<KeyValuePair<ulong, DetectedProc>> VMCSScanSet;
#endif

        #region class instance variables
        public string Filename;
        public ulong FileSize;
        public List<VMCS> HVLayer;
        bool DumpVMCSPage;

        PTType HostOS;
        List<MemoryRun> Gaps;

        #endregion

        public Scanner(string InputFile)
        {
#if Serial
            DetectedProcesses = new Dictionary<ulong, DetectedProc>();
#else
            DetectedProcesses = new ConcurrentDictionary<ulong, DetectedProc>();
#endif
            HVLayer = new List<VMCS>();
            Filename = InputFile;
            DumpVMCSPage = true;
            FileSize = 0;
            Gaps = new List<MemoryRun>();
        }

        Dictionary<DetectedProc, PageTable> ptCache;
        static long roundUp(long numToRound, long multiple)
        {
            return ((numToRound + multiple - 1) / multiple) * multiple;
        }
        static long roundDown(long numToRound, long multiple)
        {
            return (long)(((double)numToRound / multiple) * multiple);
        }
        public void GroupResults(List<DetectedProc> Procs)
        {
            long runStart = 0, runEnd = 0;

            using (var memAxs = new Mem(Filename))
            {
                var lowestProc = Procs.OrderBy(x => x.FileOffset).FirstOrDefault();
                if (lowestProc == null)
                    return;

                HostOS = lowestProc.PageTableType;

                // first detected proc will belong to the host.
                // any detected proc with the same "diff" value as this also belongs to the hsot.
                foreach (var p in Procs)
                {
                    if(p.Diff == lowestProc.Diff)
                        p.Group = 1;
                }

                DetectedProc prev = null;
                // find any detected proc with the same OS type who's diff went up by a power of 2.
                foreach (var p in Procs)
                {
                    if(p.PageTableType == HostOS && p.Group != 1)
                    {
                        // probably some cases where the run gap's are not powers of 2... 
                        // but then it's hard to figure out who's who w/o inspect every element of the PT
                        // power of 2 check
                        if(p.Diff != 0 && ((p.Diff & (p.Diff - 1)) == 0))
                        {
                            // likely we found a gap
                            if(prev != null)
                            {
                                runEnd = roundDown((long) p.CR3Value, p.Diff);
                                runStart = roundUp((long) prev.CR3Value, p.Diff);
                            }
                            // we found a run
                            Gaps.Add(new MemoryRun { BasePage = (ulong) runStart, PageCount = (ulong) (runEnd - runStart) });
                        }
                    }

                    prev = p;
                }


                
            }
        }


        /// <summary>
        /// VMCS Scan based on detected page tables CR3 value only
        /// Were not joining across offset yet, can ignore what offset the CR3 origionally camer from
        /// </summary>
        /// <param name="block"></param>
        /// <param name="CurrWindowBase"></param>
        /// <param name="CurrMapBase"></param>
        /// <returns></returns>
        public bool VMCS()
        {
            var RevID = (REVISION_ID)(block[0] & 0xffffffff);
            var Acode = (VMCS_ABORT)((block[0] >> 32) & 0x7fffffff);
            var KnownAbortCode = false;
            var KnownRevision = false;
            var Candidate = false;
            var LinkCount = 0;
            var Neg1 = 0xffffffffffffffff;

            var offset = CurrWindowBase + CurrMapBase;

#if Serial
            KnownRevision = Enum.GetValues(typeof(REVISION_ID)).Cast<REVISION_ID>().Any(x => x == RevID);
            KnownAbortCode = Enum.GetValues(typeof(VMCS_ABORT)).Cast<VMCS_ABORT>().Any(x => x == Acode);
#else
            // this might be a bit micro-opt-pointless ;)
            Parallel.Invoke(() =>
            {
                KnownRevision = Enum.GetValues(typeof(REVISION_ID)).Cast<REVISION_ID>().Any(x => x == RevID);
            }, () =>
            {
                KnownAbortCode = Enum.GetValues(typeof(VMCS_ABORT)).Cast<VMCS_ABORT>().Any(x => x == Acode);
            });
#endif
            // Find a 64bit value for link ptr
            for (int i = 0; i < block.Length; i++)
            {
                if (block[i] == Neg1)
                    LinkCount++;

                // too many
                if (LinkCount > 32)
                    return false;
            }
            // We expect to have 1 Link pointer at least
            if (LinkCount == 0 || !KnownAbortCode)
                return false;


            // curr width of line to screen
            var lobj = new Object();
            Candidate = false;
#if Serial
            foreach(var vmcs_entry in VMCSScanSet)
#else
            Parallel.ForEach(VMCSScanSet, (vmcs_entry) =>
#endif
            {
                for (int check = 1; check < block.Length; check++)
                {
                    if (block[check] == vmcs_entry.Value.CR3Value && Candidate == false)
                    {
                        lock (lobj)
                        {
                            Candidate = true;

                            // reverse endianess for easy reading in hex dumps/editors
                            var shorted = BitConverter.GetBytes(block[check]);
                            Array.Reverse(shorted, 0, 8);
                            var Converted = BitConverter.ToUInt64(shorted, 0);

                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Hypervisor: VMCS revision field: {RevID} [{((uint)RevID):X8}] abort indicator: {Acode} [{((int)Acode):X8}]");
                            Console.WriteLine($"Hypervisor: {vmcs_entry.Value.PageTableType} CR3 found = [{vmcs_entry.Value.CR3Value:X16})] byte-swapped: [{Converted:X16}] @ PAGE/File Offset = [{offset:X16}]");

                            if (DumpVMCSPage)
                            {
                                Console.WriteLine("Dumping possiable physical Block Values.  [Offset-decimal][Value-hex] ");
                                var sb = new StringBuilder();
                                var curr_width = 0;

                                for (int i = 0; i < block.Length; i++)
                                {
                                    // any good minimum size? 64kb?
                                    if (block[i] > 0x40000 && block[i] < FileSize)
                                    {
                                        var linefrag = $"[{i}][{block[i]:X16}] ";

                                        if (curr_width + linefrag.Length > MAX_LINE_WIDTH)
                                        {
                                            sb.Append(Environment.NewLine);
                                            curr_width = 0;
                                        }
                                        sb.Append(linefrag);
                                        curr_width += linefrag.Length;
                                    }
                                }

                                Console.ForegroundColor = ConsoleColor.DarkGreen;
                                Console.WriteLine(sb.ToString());
                            }
                            // here's a canned example for VMWare 
                            // however we can also just check the relativly few physical addresses in the candiate page regardless
                            if (RevID == REVISION_ID.VMWARE_NESTED && block[14] < FileSize && block[14] > 0)
                                HVLayer.Add(new VMCS { dp = vmcs_entry.Value, EPTP = block[14], gCR3 = vmcs_entry.Value.CR3Value });
                        }
                    }
                }
#if Serial
            }
#else
            });
#endif
            return Candidate;
        }

        // NetBSD needs some analysis, skipping for now as I'm getting onto EPTP
        public bool NetBSD()
        {
            var Candidate = false;

            var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[255] & 0xFFFFFFFFF000);
            var diff = (long) (offset - shifted);


            if (((block[511] & 0xf3) == 0x63) && ((0x63 == (block[320] & 0xf3)) || (0x63 == (block[256] & 0xf3))))
            {
                if (((block[255] & 0xf3) == 0x63) && (0 == (block[255] & 0x7FFF000000000000)))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.NetBSD };
                        DetectedProcesses.TryAdd(offset, dp);
                        Console.WriteLine(dp);
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }

        /*   OpenBSD /src/sys/arch/amd64/include/pmap.h
            #define L4_SLOT_PTE		255
            #define L4_SLOT_KERN		256
            #define L4_SLOT_KERNBASE	511
            #define L4_SLOT_DIRECT		510
        */
        public bool OpenBSD()
        {
            var Candidate = false;

            var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[255] & 0xFFFFFFFFF000);
            var diff = (long)(offset - shifted);

            if (((block[510] & 0xf3) == 0x63) && (0x63 == (block[256] & 0xf3)) && (0x63 == (block[254] & 0xf3)))
            {
                if (((block[255] & 0xf3) == 0x63) && (0 == (block[255] & 0x7FFF000000000000)))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.OpenBSD };
                        DetectedProcesses.TryAdd(offset, dp);
                        Console.WriteLine(dp);
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }

        public bool FreeBSD()
        {
            var Candidate = false;

            var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[0x100] & 0xFFFFFFFFF000);
            var diff = (long)(offset - shifted);

            if (((block[0] & 0xff) == 0x67) && (0x67 == (block[0xff] & 0xff)))
            {
                if (((block[0x100] & 0xff) == 0x63) && (0 == (block[0x100] & 0x7FFF000000000000)))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.FreeBSD };
                        DetectedProcesses.TryAdd(offset, dp);
                        Console.WriteLine(dp);
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }

        public bool Windows()
        {
            var Candidate = false;

            var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[0x1ed] & 0xFFFFFFFFF000);
            var diff = (long)(offset - shifted);

            // detect mode 2, 2 seems good for most purposes and is more portable
            // maybe 0x3 is sufficient
            if (((block[0] & 0xfdf) == 0x847) && ((block[0x1ed] & 0xff) == 0x63 || (block[0x1ed] & 0xff) == 0x67))
            {
                // we disqualify entries that have these bits configured
                //111 1111 1111 1111 0000 0000 0000 0000 0000 0000 0000 0000 0000 0100 1000 0000
                if ((block[0x1ed] & 0x7FFF000000000480) == 0)
                {
#if MODE_1
                    if (!SetDiff)
                    {
                        FirstDiff = diff;
                        SetDiff = true;
                    }
#endif
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.Windows };
                        DetectedProcesses.TryAdd(offset, dp);
                        Console.WriteLine(dp);
                        Candidate = true;
                    }
                }
            }
            // mode 1 is implmented to hit on very few supported bits
#region MODE 1 IS PRETTY LOOSE
#if MODE_1
            else
                /// detect MODE 1, we can probably get away with even just testing & 1, the valid bit
                //if (((block[0] & 3) == 3) && (block[0x1ed] & 3) == 3)		
                if ((block[0] & 1) == 1 && (block[0xf68 / 8] & 1) == 1)
            {
                // a posssible kernel first PFN? should look somewhat valid... 
                if (!SetDiff)
                {
                    // I guess we could be attacked here too, the system kernel could be modified/hooked/bootkit enough 
                    // we'll see if we need to analyze this in the ulong run
                    // the idea of mode 1 is a very low bit-scan, but we also do not want to mess up FirstDiff
                    // these root entries are valid for all win64's for PTE/hyper/session space etc.
                    if ((block[0xf78 / 8] & 1) == 1 && (block[0xf80 / 8] & 1) == 1 && (block[0xff8 / 8] & 1) == 1 && (block[0xff0 / 8] == 0))
                    {
                        // W/O this we may see some false positives 
                        // however can remove if you feel aggressive
                        if (diff < FileSize && (offset > shifted ? (diff + shifted == offset) : (diff + offset == shifted)))
                        {
                            FirstDiff = diff;
                            SetDiff = true;
                        }
                    }
                }

                if (SetDiff &&
                    !(FirstDiff != diff) &&
                     (shifted < (FileSize + diff)
                     //|| shifted != 0
                     ))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 1, PageTableType = PTType.Windows };

                        DetectedProcesses.TryAdd(offset, dp);
                        Console.WriteLine(dp);

                        Candidate = true;
                    }
                }
            }
#endif
#endregion
            return Candidate;
        }

        static ulong CurrMapBase;
        static ulong CurrWindowBase;
        static ulong mapSize = (64 * 1024 * 1024);
        static ulong[] block = new ulong[512];
        static ulong[][] buffers = { new ulong[512], new ulong[512] };
        static int filled = 0;

        /// <summary>
        /// A simple memory mapped scan over the input provided inthe constructor
        /// </summary>
        /// <param name="Checkers">a List of Func which return bool if the current page is a candidate</param>
        /// <param name="ExitAfter">Optionally stop checking or exit early after this many candidates.  0 does not exit early.</param>
        /// <returns></returns>
        public int Analyze(List<Func<bool>> Checkers, int ExitAfter = 0)
        {
            var rv = 0x0;

            CurrWindowBase = 0;
            mapSize = (64 * 1024 * 1024);

            if (File.Exists(Filename))
            {
                using (var fs = new FileStream(Filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var mapName = Path.GetFileNameWithoutExtension(Filename) + DateTime.Now.ToBinary().ToString("X16");
                    using (var mmap =
                        MemoryMappedFile.CreateFromFile(fs,
                        mapName,
                        0,
                        MemoryMappedFileAccess.Read,
                        null,
                        HandleInheritability.Inheritable,
                        false))
                    {
                        var fi = new FileInfo(Filename);
                        FileSize = (ulong)fi.Length;

                        while (CurrWindowBase < FileSize)
                        {
                            using (var reader = mmap.CreateViewAccessor((long)CurrWindowBase, (long)mapSize, MemoryMappedFileAccess.Read))
                            {
                                CurrMapBase = 0;
                                reader.ReadArray<ulong>((long)CurrMapBase, buffers[filled], 0, 512);


                                while (CurrMapBase < mapSize)
                                {
                                    // next page, may be faster with larger chunks but it's simple to view 1 page at a time
                                    CurrMapBase += 4096;

                                    block = buffers[filled];
                                    filled ^= 1;
#if Serial
                                foreach (var check in Checkers)
                                    if(check())
                                        rv++;
#else
                                    Parallel.Invoke(
                                        () => Parallel.ForEach<Func<bool>>(Checkers, (check) =>
                                            {
                                                if (check())
                                                    Interlocked.Increment(ref rv);
                                            }), () =>
                                            {
                                                if(CurrMapBase < mapSize)
                                                    reader.ReadArray<ulong>((long)CurrMapBase, buffers[filled], 0, 512);
                                            });
#endif
                                    if (ExitAfter > 0 && rv == ExitAfter)
                                        return rv;
                                }
                            } // close current window

                            CurrWindowBase += CurrMapBase;

                            if (CurrWindowBase + mapSize > FileSize)
                                mapSize = FileSize - CurrWindowBase;
                        }
                    }
                } // close map
            } // close stream
            return rv;
        }
    }
}
