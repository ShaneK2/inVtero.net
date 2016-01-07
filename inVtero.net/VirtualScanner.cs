using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Reloc;
using System.IO;
using System.Collections.Concurrent;
using RaptorDB;

namespace inVtero.net
{
    /// <summary>
    /// Similar to the file/raw input version, but were now scanning Virtual Spaces
    /// </summary>
    public class VirtualScanner
    {
        Mem BackingBlocks;
        ConcurrentDictionary<int, Mem> MemoryBank;
        public ConcurrentDictionary<long, Extract> Artifacts;
        PhysicalMemoryStream BackingStream;

        /// <summary>
        /// Detected processes are the fundamental unit were after since a process maintains the address
        /// space configuration information.  Naturally there can be (bad)things running outside of this context
        /// in hardware, process-less threads/co-routines or through the interaction of some shared memory
        /// between several processes causes a Turing complete mechanism weird-machine...
        /// 
        /// But I think we have to start somewhere ;) 
        /// </summary>
        DetectedProc DPContext;

        WAHBitArray ScanList;


        // similar to the file based interface, we will only scan 1 page at a time 
        // but if we hit a signature in a check it's free to non-block the others while it completes 
        // a deeper scan
        List<Func<long, byte[], VAScanType>> CheckMethods;

        VAScanType scanMode;
        public VAScanType ScanMode
        {
            get { return scanMode; }
            set
            {
                scanMode = value;
                CheckMethods.Clear();

                if ((value & VAScanType.PE_FAST) == VAScanType.PE_FAST)
                    CheckMethods.Add(FastPE);
            }
        }

        public VirtualScanner()
        {
            DetectedFragments = new ConcurrentDictionary<long, VAScanType>();
            Artifacts = new ConcurrentDictionary<long, Extract>();

            CheckMethods = new List<Func<long, byte[], VAScanType>>();
            ScanList = new WAHBitArray(); 
        }

        public VirtualScanner(DetectedProc Ctx, Mem backingBlocks) : this()
        {
            DPContext = Ctx;
            BackingBlocks = backingBlocks;
            BackingStream = new PhysicalMemoryStream(backingBlocks, Ctx);

            MemoryBank = new ConcurrentDictionary<int, Mem>();
            for(int i=0; i< Environment.ProcessorCount; i++)
                MemoryBank[i] = new Mem(BackingBlocks);
        }

        public VAScanType FastPE(long VA, byte[] Block)
        {
            // magic check
            if((Block[0] == 'M' && Block[1] == 'Z'))
            {
                // TODO: improve/fix check
                var extracted = Extract.IsBlockaPE(Block);
                if (extracted != null)
                {
                    Artifacts.TryAdd(VA, extracted);
                    return VAScanType.PE_FAST;
                }
            }
            return VAScanType.UNDETERMINED;
        }

        public ConcurrentDictionary<long, VAScanType> DetectedFragments;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Start"></param>
        /// <param name="Stop">We just truncate VA's at 48 bit's</param>
        /// <returns>count of new detections since last Run</returns>
        public long Run(long Start=0, long Stop = 0xFFFFffffFFFF)
        {
            long rv = DetectedFragments.Count();
            bool StillGoing = true;

            do
            {
                Parallel.For(0, Environment.ProcessorCount, (j) =>
                //for (int j = 0; j < 1; j++)
                {
                    // convert index to an address 
                    // then add start to it
                    long i = Start + (j << 12);

                    var block = new long[0x200]; // 0x200 * 8 = 4k
                    var bpage = new byte[0x1000];
                    unsafe
                    {
                        while (i < Stop)
                        {
                            foreach (var scanner in CheckMethods)
                            {
                                HARDWARE_ADDRESS_ENTRY locPhys = HARDWARE_ADDRESS_ENTRY.MinAddr;

                                if (DPContext.vmcs != null)
                                    locPhys = MemoryBank[j].VirtualToPhysical(DPContext.vmcs.EPTP, DPContext.CR3Value, i);
                                else
                                    locPhys = MemoryBank[j].VirtualToPhysical(DPContext.CR3Value, i);

                                if (HARDWARE_ADDRESS_ENTRY.IsBadEntry(locPhys))
                                    continue;

                                fixed (void* lp = block, bp = bpage)
                                {
                                    bool GotData = false;

                                    MemoryBank[j].GetPageForPhysAddr(locPhys, ref block, ref GotData);

                                    Buffer.MemoryCopy(lp, bp, 4096, 4096);
                                }

                                var scan_detect = scanner(i, bpage);
                                if (scan_detect != VAScanType.UNDETERMINED)
                                {
                                    DetectedFragments.TryAdd(i, scan_detect);
                                    if (Vtero.VerboseOutput)
                                        Console.WriteLine($"Detected PE @ VA {i:X}");
                                }
                            }
                            i += Environment.ProcessorCount << 12;
                            // for easier debugging if your not using Parallel loop
                            //i += 1 << 12;
                        }
                        StillGoing = false;
                    }
                });
                //}

            } while (StillGoing);

            return DetectedFragments.Count() - rv;
        }
    }
}
