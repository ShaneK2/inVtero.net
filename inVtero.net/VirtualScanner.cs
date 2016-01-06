using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Reloc;
using System.IO;
using System.Collections.Concurrent;

namespace inVtero.net
{
    /// <summary>
    /// Similar to the file/raw input version, but were now scanning Virtual Spaces
    /// </summary>
    public class VirtualScanner
    {
        Mem BackingBlocks;
        ConcurrentDictionary<int, Mem> MemoryBank;
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
            CheckMethods = new List<Func<long, byte[], VAScanType>>();
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
            bool rv = false;
            var extracted = Extract.IsBlockaPE(Block);

            return (extracted != null ? VAScanType.PE_FAST : VAScanType.UNDETERMINED);
        }

        public ConcurrentDictionary<long, VAScanType> DetectedFragments;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Start"></param>
        /// <param name="Stop">We just truncate VA's at 48 bit's</param>
        /// <returns></returns>
        public long Run(long Start=0, long Stop = 0xFFFFffffFFFF)
        {
            long rv = 0;
            bool StillGoing = true;

            DetectedFragments = new ConcurrentDictionary<long, VAScanType>();

            //for(long i = StartPage; i < d; i+=Environment.ProcessorCount)
            //

            do
            {
                Parallel.For(0, Environment.ProcessorCount-1, (j) =>
                {
                    // convert index to an address 
                    // then add start to it
                    long i = Start + (j << 12);

                    var block = new long[0x200]; // 0x200 * 8 = 4k
                    var bpage = new byte[0x1000];
                    unsafe
                    {
                        fixed (void* lp = block, bp = bpage)
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

                                    MemoryBank[j].GetPageForPhysAddr(locPhys, ref block);

                                    Buffer.MemoryCopy(lp, bp, 4096, 4096);

                                    var scan_detect = scanner(i, bpage);
                                    if (scan_detect != VAScanType.UNDETERMINED)
                                    {
                                        DetectedFragments.TryAdd(i, scan_detect);
                                        if (Vtero.VerboseOutput)
                                            Console.WriteLine($"Detected PE @ VA {i:X}");
                                    }
                                }

                                i += Environment.ProcessorCount << 12;
                            }
                            StillGoing = false;
                        }
                    }
                });



            } while (StillGoing);
            //}


            return rv;
        }
    }
}
