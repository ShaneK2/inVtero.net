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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Reloc;
using System.IO;
using System.Collections.Concurrent;
using ProtoBuf;

namespace inVtero.net
{
    /// <summary>
    /// Similar to the file/raw input version, but were now scanning Virtual Spaces
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class VirtualScanner
    {
        Mem BackingBlocks;
        //ConcurrentDictionary<int, Mem> MemoryBank;
        PhysicalMemoryStream BackingStream;
        bool HeaderScan;
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

        public VirtualScanner()
        {
        }

        public VirtualScanner(DetectedProc Ctx, Mem backingBlocks, bool DoHeaderScan = false) : this()
        {
            DPContext = Ctx;
            BackingBlocks = backingBlocks;
            BackingStream = new PhysicalMemoryStream(backingBlocks, Ctx);
            HeaderScan = DoHeaderScan;
        }
        

        // this guy store's his results in a global thread safe array
        List<Extract> FastPE(long VA, long[] Block)
        {
            int Pos = 0;
            int Lim = Block.Length;
            List<Extract> rv = new List<Extract>();

            while (Pos < Lim)
            {
                // magic check before copying into byte[]
                uint PEMagic = (uint)Block[Pos] & 0xffff;
                if (PEMagic == 0x5a4d)
                {
                    var bpage = new byte[0x1000];
                    Buffer.BlockCopy(Block, Pos*8, bpage, 0, 4096);
                    // TODO: improve/fix check
                    var extracted = Extract.IsBlockaPE(bpage);
                    if (extracted != null)
                    {
                        extracted.VA = VA + (Pos*8);
                        rv.Add(extracted);
                    }
                }
                Pos += 512;
            }
            return rv;
        }

        /// <summary>
        /// Scan and return Extract objects which represent detected PE's
        /// 
        /// TODO:simplify/rewrite this
        /// </summary>
        /// <param name="Start"></param>
        /// <param name="Stop">We just truncate VA's at 48 bit's</param>
        /// <returns>count of new detections since last Run</returns>
        public List<Extract> Run(long Start=0, long Stop = 0xFFFFffffFFFF, PFN entry = null, ParallelLoopState pState = null, Mem Instance = null)
        {
            bool GotData = false;
            var memAxss = Instance == null ? BackingBlocks : Instance;
            long i = Start, Curr = 0;
            long[] block;
            var rv = new List<Extract>();

            // large page read
            if (entry != null && entry.PTE.LargePage)
            {
                block = new long[0x40000];
                memAxss.GetPageForPhysAddr(entry.PTE, ref block, ref GotData);
                if (GotData)
                    rv = FastPE(Start, block);

                return rv;
            }
            else
            // use supplied page sized physical entry
            if(entry != null && Stop - Start == MagicNumbers.PAGE_SIZE)
            { 
                block = new long[0x200];
                memAxss.GetPageForPhysAddr(entry.PTE, ref block, ref GotData);
                if (GotData)
                    rv = FastPE(Start, block);

                // we only header scan when asked and if the page read is 1 from an alignment 
                if (!HeaderScan)
                    return rv;
                if ((Start & 0xF000) != 0x1000)
                    return rv;
                // if were doing a header scan back up i so we do the previous page 
                i -= 0x1000;
                // back up Stop also so we just scan this current page one time
                Stop -= 0x1000; 
            }
            // just use the virtual addresses and attempt to locate phys from page walk
            // this is a really slow way to enumerate memory
            // convert index to an address 
            // then add start to it
            block = new long[0x200]; // 0x200 * 8 = 4k
            while (i < Stop)
            {
                if (pState != null && pState.IsStopped)
                    return rv;

                HARDWARE_ADDRESS_ENTRY locPhys = HARDWARE_ADDRESS_ENTRY.MinAddr;
                if (DPContext.vmcs != null)
                    locPhys = memAxss.VirtualToPhysical(DPContext.vmcs.EPTP, DPContext.CR3Value, i);
                else
                    locPhys = memAxss.VirtualToPhysical(DPContext.CR3Value, i);

                Curr = i;
                i += 0x1000;

                if (HARDWARE_ADDRESS_ENTRY.IsBadEntry(locPhys) || !locPhys.Valid )
                    continue;

                memAxss.GetPageForPhysAddr(locPhys, ref block, ref GotData);
                if (!GotData)
                    continue;

                var new_pe = FastPE(Curr, block);
                rv.AddRange(new_pe);
                if (Vtero.VerboseOutput && new_pe.Count > 0)
                    Console.WriteLine($"Detected PE @ VA {Curr:X}");
            }
            return rv;
        }
    }
}
