// Shane.Macaulay @IOActive.com Copyright (C) 2013-2015

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

// Shane.Macaulay@IOActive.com (c) copyright 2014,2015,2016 all rights reserved. GNU GPL License

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Reloc;
using System.IO;
using System.Collections.Concurrent;
using RaptorDB;
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

        public VirtualScanner(DetectedProc Ctx, Mem backingBlocks) : this()
        {
            DPContext = Ctx;
            BackingBlocks = backingBlocks;
            BackingStream = new PhysicalMemoryStream(backingBlocks, Ctx);
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

            var rv = new List<Extract>();

            // large page read
            if (entry != null && entry.PTE.LargePage)
            {
                var block = new long[0x40000];
                memAxss.GetPageForPhysAddr(entry.PTE, ref block, ref GotData);
                if (GotData)
                    rv = FastPE(Start, block);
            }
            // use supplied page sized physical entry
            else if(entry != null && Stop - Start == MagicNumbers.PAGE_SIZE)
            {
                var block = new long[0x200];
                memAxss.GetPageForPhysAddr(entry.PTE, ref block, ref GotData);
                if (GotData)
                    rv = FastPE(Start, block);
            }
            // just use the virtual addresses and attempt to locate phys from page walk
            // this is a really slow way to enumerate memory
            else
            {
                // convert index to an address 
                // then add start to it
                var block = new long[0x200]; // 0x200 * 8 = 4k
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
            }
            return rv;
        }
    }
}
