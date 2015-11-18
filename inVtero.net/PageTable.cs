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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Specialized;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Diagnostics;
using ProtoBuf;
using static System.Console;

namespace inVtero.net
{
    /// <summary>
    /// Maintain a cached representation of scanned results from analysis
    /// Group regions and address spaces
    /// 
    /// TODO: Enumerate and expose available virtual addresses for a given page table
    ///  - probably just do a recursive routine to desend/enum all available virtual addresses
    /// 
    /// TODO: Implment join-on-shared-kernel-spaces
    /// 
    /// TODO: Convert all of the names into tee http://www.pagetable.com/?p=308 convention :)
    /// </summary>
    [ProtoContract]
    public class PageTable
    {
        // Faild List is the list of entries which were not able to load
        // this is uaually the result of a miscalculated memory run configuration
        [ProtoMember(1)]
        public List<HARDWARE_ADDRESS_ENTRY> Failed;

        // The present invalid list is the list of 'invalid' as far as the hardware goes
        // This is uaually due to software paging, prototype or some alternative PTE state
        // It may be better to say 'Present' here but over all an invalid state just means that 
        // the OS/MM is handling the state of the page and not the hardware.  (swap etc..)
        [ProtoMember(2)]
        public List<HARDWARE_ADDRESS_ENTRY> PresentInvalid;

        // HighestFound is a hint to the extent of the highest PFN which was able to load a page
        // This helps determine the extent of a memory run.
        [ProtoMember(3)]
        public HARDWARE_ADDRESS_ENTRY HighestFound;

        [ProtoMember(4)]
        public PFN RootPageTable;

        DetectedProc DP;
        Mem mem;

        public static PageTable AddProcess(DetectedProc dp, Mem mem)
        {
            long Address = 0;
            int AddressIndex = 0;

            // dump Page table high to low
            var va = new VIRTUAL_ADDRESS(long.MaxValue - 0xfff);

            var rv = new PageTable
            {
                Failed = new List<HARDWARE_ADDRESS_ENTRY>(),
                DP = dp,
                mem = mem
            };

            // TODO: encode VA's for self/recursive physical addr's
            if (dp.PageTableType == PTType.Windows)
            {
                Address = MagicNumbers.Windows_SelfAsVA;
                AddressIndex = MagicNumbers.Windows_SelfPtr;
            }

            // any output is error/warning output

            var cnt = rv.FillTable(new VIRTUAL_ADDRESS(Address), AddressIndex, dp.CR3Value);
            Debug.WriteLine($"extracted {cnt} PTE from process {dp.vmcs.EPTP:X16}:{dp.CR3Value:X16}");

            dp.PT = rv;
            return rv;
        }

        long InlineExtract(PFN top, int Level)
        {
            if (Level == 0)
                return 0;

            var entries = 0L;

            var VA = new VIRTUAL_ADDRESS(top.VA);
            var hPA = HARDWARE_ADDRESS_ENTRY.MinAddr;

            var CR3 = top.PageTable;
            var SLAT = top.SLAT;

            // pull level 4 entries attach level 3
            foreach (var top_sub in top.SubTables)
            {
                // scan each page for the level 4 entry
                var PTE = top_sub.Value.PTE;

                var l3HW_Addr = PTE.NextTableAddress | top_sub.Key.PML4;

                // if we have an EPTP use it and request resolution of the HW_Addr
                if (SLAT != 0)
                {
                    var hl3HW_Addr = HARDWARE_ADDRESS_ENTRY.MaxAddr;
                    hl3HW_Addr = mem.VirtualToPhysical(SLAT, l3HW_Addr);
                    l3HW_Addr = hl3HW_Addr;
                }
                if (l3HW_Addr == long.MaxValue)
                    continue;

                // copy VA since were going to be making changes
                var s3va = new VIRTUAL_ADDRESS(top_sub.Key.Address);

                top_sub.Value.hostPTE = l3HW_Addr; // cache translated value
                var lvl3_page = new long[512];

                // extract the l3 page for each PTEEntry we had in l4
                try { mem.GetPageForPhysAddr(l3HW_Addr, ref lvl3_page); } catch (Exception) { WriteLine($"level3: Failed lookup {l3HW_Addr:X16}"); }

                if (lvl3_page == null)
                    continue;

                for (uint i3 = 0; i3 < 512; i3++)
                {
                    if (lvl3_page[i3] == 0)
                        continue;

                    var l3PTE = new HARDWARE_ADDRESS_ENTRY(lvl3_page[i3]);

                    // adjust VA to match extracted page entries
                    s3va.DirectoryPointerOffset = i3;

                    // save 'PFN' entry into sub-table I should really revisit all these names
                    var l3PFN = new PFN(l3PTE, s3va.Address, CR3, SLAT);
                    top_sub.Value.SubTables.Add(s3va, l3PFN);
                    entries++;

                    // get the page that the current l3PFN describes
                    var l2HW_Addr = l3PTE.NextTableAddress;
                    if (SLAT != 0)
                    {
                        var hl2HW_Addr = HARDWARE_ADDRESS_ENTRY.MaxAddr;
                        try { hl2HW_Addr = mem.VirtualToPhysical(SLAT, l2HW_Addr); } catch(Exception ex) { WriteLine($"level2: Unable to V2P {l3PTE}"); }
                        l2HW_Addr = hl2HW_Addr;
                    }
                    // TODO: more error handlng of exceptions & bad return's
                    // TODO: support software PTE types 
                    if (l2HW_Addr == HARDWARE_ADDRESS_ENTRY.MaxAddr)
                        continue;

                    l3PFN.hostPTE = l2HW_Addr;
                    var lvl2_page = new long[512];

                    try { mem.GetPageForPhysAddr(l2HW_Addr, ref lvl2_page); } catch (Exception ex) { WriteLine($"level2: Failed lookup {l2HW_Addr:X16}"); }

                    if (lvl2_page == null)
                        continue;

                    // copy VA 
                    var s2va = new VIRTUAL_ADDRESS(s3va.Address);
                    // extract PTE's for each set entry
                    for (uint i2 = 0; i2 < 512; i2++)
                    {
                        if (lvl2_page[i2] == 0)
                            continue;

                        var l2PTE = new HARDWARE_ADDRESS_ENTRY(lvl2_page[i2]);
                        s2va.DirectoryOffset = i2;

                        var l2PFN = new PFN(l2PTE, s2va.Address, CR3, SLAT);
                        l3PFN.SubTables.Add(s2va, l2PFN);
                        entries++;

                        if (!l2PTE.LargePage)
                        {

                            var l1HW_Addr = l2PTE.NextTableAddress;
                            if (SLAT != 0)
                            {
                                var hl1HW_Addr = HARDWARE_ADDRESS_ENTRY.MaxAddr;
                                try { hl1HW_Addr = mem.VirtualToPhysical(SLAT, l1HW_Addr); } catch (Exception ex) { WriteLine($"level1: Unable to V2P {l2PTE}"); }

                                l1HW_Addr = hl1HW_Addr;
                            }
                            if (l1HW_Addr == HARDWARE_ADDRESS_ENTRY.MaxAddr)
                                continue;

                            l2PFN.hostPTE = l1HW_Addr;

                            var lvl1_page = new long[512];

                            try { mem.GetPageForPhysAddr(l1HW_Addr, ref lvl1_page); } catch (Exception ex) { WriteLine($"level1: Failed lookup {l1HW_Addr:X16}"); }

                            if (lvl1_page == null)
                                continue;

                            var s1va = new VIRTUAL_ADDRESS(s2va.Address);

                            for (uint i1 = 0; i1 < 512; i1++)
                            {
                                if (lvl1_page[i1] == 0)
                                    continue;

                                var l1PTE = new HARDWARE_ADDRESS_ENTRY(lvl1_page[i1]);
                                s1va.TableOffset = i1;

                                var l1PFN = new PFN(l1PTE, s1va.Address, CR3, SLAT);
                                l2PFN.SubTables.Add(s1va, l1PFN);
                                entries++;
                            }
                        }
                    }
                }
            }
            top.PFNCount += entries;
            return entries;
        }

        long FillTable(VIRTUAL_ADDRESS VA, int PageIndex, long CR3)
        {
            var entries = 0L;
            var PageTable = new Dictionary<VIRTUAL_ADDRESS, PFN>();

            // We can just pick up the top level page to speed things up 
            // we've already visited this page so were not going to waste time looking up the VA->PA
            //var page = new long[512];
            //mem.GetPageFromFileOffset(FileOffset, ref page);


            // clear out the VA for the other indexes since were looking at the top level
            VA.Address = 0;

            foreach (var kvp in DP.TopPageTablePage)
            {
                // Only extract user portion, kerenl will be mostly redundant
                if (kvp.Key >= 256)
                    continue;


                // were at the top level (4th)
                VA.PML4 = kvp.Key;

                var pfn = new PFN(kvp.Value, VA.Address, CR3, DP.vmcs.EPTP);
                PageTable.Add(VA, pfn);
                entries++;
            }
            WriteLine();

            // simulated top entry
            RootPageTable = new PFN(DP.TopPageTablePage[PageIndex], VA.Address, CR3, DP.vmcs.EPTP)
            {
                SubTables = PageTable,
                // a hint for the full count of entries extracted
                PFNCount = entries
            };

            // desend the remaining levels
            entries += InlineExtract(RootPageTable, 3);

            return entries;
        }
    }
}




#if FALSE
            try {
                if (Level == 4)
                {
                    hPA = mem.VirtualToPhysical(DP.vmcs.EPTP, DP.CR3Value, VA.Address);
                    data = mem.GetPageForPhysAddr(hPA.NextTableAddress | VA.DirectoryPointerOffset);
                } else
                {
                hPA = mem.VirtualToPhysical(DP.vmcs.EPTP, top.PTE.NextTableAddress);
                if (hPA == HARDWARE_ADDRESS_ENTRY.MinAddr)
                    return entries;

                HARDWARE_ADDRESS_ENTRY pa = hPA.NextTableAddress | VA.DirectoryPointerOffset;
                data = mem.GetPageForPhysAddr(pa);

                if(HighestFound.PTE < pa.PTE)
                    HighestFound.PTE = pa.PTE;

            } catch (Exception ex)
            {
                Failed.Add(top.PTE);
                //Console.WriteLine("Swallowing failed lookups to build complete fail list. " + ex.ToString());
            }
#endif



#if FALSE



            // take the page that was loaded by the top PFN
            // extract the specified VA for the 
            var j = 512L;
            var AddrOffsetBits = 0L;

            // using a backwards do-while so we extract kernel address ranges first
            // these ranges are more likely to be present 
            do
            {
                j--;
                // adjust address for the index
                switch (Level)
                {
                    case 4: // should never get here
                        VA.PML4 = j;
                        AddrOffsetBits = VA.PML4;
                        Debug.WriteLine("Invalid page table index specified");
                        break;
                    case 3:
                        VA.DirectoryPointerOffset = j;
                        break;
                    case 2:
                        VA.DirectoryOffset = j;
                        break;
                    case 1:
                        VA.TableOffset = j;
                        break;
                    default:// were never going to get here either
                    case 0:
                        VA.Offset = j * 8;
                        Debug.WriteLine("Invalid page table index specified");
                        break;
                }


                var pAddr = 0;
                
                // if we have an EPTP use it
                if(DP.vmcs != null && DP.vmcs.EPTP != 0)
                {

                }

                var next_data = mem.GetPageForPhysAddr(top.SubTables[VA].PTE.NextTableAddress | j);
                if(next_data != null)
                {
                    var next_pfn = new PFN(data[j], VA.Address, DP.CR3Value, DP.vmcs.EPTP);
                    top.SubTables[VA].SubTables.Add(VA, next_pfn);
                    entries++;
                }
            } while (j > -1);

            foreach (var pfn in top.SubTables.Values)
                try
                {
                    entries += NextLevel(pfn, Level - 1);
                }
                catch (Exception ex)
                { }
#endif

#if FALSE



            // take the page that was loaded by the top PFN
            // extract the specified VA for the 
            var j = 512L;
            var AddrOffsetBits = 0L;

            // using a backwards do-while so we extract kernel address ranges first
            // these ranges are more likely to be present 
            do
            {
                j--;
                // adjust address for the index
                switch (Level)
                {
                    case 4: // should never get here
                        VA.PML4 = j;
                        AddrOffsetBits = VA.PML4;
                        Debug.WriteLine("Invalid page table index specified");
                        break;
                    case 3:
                        VA.DirectoryPointerOffset = j;
                        break;
                    case 2:
                        VA.DirectoryOffset = j;
                        break;
                    case 1:
                        VA.TableOffset = j;
                        break;
                    default:// were never going to get here either
                    case 0:
                        VA.Offset = j * 8;
                        Debug.WriteLine("Invalid page table index specified");
                        break;
                }


                var pAddr = 0;
                
                // if we have an EPTP use it
                if(DP.vmcs != null && DP.vmcs.EPTP != 0)
                {

                }

                var next_data = mem.GetPageForPhysAddr(top.SubTables[VA].PTE.NextTableAddress | j);
                if(next_data != null)
                {
                    var next_pfn = new PFN(data[j], VA.Address, DP.CR3Value, DP.vmcs.EPTP);
                    top.SubTables[VA].SubTables.Add(VA, next_pfn);
                    entries++;
                }
            } while (j > -1);

            foreach (var pfn in top.SubTables.Values)
                try
                {
                    entries += NextLevel(pfn, Level - 1);
                }
                catch (Exception ex)
                { }
#endif
