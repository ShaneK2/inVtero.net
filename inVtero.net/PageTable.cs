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

using ProtoBuf;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using static System.Console;

namespace inVtero.net
{
    /// <summary>
    /// Maintain a cached representation of scanned results from analysis
    /// Group regions and address spaces
    /// 
    /// TODO: Enumerate and expose available virtual addresses for a given page table
    ///  - probably just do a recursive routine to descend/enum all available virtual addresses
    /// 
    /// TODO: Implement join-on-shared-kernel-spaces
    /// 
    /// TODO: Convert all of the names into tee http://www.pagetable.com/?p=308 convention :)
    /// </summary>
    [ProtoContract]
    public class PageTable
    {
        // failed List is the list of entries which were not able to load
        // this is usually the result of a miscalculated memory run configuration
        [ProtoMember(1)]
        public List<HARDWARE_ADDRESS_ENTRY> Failed;

        // The present invalid list is the list of 'invalid' as far as the hardware goes
        // This is usually due to software paging, prototype or some alternative PTE state
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
        
        public static PageTable AddProcess(DetectedProc dp, Mem mem, bool OnlyUserSpace = false)
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

            var cnt = rv.FillTable(new VIRTUAL_ADDRESS(Address), AddressIndex, dp.CR3Value, OnlyUserSpace);

            if (cnt == 0)
            {
                if (dp.vmcs != null)
                    WriteLine($"BAD EPTP/DirectoryTable Base {dp.vmcs.EPTP:X16}, try a different candidate or this dump may lack a hypervisor. Attempting PT walk W/O SLAT");
                else
                    WriteLine($"Decoding failed for {dp.CR3Value:X16}");
                /*cnt = rv.FillTable(new VIRTUAL_ADDRESS(Address), AddressIndex, dp.CR3Value, OnlyUserSpace);
                WriteLine($"Physical walk w/o SLAT yielded {cnt} entries");*/
            }

            dp.PT = rv;
            return rv;
        }

        /// <summary>
        /// An Inline extraction for the page table hierarchy.
        /// Why not let the compiler do it?  I have code clones here?
        /// 
        /// I guess so, but we can see/deal with the subtle differences at each level here as we implement them.
        /// e.g. some levels have LargePage bits and we may also lay over other CPU modes here like 32 in 64 etc..
        /// </summary>
        /// <param name="top"></param>
        /// <param name="Level"></param>
        /// <returns></returns>
        long InlineExtract(PFN top, int Level)
        {
            if (Level == 0)
                return 0;

            var entries = 0L;

            var VA = new VIRTUAL_ADDRESS(top.VA);
            //WriteLine($"4: Scanning {top.PageTable:X16}");

            var hPA = HARDWARE_ADDRESS_ENTRY.MinAddr;

            var SLAT = top.SLAT;
            var CR3 = top.PageTable;

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

                    try { hl3HW_Addr = mem.VirtualToPhysical(SLAT, l3HW_Addr); } catch (Exception) { if (Vtero.DiagOutput) WriteLine($"level3: Failed lookup {l3HW_Addr:X16}"); }

                    l3HW_Addr = hl3HW_Addr;
                }
                if (SLAT != 0 && (l3HW_Addr == long.MaxValue || l3HW_Addr == long.MaxValue-1))
                    continue;

                // copy VA since were going to be making changes
                var s3va = new VIRTUAL_ADDRESS(top_sub.Key.Address);
                //WriteLine($"3: Scanning {s3va.Address:X16}");

                top_sub.Value.hostPTE = l3HW_Addr; // cache translated value
                var lvl3_page = new long[512];

                // extract the l3 page for each PTEEntry we had in l4
                try { mem.GetPageForPhysAddr(l3HW_Addr, ref lvl3_page); } catch (Exception) { if (Vtero.DiagOutput) WriteLine($"level3: Failed lookup {l3HW_Addr:X16}"); }

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

                    /// TODO: Double check if this is a real bit... 
                    /// I added it to help weed out some failure cases
                    if (!l3PTE.LargePage)
                    {
                        // get the page that the current l3PFN describes
                        var l2HW_Addr = l3PTE.NextTableAddress;
                        if (SLAT != 0)
                        {
                            var hl2HW_Addr = HARDWARE_ADDRESS_ENTRY.MaxAddr;
                            try { hl2HW_Addr = mem.VirtualToPhysical(SLAT, l2HW_Addr); } catch (Exception ex) { if (Vtero.DiagOutput) WriteLine($"level2: Unable to V2P {l3PTE}"); }
                            l2HW_Addr = hl2HW_Addr;
                        }
                        // TODO: more error handling of exceptions & bad returns
                        // TODO: support software PTE types 
                        if (l2HW_Addr == HARDWARE_ADDRESS_ENTRY.MaxAddr)
                            continue;

                        l3PFN.hostPTE = l2HW_Addr;
                        var lvl2_page = new long[512];

                        try { mem.GetPageForPhysAddr(l2HW_Addr, ref lvl2_page); } catch (Exception ex) { if (Vtero.DiagOutput) WriteLine($"level2: Failed lookup {l2HW_Addr:X16}"); }

                        if (lvl2_page == null)
                            continue;

                        // copy VA 
                        var s2va = new VIRTUAL_ADDRESS(s3va.Address);
                        //WriteLine($"2: Scanning {s2va.Address:X16}");

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
                                    try { hl1HW_Addr = mem.VirtualToPhysical(SLAT, l1HW_Addr); } catch (Exception ex) { if (Vtero.DiagOutput) WriteLine($"level1: Unable to V2P {l2PTE}"); }

                                    l1HW_Addr = hl1HW_Addr;
                                }
                                if (l1HW_Addr == HARDWARE_ADDRESS_ENTRY.MaxAddr)
                                    continue;

                                l2PFN.hostPTE = l1HW_Addr;

                                var lvl1_page = new long[512];

                                try { mem.GetPageForPhysAddr(l1HW_Addr, ref lvl1_page); } catch (Exception ex) { if(Vtero.DiagOutput) WriteLine($"level1: Failed lookup {l1HW_Addr:X16}"); }

                                if (lvl1_page == null)
                                    continue;

                                var s1va = new VIRTUAL_ADDRESS(s2va.Address);
                                //WriteLine($"1: Scanning {s1va.Address:X16}");

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
            }
            //top.PFNCount += entries;
            return entries;
        }

        long FillTable(VIRTUAL_ADDRESS VA, int PageIndex, long CR3, bool OnlyUserSpace = false)
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
                // Only extract user portion, kernel will be mostly redundant
                if(OnlyUserSpace && kvp.Key >= 256)
                    continue;

                // were at the top level (4th)
                VA.PML4 = kvp.Key;

                var pfn = new PFN(kvp.Value, VA.Address, CR3, DP.vmcs == null ? 0 : DP.vmcs.EPTP);
                PageTable.Add(VA, pfn);
                entries++;
            }

            // simulated top entry
            RootPageTable = new PFN(DP.TopPageTablePage[PageIndex], VA.Address, CR3, DP.vmcs == null ? 0 : DP.vmcs.EPTP)
            {
                SubTables = PageTable
            };

            // descend the remaining levels
            // if we find nothing, we can be sure the value were using for EPTP or CR3 is bogus
            var new_entries = InlineExtract(RootPageTable, 3);
            if (new_entries == 0)
                return 0;

            entries += new_entries;
            // a hint for the full count of entries extracted
            RootPageTable.PFNCount = entries;
            
            return entries;
        }
    }
}

