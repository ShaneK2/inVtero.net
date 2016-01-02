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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using static System.Console;
using ProtoBuf;

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
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class PageTable
    {
        // failed List is the list of entries which were not able to load
        // this is usually the result of a miscalculated memory run configuration
        public List<HARDWARE_ADDRESS_ENTRY> Failed;

        // The present invalid list is the list of 'invalid' as far as the hardware goes
        // This is usually due to software paging, prototype or some alternative PTE state
        // It may be better to say 'Present' here but over all an invalid state just means that 
        // the OS/MM is handling the state of the page and not the hardware.  (swap etc..)
        public List<HARDWARE_ADDRESS_ENTRY> PresentInvalid;

        // HighestFound is a hint to the extent of the highest PFN which was able to load a page
        // This helps determine the extent of a memory run.
        public HARDWARE_ADDRESS_ENTRY HighestFound;

        public PageTableRoot Root;
        [ProtoIgnore]
        DetectedProc DP;
        [ProtoIgnore]
        Mem mem;
        bool KernelSpace;


        public static PageTable AddProcess(DetectedProc dp, Mem mem, bool RedundantKernelEntries = true)
        {
            if(Vtero.VerboseOutput)
                WriteLine($"PT analysis of {dp}");

            var rv = new PageTable
            {
                Root = new PageTableRoot() { SLAT = dp.vmcs != null ? dp.vmcs.EPTP : 0, CR3 = dp.CR3Value, Entries = new PFN() },
                Failed = new List<HARDWARE_ADDRESS_ENTRY>(),
                DP = dp,
                mem = mem
            };

            // any output is error/warning output

            var cnt = rv.FillTable(RedundantKernelEntries);

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
        /// 

        // TODO: RE-RE-Write this into an on-demand evaluated set of delegates to ease memory load
        // some testing on Windows 10: Virtualized Process PT Entries [1625181] Type [Windows] PID [97C0301E:1AB000]
        // that's over _1.6 Million_ page table entries, wow!!!
        long InlineExtract(PageTableRoot Root, int Depth = 4)
        {
            VIRTUAL_ADDRESS VAddr;

            var entries = 0L;

            var SLAT = Root.SLAT;
            var CR3 = Root.CR3;
            var top = Root.Entries;

            // pull level 4 entries attach level 3
            foreach (var top_sub in top.SubTables)
            {
                //WriteLine($"4: Scanning {top_sub.Value.PTE:X16}");
                // scan each page for the level 4 entry
                var PTE = top_sub.Value.PTE;

                // we don't need to | in the PML4 AO (address offset) since were pulling down the whole page not just the one value
                // and were going to brute force our way through the entire table so this was just confusing things.
                var l3HW_Addr = PTE.NextTableAddress;

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

                    //WriteLine($"3: Scanning VA {s3va.Address:X16}");

                    // save 'PFN' entry into sub-table I should really revisit all these names
                    VAddr = new VIRTUAL_ADDRESS(s3va.Address);
                    var l3PFN = new PFN() { PTE = l3PTE, VA = VAddr };

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

                        var lvl2_page = new long[512];

                        try { mem.GetPageForPhysAddr(l2HW_Addr, ref lvl2_page); } catch (Exception ex) { if (Vtero.DiagOutput) WriteLine($"level2: Failed lookup {l2HW_Addr:X16}"); }

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
                            ///WriteLine($"2: Scanning VA {s2va.Address:X16}");
                            VAddr = new VIRTUAL_ADDRESS(s2va.Address);
                            var l2PFN = new PFN() { PTE = l2PTE, VA = VAddr };

                            l3PFN.SubTables.Add(s2va, l2PFN);
                            entries++;


                            if (!l2PTE.LargePage && !KernelSpace)
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

                                var lvl1_page = new long[512];

                                try { mem.GetPageForPhysAddr(l1HW_Addr, ref lvl1_page); } catch (Exception ex) { if(Vtero.DiagOutput) WriteLine($"level1: Failed lookup {l1HW_Addr:X16}"); }

                                if (lvl1_page == null)
                                    continue;

                                var s1va = new VIRTUAL_ADDRESS(s2va.Address);

                                for (uint i1 = 0; i1 < 512; i1++)
                                {
                                    if (lvl1_page[i1] == 0)
                                        continue;

                                    var l1PTE = new HARDWARE_ADDRESS_ENTRY(lvl1_page[i1]);
                                    s1va.TableOffset = i1;

                                    //WriteLine($"1: Scanning VA {s1va.Address:X16}");
                                    // copy this since were in a loop scanning and it (VA) changes every time
                                    VAddr = new VIRTUAL_ADDRESS(s1va.Address);
                                    var l1PFN = new PFN() { PTE = l1PTE, VA = VAddr };

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

        IEnumerable<PFN> ExtractNextLevel(PFN PageContext, bool RedundantKernelSpaces, int Level = 4)
        {
            if (PageContext == null) yield break;

            RedundantKernelSpaces = true;

            var SLAT = Root.SLAT;
            var CR3 = Root.CR3;
            var top = Root.Entries;

            VIRTUAL_ADDRESS SubVA = PageContext.VA;
            HARDWARE_ADDRESS_ENTRY PA = PageContext.PTE;

            if (!PA.LargePage)
            {
                // get the page that the current PFN describes
                var HW_Addr = PA.NextTableAddress;
                if (SLAT != 0)
                {
                    var hHW_Addr = HARDWARE_ADDRESS_ENTRY.MaxAddr;
                    try { hHW_Addr = mem.VirtualToPhysical(SLAT, HW_Addr); } catch (Exception ex) { if (Vtero.DiagOutput) WriteLine($"level{Level}: Unable to V2P {HW_Addr}"); }
                    HW_Addr = hHW_Addr;

                    if (HW_Addr == long.MaxValue || HW_Addr == long.MaxValue - 1)
                        yield break;
                }

                long[] page = new long[512];  

                // copy VA since were going to be making changes

                try { mem.GetPageForPhysAddr(HW_Addr, ref page); } catch (Exception ex) { if (Vtero.DiagOutput) WriteLine($"Physical Address can not find {HW_Addr:X16}"); }

                if (page == null)
                    yield break;

                var dupVA = new VIRTUAL_ADDRESS(SubVA.Address);

                for (int i = 0; i < 512; i++)
                {
                    if (!RedundantKernelSpaces && i >= 256)
                        continue;

                    if (page[i] == 0)
                        continue;

                    switch (Level)
                    {
                        case 4:
                            dupVA.PML4 = i;
                            break;
                        case 3:
                            dupVA.DirectoryPointerOffset = i;
                            break;
                        case 2:
                            dupVA.DirectoryOffset = i;
                            break;
                        case 1:
                            dupVA.TableOffset = i;
                            break;
                        default:
                            break;
                    }

                    var pfn = new PFN
                    {
                        VA = new VIRTUAL_ADDRESS(dupVA.Address),
                        PTE = new HARDWARE_ADDRESS_ENTRY(page[i])
                    };
                    
                    PageContext.SubTables.Add(
                            pfn.VA,
                            pfn);   

                    yield return pfn;
                }
            }
            yield break;
        }



        long FillTable(bool RedundantKernelSpaces, int depth = 4)
        {
            var entries = 0L;
            var PageTables = new Dictionary<VIRTUAL_ADDRESS, PFN>();

            KernelSpace = RedundantKernelSpaces;
            // clear out the VA for the other indexes since were looking at the top level
            VIRTUAL_ADDRESS VA;
            VA.Address = 0;


            int level = 3;
            foreach (var kvp in DP.TopPageTablePage)
            {
                // Only extract user portion, kernel will be mostly redundant
                if(!RedundantKernelSpaces && kvp.Key >= 256)
                    continue;

                // were at the top level (4th)
                VA.PML4 = kvp.Key;

                var pfn = new PFN { PTE = kvp.Value, VA = new VIRTUAL_ADDRESS(VA.PML4 << 39) };
                PageTables.Add(VA, pfn);
                foreach(var DirectoryPointerOffset in ExtractNextLevel(pfn, KernelSpace, level))
                {
                    if (DirectoryPointerOffset == null) continue;

                    foreach (var DirectoryOffset in ExtractNextLevel(DirectoryPointerOffset, KernelSpace, level-1))
                    {
                        if (DirectoryOffset == null) continue;
                        foreach (var TableOffset in ExtractNextLevel(DirectoryOffset, KernelSpace, level - 2))
                        {
                            if (TableOffset == null) continue;
                            entries++;
                        }
                        entries++;
                    }
                    entries++;
                }
                entries++;
            }

            Root.Entries = new PFN()
            {
                SubTables = PageTables
            };

            // InlineExtract may be faster but it's memory requirement is higher which was a problem
            // when analyzing 64GB+ dumps (yes InVtero.net handles very big memory)++
#if FALSE
            

            // descend the remaining levelsPageTableEntries
            // if we find nothing, we can be sure the value were using for EPTP or CR3 is bogus
            var new_entries = InlineExtract(Root);
            if (new_entries == 0)
                return 0;

            entries += new_entries;
#endif
            // a hint for the full count of entries extracted
            Root.Count = entries;
            
            return entries;
        }
    }
}

