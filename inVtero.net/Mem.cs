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
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.MemoryMappedFiles;
using System.Diagnostics;
using System.Collections.Concurrent;
// Details on this struct can be found here and likely many other sources
// Microsoft published this origionally on the singularity project's codeplex (along with some other ingerestiVng things)
//      http://volatility.googlecode.com/svn-history/r2779/branches/scudette/tools/windows/winpmem/executable/Dump.h
//          //  Microsoft Research Singularity
//          typedef struct _PHYSICAL_MEMORY_RUN64
//          {
//              ULONG64 BasePage;
//              ULONG64 PageCount;
//          }
//          typedef struct _PHYSICAL_MEMORY_DESCRIPTOR64
//          {
//              ULONG NumberOfRuns;
//              ULONG64 NumberOfPages;
//              PHYSICAL_MEMORY_RUN64 Run[1];
//          }
//
namespace inVtero.net
{
    /// <summary>
    /// Physical to Virtual and Physical to Hypervisor Guest Virtual memory dump class
    /// 
    /// Convienent generic interfaces for extracting preferred types
    ///     * Type has to be a value/struct type and is expected to be 64 bits width
    ///     * TODO: Adjust for other size structs & values stradling page boundries
    /// </summary>
    public class Mem : IDisposable
    {
        public ulong StartOfMemory; // adjust for .DMP headers or something
        public ulong GapScanSize;   // auto-tune for seeking gaps default is 0x10000000 

        IDictionary<ulong, ulong> DiscoveredGaps;

        MemoryMappedViewAccessor mappedAccess;
        MemoryMappedFile mappedFile;
        FileStream mapStream;
        MemoryDescriptor MD;

        string MemoryDump;
        ulong FileSize;

        const int PAGE_SIZE = 0x1000;

        public Mem(String mFile)
        {
            GapScanSize = 0x10000000;
            StartOfMemory = 0;

            if (File.Exists(mFile))
            {
                MemoryDump = mFile;
                FileSize = (ulong)new FileInfo(MemoryDump).Length;
                MD = new MemoryDescriptor(FileSize);

                mapStream = new FileStream(MemoryDump, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                mappedFile = MemoryMappedFile.CreateFromFile(mapStream,
                        Path.GetFileNameWithoutExtension(MemoryDump),
                        0,
                        MemoryMappedFileAccess.Read,
                        null,
                        HandleInheritability.Inheritable,
                        false);

                DiscoveredGaps = new Dictionary<ulong, ulong>();
                AddressEnvalope = new ConcurrentDictionary<HARDWARE_ADDRESS_ENTRY, List<AddressX>>();

            }
        }


        public T[] GetValueFromPT<T>(ulong TableRegister, ulong Addr, ref bool Success) where T : struct
        {
            var paddr = VirtualToPhysical(TableRegister, Addr, ref Success);
            if (!Success)
                return null;
            var data = GetPageForPhysAddr<T>(paddr);
            return data;
        }

        // Extract a single page of data from a Virtual location (CR3 translation)
        public T[] GetVirtualPage<T>(ulong CR3, ulong Addr, ref bool Success) where T : struct
        {
            var paddr = VirtualToPhysical(CR3, Addr, ref Success);
            if (!Success)
                return null;
            var data = GetPageForPhysAddr<T>(paddr);
            return data;
        }

        // Extract a single page of data from a Virtual location (EPTP & CR3 translation)
        public T[] GetHyperPage<T>(HARDWARE_ADDRESS_ENTRY eptp, HARDWARE_ADDRESS_ENTRY CR3, ulong Addr, ref bool Success) where T : struct
        {
            var paddr = VirtualToPhysical(eptp, CR3, Addr, ref Success);
            if (!Success)
                return null;
            var data = GetPageForPhysAddr<T>(paddr);
            
            return data;
        }
        // Extract a single page of data from a physical address in source dump
        // accout for memory gaps/run layout
        // TODO: Add windowing currently uses naieve single-page-at-a-time view
        public T[] GetPageForPhysAddr<T>(HARDWARE_ADDRESS_ENTRY PAddr) where T : struct
        {
            ulong FileOffset = 0;
            // convert PAddr to PFN
            var PFN = PAddr.NextTable_PFN;

            // paranoid android setting
            var Fail = true;

            ulong IndexedPFN = 0;
            for (int i = 0; i < MD.NumberOfRuns; i++)
            {
                if (PFN >= MD.Run[i].BasePage && PFN < (MD.Run[i].BasePage + MD.Run[i].PageCount))
                {
                    var currBaseOffset = PFN - MD.Run[i].BasePage;
                    IndexedPFN += currBaseOffset;
                    Fail = false;
                    break;
                }
                IndexedPFN += MD.Run[i].PageCount;
            }
            if (Fail)
                return null;

            // Determine file offset based on indexed/gap adjusted PFN and page size
            FileOffset = StartOfMemory + (IndexedPFN * PAGE_SIZE);

            T[] block = null;

            try {
                block = new T[512];
                mappedAccess = mappedFile.CreateViewAccessor(
                    (long)FileOffset,
                    (long)4096,
                    MemoryMappedFileAccess.Read);

                mappedAccess.ReadArray(0, block, 0, 512);

            } catch (Exception) {
                Fail = true;
            }

            if (Fail)
                return null;

            return block;
        }

        public ulong GetPFNAtPhysicalAddr(HARDWARE_ADDRESS_ENTRY PAddr, ref bool Success)
        {
            var pageData = GetPageForPhysAddr<ulong>(PAddr);
            if (pageData == null)
            {
                Success = false;
                return 0;
            }
            Success = true;

            return pageData[PAddr.AddressOffset >> 3] & 0xFFFFFFFFFF000;
        }

        public T GetValueAtPhysicalAddr<T>(HARDWARE_ADDRESS_ENTRY PAddr, ref bool Success) where T : struct
        {
            Success = false;
            var pageData = GetPageForPhysAddr<T>(PAddr);
            if (pageData == null)
                return default(T);

            Success = true;
            return pageData[PAddr.AddressOffset >> 3];
        }

        // Translates virtual address to physical address  (normal CR3 path)
        // Since Valid & Read access overlap each other for EPT and normal PT go through this path for both
        public HARDWARE_ADDRESS_ENTRY VirtualToPhysical(HARDWARE_ADDRESS_ENTRY aCR3, ulong Addr, ref bool Success)
        {
            var rv = HARDWARE_ADDRESS_ENTRY.MinAddr;
            var va = new VIRTUAL_ADDRESS(Addr);

            //Console.WriteLine($"V2P CR3 = {aCR3.PTE:X16}  VA = {va}");

            // PML4E
            var PML4E = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>(aCR3.NextTableAddress | va.PML4, ref Success);
            //Console.WriteLine($"PML4E = {PML4E.PTE:X16}");

            if (PML4E.Valid && Success)
            {
                // PDPTE
                var PDPTE = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>(PML4E.NextTableAddress | va.DirectoryPointerOffset, ref Success);
                //Console.WriteLine($"PDPTE = {PDPTE.PTE:X16}");

                if (PDPTE.Valid && Success)
                {
                    if (!PDPTE.LargePage)
                    {
                        // PDE
                        var PDE = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>(PDPTE.NextTableAddress | va.DirectoryOffset, ref Success);
                        //Console.WriteLine($"PDE = {PDE.PTE:X16}");

                        if (PDE.Valid && Success)
                        {
                            if (!PDE.LargePage)
                            {
                                // PTE
                                var PTE = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>(PDE.NextTableAddress | va.TableOffset, ref Success);
                                //Console.WriteLine($"PTE = {PTE.PTE:X16}");

                                // page is normal 4kb
                                if (PTE.Valid && Success)
                                    rv = PTE.NextTableAddress | va.Offset;
                                else
                                    Success = false;
                            }
                            else
                            {   // we have a 2MB page
                                rv = (PDE.PTE & 0xFFFFFFE00000) | (Addr & 0x1FFFFF);
                            }
                        }else
                            Success = false;
                    }
                    else
                    {   // we have a 1GB page
                        rv = (PDPTE.PTE & 0xFFFFC0000000) | (Addr & 0x3FFFFFFF);
                    }
                }
                else
                    Success = false;
            }
            else
                Success = false;

            Console.WriteLine($"return from V2P {rv:X16}");
            return rv;
        }

        /// <summary>
        /// Determine if there's a memory gap we need to adjust for behind a hypervisor layer
        /// This should be done 
        /// </summary>
        /// <param name="HPA_CR3">Host Physical Address of CR3 to be verified</param>
        /// <param name="GPA_CR3">Guest Physical Address of CR3 </param>
        /// <returns>a size that needs to be subtrated from the address to re-align</returns>
        ulong ValidateAndGetGap(HARDWARE_ADDRESS_ENTRY HPA_CR3, HARDWARE_ADDRESS_ENTRY GPA_CR3)
        {
            ulong rv = ulong.MaxValue;
            var Loc = 0;

            var hostCR3p = GetPageForPhysAddr<HARDWARE_ADDRESS_ENTRY>(HPA_CR3);

            while (Loc == 0 && hostCR3p != null)
            {
                foreach (var each in Typical_Offsets.Each)
                    if ((hostCR3p[each].PTE & 0xFFFFFFFFF000) == GPA_CR3.PTE)
                        Loc = each;

                // If we havent found the pointer, reduce by a typical gap size
                if (Loc == 0)
                {
                    if (HPA_CR3.PTE > GapScanSize)
                    {
                        HPA_CR3.PTE -= GapScanSize;
                        rv += GapScanSize;

                        hostCR3p = GetPageForPhysAddr<HARDWARE_ADDRESS_ENTRY>(HPA_CR3);
                        if (hostCR3p == null)
                            return rv;
                    }
                    else
                        return rv;
                } 
            }
            return rv;
        }

        // Translates virtual address to physical address by way of CR3->EPTP double dereferencing (up to 24 loads)
        public HARDWARE_ADDRESS_ENTRY VirtualToPhysical(HARDWARE_ADDRESS_ENTRY eptp, HARDWARE_ADDRESS_ENTRY aCR3, ulong Addr, ref bool Success)
        {
            var rv = HARDWARE_ADDRESS_ENTRY.MinAddr;
            var va = new VIRTUAL_ADDRESS(Addr);
            var gPa = new VIRTUAL_ADDRESS(aCR3);

            //convert Guest CR3 gPA into Host CR3 pPA
            var gpaCR3 = VirtualToPhysical(eptp, aCR3, ref Success);

            // Validate page table. Possibly adjust for run gaps
            var GapSize = ValidateAndGetGap(gpaCR3, aCR3);
            // let's just ignore failures for now
            if (GapSize == ulong.MaxValue)
            {
                Debug.Print("Table verification error.  YMMV.");
                GapSize = 0;
            }

            Console.WriteLine($"In V2P2P, using CR3 {aCR3.PTE:X16}, found guest phys CR3 {gpaCR3.PTE:X16}, attemptng load of PML4E from {(gpaCR3 | va.PML4):X16}");

            // gPML4E - as we go were getting gPA's which need to pPA
            var gPML4E = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>((gpaCR3.NextTableAddress - GapSize) | va.PML4, ref Success);

            Console.WriteLine($"guest PML4E = {gPML4E}");

            // take CR3 and extract gPhys for VA we want to query
            if (Success)
            {
                // hPML4E
                var hPML4E = VirtualToPhysical(eptp, gPML4E.NextTableAddress, ref Success);
                if (Success)
                {
                    // gPDPTE
                    var gPDPTE = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>((hPML4E.NextTableAddress - GapSize) | va.DirectoryPointerOffset, ref Success);
                    if (Success)
                    {
                        // hPDPTE
                        var hPDPTE = VirtualToPhysical(eptp, gPDPTE.NextTableAddress, ref Success);
                        if (Success)
                        {
                            if (!hPDPTE.LargePage)
                            {
                                // gPDE
                                var gPDE = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>((hPDPTE.NextTableAddress - GapSize) | va.DirectoryOffset, ref Success);
                                if (Success)
                                {
                                    //hPDE
                                    var hPDE = VirtualToPhysical(eptp, gPDE.NextTableAddress, ref Success);
                                    if (Success)
                                    {
                                        if (!hPDE.LargePage)
                                        {
                                            // gPTE
                                            var gPTE = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>((hPDE.NextTableAddress - GapSize) | va.TableOffset, ref Success);
                                            if (Success)
                                            {
                                                var hPTE = VirtualToPhysical(eptp, gPTE.NextTableAddress, ref Success);
                                                if (Success)
                                                {
                                                    rv = (hPTE.NextTableAddress - GapSize) | va.Offset;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            rv = (hPDE.PTE & 0xFFFFFFE00000) | (Addr & 0x1FFFFF);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                rv = (hPDPTE.PTE & 0xFFFFC0000000) | (Addr & 0x3FFFFFFF);
                            }
                        }
                    }
                }
            }
            return rv;
        }

        // meant to be key: CR3 / Top level address of page table - List's are all addresses found that can be addressed by this process.
        ConcurrentDictionary<HARDWARE_ADDRESS_ENTRY, List<AddressX>> AddressEnvalope;

        /// <summary>
        /// Suck up the page table into a managed representation
        /// 
        /// This serves several purposes.  
        ///   1. Deteciton of run's/gaps.  
        ///         We can infer run's exist when we detect abnormally large jumps in PFN values.
        ///         IF the values can not be found then there must be a gap.
        /// </summary>
        /// <param name="aCR3"></param>
        public void CacheAndEnum(HARDWARE_ADDRESS_ENTRY aCR3)
        {
            bool Success = false;
            if (AddressEnvalope == null)
            {
                //var PML4E = GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>(aCR3.NextTableAddress, ref Success);
                HARDWARE_ADDRESS_ENTRY[] PML4E = GetPageForPhysAddr<HARDWARE_ADDRESS_ENTRY>(aCR3.NextTableAddress);

                if (!Success)
                    return;

                for (int i = 0; i < 512; i++)
                {
                }
            }
        }


        public void CacheAndEnum(HARDWARE_ADDRESS_ENTRY eptp, HARDWARE_ADDRESS_ENTRY aCR3)
        {

        }


        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                // release / clear up streams
                if (disposing)
                {
                    if(mappedAccess != null)
                        mappedAccess.Dispose();

                    if(mappedFile != null)
                        mappedFile.Dispose();

                    if(mapStream != null)
                        mapStream.Dispose();

                    mappedAccess = null;
                    mappedFile = null;
                    mapStream = null;
                }
                // no unmanaged resources e.g. AllocHGlobal etc...
                disposedValue = true;
            }
        }
        /// <summary>
        /// Finalizer override not really needed
        /// No unmanaged buffers
        /// </summary>
        ~Mem()
        {
            Dispose(false);
        }
        /// <summary>
        /// Dispose streams held in class instance
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            // mine as well even though only releasing managed streams
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
