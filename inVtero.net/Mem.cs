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
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Threading;

using System.Collections.Concurrent;
using inVtero.net.Support;
using ProtoBuf;
using inVtero.net.Specialties;

using System.Diagnostics;

// Details on this struct can be found here and likely many other sources
// Microsoft published this originally on the singularity project's codeplex (along with some other ingerestiVng things)
//
//          //  Microsoft Research Singularity
//          typedef struct _PHYSICAL_MEMORY_RUN64
//          {
//              long64 BasePage;
//              long64 PageCount;
//          }
//          typedef struct _PHYSICAL_MEMORY_DESCRIPTOR64
//          {
//              long NumberOfRuns;
//              long64 NumberOfPages;
//              PHYSICAL_MEMORY_RUN64 Run[1];
//          }
//
namespace inVtero.net
{
    /// <summary>
    /// Physical to Virtual and Physical to Hypervisor Guest Virtual memory dump class
    /// 
    /// Convenient generic interfaces for extracting preferred types
    ///     * Type has to be a value/struct type and is expected to be 64 bits width
    ///     * TODO: Adjust for other size struts & values straddling page boundaries
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class Mem : IDisposable
    {
        AMemoryRunDetector ddes;
        /// <summary>
        /// DetectedDescriptor is meant for the user to assign when they have an override
        /// </summary>
        [ProtoMember(2)]
        public AMemoryRunDetector MD { get { return ddes; } set { ddes = value; } }

        [ProtoMember(4)]
        public bool OverrideBufferLoadInput { get; set; }

        /// <summary>
        /// MD actually gets used for extracting memory
        /// </summary>
        //[ProtoMember(1)]
        //public ThreadLocal<MemoryDescriptor> MD { get; set; }

        // there is a static for this also we can inherit from
        public long StartOfMemory; // adjust for .DMP headers or something

        [ProtoIgnore]
        public long MaxLimit { get { if (MD.PhysMemDesc != null) return MD.PhysMemDesc.MaxAddressablePageNumber; return 0; } }

        const int PageCacheMax = EnvLimits.PageCacheMaxEntries;

        MemoryMappedViewAccessor mappedAccess;
        MemoryMappedFile mappedFile;
        FileStream mapStream;

        [ProtoMember(3)]
        string MemoryDump;
        [ProtoMember(5)]
        long FileSize;
        [ProtoIgnore]
        public long Length { get { return FileSize; } }

        const long PAGE_SIZE = 0x1000;
        const long LARGE_PAGE_SIZE = 1024 * 1024 * 2;

        [ProtoIgnore]
        public long MapViewBase;
        [ProtoIgnore]
        public long MapViewSize;
#if USE_BITMAP
        WAHBitArray pfnTableIdx;
#endif
        public void DumpPFNIndex()
        {
#if USE_BITMAP
            if (!Vtero.VerboseOutput || pfnTableIdx == null)
                return;
            var idx = pfnTableIdx.GetBitIndexes();
            int i = 0;

            Console.WriteLine("Dumping PFN index");
            foreach (var pfn in idx)
            {
                Console.Write($"{pfn:X8} ");
                i += 8;
                if (i >= Console.WindowWidth - 7)
                    Console.Write(Environment.NewLine);
            }
#endif
        }
        Mem()
        {  
            // common init
            MapViewBase = 0;
            MapViewSize = 0x1000 * 0x1000 * 16L;
        }

        void SetupStreams()
        {
            // we want a process/thread private name for our mapped view
            mapStream = new FileStream(MemoryDump, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            mappedFile = MemoryMappedFile.CreateFromFile(mapStream,
                null,
                0,
                MemoryMappedFileAccess.Read,
                null,
                HandleInheritability.None,
                false);
            mappedAccess = mappedFile.CreateViewAccessor(
                MapViewBase,
                MapViewSize,
                MemoryMappedFileAccess.Read);
        }


        public Mem(Mem parent) : this()
        {
            MD = parent.MD;

            StartOfMemory = parent.StartOfMemory;
            MemoryDump = parent.MemoryDump;
            FileSize = parent.FileSize;
            MapViewSize = parent.MapViewSize;

            SetupStreams();
        }

        public static Mem InitMem(String mFile, AMemoryRunDetector Detector, uint[] BitmapArray = null) //: this()
        {
            
            var thiz = new Mem();

            thiz.StartOfMemory = Detector != null ? Detector.StartOfMem : 0;

            if (Detector != null)
            {
                thiz.StartOfMemory = Detector.StartOfMem;
                thiz.MD = Detector;
            }
#if USE_BITMAP
            // maybe there's a bit map we can use from a DMP file
            if (BitmapArray != null)
                pfnTableIdx = new WAHBitArray(WAHBitArray.TYPE.Bitarray, BitmapArray);
            else
                pfnTableIdx = new WAHBitArray();

            // 32bit's of pages should be plenty?
            pfnTableIdx.Length = (int) (MapViewSize / 0x1000);
#endif

            if (File.Exists(mFile))
            {
                thiz.MemoryDump = mFile;
                thiz.FileSize = new FileInfo(mFile).Length;

                if (Detector != null)
                    thiz.MD = Detector;
            }

            thiz.SetupStreams();

            return thiz;
        }


        public static ulong cntInAccessor = 0;
        public static ulong cntOutAccsor = 0;

        /// <summary>
        /// Get a pagesized block that contains the data from the byte offset specified
        /// </summary>
        /// <param name="FileOffset">byte offset of long aligned page block</param>
        /// <param name="block">to be filled on return optionally</param>
        /// <param name="DataRead">signals success</param>
        /// <returns>long value from fileoffset</returns>
        public long GetPageFromFileOffset(long FileOffset, ref long[] block, ref bool DataRead)
        {
            var rv = 0L;
            DataRead = false;
            var NewMapViewSize = MapViewSize;

            var CheckBase = FileOffset / MapViewSize;
            var NewMapViewBase = CheckBase * MapViewSize;

            if (FileOffset > FileSize)
                return 0;

            var AbsOffset = FileOffset - NewMapViewBase;
            var BlockOffset = AbsOffset & ~(PAGE_SIZE - 1);

            try
            {
                if (NewMapViewBase != MapViewBase)
                {
                    cntInAccessor++;

                    if (NewMapViewBase + MapViewSize > FileSize)
                        NewMapViewSize= FileSize - NewMapViewBase;
                    else
                        NewMapViewSize = MapViewSize;

                    mappedAccess = mappedFile.CreateViewAccessor(
                        NewMapViewBase,
                        NewMapViewSize,
                        MemoryMappedFileAccess.Read);

                    MapViewBase = NewMapViewBase;

                }
                else
                    cntOutAccsor++;

                if (block != null)
                {
                    var copy_len = block.Length;
                    if (BlockOffset + (block.Length * 8) > NewMapViewSize)
                        copy_len = (int) ((NewMapViewSize - BlockOffset) / 8);

                    UnsafeHelp.ReadBytes(mappedAccess, BlockOffset, ref block, copy_len);
                    rv = block[((AbsOffset >> 3) & 0x1ff)];
                }
                // FIX: ReadInt64 uses byte address so when we use it must adjust, check for other callers
                // assumptions since we changed this from array<long>[] maybe expecting old behavior, however
                // caller from getpageforphysaddr passes valid block usually so that's the main one from V2P
                else 
                    rv = mappedAccess.ReadInt64(BlockOffset | (AbsOffset & 0x1ff));
                DataRead = true;

            }
            catch (Exception ex)
            {
                throw new MemoryMapWindowFailedException("Unable to map or read memory offset", ex);
            }
            return rv;
        }


        public long RawOffsetToPFN(long offset)
        {
            long rv = 0;

            var aPFN = offset >> MagicNumbers.PAGE_SHIFT;

            for (int i = 0; i < MD.PhysMemDesc.NumberOfRuns; i++)
            {
                if (aPFN >= MD.PhysMemDesc.Run[i].BasePage &&
                    aPFN < (MD.PhysMemDesc.Run[i].BasePage + MD.PhysMemDesc.Run[i].PageCount))
                {
                    var currBaseOffset = aPFN - MD.PhysMemDesc.Run[i].BasePage;
                    rv += currBaseOffset;
                    break;
                }

                // if the page is not in a run, it does not exist!

                if(aPFN >= MD.PhysMemDesc.Run[i].BasePage)
                    rv += MD.PhysMemDesc.Run[i].PageCount;
            }

            return rv;
        }


        /// <summary>
        /// Code to convert a PFN, which is based on file offset >> PAGE_SHIFT,
        /// into an indexed PFN.
        /// 
        /// Physical memory is meant to have "gaps" historically reserved for hw interactions.
        /// 
        /// This means we need to adjust the byte offset into an index accounting for gaps.
        /// 
        /// TODO: Something similar is needed to natively support "extent" based sources. 
        /// </summary>
        /// <param name="aPFN">PFN (PAGE NUMBER)</param>
        /// <param name="MD">MemoryDescriptor with a configured Runs</param>
        /// <returns>adjusted file byte offset from backing storage (file)</returns>
        public long OffsetToMemIndex(long aPFN)
        {
            long bIndexedPFN = 0, bPFN = aPFN;
            bool Good = false;

            if (aPFN > MD.PhysMemDesc.MaxAddressablePageNumber)
                return -2;
            if (MD.PhysMemDesc == null)
                return -3;

            // Deal with best memory run
            int i = 0;
            for (i=0; i < MD.PhysMemDesc.NumberOfRuns; i++)
            {
                if (bPFN >= MD.PhysMemDesc.Run[i].BasePage &&
                    bPFN < (MD.PhysMemDesc.Run[i].BasePage + MD.PhysMemDesc.Run[i].PageCount))
                {
                    var currBaseOffset = bPFN - MD.PhysMemDesc.Run[i].BasePage;
                    bIndexedPFN += currBaseOffset;
                    Good = true;
                    break;
                }
                if(bPFN >= MD.PhysMemDesc.Run[i].BasePage)
                    bIndexedPFN += MD.PhysMemDesc.Run[i].PageCount;
            }
            // failed run lookup
            if (!Good)
                return -1;

            // Determine file offset based on indexed/gap adjusted PFN and page size
            var FileOffset = StartOfMemory + (bIndexedPFN << MagicNumbers.PAGE_SHIFT);

            return FileOffset;

        }

        public long GetPageForPhysAddr(HARDWARE_ADDRESS_ENTRY PAddr, ref long[] block, ref bool GotData)
        {
            long rv = 0;
            // convert PAddr to PFN
            var aPFN = PAddr.NextTable_PFN;
            GotData = false;

            // should return with - error_value
            // This happens quite a bit and is a good boost
            // I guess were constrained by int.MaxValue pages here. 
            // so that is about 8TB
            // TODO: explore 5 level page tables and larger than 8TB inputs :)
            if (aPFN > int.MaxValue || aPFN < 0)
                return 0;
#if USE_BITMAP
            if(pfnTableIdx != null)
                pfnTableIdx.Set((int)PFN, true);
#endif
            // paranoid android setting

            var FileOffset = OffsetToMemIndex(aPFN);
            if (FileOffset >= 0)
                rv = GetPageFromFileOffset(FileOffset + PAddr.AddressOffset, ref block, ref GotData);

            if (!GotData)
                rv = MagicNumbers.BAD_VALUE_READ;

            return rv;

        }

        /// <summary>
        /// Extract a single page of data from a physical address in source dump
        /// accounts for memory gaps/run layout
        /// </summary>
        /// <param name="PAddr">byte address an address contained in the block</param>
        /// <param name="block">array to be filled</param>
        /// <returns>specific return value for long value at </returns>
        public long GetPageForPhysAddr(HARDWARE_ADDRESS_ENTRY PAddr, ref long[] block) 
        {
            bool GoodRead = false;
            return GetPageForPhysAddr(PAddr, ref block, ref GoodRead);
        }


        /// <summary>
        /// Get a long back for the address specified
        /// </summary>
        /// <param name="PAddr">physical address (byte address)</param>
        /// <returns>value</returns>
        public long GetValueAtPhysicalAddr(HARDWARE_ADDRESS_ENTRY PAddr)
        {

            bool Ignored = false;
            long[] block = new long[512];

            return GetPageForPhysAddr(PAddr, ref block, ref Ignored);

            //return pageData[PAddr.AddressOffset >> 3];
        }

        // Translates virtual address to physical address  (normal CR3 path)
        // Since Valid & Read access overlap each other for EPT and normal PT go through this path for both
        public HARDWARE_ADDRESS_ENTRY VirtualToPhysical(HARDWARE_ADDRESS_ENTRY aCR3, long Addr)
        {
            var rv = HARDWARE_ADDRESS_ENTRY.MaxAddr;
            var va = new VIRTUAL_ADDRESS(Addr);
            var ConvertedV2P = new List<HARDWARE_ADDRESS_ENTRY>();
            var Attempted = HARDWARE_ADDRESS_ENTRY.MinAddr;

            //Console.WriteLine($"V2P CR3 = {aCR3.PTE:X16}  VA = {va}");
            // PML4E
            try
            {
                Attempted = (HARDWARE_ADDRESS_ENTRY) aCR3.NextTableAddress | (va.PML4 << 3);
                
                var PML4E = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                //Console.WriteLine($"PML4E = {PML4E.PTE:X16}");
                ConvertedV2P.Add(PML4E);
                if (PML4E.Valid)
                {
                    Attempted = PML4E.NextTableAddress | (va.DirectoryPointerOffset << 3);
                    var PDPTE = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                    ConvertedV2P.Add(PDPTE);
                    //Console.WriteLine($"PDPTE = {PDPTE.PTE:X16}");

                    if (PDPTE.Valid)
                    {
                        if (!PDPTE.LargePage)
                        {
                            Attempted = PDPTE.NextTableAddress | (va.DirectoryOffset << 3);
                            var PDE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                            ConvertedV2P.Add(PDE);
                            //Console.WriteLine($"PDE = {PDE.PTE:X16}");

                            if (PDE.Valid)
                            {
                                if (!PDE.LargePage)
                                {
                                    Attempted = PDE.NextTableAddress | (va.TableOffset << 3);
                                    var PTE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                                    ConvertedV2P.Add(PTE);
                                    //Console.WriteLine($"PTE = {PTE.PTE:X16}");
                                    //rv = PTE;
                                    // page is normal 4kb
                                    if (PTE.Valid)
                                        rv = PTE.PTE | (PTE.NextTableAddress | va.Offset);
                                    else
                                        rv.Valid = false;
                                }
                                else
                                {   // we have a 2MB page
                                    rv = PDE.PTE | ((PDE.PTE & 0xFFFFFFE00000) | va.TableOffset << 12);
                                }
                            }
                            else
                                rv.Valid = false;
                        }
                        else
                        {   // we have a 1GB page

                            rv = PDPTE.PTE | ((PDPTE.PTE & 0xFFFFC0000000) | va.DirectoryOffset << 12 << 9);
                            //rv = PDPTE;
                        }
                    }
                    else
                        rv.Valid = false;
                }
                else
                    rv.Valid = false;
            }
            catch (Exception ex)
            {
                rv.Valid = false;
            }
            finally
            {
                //foreach(var paddr in ConvertedV2P)
                //{
                //}
            }
            //Console.WriteLine($"return from V2P {rv:X16}");
            // serialize the dictionary out
            return rv;
        }

        // Translates virtual address to physical address by way of CR3->EPTP double dereferencing (up to 24 loads)
        public HARDWARE_ADDRESS_ENTRY VirtualToPhysical(HARDWARE_ADDRESS_ENTRY eptp, HARDWARE_ADDRESS_ENTRY aCR3, long Addr)
        {
            var rv = HARDWARE_ADDRESS_ENTRY.MinAddr;
            var va = new VIRTUAL_ADDRESS(Addr);
            var gVa = new VIRTUAL_ADDRESS(aCR3.PTE);
            var Attempted = HARDWARE_ADDRESS_ENTRY.MinAddr;
            var ConvertedV2hP = new List<HARDWARE_ADDRESS_ENTRY>();

            try
            {
                Attempted = gVa.Address;
                //convert Guest CR3 gPA into Host CR3 pPA
                var gpaCR3 = VirtualToPhysical(eptp, gVa.Address);

                //Console.WriteLine($"In V2P2P, using CR3 {aCR3.PTE:X16}, found guest phys CR3 {gpaCR3.PTE:X16}, attempting load of PML4E from {(gpaCR3 | va.PML4):X16}");
                // gPML4E - as we go were getting gPA's which need to pPA

                Attempted = gpaCR3.NextTableAddress | va.PML4 ;

                var gPML4E = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                ConvertedV2hP.Add(gPML4E);

                //Console.WriteLine($"guest PML4E = {gPML4E}");
                // take CR3 and extract gPhys for VA we want to query
                
                var hPML4E = VirtualToPhysical(eptp, gPML4E.NextTableAddress);
                if (EPTP.IsValid(hPML4E.PTE) && EPTP.IsValid2(hPML4E.PTE) && HARDWARE_ADDRESS_ENTRY.IsBadEntry(hPML4E))
                { 
                    Attempted = hPML4E.NextTableAddress | (va.DirectoryPointerOffset << 3);
                    var gPDPTE = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                    ConvertedV2hP.Add(gPDPTE);
                    var hPDPTE = VirtualToPhysical(eptp, gPDPTE.NextTableAddress);

                    if (EPTP.IsValid(hPDPTE.PTE))
                    {
                        if (!EPTP.IsLargePDPTE(hPDPTE.PTE))
                        {
                            if (EPTP.IsValid2(hPDPTE.PTE))
                            {
                                Attempted = hPDPTE.NextTableAddress | (va.DirectoryOffset << 3);
                                var gPDE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                                ConvertedV2hP.Add(gPDE);
                                var hPDE = VirtualToPhysical(eptp, gPDE.NextTableAddress);

                                if (EPTP.IsValid(hPDE.PTE))
                                {
                                    if (!EPTP.IsLargePDE(hPDE.PTE))
                                    {
                                        if (EPTP.IsValid2(hPDE.PTE))
                                        {
                                            Attempted = hPDE.NextTableAddress | (va.TableOffset << 3);
                                            var gPTE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                                            ConvertedV2hP.Add(gPTE);
                                            var hPTE = VirtualToPhysical(eptp, gPTE.NextTableAddress);

                                            if (EPTP.IsValidEntry(hPTE.PTE))
                                                rv = hPTE.NextTableAddress | va.Offset;
                                        }
                                    }
                                    else {
                                        rv = (hPDE.PTE & 0xFFFFFFE00000) | va.TableOffset; //(Addr & 0x1FFFFF);
                                    }
                                }
                            }
                        }
                        else {
                            rv = (hPDPTE.PTE & 0xFFFFC0000000) | va.DirectoryOffset; //(Addr & 0x3FFFFFFF);
                        }
                    }
                }
            }
            catch(PageNotFoundException ex)
            {
                throw new ExtendedPageNotFoundException(
                    $"V2gP2hP conversion error. EPTP:{eptp}, CR3:{aCR3}, Requesting:{Attempted} Step:{ConvertedV2hP.Count()}. Step of 0 may indicate invalid EPTP.{Environment.NewLine}"
                    , eptp, aCR3, Attempted, ConvertedV2hP, ex);
            }
            return rv;
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
                    if (mappedAccess != null)
                        mappedAccess.Dispose();

                    if (mappedFile != null)
                        mappedFile.Dispose();

                    if (mapStream != null)
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


    public class MemException : Exception
    {
        public MemException() { }
        public MemException(string message) : base(message) { }
    }

    public class PageNotFoundException : Exception
    {
        public List<HARDWARE_ADDRESS_ENTRY> PagesFound;
        public HARDWARE_ADDRESS_ENTRY LastPageAttempted;

        public PageNotFoundException(string message, HARDWARE_ADDRESS_ENTRY lastPageAttempted, List<HARDWARE_ADDRESS_ENTRY> pagesFound, Exception ex)
            : base(message, ex)
        {
            PagesFound = pagesFound;
            LastPageAttempted = lastPageAttempted;
        }
    }

    public class ExtendedPageNotFoundException : Exception
    {
        public List<HARDWARE_ADDRESS_ENTRY> EPFound;
        public HARDWARE_ADDRESS_ENTRY LastEPAttempted;
        public HARDWARE_ADDRESS_ENTRY RequestedEPTP;
        public HARDWARE_ADDRESS_ENTRY RequestedCR3;

        public ExtendedPageNotFoundException(string message, HARDWARE_ADDRESS_ENTRY eptpUsed, HARDWARE_ADDRESS_ENTRY cr3Used, HARDWARE_ADDRESS_ENTRY lastEPAttempted, List<HARDWARE_ADDRESS_ENTRY> ePFound, PageNotFoundException ex)
            : base(message, ex)
        {

            EPFound = ePFound;
            LastEPAttempted = lastEPAttempted;
            RequestedCR3 = cr3Used;
            RequestedEPTP = eptpUsed;
        }
    }

    public class MemoryRunMismatchException : Exception
    {
        public long PageRunNumber;
        public MemoryRunMismatchException()
            : base("Examine Mem:MemoryDescriptor to determine why the requested PFN (page run number) was not present. Inaccurate gap list creation/walking is typically to blame.")
        { }
        public MemoryRunMismatchException(long pageRunNumber) : this()
        {
            PageRunNumber = pageRunNumber;
        }
    }


    public class MemoryMapWindowFailedException : Exception
    {
        public MemoryMapWindowFailedException() : base()
        { }
        public MemoryMapWindowFailedException(string message) : base(message)
        { }
        public MemoryMapWindowFailedException(string message, Exception ex) : base(message, ex)
        { }

    }
}


