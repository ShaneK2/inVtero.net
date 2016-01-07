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
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Threading;

using RaptorDB;
using System.Collections.Concurrent;
using inVtero.net.Support;

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
    public class Mem : IDisposable
    {
        MemoryDescriptor ddes;
        /// <summary>
        /// DetectedDescriptor is meant for the user to assign when they have an override
        /// </summary>
        public MemoryDescriptor DetectedDescriptor { get { return ddes; } set { ddes = value; if(value != null) MD = value; } }
        public bool BufferLoadInput { get { return OverrideBufferLoadInput ? true : FileSize < BufferLoadMax; } }

        public bool OverrideBufferLoadInput { get; set; }

        /// <summary>
        /// MD actually gets used for extracting memory
        /// </summary>
        MemoryDescriptor MD { get; set; }


        public long StartOfMemory; // adjust for .DMP headers or something
        public long GapScanSize;   // auto-tune for seeking gaps default is 0x10000000 

        const long BufferLoadMax = 20L * 1024 * 1024 * 1024; // If the input is larger than 20GB were not going to buffer load it 
        const int PageCacheMax = 100000;

        IDictionary<long, long> DiscoveredGaps;

        MemoryMappedViewAccessor mappedAccess;
        MemoryMappedFile mappedFile;
        FileStream mapStream;

        string MemoryDump;
        long FileSize;
        public long Length { get { return FileSize; } }

        const long PAGE_SIZE = 0x1000;
        static int mindex = 0;

        long MapViewBase;
        long MapViewSize;

        WAHBitArray pfnTableIdx;
        public void DumpPFNIndex()
        {
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
        }

        Mem()
        {
            // so not even 1/2 the size of the window which was only getting < 50% hit ratio at best
            // PageCache may be better off than a huge window...
            // PageCacheMax default is 100000 which is 390MB or so.
            if(!PageCache.Initalized)
                PageCache.InitPageCache(Environment.ProcessorCount * 4, PageCacheMax);

            // not really used right now
            GapScanSize = 0x10000000;

            // common init
            MapViewBase = 0;
            // 64MB
            MapViewSize = (0x1000 * 0x1000 * 4);

            DiscoveredGaps = new Dictionary<long, long>();
        }

        void SetupStreams()
        {
            var lmindex = Interlocked.Increment(ref mindex);
            var mapName = Path.GetFileNameWithoutExtension(MemoryDump) + lmindex.ToString();

            mapStream = new FileStream(MemoryDump, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            mappedFile = MemoryMappedFile.CreateFromFile(mapStream,
                    mapName,
                    0,
                    MemoryMappedFileAccess.Read,
                    null,
                    HandleInheritability.Inheritable,
                    false);

            mappedAccess = mappedFile.CreateViewAccessor(
                MapViewBase,
                MapViewSize,
                MemoryMappedFileAccess.Read);
        }



        public Mem(Mem parent) : this()
        {
            MD = parent.MD;
            DetectedDescriptor = parent.DetectedDescriptor;

            StartOfMemory = parent.StartOfMemory;
            MemoryDump = parent.MemoryDump;
            FileSize = parent.FileSize;

            SetupStreams();
        }

        public Mem(String mFile, uint[] BitmapArray = null, MemoryDescriptor Override = null) : this()
        {

            StartOfMemory = Override != null ? Override.StartOfMemmory : 0;

            if (Override != null)
            {
                StartOfMemory = Override.StartOfMemmory;
                MD = Override;
            }

            // maybe there's a bit map we can use from a DMP file
            if (BitmapArray != null)
                pfnTableIdx = new WAHBitArray(WAHBitArray.TYPE.Bitarray, BitmapArray);
            else
                pfnTableIdx = new WAHBitArray();

            // 32bit's of pages should be plenty?
            pfnTableIdx.Length = (int) (MapViewSize / 0x1000);


            if (File.Exists(mFile))
            {
                MemoryDump = mFile;
                FileSize = new FileInfo(MemoryDump).Length;

                if (Override != null)
                    MD = Override;
                else {
                    MD = new MemoryDescriptor(FileSize);
                    if (DetectedDescriptor != null)
                        MD = DetectedDescriptor;
                }
            }

            SetupStreams();
        }

        public static ulong cntInAccessor = 0;
        public static ulong cntOutAccsor = 0;

        public long GetPageFromFileOffset(long FileOffset, ref long[] block, ref bool DataRead)
        {
            var rv = 0L;
            var NewMapViewBase = MapViewBase;
            var NewMapViewSize = MapViewSize;
            DataRead = false;


            var CheckBase = FileOffset / MapViewSize;
            if (MapViewBase != CheckBase * MapViewSize)
                NewMapViewBase = CheckBase * MapViewSize;

            if (FileOffset > FileSize)
                return 0;

            if (FileOffset < NewMapViewBase)
                throw new OverflowException("FileOffset must be >= than base");

            var AbsOffset = FileOffset - NewMapViewBase;
            var BlockOffset = AbsOffset & ~(PAGE_SIZE - 1);

            try
            {
                if (NewMapViewBase != MapViewBase)
                {
                    cntInAccessor++;

                    if (NewMapViewBase + MapViewSize > FileSize)
                        NewMapViewSize = FileSize - NewMapViewBase;
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

                if(block != null)
                    UnsafeHelp.ReadBytes(mappedAccess, BlockOffset, ref block);

                rv = mappedAccess.ReadInt64(AbsOffset);
                DataRead = true;

            }
            catch (Exception ex)
            {
                throw new MemoryMapWindowFailedException("Unable to map or read memory offset", ex);
            }
            return rv;
        }

        public long GetPageForPhysAddr(HARDWARE_ADDRESS_ENTRY PAddr, ref long[] block, ref bool GotData, bool NoCache = false)
        {
            // convert PAddr to PFN
            var PFN = PAddr.NextTable_PFN;
            GotData = false;

            if (!NoCache && PageCache.ContainsKey(PFN))
            {
                do
                    PageCache.TryGetValue(PFN, out block);
                while (block == null);

                return block[PAddr & 0x1ff];
            }

            // record our access attempt to the pfnIndex
            if (PFN > int.MaxValue || PFN > MD.MaxAddressablePageNumber)
                return 0;

            if(pfnTableIdx != null)
                pfnTableIdx.Set((int)PFN, true);

            // paranoid android setting
            var Fail = true;

            long IndexedPFN = 0;
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
                throw new MemoryRunMismatchException(PAddr.PTE);

            // Determine file offset based on indexed/gap adjusted PFN and page size
            var FileOffset = StartOfMemory + (IndexedPFN * PAGE_SIZE);

            // add back in the file offset for possible exact byte lookup
            var rv = GetPageFromFileOffset(FileOffset + PAddr.AddressOffset, ref block, ref GotData);


            if(!NoCache && GotData)
                PageCache.TryAdd(PFN, block);

            else if (!GotData)
                rv = MagicNumbers.BAD_VALUE_READ;

            return rv;

        }

        // Extract a single page of data from a physical address in source dump
        // account for memory gaps/run layout
        // TODO: Add windowing currently uses naïve single-page-at-a-time view
        public long GetPageForPhysAddr(HARDWARE_ADDRESS_ENTRY PAddr, ref long[] block) 
        {
            bool GoodRead = false;
            return GetPageForPhysAddr(PAddr, ref block, ref GoodRead);
        }


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
                Attempted = (HARDWARE_ADDRESS_ENTRY) aCR3.NextTableAddress | va.PML4;
                var PML4E = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                //Console.WriteLine($"PML4E = {PML4E.PTE:X16}");
                ConvertedV2P.Add(PML4E);
                if (PML4E.Valid)
                {
                    Attempted = PML4E.NextTableAddress | va.DirectoryPointerOffset;
                    var PDPTE = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                    ConvertedV2P.Add(PDPTE);
                    //Console.WriteLine($"PDPTE = {PDPTE.PTE:X16}");

                    if (PDPTE.Valid)
                    {
                        if (!PDPTE.LargePage)
                        {
                            Attempted = PDPTE.NextTableAddress | va.DirectoryOffset;
                            var PDE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                            ConvertedV2P.Add(PDE);
                            //Console.WriteLine($"PDE = {PDE.PTE:X16}");

                            if (PDE.Valid)
                            {
                                if (!PDE.LargePage)
                                {
                                    Attempted = PDE.NextTableAddress | va.TableOffset;
                                    var PTE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                                    ConvertedV2P.Add(PTE);
                                    //Console.WriteLine($"PTE = {PTE.PTE:X16}");

                                    // page is normal 4kb
                                    if (PTE.Valid)
                                        rv = PTE.NextTableAddress | va.Offset;
                                    else
                                        rv.Valid = false;
                                }
                                else
                                {   // we have a 2MB page
                                    rv = (PDE.PTE & 0xFFFFFFE00000) | va.TableOffset << 12;
                                }
                            }
                            else
                                rv.Valid = false;
                        }
                        else
                        {   // we have a 1GB page
                            rv = (PDPTE.PTE & 0xFFFFC0000000) | va.DirectoryOffset << 12 << 9;
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
                throw new PageNotFoundException("V2P conversion error page not found", Attempted, ConvertedV2P, ex);
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

                // Validate page table. Possibly adjust for run gaps
                //var GapSize = ValidateAndGetGap(gpaCR3, aCR3);
                // let's just ignore failures for now
                //if (GapSize == long.MaxValue)
                //Debug.Print("Table verification error.  YMMV.");
                long GapSize = 0;
                //}

                //Console.WriteLine($"In V2P2P, using CR3 {aCR3.PTE:X16}, found guest phys CR3 {gpaCR3.PTE:X16}, attempting load of PML4E from {(gpaCR3 | va.PML4):X16}");
                // gPML4E - as we go were getting gPA's which need to pPA

                Attempted = (gpaCR3.NextTableAddress - GapSize) | va.PML4 ;

                var gPML4E = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                ConvertedV2hP.Add(gPML4E);

                //Console.WriteLine($"guest PML4E = {gPML4E}");
                // take CR3 and extract gPhys for VA we want to query
                
                var hPML4E = VirtualToPhysical(eptp, gPML4E.NextTableAddress);
                if (EPTP.IsValid(hPML4E.PTE) && EPTP.IsValid2(hPML4E.PTE) && HARDWARE_ADDRESS_ENTRY.IsBadEntry(hPML4E))
                { 
                    Attempted = (hPML4E.NextTableAddress - GapSize) | va.DirectoryPointerOffset;
                    var gPDPTE = (HARDWARE_ADDRESS_ENTRY) GetValueAtPhysicalAddr(Attempted);
                    ConvertedV2hP.Add(gPDPTE);
                    var hPDPTE = VirtualToPhysical(eptp, gPDPTE.NextTableAddress);

                    if (EPTP.IsValid(hPDPTE.PTE))
                    {
                        if (!EPTP.IsLargePDPTE(hPDPTE.PTE))
                        {
                            if (EPTP.IsValid2(hPDPTE.PTE))
                            {
                                Attempted = (hPDPTE.NextTableAddress - GapSize) | va.DirectoryOffset;
                                var gPDE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                                ConvertedV2hP.Add(gPDE);
                                var hPDE = VirtualToPhysical(eptp, gPDE.NextTableAddress);

                                if (EPTP.IsValid(hPDE.PTE))
                                {
                                    if (!EPTP.IsLargePDE(hPDE.PTE))
                                    {
                                        if (EPTP.IsValid2(hPDE.PTE))
                                        {
                                            Attempted = (hPDE.NextTableAddress - GapSize) | va.TableOffset;
                                            var gPTE = (HARDWARE_ADDRESS_ENTRY)GetValueAtPhysicalAddr(Attempted);
                                            ConvertedV2hP.Add(gPTE);
                                            var hPTE = VirtualToPhysical(eptp, gPTE.NextTableAddress);

                                            if (EPTP.IsValidEntry(hPTE.PTE))
                                                rv = (hPTE.NextTableAddress - GapSize) | va.Offset;
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


