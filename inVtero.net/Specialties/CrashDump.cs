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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Console;
using inVtero.net;
using static inVtero.net.Misc;


/// <summary>
/// Adding some specialties for practical purposes.
/// 
/// Having a completely generic system is great but to ignore the utility of a strong type is 
/// a bit crazy...
/// 
/// Initial support for CrashDump based on public sources (see: wasm.ru) 
/// 
/// We will aim to detect 2 things, RUN[] (memory run data) and Mem* (start of data)
/// 
/// That should be all that is required.  After we initialize these 2 values the next order of operations,
/// in the case of Windows we can brute force the debug block
/// and do a symbol lookup of the in-memory GUID to find the offset into the patch guard ^ keys so we 
/// can do a decodepointer to give us the DEBUGGER data for pretty much * symbols.
/// 
/// Adding DMP will also give us the ability to do a faster dev cycle since we'll be able to simply bring up
/// an equivalent analysis in windbg to see if our interpretation is accurate.
/// 
/// </summary>
namespace inVtero.net.Specialties
{
    /// <summary>
    /// DMP is the most practical for now, perhaps VMWARE (which for our purposes is very easy,
    /// since we don't care about register data or anything other than memory run gaps that would
    /// desynchronize our PFN lookup) after this.
    /// 
    /// Amazingly simple to support the basic CrashDump format (Thank you MicroSoft)
    /// </summary>
    public class CrashDump : AMemoryRunDetector, IMemAwareChecking
    {

        // TODO: All these things that do file I/O need to be better at closing resources down / ISTREAM
        string DumpFile;
        long MemSize;
        FileInfo finfo;
        long MaxNumPages;

#if OLD_CODE
        public MemoryDescriptor ExtractMemDesc(Vtero vtero)
        {
            MemoryDescriptor MemRunDescriptor = null;
            var off = vtero.ScanValue(false, 0x6c4d6d4d, 4);
            
            using (var dstream = File.OpenRead(vtero.MemFile))
            {
                using (var dbin = new BinaryReader(dstream))
                {
                    foreach (var xoff in off)
                    {
                        //WriteLine($"Checking Memory Descriptor @{(xoff + 28):X}");
                        if (xoff > vtero.FileSize)
                        {
                        //    WriteLine($"offset {xoff:X} > FileSize {vtero.FileSize:X}");
                            continue;
                        }

                        dstream.Position = xoff + 20; // TODO: double check we ma need to do a sub loop step range 8,16,20,24,28,32 -- ensure we scan hard'r
                        MemRunDescriptor = new MemoryDescriptor();
                        MemRunDescriptor.NumberOfRuns = dbin.ReadInt64();
                        MemRunDescriptor.NumberOfPages = dbin.ReadInt64();

                        Console.WriteLine($"Runs: {MemRunDescriptor.NumberOfRuns}, Pages: {MemRunDescriptor.NumberOfPages} ");

                        if (MemRunDescriptor.NumberOfRuns >= 0 && MemRunDescriptor.NumberOfRuns < 32
                            &&
                            // this means the descriptor covers our input
                            (((MemSize - StartOfMem) >> MagicNumbers.PAGE_SHIFT) & 0xffffff00) == (MemRunDescriptor.NumberOfPages & 0xffffff00))
                            GoodDesc = true;

                        if (GoodDesc)
                        {
                            for (int i = 0; i < MemRunDescriptor.NumberOfRuns; i++)
                            {
                                var basePage = dbin.ReadInt64();
                                var pageCount = dbin.ReadInt64();

                                MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = basePage, PageCount = pageCount });
                            }
                            WriteLine($"MemoryDescriptor {MemRunDescriptor}");

                            return MemRunDescriptor;
                        }
                    }
                }
            }
            WriteLine("Finished VALUE scan.");
            return MemRunDescriptor;
        }
#endif
        public override bool IsSupportedFormat(Vtero vtero)
        {
            bool rv = false;
            if (!File.Exists(DumpFile))
                return rv;

            // use abstract implementation & scan for internal 
            LogicalPhysMemDesc = ExtractMemDesc(vtero);

            using (var dstream = File.OpenRead(DumpFile))
            {
                MemSize = dstream.Length;

                using (var dbin = new BinaryReader(dstream))
                {
                    // start with a easy to handle format of DMP
                    if (ASCIIEncoding.ASCII.GetString(dbin.ReadBytes(8)) != "PAGEDU64")
                        return rv;

                    dbin.BaseStream.Position = 0x2020;
                    StartOfMem = dbin.ReadUInt32();

                    // Find the RUN info
                    dbin.BaseStream.Position = 0x88;

                    var MemRunDescriptor = new MemoryDescriptor();
                    MemRunDescriptor.StartOfMemmory = StartOfMem;
                    MemRunDescriptor.NumberOfRuns = dbin.ReadInt64();
                    MemRunDescriptor.NumberOfPages = dbin.ReadInt64();

                    // this struct has to fit in the header which is only 0x2000 in total size
                    if (MemRunDescriptor.NumberOfRuns > 32 || MemRunDescriptor.NumberOfRuns < 0)
                    {
                        // TODO: in this case we have to de-patchguard the KDDEBUGGER_DATA block
                        // before resulting to that... implemented a memory scanning mode to extract the runs out via struct detection
                        PhysMemDesc = LogicalPhysMemDesc;
                        PhysMemDesc.StartOfMemmory = StartOfMem;
                        // physmem is preferred place to load from so if we have only 1 run move it to phys.
                        LogicalPhysMemDesc = null;
                    }
                    else
                    {
                        // in this case StartOfMem is 0x2000
                        MemRunDescriptor.StartOfMemmory = 0x2000;

                        // we have an embedded RUN in the DMP file that appears to conform to the rules we know
                        for (int i = 0; i < MemRunDescriptor.NumberOfRuns; i++)
                        {
                            var basePage = dbin.ReadInt64();
                            var pageCount = dbin.ReadInt64();

                            MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = basePage, PageCount = pageCount });
                        }
                        PhysMemDesc = MemRunDescriptor;
                    } 
                    rv = true;
                }
            }

            long aSkipCount = 0;

            for (int i = 0; i < PhysMemDesc.NumberOfRuns; i++)
            {
                var RunSkip = PhysMemDesc.Run[i].BasePage - aSkipCount;
                PhysMemDesc.Run[i].SkipCount = RunSkip;
                aSkipCount = PhysMemDesc.Run[i].BasePage + PhysMemDesc.Run[i].PageCount;
            }


            return rv;
        }


        /// <summary>
        // extract initialization values from FilePath to derive memory RUN/base
        /// 
        /// TODO: Other Crashdump formats (bitmap assisted etc).
        /// </summary>
        /// <param name="FilePath"></param>
        public CrashDump(string FilePath)
        {
            MemFile = DumpFile = FilePath;
            finfo = new FileInfo(DumpFile);
            MaxNumPages = finfo.Length >> MagicNumbers.PAGE_SHIFT;
            MemSize = finfo.Length;
        }

    }
}
