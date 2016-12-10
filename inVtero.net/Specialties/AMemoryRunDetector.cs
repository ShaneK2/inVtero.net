using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProtoBuf;

namespace inVtero.net.Specialties
{
    [
        ProtoContract(AsReferenceDefault = true, 
            ImplicitFields = ImplicitFields.AllPublic), 
            ProtoInclude(1001, typeof(XEN)),
            ProtoInclude(1002, typeof(CrashDump)),
            ProtoInclude(1003, typeof(VMWare)),
            ProtoInclude(1004, typeof(BasicRunDetector))
        ]
    public abstract class AMemoryRunDetector : IMemAwareChecking
    {
        /// <summary>
        /// 
        /// This is allows for a link down 
        /// so at least the case of a guest in a hypervisor
        /// this will be the guest memory run mappings
        /// </summary>
        public MemoryDescriptor LogicalPhysMemDesc { get; set; }


        /// <summary>
        /// This is the top layer view 
        /// I.e. specified by hypervisor device memory settings
        /// </summary>
        public MemoryDescriptor PhysMemDesc { get; set; }


        public string vDeviceFile { get; set; }
        public string MemFile { get; set; }

        /// <summary>
        /// Offset from the start of the file where page ZERO data is to be counted from
        /// </summary>
        public long StartOfMem { get; set; }

        /// <summary>
        /// Extract memory extents info from the guest memory
        /// </summary>
        /// <param name="vtero"></param>
        /// <returns></returns>
        public MemoryDescriptor ExtractMemDesc(Vtero vtero)
        {
            MemoryDescriptor MemRunDescriptor = null;
            // rarely used pool tag
            var off = Scanner.BackwardsValueScan(vtero.MemFile, 0x6c4d6d4d);

            using (var dstream = File.OpenRead(vtero.MemFile))
            {
                var MemSize = dstream.Length;
                long totPageCnt = 0;

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
                        for (long doff = 16; doff <= 32; doff += 4)
                        {
                            dstream.Position = xoff + doff; 
                            MemRunDescriptor = new MemoryDescriptor();
                            MemRunDescriptor.NumberOfRuns = dbin.ReadInt64();
                            MemRunDescriptor.NumberOfPages = dbin.ReadInt64();

                            var RunCnt = MemRunDescriptor.NumberOfRuns;
                            var PageCnt = MemRunDescriptor.NumberOfPages;

                            //Console.WriteLine($"Runs: {RunCnt}, Pages: {MemRunDescriptor.NumberOfPages} ");
                            long lastBasePage = 0;

                            if (RunCnt > 0 && MemRunDescriptor.NumberOfRuns < 32)
                            {
                                MemRunDescriptor.Run = new List<MemoryRun>((int)RunCnt);
                                for (int i = 0; i < RunCnt; i++)
                                {
                                    var basePage = dbin.ReadInt64();
                                    // error check range too high/low
                                    if (basePage < lastBasePage || basePage < 0)
                                        break;

                                    lastBasePage = basePage;

                                    var pageCount = dbin.ReadInt64();
                                    if (pageCount > PageCnt || pageCount <= 0)
                                        break;

                                    totPageCnt += pageCount;
                                    MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = basePage, PageCount = pageCount });
                                }

                                if (totPageCnt > (PageCnt + 1024) || totPageCnt <= 0)
                                    continue;

                                // if we have counted more pages than we have in disk
                                // or
                                // if we have less than 1/2 the pages we need (this is fudge factor should be precise right!)
                                if (totPageCnt > (((MemSize - StartOfMem) >> MagicNumbers.PAGE_SHIFT) & 0xffffffff) ||
                                    totPageCnt < (((MemSize - StartOfMem) >> MagicNumbers.PAGE_SHIFT) & 0xffffffff) / 2
                                    )
                                {
                                    //Console.WriteLine($"odd/bad memory run, skipping");
                                    continue;
                                }
                                else
                                    return MemRunDescriptor;
                            }

                            //WriteLine($"MemoryDescriptor {MemRunDescriptor}");
                        }
                    }
                }
            }
#if OLD_CODE
            long aSkipCount = 0;

            for (int i=0; i < MemRunDescriptor.NumberOfRuns; i++)
            {
                var RunSkip = MemRunDescriptor.Run[i].BasePage - aSkipCount;
                MemRunDescriptor.Run[i].SkipCount = RunSkip;
                aSkipCount = MemRunDescriptor.Run[i].PageCount;
            }
#endif
            //WriteLine("Finished VALUE scan.");
            return MemRunDescriptor;
        }

        public abstract bool IsSupportedFormat(Vtero vtero);
    }
}
