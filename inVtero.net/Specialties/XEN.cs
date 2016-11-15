using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using System.IO;

namespace inVtero.net.Specialties
{
    public class XEN : IMemAwareChecking
    {
        ELF<long> Elf;
        Section<long> ELFInfo, ELFPages, ELFPfn;
        bool SupportedStatus = false, GoodDesc = false;
        long StartOfMem = 0;

        Dictionary<long, long> DetectedRuns = new Dictionary<long, long>();

        public MemoryDescriptor PhysMemDesc { get; set; }
        public string vDeviceFile { get; set; }
        public string MemFile { get; set; }

        /// <summary>
        /// Extract memory extents info from the guest memory
        /// </summary>
        /// <param name="vtero"></param>
        /// <returns></returns>
        MemoryDescriptor ExtractMemDesc(Vtero vtero)
        {
            MemoryDescriptor MemRunDescriptor = null;
            var off = vtero.ScanValue(false, 0x6c4d6d4d, 4);

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

                        dstream.Position = xoff + 20; // TODO: double check we ma need to do a sub loop step range 8,16,20,24,28,32 -- ensure we scan hard'r
                        MemRunDescriptor = new MemoryDescriptor();
                        MemRunDescriptor.NumberOfRuns = dbin.ReadInt64();
                        MemRunDescriptor.NumberOfPages = dbin.ReadInt64();

                        Console.WriteLine($"Runs: {MemRunDescriptor.NumberOfRuns}, Pages: {MemRunDescriptor.NumberOfPages} ");

                        if (MemRunDescriptor.NumberOfRuns >= 0 && MemRunDescriptor.NumberOfRuns < 32)
                        {
                            for (int i = 0; i < MemRunDescriptor.NumberOfRuns; i++)
                            {
                                var basePage = dbin.ReadInt64();
                                var pageCount = dbin.ReadInt64();
                                totPageCnt += pageCount;
                                MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = basePage, PageCount = pageCount });
                            }
                        }
                        // if we have counted more pages than we have in disk
                        // or
                        // if we have less than 1/4 the pages we need (this is fudge factor should be precise right!)
                        if (totPageCnt > (((MemSize - StartOfMem) >> MagicNumbers.PAGE_SHIFT) & 0xffffff00) ||
                            totPageCnt < (((MemSize - StartOfMem) >> MagicNumbers.PAGE_SHIFT) & 0xffffff00) / 4
                            )
                        {
                            Console.WriteLine($"odd/bad memory run, skipping");
                            continue;
                        }

                        //WriteLine($"MemoryDescriptor {MemRunDescriptor}");
                        return MemRunDescriptor;
                    }
                }
            }
            //WriteLine("Finished VALUE scan.");
            return MemRunDescriptor;
        }

        /// <summary>
        /// This pulls info from the hypervisor areas regarding memory extents
        /// </summary>
        /// <param name="vtero"></param>
        /// <returns></returns>
        public bool IsSupportedFormat(Vtero vtero)
        {
            long InfoCnt;
            long nr_vcpu, nr_pages = 0, page_size = 0, pfn_LAST, pfn_VAL;

            using (var dstream = File.OpenRead(vtero.MemFile))
            {
                using (var ebin = new BinaryReader(dstream))
                {
                    ELFInfo = Elf.GetSection(".note.Xen"); // get note stuff and fill in da info 
                    if (ELFInfo != null)
                    {
                        ebin.BaseStream.Position = ELFInfo.Offset;
                        InfoCnt = ebin.ReadInt64();
                        for (long l = 0; l < InfoCnt; l++)
                        {
                            var InfoType = ebin.ReadInt32();
                            ebin.BaseStream.Position += 12;

                            switch (InfoType)
                            {
                                // header type
                                case 0x2000001:
                                    nr_vcpu = ebin.ReadInt64();
                                    nr_pages = ebin.ReadInt64();
                                    page_size = ebin.ReadInt64();
                                    break;
                                // none type
                                case 0x2:
                                    break;
                                default:
                                    break;
                            }

                        }

                        ELFPfn = Elf.GetSection(".xen_pfn");
                        ebin.BaseStream.Position = ELFPfn.Offset;


                        // base page, length
                        
                        long CurrBasePage = 0;
                        long CurrRunLen = 0;
                        // parse the array
                        pfn_LAST = ebin.ReadInt64();
                        for (long pfnx = 0; pfnx < nr_pages; pfnx++)
                        {
                            CurrRunLen++;

                            pfn_VAL = ebin.ReadInt64();
                            if (pfn_LAST + 1 == pfn_VAL)
                            {
                                pfn_LAST = pfn_VAL;
                                continue;
                            }

                            // add run
                            DetectedRuns.Add(CurrBasePage, CurrRunLen);

                            // reset counter
                            // that is adjusted in the value 
                            pfn_LAST = CurrBasePage = pfn_VAL;
                            CurrRunLen = 0;

                            if (CurrBasePage >= nr_pages)
                                break;
                        }
                    }
                }
            }
            ELFPages = Elf.GetSection(".xen_pages");
            if (ELFPages != null)
                StartOfMem = ELFPages.Offset;


            PhysMemDesc = new MemoryDescriptor(nr_pages * page_size);
            PhysMemDesc.NumberOfRuns = DetectedRuns.Count;
            PhysMemDesc.NumberOfPages = nr_pages;
            PhysMemDesc.StartOfMemmory = StartOfMem;
            PhysMemDesc.Run = new List<MemoryRun>();

            foreach (var kvp in DetectedRuns)
                PhysMemDesc.Run.Add(new MemoryRun() { BasePage = kvp.Key, PageCount = kvp.Value });


            return SupportedStatus;
        }

        public XEN(string XenDump)
        {
            MemFile = XenDump;

            SupportedStatus = ELFReader.TryLoad<long>(MemFile, out Elf);
        }
    }
}
