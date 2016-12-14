using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using System.IO;
using ProtoBuf;

namespace inVtero.net.Specialties
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class XEN : AMemoryRunDetector, IMemAwareChecking
    {
        ELF<long> Elf;
        Section<long> ELFInfo, ELFPages, ELFPfn;
        bool SupportedStatus = false;

        Dictionary<long, long> DetectedRuns = new Dictionary<long, long>();

        /// <summary>
        /// This pulls info from the hypervisor areas regarding memory extents
        /// </summary>
        /// <param name="vtero"></param>
        /// <returns></returns>
        public override bool IsSupportedFormat(Vtero vtero)
        {
            long InfoCnt;
            long nr_vcpu, nr_pages = 0, page_size = 0, pfn_LAST, pfn_VAL;

            // use abstract implementation & scan for internal 
            LogicalPhysMemDesc = ExtractMemDesc(vtero);

            if (Elf == null)
                return false;

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

        public XEN()
        {}

        public XEN(string XenDump)
        {
            MemFile = XenDump;

            SupportedStatus = ELFReader.TryLoad<long>(MemFile, out Elf);
        }
    }
}
