using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace inVtero.net.Specialties
{
    /// <summary>
    /// Turn's out VMWare 11 & 12 support is very easy given the current model
    /// </summary>
    public class VMWare
    {
        public MemoryDescriptor PhysMemDesc;
        public string DumpFile;
        public string MemFile;

        public bool IsSupportedFormat()
        {
            bool rv = false;
            if (!File.Exists(DumpFile) || !File.Exists(MemFile))
                return rv;

            using (var dstream = File.OpenRead(DumpFile))
            {
                using (var dbin = new BinaryReader(dstream))
                {
                    // D2BE is really easy to extract data from
                    if (dbin.ReadUInt32() != 0xBED2BED2)
                        return rv;
                }
            }

            rv = true;

            var MemRunDescriptor = new MemoryDescriptor();
            // vmem files are contagious starting from 0
            MemRunDescriptor.StartOfMemmory = 0;
            
            var stateData = File.ReadAllBytes(DumpFile);
            var ToFind = ASCIIEncoding.ASCII.GetBytes("regionsCount");
            var rpn = ASCIIEncoding.ASCII.GetBytes("regionPageNum");
            var ppn = ASCIIEncoding.ASCII.GetBytes("regionPPN");
            var rsiz = ASCIIEncoding.ASCII.GetBytes("regionSize");

            int i;
            for(i=0; i < stateData.Length-ToFind.Length; i++)
            {
                int n = 0;
                bool Found = false;
                do
                {
                    if (stateData[i + n] != ToFind[n])
                        break;

                    n++;
                    if (n >= ToFind.Length)
                        Found = true;
                } while (!Found);

                if (Found)
                {
                    Console.WriteLine($"Found it at 0x{i:X}");
                    break;
                }
            }

            long TotalPages = 0;

            i += ToFind.Length;
            var Count = BitConverter.ToUInt32(stateData, i);
            MemRunDescriptor.NumberOfRuns = Count;
            i += 4; i += 2; // 2 bytes looks like a typeID or some sort
            for (int r = 0; r < Count; r++)
            {
                i += rpn.Length;
                var basePage = BitConverter.ToInt64(stateData, i) >> 20;
                i += 8; i += 2;
                i += ppn.Length;
                var ppnVal = BitConverter.ToInt64(stateData, i) >> 20;
                i += 8; i += 2;
                i += rsiz.Length;
                var regionSize = BitConverter.ToInt64(stateData, i) >> 20;
                i += 8; i += 2;

                TotalPages += (regionSize >> 12);


                MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = ppnVal, PageCount = regionSize, regionPPN = basePage });
            }

            MemRunDescriptor.NumberOfPages = TotalPages;
            PhysMemDesc = MemRunDescriptor;

            return rv;
        }


        public VMWare(string vMss)
        {
            DumpFile = vMss;
            MemFile = Path.Combine(Path.Combine(Path.GetDirectoryName(DumpFile)), Path.GetFileNameWithoutExtension(DumpFile) + ".vmem");
        }

    }
}
