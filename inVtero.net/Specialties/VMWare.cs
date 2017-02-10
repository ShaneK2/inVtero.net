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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using ProtoBuf;

namespace inVtero.net.Specialties
{
    /// <summary>
    /// Turn's out VMWare 11 & 12 support is very easy given the current model
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class VMWare : AMemoryRunDetector, IMemAwareChecking
    {
        /// <summary>
        /// OK need to double check later but even though there are 64 bits available in the field
        /// only 32bits are seemingly being used.  Otherwise the values have to be interpreted as
        /// physical addresses and not page numbers.
        /// </summary>
        /// <returns></returns>
        public override bool IsSupportedFormat(Vtero vtero)
        {
            // use abstract implementation & scan for internal 
            // were actually not going to use this in VMWare since were so good at vmss
            // this is sort of meaningless :( 
            //LogicalPhysMemDesc = ExtractMemDesc(vtero);

            bool rv = false;
            if (!File.Exists(vDeviceFile) || !File.Exists(MemFile))
                return rv;

            // Let's seee how far we can get w/o being to aggressive here
            //using (var dstream = File.OpenRead(vDeviceFile))
            //{
            //    using (var dbin = new BinaryReader(dstream))
            //    {
            //        // D2BE is really easy to extract data from
            //        if (dbin.ReadUInt32() != 0xBED2BED2)
            //            return rv;
            //    }
            //}

            rv = true;

            var MemRunDescriptor = new MemoryDescriptor();
            // vmem files are contagious starting from 0
            MemRunDescriptor.StartOfMemmory = 0;
            
            var inFile = File.OpenRead(vDeviceFile);

            // TODO: make this (parsing) more precise for additional versions
            var stateData = new byte[0x40000];

            inFile.Read(stateData, 0, stateData.Length);

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
                    break;
            }

            long TotalPages = 0;

            i += ToFind.Length;
            var Count = BitConverter.ToUInt32(stateData, i);
            MemRunDescriptor.NumberOfRuns = Count;
            i += 4; i += 2; // 2 bytes looks like a typeID or some sort of magic
            // below the >> 20 is/was what seemed to be an adjustment for 64-44 bits of
            // physical address range
            // however the additional >> 12 is physical address into physical pages
            // but it seemingly was supposed to be pages to begin with so who knows, but this works
            // maybe it is pages and I needed +4 on the index and then everything works with a .ToUInt32
            // but that now seems short of the physical limits, anyhow, this works ;)
            for (int r = 0; r < Count; r++)
            {
                i += rpn.Length;
                var basePage = BitConverter.ToInt64(stateData, i) >> 20 >> 12;
                i += 8; i += 2;
                i += ppn.Length;
                var ppnVal = BitConverter.ToInt64(stateData, i) >> 20 >> 12;
                i += 8; i += 2;
                i += rsiz.Length;
                var regionSize = BitConverter.ToInt64(stateData, i) >> 20 >> 12;
                i += 8; i += 2;

                TotalPages += regionSize;

                MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = ppnVal, PageCount = regionSize, regionPPN = basePage });
            }

            MemRunDescriptor.NumberOfPages = TotalPages;
            PhysMemDesc = MemRunDescriptor;
            // adjust start of memory to 
            if(vDeviceFile == MemFile)
            {
                var x = (int)(Math.Ceiling((decimal) i / 0x10000) * 0x10000);
                StartOfMem = x;
            }
            return rv;
        }

        /// <summary>
        /// Single File: 
        ///     * (ESX SERVERS) Specify a VMSN or VMSS
        /// Multiple Files:
        ///     * (WORKSTATIONS) Specify the VMEM
        ///     * MATCHING VMSS OR VMSN MUST BE IN SAME FOLDER
        /// </summary>
        /// <param name="VMEM">The path to the virtual machine MEMORY</param>
        public VMWare(string VMEM)
        {
            // this is likely a WORKSTATION version (2 fiels, vmem and vmss/vmsd)
            if (VMEM.EndsWith(".vmem"))
            {
                MemFile = VMEM;
                var GuessName = Path.Combine(Path.Combine(Path.GetDirectoryName(VMEM)), Path.GetFileNameWithoutExtension(VMEM) + ".vmss");
                if (File.Exists(GuessName))
                    vDeviceFile = GuessName;
                else
                    vDeviceFile = Path.Combine(Path.Combine(Path.GetDirectoryName(VMEM)), Path.GetFileNameWithoutExtension(VMEM) + ".vmsn");
            }
            else  
            // This is likely a combined file Virtual Device + MEM in one (SERVERS like ESX do this)
            {
                MemFile = VMEM;
                vDeviceFile = VMEM;
                
            }
        }

        /// <summary>
        /// A more precise constructor (i.e. you do the work:)
        /// </summary>
        /// <param name="VMEM">Virtual Machine memory</param>
        /// <param name="vDeviceState">The path to the virtual machine save state data</param>
        public VMWare(string VMEM, string vDeviceState)
        {
            vDeviceFile = vDeviceState;
            MemFile = VMEM;
        }
        public VMWare() { }

    }
}
