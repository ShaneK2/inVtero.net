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
    public class CrashDump
    {
        public MemoryDescriptor PhysMemDesc;
        string DumpFile;

        public bool IsSupportedFormat()
        {
            bool rv = false;
            if (!File.Exists(DumpFile))
                return rv;

            var finfo = new FileInfo(DumpFile);

            using(var dstream = File.OpenRead(DumpFile))
            {
                using (var dbin = new BinaryReader(dstream))
                {
                    // start with a easy to handle format of DMP
                    if (ASCIIEncoding.ASCII.GetString(dbin.ReadBytes(8)) != "PAGEDU64")
                        return rv;

                    dbin.BaseStream.Position = 0x2020;
                    var StartOfMem = dbin.ReadUInt32();

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
                    }
                    else
                    {
                        // in this case StartOfMem is 0x2000
                        MemRunDescriptor.StartOfMemmory = 0x2000;

                        rv = true;
                        // we have an embedded RUN in the DMP file that appears to conform to the rules we know
                        for (int i = 0; i < MemRunDescriptor.NumberOfRuns; i++)
                        {
                            var basePage = dbin.ReadInt64();
                            var pageCount = dbin.ReadInt64();

                            MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = basePage, PageCount = pageCount });
                        }

                        PhysMemDesc = MemRunDescriptor;
                    } 

                }
            }
            return rv;
        }



        // extract initialization values from FilePath to derive memory RUN/base
        public CrashDump(string FilePath)
        {
            DumpFile = FilePath;
        }

    }
}
