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
// Shane.Macaulay@IOActive.com (c) copyright 2014,2015,2016 all rights reserved. GNU GPL License

using ProtoBuf;
using Reloc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using static inVtero.net.Misc;
using Dia2Sharp;
using System.Linq;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace inVtero.net
{

    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class DetectedProc : IComparable, IDisposable
    {
        public DetectedProc()
        {
            SymbolStore = new Dictionary<string, long>();
            TopPageTablePage = new Dictionary<int, long>();
            LogicalProcessList = new List<dynamic>();
            Sections = new ConcurrentDictionary<long, MemSection>();
            ID = Guid.NewGuid();
        }
        public int ASGroup;
        public int Group;       // linux only 
        public VMCS vmcs;       // vmcs if available
        public List<VMCS> CandidateList;
        public PageTable PT;    // extracted page table
        public long CR3Value;
        public long FileOffset;
        public long TrueOffset;
        public long Diff;
        public int Mode; // 1 or 2
        public PTType PageTableType;

        public Guid ID;

        // symbol info provider
        [ProtoIgnore]
        public Sym sym;

        public ConcurrentDictionary<long, MemSection> Sections;

        /*
        public CODEVIEW_HEADER DebugData;
        public Extract ext;
        */

        public Dictionary<int, long> TopPageTablePage;

        // Since we have a known PT, start collecting meta info
        // Mapped Modules

        // This is really to aid Debugging 
        [ProtoIgnore]
        public Dictionary<string, long> SymbolStore;

        [ProtoIgnore]
        // Relevant when parsing Kernel
        public List<dynamic> LogicalProcessList;

        // the high bit signals if we collected a kernel address space for this AS group
        public int AddressSpaceID;



        public dynamic xStructInfo(string Struct, long Address, int minLen = 4096, string Module = "ntkrnlmp")
        {

            var pdbPaths = from files in Sections.Values
                           where files.DebugDetails != null &&
                           files.DebugDetails.PDBFullPath.ToLower().Contains(Module.ToLower())
                           select files;

            var pdb = pdbPaths.FirstOrDefault();

            long[] memRead = null;
            if(Address != 0)
                memRead = GetVirtualLongLen(Address, minLen);

            var rv = sym.xStructInfo(pdb.DebugDetails.PDBFullPath, Struct, memRead, GetVirtualByte, GetVirtualLong);
            rv.SelfAddr = Address;

            return rv;
        }

        public dynamic xStructInfo(string Struct, long[] memRead = null, string Module = "ntkrnlmp")
        {

            var pdbPaths = from files in Sections.Values
                           where files.DebugDetails != null &&
                           files.DebugDetails.PDBFullPath.ToLower().Contains(Module.ToLower())
                           select files;

            var pdb = pdbPaths.FirstOrDefault();

            return sym.xStructInfo(pdb.DebugDetails.PDBFullPath, Struct, memRead, GetVirtualByte, GetVirtualLong);
        }

        /// <summary>
        /// TODO: Make better for all types
        /// </summary>
        /// <param name="dp"></param>
        /// <param name="SymName"></param>
        /// <returns>Currently a single byte for the address resolved from the Name</returns>
        public long GetSymValueLong(string SymName)
        {
            long value = 0;

            // debugging help really
            if (SymbolStore.ContainsKey(SymName))
                return SymbolStore[SymName];

            value = GetLongValue(GetSymAddress(SymName));
            SymbolStore.Add(SymName, value);

            return value;
        }

        public long GetSymAddress(string SymName)
        {
            var AddrName = SymName + "Address";
            if (SymbolStore.ContainsKey(AddrName))
                return SymbolStore[AddrName];

            DebugHelp.SYMBOL_INFO symInfo = new DebugHelp.SYMBOL_INFO();

            symInfo.SizeOfStruct = 0x58;
            symInfo.MaxNameLen = 1024;

            var rv = DebugHelp.SymFromName(ID.GetHashCode(), SymName, ref symInfo);
            if (!rv)
            {
                WriteColor(ConsoleColor.Red, $"GetSymValue: {new Win32Exception(Marshal.GetLastWin32Error()).Message }.");
                return MagicNumbers.BAD_VALUE_READ;
            }

            SymbolStore.Add(AddrName, symInfo.Address);

            return symInfo.Address;
        }

        public void LoadModulesInRange(long VA, long length, string OnlyModule = null)
        {
            var KVS = new VirtualScanner(this, new Mem(MemAccess));
            KVS.ScanMode = VAScanType.PE_FAST;

            KVS.Run(VA, VA + length);

            foreach(var artifact in KVS.Artifacts)
            {
                var ms = new MemSection() { IsExec = true, Module = artifact.Value, VA = new VIRTUAL_ADDRESS(artifact.Key) };
                var extracted = ExtractCVDebug(ms);
                if (extracted == null)
                    continue;

                if (!string.IsNullOrWhiteSpace(OnlyModule) && OnlyModule != ms.Name)
                    continue;

                if (!Sections.ContainsKey(artifact.Key))
                    Sections.TryAdd(artifact.Key, ms);

                // we can clobber this guy all the time I guess since everything is stateless in Sym and managed
                // entirely by the handle ID really which is local to our GUID so....   
                sym = Vtero.TryLoadSymbols(ID.GetHashCode(), ms.DebugDetails, ms.VA.Address);
                if (Vtero.VerboseOutput)
                    WriteColor(ConsoleColor.Green, $"symbol loaded [{sym != null}] from file [{ms.DebugDetails.PDBFullPath}]");
            }

        }

        public void LoadSymbols(MemSection OnlyMS = null)
        {
            foreach(var ms in Sections)
            {
                if(OnlyMS == null || (OnlyMS != null && OnlyMS.VA.Address == ms.Key))
                {
                    sym = Vtero.TryLoadSymbols(ID.GetHashCode(), ms.Value.DebugDetails, ms.Value.VA.Address);
                    if (Vtero.VerboseOutput)
                        WriteColor(ConsoleColor.Green, $"symbol loaded [{sym != null}] from file [{ms.Value.DebugDetails.PDBFullPath}]");
                }
            }
        }

        /// <summary>
        /// Currently we scan hard for only kernel regions (2MB pages + ExEC)
        /// If there are kernel modules named the OnlyModule it may cause us to ignore the real one in that case
        /// you can still scan for * by passing null or empty string
        /// </summary>
        /// <param name="OnlyModule">Stop when the first module named this is found</param>
        public VirtualScanner ScanAndLoadModules(string OnlyModule = "ntkrnlmp")
        {
            PageTable.AddProcess(this, new Mem(MemAccess));
            var cnt = PT.FillPageQueue(true);

            var KVS = new VirtualScanner(this, new Mem(MemAccess));
            KVS.ScanMode = VAScanType.PE_FAST;

            Parallel.For(0, cnt, (i, loopState) =>
            {
                PFN range;



                var curr = cnt - PT.PageQueue.Count;
                var done = (int)(Convert.ToDouble(curr) / Convert.ToDouble(cnt) * 100.0) + 0.5;

                if (PT.PageQueue.TryDequeue(out range) && range.PTE.Valid)
                {
                    var found = KVS.Run(range.VA.Address, range.VA.Address + (range.PTE.LargePage ? (1024 * 1024 * 2) : 0x1000), loopState);
                    // Attempt load
                    foreach(var artifact in found)
                    {
                        var ms = new MemSection() { IsExec = true, Module = artifact.Value, VA = new VIRTUAL_ADDRESS(artifact.Key) };
                        var extracted = ExtractCVDebug(ms);
                        if (extracted == null)
                            continue;

                        if (!string.IsNullOrWhiteSpace(OnlyModule) && OnlyModule != ms.Name)
                            continue;

                        if (!Sections.ContainsKey(artifact.Key))
                            Sections.TryAdd(artifact.Key, ms);

                        // we can clobber this guy all the time I guess since everything is stateless in Sym and managed
                        // entirely by the handle ID really which is local to our GUID so....   
                        sym = Vtero.TryLoadSymbols(ID.GetHashCode(), ms.DebugDetails, ms.VA.Address);
                        if (Vtero.VerboseOutput)
                            WriteColor(ConsoleColor.Green, $"symbol loaded [{sym != null}] from file [{ms.DebugDetails.PDBFullPath}]");

                        if (!string.IsNullOrWhiteSpace(OnlyModule))
                        {
                            if (!string.IsNullOrWhiteSpace(ms.Name) && ms.Name == OnlyModule)
                            {
                                loopState.Stop();
                                return;
                            }
                        }
                        if (loopState.IsStopped)
                            return;
                    }
                }

                if (loopState.IsStopped)
                    return;
            });
            return KVS;
        }

        /// <summary>
        ///  This guy names the section and establishes the codeview data needed for symbol handling
        /// </summary>
        /// <param name="sec"></param>
        /// <returns></returns>
        public CODEVIEW_HEADER ExtractCVDebug(MemSection sec)
        {
            uint SizeData = 0, RawData = 0, PointerToRawData = 0;

            Extract Ext = sec.Module;
            long VA = sec.VA.Address;

            var _va = VA + Ext.DebugDirPos;
            var block = VGetBlock(_va);
            var TimeDate2 = BitConverter.ToUInt32(block, ((int)Ext.DebugDirPos & 0xfff) + 4);
            if (TimeDate2 != Ext.TimeStamp & Vtero.VerboseOutput)
            {
                WriteColor(ConsoleColor.Yellow, "Unable to lock on to CV data.");
                return null;
            }

            var max_offset = (int)(_va & 0xfff) + 28;
            if (max_offset > 0x1000)
                return null;

            SizeData = BitConverter.ToUInt32(block, (int)(_va & 0xfff) + 16);
            RawData = BitConverter.ToUInt32(block, (int)(_va & 0xfff) + 20);
            PointerToRawData = BitConverter.ToUInt32(block, (int)(_va & 0xfff) + 24);

            _va = VA + RawData;

            var bytes = new byte[16];

            block = VGetBlock(_va);

            // first 4 bytes
            var sig = block[((int)_va & 0xfff)];

            Array.ConstrainedCopy(block, (((int)_va & 0xfff) + 4), bytes, 0, 16);
            var gid = new Guid(bytes);

            // after GUID
            var age = block[((int)_va & 0xfff) + 20];

            // char* at end
            var str = Encoding.Default.GetString(block, (((int)_va & 0xfff) + 24), 32).Trim();
            var cv = new CODEVIEW_HEADER { VSize = (int)Ext.SizeOfImage, TimeDateStamp = TimeDate2, byteGuid = bytes, Age = age, aGuid = gid, Sig = sig, PdbName = str };
            sec.Name = str.Substring(0, str.IndexOf('.')).ToLower();
            sec.DebugDetails = cv;

            return cv;
        }


        #region Memory Accessors 
        public byte GetByteValue(long VA)
        {
            var data = VGetBlock(VA);
            return data[VA & 0xfff];
        }

        public uint GetUIntValue(long VA)
        {
            var data = VGetBlock(VA);
            return BitConverter.ToUInt32(data, (int)(VA & 0xfff));
        }

        public int GetIntValue(long VA)
        {
            var data = VGetBlock(VA);
            return BitConverter.ToInt32(data, (int)(VA & 0xfff));
        }

        public long GetLongValue(long VA)
        {
           var data = VGetBlock(VA);
           return BitConverter.ToInt64(data, (int) (VA & 0xfff));
        }

        public ulong GetULongValue(long VA)
        {
            var data = VGetBlock((long) VA);
            return BitConverter.ToUInt64(data, (int)(VA & 0xfff));
        }

        /// <summary>
        /// BLOCK ALIGNED
        /// </summary>
        /// <param name="VA"></param>
        /// <returns>BLOCK of memory (ALIGNED)</returns>
        public byte[] VGetBlock(long VA)
        {
            bool GotData = false;
            long[] rv = new long[512];

            var _va = VA & ~0xfff;

            HARDWARE_ADDRESS_ENTRY hw;
            if (vmcs == null)
                hw = MemAccess.VirtualToPhysical(CR3Value, _va);
            else
                hw = MemAccess.VirtualToPhysical(vmcs.EPTP, CR3Value, _va);
            
            MemAccess.GetPageForPhysAddr(hw, ref rv, ref GotData);
            if (!GotData)
                return null;

            byte[] buffer = new byte[4096];
            Buffer.BlockCopy(rv, 0, buffer, 0, 4096);
            return buffer;
        }

        /// <summary>
        /// Block aligned
        /// </summary>
        /// <param name="VA"></param>
        /// <returns>PAGE ALIGNED </returns>
        public long[] VGetBlockLong(long VA)
        {
            bool GotData = false;
            long[] rv = new long[512];

            var _va = VA & ~0xfff;

            HARDWARE_ADDRESS_ENTRY hw;
            if (vmcs == null)
                hw = MemAccess.VirtualToPhysical(CR3Value, _va);
            else
                hw = MemAccess.VirtualToPhysical(vmcs.EPTP, CR3Value, _va);

            MemAccess.GetPageForPhysAddr(hw, ref rv, ref GotData);
            return rv;
        }

        /// <summary>
        /// See all other PAGE ALIGNED
        /// </summary>
        /// <param name="VA"></param>
        /// <param name="GotData"></param>
        /// <returns></returns>
        public long[] VGetBlockLong(long VA, ref bool GotData)
        {
            long[] rv = new long[512];

            var _va = VA & ~0xfff;

            HARDWARE_ADDRESS_ENTRY hw;
            if (vmcs == null)
                hw = MemAccess.VirtualToPhysical(CR3Value, _va);
            else
                hw = MemAccess.VirtualToPhysical(vmcs.EPTP, CR3Value, _va);

            MemAccess.GetPageForPhysAddr(hw, ref rv, ref GotData);

            return rv;
        }

        /// <summary>
        /// GetVirtual get's at least 1 block sized byte aligned chunk of memory.
        /// The chunk may be up to 2Pages-1 in size since we always get the next page
        /// in case you need it...
        /// </summary>
        /// <param name="VA"></param>
        /// <param name="GotData">Byte aligned chunk MIN (PageSize+8) MAX (PageSize*2-8)</param>
        /// <returns></returns>
        public long[] GetVirtualLong(long VA, ref bool GotData)
        {
            // offset to index
            long startIndex = (VA & 0xfff) / 8;
            long count = 512 - startIndex;
            // get data
            var block = VGetBlockLong(VA, ref GotData);

            // adjust into return array 
            var rv = new long[count+512];
            Array.Copy(block, startIndex, rv, 0, count);

            VA += 4096;
            var block2 = VGetBlockLong(VA, ref GotData);
            Array.Copy(block2, 0, rv, count, 512);

            return rv;
        }

        public long[] GetVirtualLong(long VA)
        {
            return GetVirtualLongLen(VA, 4096);
        }
        public long[] GetVirtualLongLen(long VA, int len = 4096)
        {
            // offset to index
            long startIndex = (VA & 0xfff) / 8;
            int count = 512 - (int)startIndex;
            // get data
            var block = VGetBlockLong(VA);

            long extra = len / 8;

            // adjust into return array 
            var rv = new long[count + extra];
            Array.Copy(block, startIndex, rv, 0, count);

            var done = count * 8;
            do
            {
                VA += 4096;
                var block2 = VGetBlockLong(VA);
                int copy_cnt = len - done < 4096 ? (len - done) / 8 : 512;
                Array.Copy(block2, 0, rv, count, copy_cnt);
                done += 512 * 8;
                count += 512;
            } while (done < len);
            return rv;
        }

        public long[] GetVirtualULong(ulong VA)
        {
            // offset to index
            ulong startIndex = (VA & 0xfff) / 8;
            long count = 512 - (long) startIndex;
            // get data
            var block = VGetBlockLong((long) VA);

            // adjust into return array 
            var rv = new long[count + 512];
            Array.Copy(block, (long) startIndex, rv, 0, count);

            VA += 4096;
            var block2 = VGetBlockLong((long) VA);
            Array.Copy(block2, 0, rv, count, 512);

            return rv;
        }


        /// <summary>
        /// This is byte aligned
        /// </summary>
        /// <param name="VA"></param>
        /// <returns>SINGLE PAGE OR LESS</returns>
        public byte[] GetVirtualByte(long VA)
        {
            long startIndex = VA & 0xfff;
            long count = 4096 - startIndex;

            var block = VGetBlock(VA);

            var rv = new byte[count];

            if(block != null)
                Array.Copy(block, startIndex, rv, 0, count);
            return rv;
        }
        #endregion

        [ProtoIgnore]
        public Mem MemAccess { get; set; }
        [ProtoIgnore]
        public string ShortName {get { if (vmcs != null) return $"{vmcs.EPTP:X}-{CR3Value:X}"; return $"{CR3Value:X}"; } }

        public override string ToString() => $"Process CR3 [{CR3Value:X12}] File Offset [{FileOffset:X12}] Diff [{Diff:X12}] Type [{PageTableType}] VMCS [{vmcs}]";

        public int CompareTo(object obj)
        {
            int vi = 0;
            if(obj is DetectedProc)
            {
                DetectedProc dp = obj as DetectedProc;
                if(vmcs != null || dp.vmcs != null)
                {
                    if (vmcs == null && dp.vmcs == null)
                        return FileOffset.CompareTo(dp.FileOffset);
                    else if (vmcs != null && dp.vmcs == null)
                        return 1;
                    else if (vmcs == null && dp.vmcs != null)
                        return -1;
                    else
                        vi = vmcs.Offset.CompareTo(dp.vmcs.Offset);
                }
                return vi + FileOffset.CompareTo(dp.FileOffset);
            }
            return int.MinValue;
        }

        public void Dispose()
        {
            foreach (var addr in Sections)
                DebugHelp.SymUnloadModule64(ID.GetHashCode(), (ulong) addr.Key);
        }
    }


    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class VMCS
    {
        public VMCS()
        {
        }

        [ProtoIgnore]
        public DetectedProc dp; // which proc this came from
        public long gCR3_off;
        public long gCR3;
        public long hCR3_off;
        public long hCR3;
        public long EPTP;
        public long EPTP_off;
        public long Offset;
        public override string ToString() => $"EPTP:[{new EPTP(this.EPTP):X12}]";
    }

    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class CODEVIEW_HEADER
    {
        public int VSize;
        public byte[] byteGuid;
        public uint Sig;
        public Guid aGuid;
        public int Age;
        public string PdbName;
        public uint TimeDateStamp;

        // This field is determined through a call to SymFindFileInPath/Ex from the above info 
        public string PDBFullPath;
    }

}
