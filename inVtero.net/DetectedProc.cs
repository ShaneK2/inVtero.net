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
using libyaraNET;

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

        [ProtoIgnore]
        public List<ScanResult> YaraOutput;
        public long YaraTotalScanned;

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

        public Tuple<String, ulong>[] MatchSymbols(string Match, string Module = "ntkrnlmp")
        {
            List<Tuple<String, ulong>> rv = new List<Tuple<string, ulong>>();
            foreach(var sec in Sections)
                if(sec.Value.DebugDetails.PDBFullPath.Contains(Module) || string.IsNullOrWhiteSpace(Module))
                    rv.AddRange(sym.MatchSyms(Match, sec.Value.DebugDetails.PDBFullPath, sec.Value.VA.FullAddr));

            return rv.ToArray();
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

            foreach(var artifact in KVS.Run(VA, VA + length))
            {
                var ms = new MemSection() { IsExec = true, Module = artifact, VA = new VIRTUAL_ADDRESS(artifact.VA) };
                var extracted = ExtractCVDebug(ms);
                if (extracted == null)
                    continue;

                if (!string.IsNullOrWhiteSpace(OnlyModule) && OnlyModule != ms.Name)
                    continue;

                if (!Sections.ContainsKey(artifact.VA))
                    Sections.TryAdd(artifact.VA, ms);

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
        /// If there are kernel modules named the OnlyModule it may cause us to ignore the real one in   that case
        /// you can still scan for * by passing null or empty string
        /// </summary>
        /// <param name="OnlyModule">Stop when the first module named this is found</param>
        public VirtualScanner ScanAndLoadModules(string OnlyModule = "ntkrnlmp", bool OnlyLarge = true, bool IncludeKernelSpace = true, bool OnlyValid = true, bool IncludeData = false, bool DoExtraHeaderScan = false)
        {
            const int LARGE_PAGE_SIZE = 1024 * 1024 * 2;
            var curr=0;
            PageTable.AddProcess(this, new Mem(MemAccess));
            //var cnt = PT.FillPageQueue(OnlyLarge, IncludeKernelSpace);

            var KVS = new VirtualScanner(this, new Mem(MemAccess), DoExtraHeaderScan);

            // single threaded worked best so far 
            //Parallel.For(0, cnt, (i, loopState) => x
            foreach(var range in PT.FillPageQueue(OnlyLarge, IncludeKernelSpace, OnlyValid, IncludeData))
            //for (int i = 0; i < cnt; i++)
            {
                curr++;
                bool stop = false;
                if (Vtero.VerboseLevel > 1)
                {
                    //var curr = cnt - PT.PageQueue.Count;
                    //var done = Convert.ToDouble(curr) / Convert.ToDouble(cnt) * 100.0;
                    Console.CursorLeft = 0;
                    Console.Write($"{curr} scanned");
                }
                if (range.PTE.Valid && !range.PTE.NoExecute)
                {
                    foreach (var artifact in KVS.Run(range.VA.Address, range.VA.Address + (range.PTE.LargePage ? LARGE_PAGE_SIZE : MagicNumbers.PAGE_SIZE), range))
                    {
                        var ms = new MemSection() { IsExec = true, Module = artifact, VA = new VIRTUAL_ADDRESS(artifact.VA), Source = range };
                        var extracted = ExtractCVDebug(ms);
                        if (extracted == null)
                        {
                            if(Vtero.VerboseLevel > 1)
                                WriteColor(ConsoleColor.Yellow, $"failed debug info for PE @address {range.VA.Address:X}, extracted headers: {artifact}");
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(OnlyModule) && OnlyModule != ms.Name)
                            continue;

                        if (!Sections.ContainsKey(artifact.VA))
                            Sections.TryAdd(artifact.VA, ms);

                        // we can clobber this guy all the time I guess since everything is stateless in Sym and managed
                        // entirely by the handle ID really which is local to our GUID so....   
                        sym = Vtero.TryLoadSymbols(ID.GetHashCode(), ms.DebugDetails, ms.VA.Address);
                        if (Vtero.VerboseOutput) {
                            WriteColor((sym != null) ? ConsoleColor.Green : ConsoleColor.Yellow, $" symbol loaded = [{sym != null}] PDB [{ms.DebugDetails.PDBFullPath}] @ {range.VA.Address:X}, {ms.Name}");
                            if(Vtero.VerboseLevel > 1)
                                WriteColor((sym != null) ? ConsoleColor.Green : ConsoleColor.Yellow, $"headers: { artifact} ");
                        }

                        if (!string.IsNullOrWhiteSpace(OnlyModule))
                        {
                            if (!string.IsNullOrWhiteSpace(ms.Name) && ms.Name == OnlyModule)
                            {
                                stop = true;
                                //loopState.Stop();
                                break;
                            }
                        }
                        //if (loopState.IsStopped)
                        //return;
                        if (stop) break;
                    }
                }

                //if (loopState.IsStopped)
                //    return;
                //});
                if (stop) break;
            }
            return KVS;
        }

        public List<ScanResult> YaraScan(string RulesFile, bool IncludeData = false, bool KernelSpace = false)
        {
            var rv = new List<ScanResult>();
            using (var ctx = new YaraContext())
            {
                Rules rules = null;
                try
                {
                    // Rules and Compiler objects must be disposed.
                    using (var compiler = new Compiler())
                    {
                        compiler.AddRuleFile(RulesFile);
                        rules = compiler.GetRules();
                    }

                    PageTable.AddProcess(this, MemAccess);
                    //var cnt = PT.FillPageQueue(false, KernelSpace);
                    var curr = 0;
                    YaraTotalScanned = 0;
                    // single threaded worked best so far 
                    //Parallel.For(0, cnt, (i, loopState) => x
                    foreach(var range in PT.FillPageQueue(false, KernelSpace, true, false))
                    //for (int i = 0; i < cnt; i++)
                    {
                        curr++;
                        if (Vtero.VerboseLevel > 1)
                        {
                            //var curr = cnt - PT.PageQueue.Count;
                            //var done = Convert.ToDouble(curr) / Convert.ToDouble(cnt) * 100.0;
                            Console.CursorLeft = 0;
                            Console.Write($"{curr} scanned");
                        }
                        if (range.PTE.Valid)
                        {
                            // skip data as requested
                            if (!IncludeData && range.PTE.NoExecute)
                                continue;

                            // Scanner and ScanResults do not need to be disposed.
                            var scanner = new libyaraNET.Scanner();
                            unsafe {
                                long[] block = null;
                                bool GotData = false;

                                if (range.PTE.LargePage)
                                    block = new long[0x40000];
                                else
                                    block = new long[0x200];

                                MemAccess.GetPageForPhysAddr(range.PTE, ref block, ref GotData);
                                if (GotData)
                                {
                                    fixed (void* lp = block)
                                    {
                                        var res = scanner.ScanMemory((byte *) lp, block.Length, rules, ScanFlags.None);
                                        rv.AddRange(res);
                                        YaraTotalScanned += block.Length;
                                    }
                                }
                            }
                        }
                    }
                }
                finally
                {
                    // Rules and Compiler objects must be disposed.
                    if (rules != null) rules.Dispose();
                }
            }
            YaraOutput = rv;
            return YaraOutput;
        }

        public void DumpProc(string Folder, bool IncludeData = false, bool KernelSpace = true, bool OnlyExec = true)
        {
            //// TODO: BOILER PLATE check perf of using callbacks 
            const int LARGE_PAGE_SIZE = 1024 * 1024 * 2;
            PageTable.AddProcess(this, new Mem(MemAccess));
            var cnt = PT.FillPageQueue(false, KernelSpace);

            Folder = Folder + Path.DirectorySeparatorChar.ToString();
            Directory.CreateDirectory(Folder);

            long ContigSizeState = 0, curr = 0;
            // single threaded worked best so far 
            //Parallel.For(0, cnt, (i, loopState) => x
            foreach(var range in PT.FillPageQueue(false, KernelSpace))
            {
                curr++;
                if (Vtero.VerboseLevel > 1)
                {
                    //var curr = cnt - PT.PageQueue.Count;
                    //var done = Convert.ToDouble(curr) / Convert.ToDouble(cnt) * 100.0;
                    Console.CursorLeft = 0;
                    Console.Write($"{curr} scanned");
                }
                if (range.PTE.Valid)
                {
                    // skip data as requested
                    if (!IncludeData && range.PTE.NoExecute)
                        continue;

                     Vtero.WriteRange(range.VA, range, Folder, ref ContigSizeState, MemAccess);
                }
            }
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
            var block = GetVirtualByte(_va);

            var TimeDate2 = BitConverter.ToUInt32(block, 4);
            if (TimeDate2 != Ext.TimeStamp & Vtero.VerboseOutput)
            {
                WriteColor(ConsoleColor.Yellow, "Unable to lock on to CV data.");
                return null;
            }

            SizeData = BitConverter.ToUInt32(block, 16);
            RawData = BitConverter.ToUInt32(block,  20);
            PointerToRawData = BitConverter.ToUInt32(block, 24);

            // Advance to the debug section where we may find the code view info

            _va = VA + RawData;
            var b2 = GetVirtualByte(_va);
            var bytes2 = new byte[16];
            var s2 = b2[0];
            Array.ConstrainedCopy(b2, 4, bytes2, 0, 16);
            var gid2 = new Guid(bytes2);
            // after GUID
            var age2 = b2[20];

            // char* at end
            var str2 = Encoding.Default.GetString(b2, 24, 32).Trim();
            var cv2 = new CODEVIEW_HEADER { VSize = (int)Ext.SizeOfImage, TimeDateStamp = TimeDate2, byteGuid = bytes2, Age = age2, aGuid = gid2, Sig = s2, PdbName = str2 };
            if (str2.Contains(".") && str2.Contains(".pdb"))
                sec.Name = str2.Substring(0, str2.IndexOf(".pdb")).ToLower();
            else
                sec.Name = str2.ToLower();
            sec.DebugDetails = cv2;
            return cv2;
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
            var rv = new byte[count + 4096];

            var block = VGetBlock(VA);
            if (block == null)
                return rv;

            Array.Copy(block, startIndex, rv, 0, count);
            VA += 4096;
            var block2 = VGetBlock(VA);
            if(block2 != null)
                Array.Copy(block2, 0, rv, count, 4096);
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
