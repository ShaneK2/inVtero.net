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
using inVtero.net.Support;
using static HashLib.HashFactory.Crypto;
using System.Globalization;
using inVtero.net.Hashing;
using System.Dynamic;
using static inVtero.net.MagicNumbers;


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
        public long CR3Value { get; set; }
        public long FileOffset;
        public long TrueOffset;
        public long Diff;
        public int Mode; // 1 or 2
        public PTType PageTableType;

        public Guid ID;

        // symbol info provider
        [ProtoIgnore]
        public Sym sym;

        public ConcurrentDictionary<long, MemSection> Sections { get; private set; }

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

        [ProtoIgnore]
        public bool KernelModulesMerged;

        // the high bit signals if we collected a kernel address space for this AS group
        public int AddressSpaceID;

        [ProtoIgnore]
        public List<ScanResult> YaraOutput;
        public long YaraTotalScanned;
        [ProtoIgnore]
        public dynamic EProc;

        public long EThreadPtr;
        public long VadRootPtr;
        public long ProcessID;
        public String OSPath { get; set; }
        public String OSFileName { get; set; }
        public MemSection KernelSection;
        [ProtoIgnore]
        public HashDB HDB;

        public dynamic xStructInfo(string Struct, long Address, int minLen = 4096, string Module = "ntoskrnl")
        {
            MemSection pdb = null;

            if ((Module == "ntkrnlmp" || Module == "ntoskrnl") && KernelSection != null)
                pdb = KernelSection;
            else
            {
                var pdbPaths = from files in Sections.Values
                               where files.DebugDetails != null &&
                               !string.IsNullOrWhiteSpace(files.DebugDetails.PDBFullPath) &&
                               files.DebugDetails.PDBFullPath.ToLower().Contains(Module.ToLower())
                               select files;

                pdb = pdbPaths.FirstOrDefault();
                if ((Module == "ntkrnlmp" || Module == "ntoskrnl"))
                    KernelSection = pdb;
            }

            long[] memRead = null;
            if (Address != 0)
                memRead = GetVirtualLongLen(Address, minLen);

            var rv = Sym.xStructInfo(pdb.DebugDetails.PDBFullPath, Struct, Address, memRead, GetVirtualByteLen, GetVirtualLongLen, ExpandoChanged);
            rv.SelfAddr = Address;

            return rv;
        }

        public dynamic xStructInfo(string Struct, long[] memRead = null, string Module = "ntoskrnl")
        {
            MemSection pdb = null;

            if ((Module == "ntkrnlmp" || Module == "ntoskrnl") && KernelSection != null)
                pdb = KernelSection;
            else
            {
                var pdbPaths = from files in Sections.Values
                               where files.DebugDetails != null &&
                               !string.IsNullOrWhiteSpace(files.DebugDetails.PDBFullPath) &&
                               files.DebugDetails.PDBFullPath.ToLower().Contains(Module.ToLower())
                               select files;

                pdb = pdbPaths.FirstOrDefault();
                if ((Module == "ntkrnlmp" || Module == "ntoskrnl"))
                    KernelSection = pdb;
            }
            if (sym == null)
                CODEVIEW.TryLoadSymbols(ID.GetHashCode(), pdb.DebugDetails, pdb.VA.Address);

            return Sym.xStructInfo(pdb.DebugDetails.PDBFullPath, Struct, 0, memRead, GetVirtualByteLen, GetVirtualLongLen, ExpandoChanged);
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

        //public (string Name, ulong Address, ulong Length)[] MatchSymbols(string Match, string Module = "ntoskrnl")
        public Tuple<string,ulong,ulong>[] MatchSymbols(string Match, string Module = "ntoskrnl")
        {
            //List<(string, ulong, ulong)> rv = new List<(string, ulong, ulong)>();
            List<Tuple<string, ulong, ulong>> rv = new List<Tuple<string, ulong, ulong>>();

            var modToAdd = from mod in Sections.Values
                           where mod.DebugDetails != null && !string.IsNullOrWhiteSpace(mod.DebugDetails.PDBFullPath) &&
                           string.IsNullOrWhiteSpace(Module) ||
                           Path.GetFileNameWithoutExtension(mod.DebugDetails.PDBFullPath).ToLower().Contains(Path.GetFileNameWithoutExtension(Module).ToLower())
                           select mod;

            foreach(var toAdd in modToAdd)
                rv.AddRange(Sym.MatchSyms(Match,toAdd.DebugDetails.PDBFullPath, toAdd.VA.FullAddr));



            //foreach (var sec in Sections)
            //    if (sec.Value.DebugDetails != null &&
            //        !string.IsNullOrWhiteSpace(sec.Value.DebugDetails.PDBFullPath) &&
            //        Path.GetFileNameWithoutExtension(sec.Value.DebugDetails.PDBFullPath).ToLower().Contains(Path.GetFileNameWithoutExtension(Module).ToLower()) || 
            //        string.IsNullOrWhiteSpace(Module))
            //        rv.AddRange(sym.MatchSyms(Match, sec.Value.DebugDetails.PDBFullPath, sec.Value.VA.FullAddr));



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
                if(Vtero.VerboseLevel > 1)
                    WriteColor(ConsoleColor.Yellow, $"GetSymValue: {new Win32Exception(Marshal.GetLastWin32Error()).Message }.");
                return BAD_VALUE_READ;
            }

            SymbolStore.Add(AddrName, symInfo.Address);

            return symInfo.Address;
        }

        public string GetSymNameHard(ulong Address, MemSection sec = null)
        {
            MemSection s = null;

            if (sec == null)
                s = GetEnclosingSection((long)Address);
            else
                s = sec;

            var detailed = GetSymNameDetails((long) Address, s);
            if (detailed.Item1 != string.Empty)
                return detailed.Item1;


            return GetSymName((long)Address);
        }

        //public (string Name, ulong Address, ulong Length) GetSymNameDetails(long Address, MemSection enclosedBy = null)
        public Tuple<string, ulong, ulong> GetSymNameDetails(long Address, MemSection enclosedBy = null)
        {
            //(string, ulong, ulong) rv = ValueTuple.Create(string.Empty, ulong.MinValue, ulong.MinValue);
            Tuple<string, ulong, ulong> rv = Tuple.Create<string, ulong, ulong>(string.Empty, 0,0);
            MemSection PDB = null;

            if (enclosedBy == null || enclosedBy.DebugDetails == null)
                PDB = GetEnclosingSection(Address, true);
            else
                PDB = enclosedBy;

            if (PDB == null || PDB.DebugDetails == null || string.IsNullOrWhiteSpace(PDB.DebugDetails.PDBFullPath))
                return rv;

            rv = Sym.FindSymByAddress((ulong) Address, PDB.DebugDetails.PDBFullPath, (ulong) PDB.VadAddr);

            return rv;
        }

        public string GetSymName(long Address)
        {
            ulong displaced = 0;
            DebugHelp.SYMBOL_INFO symInfo = new DebugHelp.SYMBOL_INFO();

            symInfo.SizeOfStruct = 0x58;
            symInfo.MaxNameLen = 1024;

            var rv = DebugHelp.SymFromAddrW(ID.GetHashCode(), (ulong) Address, ref displaced, ref symInfo);
            if (!rv)
            {
                if(Vtero.VerboseLevel > 2)
                    WriteColor(ConsoleColor.Yellow, $"GetSymName: {new Win32Exception(Marshal.GetLastWin32Error()).Message }.");
                return string.Empty;
            }
            return symInfo.Name;
        }

        public void LoadModulesInRange(long VA, long length, string OnlyModule = null)
        {
            var KVS = new VirtualScanner(this, new Mem(MemAccess));

            foreach (var artifact in KVS.Run(VA, VA + length))
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
                var local = CODEVIEW.TryLoadSymbols(ID.GetHashCode(), ms.DebugDetails, ms.VA.Address); 
                if (local != null)
                    sym = local;

                if (Vtero.VerboseOutput)
                    WriteColor(ConsoleColor.Green, $"symbol loaded [{sym != null}] from file [{ms.DebugDetails.PDBFullPath}]");
            }

        }

        public void LoadSymbols(MemSection OnlyMS = null)
        {
            foreach (var ms in Sections)
            {
                if (OnlyMS == null || (OnlyMS != null && OnlyMS.VA.Address == ms.Key))
                {
                    var local = CODEVIEW.TryLoadSymbols(ID.GetHashCode(), ms.Value.DebugDetails, ms.Value.VA.Address);
                    if (local != null)
                        sym = local;
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
        public VirtualScanner ScanAndLoadModules(string OnlyModule = "ntoskrnl.exe", bool OnlyLarge = true, bool IncludeKernelSpace = true, bool OnlyValid = true, bool IncludeData = false, bool DoExtraHeaderScan = true)
        {
            const int LARGE_PAGE_SIZE = 1024 * 1024 * 2;
            var curr = 0;
            PageTable.AddProcess(this, new Mem(MemAccess));
            var KVS = new VirtualScanner(this, new Mem(MemAccess), DoExtraHeaderScan);

            // single threaded worked best so far 
            foreach (var range in PT.FillPageQueue(OnlyLarge, IncludeKernelSpace, OnlyValid, IncludeData))
            {
                curr++;
                bool stop = false;
                if (Vtero.VerboseLevel > 1)
                {
                    Console.CursorLeft = 0;
                    Console.Write($"{curr} scanned");
                }
                if (range.PTE.Valid && !range.PTE.NoExecute)
                {
                    foreach (var artifact in KVS.Run(range.VA.Address, range.VA.Address + (range.PTE.LargePage ? LARGE_PAGE_SIZE : PAGE_SIZE), range))
                    {
                        var ms = new MemSection() { IsExec = true, Module = artifact, VA = new VIRTUAL_ADDRESS(artifact.VA), Source = range };
                        var extracted = ExtractCVDebug(ms);
                        if (extracted == null)
                        {
                            if (Vtero.VerboseLevel > 1)
                                WriteColor(ConsoleColor.Yellow, $"failed debug info for PE @address {range.VA.Address:X}, extracted headers: {artifact}");
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(OnlyModule) && OnlyModule != ms.Name)
                            continue;

                        if (!Sections.ContainsKey(artifact.VA))
                            Sections.TryAdd(artifact.VA, ms);

                        // cache this for everybody
                        if (ms.Name == "ntkrnlmp.pdb" || ms.Name == "ntoskrnl.exe")
                        {
                            KernelSection = ms;
                            KernelSection.VadLength = KernelSection.Length = artifact.SizeOfImage;
                            KernelSection.VadAddr = artifact.VA;
                            KernelSection.VadFile = ms.Name = "ntoskrnl.exe";
                        }

                        // we can clobber this guy all the time I guess since everything is stateless in Sym and managed
                        // entirely by the handle ID really which is local to our GUID so....   
                        var local = CODEVIEW.TryLoadSymbols(ID.GetHashCode(), ms.DebugDetails, ms.VA.Address);
                        if (local != null)
                            sym = local;

                        if (Vtero.VerboseOutput)
                        {
                            WriteColor((sym != null) ? ConsoleColor.Green : ConsoleColor.Yellow, $" symbol loaded = [{sym != null}] PDB [{ms.DebugDetails.PDBFullPath}] @ {range.VA.Address:X}, {ms.Name}");
                            if (Vtero.VerboseLevel > 1)
                                WriteColor((sym != null) ? ConsoleColor.Green : ConsoleColor.Yellow, $"headers: { artifact} ");
                        }

                        if (!string.IsNullOrWhiteSpace(OnlyModule))
                        {
                            if (!string.IsNullOrWhiteSpace(ms.Name) && ms.Name == OnlyModule)
                            {
                                stop = true;
                                break;
                            }
                        }
                        if (stop) break;
                    }
                }
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
                    foreach (var range in PT.FillPageQueue(false, KernelSpace, true, false))
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
                            unsafe
                            {
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
                                        var res = scanner.ScanMemory((byte*)lp, block.Length, rules, ScanFlags.None);
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

        // tid&buffer
        public List<Tuple<long, long[]>> KernelThreadStacks;
        public List<Tuple<long, long[]>> UserThreadStacks;

        public long LoadThreads()
        {
            if (EThreadPtr == 0)
                return 0;

            long PossiableStackEntries = 0;

            KernelThreadStacks = new List<Tuple<long, long[]>>();
            UserThreadStacks = new List<Tuple<long, long[]>>();

            var _ETHR_ADDR = EThreadPtr;

            // using typedef's & offsetof give's us speedier access to the underlying struct
            var typedefTEB = xStructInfo("_TEB");
            var userStackBaseOffsetOf = typedefTEB.NtTib.StackBase.OffsetPos;
            var userStackLimitOffsetOf = typedefTEB.NtTib.StackLimit.OffsetPos;

            // base area above curr can have lots of random stuff in it...
            //var sbOffsetOf = typedef.Tcb.StackBase.OffsetPos;
            var typedef = xStructInfo("_ETHREAD");
            var ThreadOffsetOf = typedef.ThreadListEntry.OffsetPos;
            var CurrKerUseOffsetOf = typedef.Tcb.KernelStack.OffsetPos;
            var sbLimitOf = typedef.Tcb.StackLimit.OffsetPos;
            var cidOffsetOf = typedef.Cid.UniqueThread.OffsetPos;
            var tebOffsetOf = typedef.Tcb.Teb.OffsetPos;

            var etr = _ETHR_ADDR - ThreadOffsetOf;
            var memRead = GetVirtualLongLen(etr, (int) typedef.Length);
            do
            {
                _ETHR_ADDR = memRead[ThreadOffsetOf / 8];
                if (_ETHR_ADDR == EThreadPtr)
                    return PossiableStackEntries;

                var ID = memRead[cidOffsetOf / 8];
                var StackLimit = memRead[sbLimitOf / 8];
                var CurrentUse = memRead[CurrKerUseOffsetOf / 8];
                var len = (int)(CurrentUse - StackLimit);

                PossiableStackEntries += len >> 3;

                KernelThreadStacks.Add(Tuple.Create<long, long[]>(ID, GetVirtualLongLen(StackLimit, len)));

                // read out user space info
                var teb_tib_read = memRead[tebOffsetOf / 8];
                memRead = GetVirtualLong(teb_tib_read);

                var UserLim = memRead[userStackLimitOffsetOf / 8];
                var UserBase = memRead[userStackBaseOffsetOf / 8];
                var userLen = (int)(UserBase - UserLim);
                PossiableStackEntries += userLen >> 3;

                UserThreadStacks.Add(Tuple.Create<long, long[]>(ID, GetVirtualLongLen(UserLim, userLen)));

                memRead = GetVirtualLong(_ETHR_ADDR - ThreadOffsetOf);
            } while (_ETHR_ADDR != EThreadPtr);

            // at this point we habe ThreadStacks saved and can scan for RoP badness
            // also need to scan the TEB for TEB base/limit and add those ranges for user space roppers
            return PossiableStackEntries;
        }
    
        // TODO: Double check the perf benifit of using these over the ExpandoObject
        dynamic _MMVAD_Def, _SUBSECTION_Def, _CONTROL_AREA_Def, _FILE_OBJECT_Def;
        long ssPos, caPos, foPos, fnPos, flagBitPos, flagsOffsetPos, flagsLength;
        long startingVPNPos, endingVPNPPos, startHighPos, endHighPos;
        long rightPos, leftPos;
        int vadLength; 

        public void InitSymbolsForVad()
        {
            _MMVAD_Def = xStructInfo("_MMVAD");
            if (_MMVAD_Def.Dictionary.ContainsKey("Core"))
            {
                flagBitPos = _MMVAD_Def.Core.u.VadFlags.Protection.BitPosition;
                flagsOffsetPos = _MMVAD_Def.Core.u.VadFlags.Protection.OffsetPos;
                flagsLength = (long)_MMVAD_Def.Core.u.VadFlags.Protection.Length;

                rightPos = _MMVAD_Def.Core.VadNode.Right.OffsetPos;
                leftPos = _MMVAD_Def.Core.VadNode.Left.OffsetPos;

                startingVPNPos = _MMVAD_Def.Core.StartingVpn.OffsetPos;
                endingVPNPPos = _MMVAD_Def.Core.EndingVpn.OffsetPos;
                startHighPos = _MMVAD_Def.Core.StartingVpnHigh.OffsetPos;
                endHighPos = _MMVAD_Def.Core.EndingVpnHigh.OffsetPos;
            }
            else
            {
                flagBitPos = _MMVAD_Def.u.VadFlags.Protection.BitPosition;
                flagsOffsetPos = _MMVAD_Def.u.VadFlags.Protection.OffsetPos;
                flagsLength = (long)_MMVAD_Def.u.VadFlags.Protection.Length;

                rightPos = _MMVAD_Def.RightChild.OffsetPos;
                leftPos = _MMVAD_Def.LeftChild.OffsetPos;

                startingVPNPos = _MMVAD_Def.StartingVpn.OffsetPos;
                endingVPNPPos = _MMVAD_Def.EndingVpn.OffsetPos;

                startHighPos = -1;
                endHighPos = -1;
                // startHighPos = _MMVAD_Def.StartingVpnHigh.OffsetPos;
                //endHighPos = _MMVAD_Def.EndingVpnHigh.OffsetPos;
            }

            _SUBSECTION_Def = xStructInfo("_SUBSECTION");
            _CONTROL_AREA_Def = xStructInfo("_CONTROL_AREA");
            _FILE_OBJECT_Def = xStructInfo("_FILE_OBJECT");

            ssPos = _MMVAD_Def.Subsection.OffsetPos;
            caPos = _SUBSECTION_Def.ControlArea.OffsetPos;
            foPos = _CONTROL_AREA_Def.FilePointer.OffsetPos;
            fnPos = _FILE_OBJECT_Def.FileName.OffsetPos;

            vadLength = (int)_MMVAD_Def.Length;
        }

        public void CopySymbolsForVad(DetectedProc other)
        {
            _MMVAD_Def = other._MMVAD_Def;

            flagBitPos = other.flagBitPos;
            flagsOffsetPos = other.flagsOffsetPos;
            flagsLength = other.flagsLength;
            rightPos = other.rightPos;
            leftPos = other.leftPos;
            startingVPNPos = other.startingVPNPos;
            endingVPNPPos = other.endingVPNPPos;
            startHighPos = other.startHighPos;
            endHighPos = other.endHighPos;

            ssPos = other.ssPos;
            caPos = other.caPos;
            foPos = other.foPos;
            fnPos = other.fnPos;
            vadLength = other.vadLength;
        }

        public void ListVad(long AddressRoot = 0, bool AllVad = false)
        {
            if (_MMVAD_Def == null)
                InitSymbolsForVad();

            // use the simple method for VAD parsing since it's a very hot path
            if (AddressRoot == 0)
                return;
            try
            {
                // for the VAD
                // limit all these reads with tLongLen read so we do not over read if we do not need
                var memRead = GetVirtualLongLen(AddressRoot, vadLength);
                
                long StartingVPN = 0, EndingVPN = 0;
                long LeftPtr = 0, RightPtr = 0;
                ulong VADflags = 0;
                bool IsExec = false;
                VADflags = (ulong)memRead[flagsOffsetPos / 8];
                var mask = 1UL;
                for (int x = (int)flagsLength - 1; x > 0; x--)
                {
                    mask = mask << 1;
                    mask |= 1;
                }
                var new_mask = mask << (int)flagBitPos;

                VADflags &= new_mask;

                // move lvalue to bitposition 0 
                // saves having todo this every time we evaluate Value
                VADflags = VADflags >> (int)flagBitPos;

                LeftPtr = memRead[leftPos / 8];
                RightPtr = memRead[rightPos / 8];
                if (((VADflags & 2) != 0) || AllVad)
                {
                    if((VADflags & 2) != 0)
                        IsExec = true;

                    int shift;
                    long StartingVPNHighTmp = 0, EndingVPNHighTmp = 0;

                    if (startHighPos > 0)
                    {
                        shift = ((int)startHighPos % 8 * 8);
                        StartingVPNHighTmp = memRead[startHighPos / 8];
                        StartingVPNHighTmp = (StartingVPNHighTmp >> shift) & 0xff;
                    }
                    if (endHighPos > 0)
                    {
                        shift = ((int)endHighPos % 8 * 8);
                        EndingVPNHighTmp = memRead[endHighPos / 8];
                        EndingVPNHighTmp = (EndingVPNHighTmp >> shift) & 0xff;
                    }

                    shift = ((int)startingVPNPos % 8 * 8);
                    var StartingVPNTmp = memRead[startingVPNPos / 8];
                    StartingVPNTmp = (StartingVPNTmp >> shift) & 0xffffffff;

                    shift = ((int)endingVPNPPos % 8 * 8);
                    var EndingVPNTmp = memRead[endingVPNPPos / 8];
                    EndingVPNTmp = (EndingVPNTmp >> shift) & 0xffffffff;

                    StartingVPN = StartingVPNHighTmp << 32 | StartingVPNTmp;
                    EndingVPN = EndingVPNHighTmp << 32 | EndingVPNTmp;
                }

                long StartingAddress = StartingVPN << PAGE_SHIFT;
                long Length = (EndingVPN - StartingVPN) * PAGE_SIZE;
                if (IsExec)
                {
                    var ssPtr = memRead[ssPos / 8];
                    memRead = GetVirtualLongLen(ssPtr, (int)caPos + 8);

                    var caPtr = memRead[caPos / 8];
                    memRead = GetVirtualLongLen(caPtr, (int)foPos + 8);

                    var foPtr = memRead[foPos / 8] & -16;
                    memRead = GetVirtualLongLen(foPtr, (int)fnPos + 0x10);

                    var lvalue = memRead[fnPos / 8];
                    var fnPtr = memRead[(fnPos + 8) / 8];

                    if (foPtr != 0)
                    {
                        var strLen = (short)lvalue & 0xffff;
                        var strByteArr = GetVirtualByteLen(fnPtr, strLen);
                        var FileName = Encoding.Unicode.GetString(strByteArr, 0, strLen);

                        if (Vtero.VerboseLevel > 2 & Vtero.DiagOutput)
                            WriteColor($"VAD found executable file mapping {FileName} Mapped @ [{StartingAddress:X}] Length [{Length:X}]");

                        bool KnownSection = false;
                        // walk memsections and bind this information 
                        foreach (var sec in Sections)
                        {
                            // We have a section that is known 
                            // populate extra details
                            if (sec.Key >= StartingAddress && sec.Key < StartingAddress + Length)
                            {
                                KnownSection = true;
                                sec.Value.VadFile = FileName;
                                sec.Value.VadAddr = StartingAddress;
                                sec.Value.VadLength = Length;
                                if (sec.Value.Length < sec.Value.VadLength)
                                    sec.Value.Length = sec.Value.VadLength;
                                break;
                            }
                        }
                        // if it's unknown, that the VAD is the sole source of information
                        if (!KnownSection && (StartingAddress != 0 && Length != 0))
                            Sections.TryAdd(StartingAddress, new MemSection()
                            {
                                Length = Length,
                                VadLength = Length,
                                VadAddr = StartingAddress,
                                VadFile = FileName,
                                Name = FileName,
                                VA = new VIRTUAL_ADDRESS(StartingAddress)
                            });
                    }
                } else if(StartingAddress != 0 && Length != 0)
                    Sections.TryAdd(StartingAddress, new MemSection()
                    {
                        Length = Length,
                        VadLength = Length,
                        VadAddr = StartingAddress,
                        VA = new VIRTUAL_ADDRESS(StartingAddress)
                    });
                ListVad(LeftPtr, AllVad);
                ListVad(RightPtr, AllVad);
            } catch (Exception all)
            {
                // dynamic drop exceptions
            }
        }


        /// <summary>
        /// Process specialized 
        /// 
        /// This is a cheat function to basically force deferred execution to occur.
        /// 
        /// All of this sort of late bound meta-data from the system needs to be carefully written to not be too expensive.
        /// (e.g. use the .OffsetPos rather than too heavy on dynamic resolution)
        /// 
        /// Ensure we have symbols & kernel meta data parsed into our type info
        /// 
        /// Also We need vtero.WalkProcList to have been called which isolates vadroot
        /// 
        /// </summary>
        public void MergeVAMetaData(bool DoStackCheck = false)
        {
            // setup kernel in optimized scan
            ScanAndLoadModules();
            // Load as much as possible from full user space scan for PE / load debug data
            ScanAndLoadModules("", false, false);

            var codeRanges = new ConcurrentDictionary<long, long>();

            /// All page table entries 
            /// including kernel
            var execPages = PT.FillPageQueue(false, true);
            foreach (var pte in execPages)
            {
                var Len = pte.PTE.LargePage ? LARGE_PAGE_SIZE : PAGE_SIZE;
                codeRanges.TryAdd(pte.VA.Address, pte.VA.Address + Len);
            }
            // Walk Vad and inject into 'sections'
            // scan VAD data to additionally bind 
            ListVad(VadRootPtr);

            // Dig all threads
            if (DoStackCheck)
            {
                var StackEntries = LoadThreads();
                var checkPtrs = new ConcurrentBag<long>();

                // instead of using memsections we should use apge table info
                // then push in memsection after this round
                Parallel.Invoke(() =>
                {
                    // each stack
                    foreach (var userRange in UserThreadStacks)
                    {
                        // every value
                        foreach (var pointer in userRange.Item2)
                        {
                            if (pointer > -4096 && pointer < 4096)
                                continue;

                            // see if in range of code
                            foreach (var codeRange in codeRanges)
                                // if so we need to double check that the code ptr is a good one
                                if (pointer >= codeRange.Key && pointer < codeRange.Value)
                                    checkPtrs.Add(pointer);
                        }
                    }
                }, () =>
                {
                    // each stack
                    foreach (var kernelRange in KernelThreadStacks)
                    {
                        // every value
                        foreach (var pointer in kernelRange.Item2)
                        {
                            if (pointer > -4096 && pointer < 4096)
                                continue;

                            // see if in range of code
                            foreach (var codeRange in codeRanges)
                                // if so we need to double check that the code ptr is a good one
                                if (pointer >= codeRange.Key && pointer < codeRange.Value)
                                    checkPtrs.Add(pointer);
                        }
                    }
                });

                WriteColor(ConsoleColor.Cyan, $"Identified {checkPtrs.Count} possiable code pointers from the stack of a total {StackEntries}");

                bool GotData = false;

                var CheckArr = checkPtrs.ToArray();
                Array.Sort(CheckArr);
                long lastPtr = 0;
                byte[] ptrTo = null;

                // validate checkPtrs pointers here
                foreach (var ptr in CheckArr)
                {
                    // if the pointer is page aligned perfectly we skip it
                    var idx = ptr & 0xfff;
                    if (idx < 10 || ptr == lastPtr)
                        continue;

                    // if the curr ptr and the lastPtr are farther then a page we need a new load
                    if ((ptr & ~0xfff) != (lastPtr & ~0xfff))
                    {
                        // every pointer needs to be a function start
                        // or a properly call/ret pair
                        ptrTo = VGetBlock(ptr, ref GotData);
                        if (!GotData)
                            continue;
                    }
                    lastPtr = ptr;

                    var IsCCBefore = ptrTo[idx - 1];
                    var IsCallE8 = ptrTo[idx - 5];
                    var IsCallE8_second = ptrTo[idx - 3];
                    var IsCall9A = ptrTo[idx - 5];
                    var IsCall9A_second = ptrTo[idx - 7];

                    bool FoundFFCode = false;
                    // scan from RoPCheck
                    for (int i = 2; i < 10; i++)
                    {
                        var a = ptrTo[idx - i];
                        var b = ptrTo[idx - i + 1];

                        if (i < 8)
                        {
                            if ((a == 0xff) && (b & 0x38) == 0x10)
                            {
                                FoundFFCode = true;
                                break;
                            }
                        }
                        if ((a == 0xff) && (b & 0x38) == 0x18)
                        {
                            FoundFFCode = true;
                            break;
                        }
                    }

                    if (!FoundFFCode && IsCCBefore != 0xcc && IsCallE8 != 0xe8 && IsCallE8_second != 0xe8 && IsCall9A != 0x9a && IsCall9A_second != 0x9a)
                    {
                        var cs = Capstone.Dissassemble(ptrTo, ptrTo.Length, (ulong)(ptr & -4096));
                        for (int i = 1; i < cs.Length; i++)
                        {
                            var BeforeRetRefAddr = cs[i - 1].insn.address;
                            var RetTarget = cs[i].insn.address;
                            // if we go through the whole page before the pointer and do not find our instruction.
                            // it could be a capstone bug or more likely it was some data/alignment random bytes
                            if (RetTarget == (ulong)ptr)
                            {
                                WriteColor(ConsoleColor.Cyan, $"Stack pointer is wild {ptr:x}");

                                var Module = GetEnclosingSection((long) RetTarget, true);

                                var details = GetSymNameDetails((long)RetTarget, Module);
                                WriteColor(ConsoleColor.Yellow, $"{Module.VadFile} {BeforeRetRefAddr:x} [{details.Item1}+{(RetTarget - details.Item2):x}] {cs[i - 1].insn.bytes[0]:x} {cs[i - 1].insn.mnemonic} {cs[i - 1].insn.operands}");

                                details = GetSymNameDetails((long)BeforeRetRefAddr, Module);
                                WriteColor(ConsoleColor.Yellow, $"{Module.VadFile} {RetTarget:x} [{details.Item1}+{(BeforeRetRefAddr - details.Item2):x}] {cs[i].insn.bytes[0]:x} {cs[i].insn.mnemonic} {cs[i].insn.operands}");
                            } 
                        }
                    }
                }
            }

            // find section's with no "Module"
            foreach (var sec in Sections.Values)
            {
                if (sec.Module == null)
                {
                    // should be block aligned
                    var test = VGetBlock(sec.VadAddr);
                    if (test == null)
                        continue;

                    var ext = Extract.IsBlockaPE(test);
                    sec.Module = ext;
                }
            }
        }

        public HashRec[] HashGenBlocks(bool KernelSpace = false, bool DoReReLocate = true, HashLib.IHash iHasher = null)
        {
            long VA = 0;
            byte[] block = null;
            string Name = string.Empty;
            List<HashRec> hr = new List<HashRec>();

            HashLib.IHash hasher = iHasher;

            if (hasher == null)
                hasher = CreateTiger2();

            //// TODO: BOILER PLATE check perf of using callbacks 
            PageTable.AddProcess(this, new Mem(MemAccess));

            if (Sections.Count < 2)
                ListVad(VadRootPtr);

            foreach (var range in PT.FillPageQueue(false, KernelSpace))
            {
                if (range.PTE.Valid)
                {
                    VA = range.VA.Address;
                    block = VGetBlock(VA);
                    if (block == null)
                        continue;

                    if (DoReReLocate)
                    {
                        var sec = GetEnclosingSection(VA, true);
                        if (sec != null)
                            Name = sec.NormalizedName;

                        if (sec != null && sec.Module != null && sec.Module.ReReState != null)
                        {
                            var offset = VA - sec.VadAddr;
                            AttemptDelocate(block, sec, offset);
                        }
                    }
                    var hrecs = FractHashTree.CreateRecsFromMemory(block, HDB.MinBlockSize, null);
                    hr.AddRange(hrecs);
                }
            }
            return hr.ToArray();
        }

        [ProtoIgnore]
        public HashRecord[] HashRecords;
        [ProtoIgnore]
        public int ProcTotal = 0;
        [ProtoIgnore]
        public int ProcValidate = 0;

        public double HashRecordRate()
        {
            if(HashRecords != null)
                foreach (var rec in HashRecords)
                {
                    foreach (var slice in rec.Regions)
                    {
                        ProcTotal += slice.Total;
                        ProcValidate += slice.Validated;
                    }
                }
            else if (ProcTotal < 1)
                    return 0.0d;

            return ProcValidate * 100.0d / ProcTotal;

        }

        public HashRecord[] VADHash(bool KernelSpace = false, bool DoReReLocate = true, bool ExecOnly = true, bool SinglePFNDump = true, bool BitmapScan = true, bool CloudScan = false)
        {
            var hr = new ConcurrentStack<HashRecord>();

            if (Sections.Count < 2)
                ListVad(VadRootPtr);

            if (KernelSpace)
                MergeKernelModules();

            foreach (var s in Sections)
            {
                string Name = string.Empty;
                long VA = s.Value.VadAddr;
                var memsec = s.Value;
                bool PagedIn = false;
                byte[] block = null;

                if (memsec.Module == null)
                {
                    block = VGetBlock(VA, ref PagedIn);
                    if (PagedIn) 
                        memsec.Module = Extract.IsBlockaPE(block);
                }

                //if (ProcessID == 4 && memsec.DebugDetails != null)
                //    memsec.NormalizedName = GetNormalized(memsec.DebugDetails.PdbName, true);
                //else
                memsec.NormalizedName = GetNormalized(memsec.VadFile, true);

                if (memsec.Module != null && !Vtero.ModuleCache.ContainsKey(VA))
                    Vtero.ModuleCache[VA] = memsec;

                if (memsec.Module == null)
                {
                    // find this from other process
                    if (Vtero.ModuleCache.ContainsKey(VA))
                    {
                        var cachdSec = Vtero.ModuleCache[VA];
                        if (cachdSec.NormalizedName.Contains(memsec.NormalizedName) && cachdSec.Module != null)
                            memsec.Module = cachdSec.Module;
                    }
                }

                // proc is set in hashrecord so we can track it back later if we want to see what/where
                var hRecord = new HashRecord();

                for (long SecOffset = 0; SecOffset < s.Value.VadLength; SecOffset += PAGE_SIZE)
                {
                    var pte = MemAccess.VirtualToPhysical(CR3Value, VA + SecOffset);

                    if (SinglePFNDump)
                    {
                        if (MemAccess.IsDumpedPFN(pte))
                            continue;
                        MemAccess.SetDumpedPFN(pte);
                    }

                    if (ExecOnly && pte.NoExecute && SecOffset > 0)
                        continue;

                    // skip since we cheated and got the header early
                    if (SecOffset > 0 || block == null)
                        block = VGetBlock(VA + SecOffset, ref PagedIn);

                    if (!PagedIn)
                        continue;

                    Name = memsec.NormalizedName;

                    if (memsec.Module != null)
                    {
                        MiniSection ms = MiniSection.Empty;
                        // apply the module name
                        // append the module section name (.text whatever)
                        for (int i = 0; i < memsec.Module.Sections.Count(); i++)
                        {
                            if (SecOffset >= memsec.Module.Sections[i].VirtualAddress &&
                                SecOffset < memsec.Module.Sections[i].VirtualAddress + memsec.Module.Sections[i].RawFileSize)
                            {
                                ms = memsec.Module.Sections[i];
                                Name += GetNormalized(ms.Name, false);
                                break;
                            }
                        }
                        if (ExecOnly && (ms.IsExec || ms.IsCode) && DoReReLocate)
                            AttemptDelocate(block, memsec, SecOffset);
                    }
                    else
                        Name += $"+0x{SecOffset:x}";

                    HashRec[] hrecs = null;

                    if(!CloudScan)
                        hrecs = FractHashTree.CreateRecsFromMemory(block, HDB.MinBlockSize, null, 0, VA + SecOffset, HDB.MinBlockSize);
                    else
                        hrecs = FractHashTree.CreateRecsFromMemory(block, HDB.MinBlockSize, null, 0, VA + SecOffset, HDB.MinBlockSize, false, true);

                    if (BitmapScan)
                    {
                        var passed = HDB.BitmapScan(hrecs);
                        //ProcTotal += hrecs.Length;
                        //ProcValidate += passed;
                        hRecord.AddBlock(Name, VA + SecOffset, hrecs, passed);
                    } else
                        // setup records for expensive check by caller
                        hRecord.AddBlock(Name, VA + SecOffset, hrecs);
                }
                hr.Push(hRecord);
            }

            HashRecords = hr.ToArray();
            return HashRecords;
        }

        void AttemptDelocate(byte[] block, MemSection s, long SecOffset)
        {
            // were we able to get all the details we need to DeLocate (ReReLocate)?
            // This should be moved into some global cache so each Process can share the info for shared modules etc..
            if (HDB != null && HDB.ReRe != null)
            {
                DeLocate rere = null;

                if (s.Module.ReReState != null)
                    rere = s.Module.ReReState;
                else
                    s.Module.ReReState = rere = HDB.ReRe.GetLocated(s.Module.Is64, s.NormalizedName, s.Module.TimeStamp, (ulong)s.VadAddr);

                if (rere != null && (rere.OrigImageBase != (ulong)s.VA.Address))
                {
                    if (SecOffset == 0)
                        DeLocate.DelocateHeader(block, rere.OrigImageBase, s.Module.ImageBaseOffset, s.Module.Is64);
                    else if (!s.Module.Is64)
                        rere.DeLocateBuff32(block, (uint)s.Module.ReReState.Delta, (uint)SecOffset, rere.RelocData.ToArray());
                    else
                        rere.DeLocateBuff64(block, rere.Delta, (ulong)SecOffset, rere.RelocData.ToArray());
                }
            }
        }


        public void VADDump(string Folder, bool KernelSpace = false, bool DoReReLocate = true)
        {
            byte[] block = null;
            string Name = string.Empty;
            var hr = new List<HashRecord>();

            if (!Directory.Exists(Folder))
                Directory.CreateDirectory(Folder);

            PageTable.AddProcess(this, new Mem(MemAccess));

            if (Sections.Count < 2)
                ListVad(VadRootPtr);

            if (KernelSpace)
                MergeKernelModules();

            foreach (var s in Sections)
            {
                long VA = s.Value.VadAddr;

                if (VIRTUAL_ADDRESS.IsKernelRange(VA) && !KernelSpace)
                    continue;

                for (long SecOffset = 0; SecOffset < s.Value.VadLength; SecOffset += PAGE_SIZE)
                {
                    bool PagedIn = false;
                    block = VGetBlock(VA + SecOffset, ref PagedIn);
                    if (block == null)
                        block = new byte[PAGE_SIZE];

                    var sec = GetEnclosingSection(VA + SecOffset, true);
                    if (sec != null)
                    {
                        // apply the section name ".text" watever ;)
                        Name = sec.NormalizedName;

                        if (sec.Module != null)
                        {
                            MiniSection ms = MiniSection.Empty;
                            for (int i = 0; i < sec.Module.Sections.Count(); i++)
                            {
                                if (SecOffset >= sec.Module.Sections[i].VirtualAddress &&
                                    SecOffset < sec.Module.Sections[i].VirtualAddress + sec.Module.Sections[i].RawFileSize)
                                {
                                    ms = sec.Module.Sections[i];
                                    Name += GetNormalized(sec.Module.Sections[i].Name, false);
                                    break;
                                }
                            }
                            // were we able to get allt he details we need to DeLocate (ReReLocate)?
                            if ((ms.IsExec || ms.IsCode) && DoReReLocate)
                                AttemptDelocate(block, sec, SecOffset);
                        }
                    }

                    if (string.IsNullOrWhiteSpace(Name))
                        Name = (VA + SecOffset).ToString("X");

                    using (var fw = new FileStream(Folder + Name, FileMode.Append, FileAccess.Write))
                        fw.Write(block, 0, block.Length);
                }
            }
        }

        /// <summary>
        /// Any time were looking into kernel stuff we need to call here.
        /// </summary>
        public void MergeKernelModules()
        {
            String FileName = string.Empty;

            if (_MMVAD_Def == null)
                InitSymbolsForVad();

            // we already know this but..
            var ntosBase = GetSymValueLong("PsNtosImageBase");
            var ntosEnd = GetSymValueLong("PsNtosImageEnd");
            var halBase = GetSymValueLong("PsHalImageBase");
            var halEnd = GetSymValueLong("PsHalImageEnd");
            if(GetEnclosingSection(halEnd, false) == null)
            {
                FileName = "hal.dll";
                Sections.TryAdd(halBase, new MemSection()
                {
                    Length = halEnd - halBase,
                    VadLength = halEnd - halBase,
                    VadAddr = halBase,
                    VadFile = FileName,
                    Name = FileName,
                    VA = new VIRTUAL_ADDRESS(halBase)
                });
            }

            // add all drivers to sections list
            var pModuleHead = GetSymValueLong("PsLoadedModuleList");
            var _LDR_DATA_Def = xStructInfo("_LDR_DATA_TABLE_ENTRY");
            var _LDR_DATA_ADDR = pModuleHead;

            int LDR_LEN = (int)_LDR_DATA_Def.Length;
            long DllBaseOffsetOf = _LDR_DATA_Def.DllBase.OffsetPos;
            long SizeOfImageOffsetOf = _LDR_DATA_Def.SizeOfImage.OffsetPos;
            long FullDllNameOffsetOf = _LDR_DATA_Def.FullDllName.OffsetPos;
            long InLoadOrderLinksOffsetOf = _LDR_DATA_Def.InLoadOrderLinks.OffsetPos;

            do
            {
                var _LDR_DATA = GetVirtualLongLen(_LDR_DATA_ADDR, vadLength);
                // get->next pointer
                _LDR_DATA_ADDR = _LDR_DATA[InLoadOrderLinksOffsetOf / 8];

                var StartingAddress = _LDR_DATA[DllBaseOffsetOf / 8];
                var Length = _LDR_DATA[SizeOfImageOffsetOf / 8] & 0xffffffff;
                var lvalue = _LDR_DATA[FullDllNameOffsetOf / 8];
                var FileNamePtr = _LDR_DATA[((FullDllNameOffsetOf + 8) / 8)];
                if (FileNamePtr != 0)
                {
                    var strLen = (short)lvalue & 0xffff;
                    var strByteArr = GetVirtualByteLen(FileNamePtr, strLen + 0x10);

                    FileName = Encoding.Unicode.GetString(strByteArr, 0, strLen);
                }
                bool KnownSection = false;
                // walk memsections and bind this information 
                foreach (var sec in Sections)
                {
                    // kernel ranges < 0 since they sign extend
                    if (StartingAddress < 0)
                        StartingAddress = (long)((ulong)StartingAddress & ~0xffff000000000000);

                    if (sec.Key >= StartingAddress && sec.Key < StartingAddress + Length)
                    {
                        KnownSection = true;
                        sec.Value.VadFile = FileName;
                        sec.Value.VadAddr = StartingAddress;
                        sec.Value.VadLength = Length;
                        break;
                    }
                }

                // if it's unknown, that the VAD is the sole source of information
                if (!KnownSection)
                    Sections.TryAdd(StartingAddress, new MemSection()
                    {
                        Length = Length,
                        VadLength = Length,
                        VadAddr = StartingAddress,
                        VadFile = FileName,
                        Name = FileName,
                        VA = new VIRTUAL_ADDRESS(StartingAddress)
                    });
            } while (_LDR_DATA_ADDR != pModuleHead);

            KernelModulesMerged = true;
        }

        public long DumpProc(string Folder, bool IncludeData = false, bool KernelSpace = true)
        {
            PageTable.AddProcess(this, new Mem(MemAccess));

            if (Sections.Count < 2)
                ListVad(VadRootPtr);

            if (KernelSpace)
                MergeKernelModules();

            Folder = Folder + Path.DirectorySeparatorChar.ToString();
            Directory.CreateDirectory(Folder);

            long ContigSizeState = 0, curr = 0;
            // single threaded worked best so far 
            //Parallel.For(0, cnt, (i, loopState) => x
            foreach (var range in PT.FillPageQueue(false, KernelSpace, true, !IncludeData))
            {
                curr++;
                if (Vtero.VerboseLevel > 1)
                {
                    Console.CursorLeft = 0;
                    Console.Write($"{curr} scanned");
                }
                if (range.PTE.Valid)
                {
                    // skip data as requested
                    if (!IncludeData && range.PTE.NoExecute)
                        continue;

                    string modName = string.Empty;
                    var sec = GetEnclosingSection(range.VA.Address);
                    if (sec != null)
                        modName = sec.NormalizedName;

                    Vtero.WriteRange(range.VA, range, Folder + modName + "-", ref ContigSizeState, MemAccess);
                }
            }
            return curr;
        }

        public static string GetNormalized(string Name, bool IsFileName = true)
        {
            string modName, normName;
            if (string.IsNullOrWhiteSpace(Name))
                return string.Empty;

            var pathTrim = Name.Split('\x0');

            var ImagePath = pathTrim[0];

            if (IsFileName && ImagePath.Contains(".") && pathTrim[0].LastIndexOf(".") + 4 < pathTrim[0].Length)
                ImagePath = ImagePath.Substring(0, pathTrim[0].LastIndexOf(".") + 4);

            if (ImagePath.Contains(Path.DirectorySeparatorChar))
                normName = ImagePath.Split(Path.DirectorySeparatorChar).Last();
            else
                normName = ImagePath;

            foreach (char c in Path.GetInvalidFileNameChars())
                normName = normName.Replace(c, '_');

            if (IsFileName)
                modName = Path.GetFileName(normName); // Path.GetFileName(sec.Value.Name);
            else
                modName = normName;

            return modName;
        }

        public MemSection GetEnclosingSection(long VA, bool WithHeader = false)
        {
            // likely kernel address mask it.
            if (VIRTUAL_ADDRESS.IsKernelRange(VA))
                VA = VIRTUAL_ADDRESS.Reduce(VA);

            var modName = string.Empty;
            foreach (var sec in Sections)
                if (VA >= sec.Key &&
                    VA < sec.Key + sec.Value.Length)
                {
                    var ms = sec.Value;
                    if (string.IsNullOrWhiteSpace(ms.NormalizedName))
                        ms.NormalizedName = GetNormalized(ms.Name);

                    // check the VadAddr
                    if (WithHeader)
                    {
                        if (ms.Module == null)
                        {
                            var headerData = VGetBlock(ms.VadAddr);
                            if (headerData == null)
                            {
                                if (Vtero.VerboseLevel > 1)
                                    WriteColor(ConsoleColor.Yellow, $"Unable to read likely PE header location. {ms.VadAddr:X}");

                                return ms;
                            }
                            ms.Module = Extract.IsBlockaPE(headerData);
                        }
                    }
                    return ms;
                }
            return null;
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
                return CODEVIEW_HEADER.Init();
            }

            SizeData = BitConverter.ToUInt32(block, 16);
            RawData = BitConverter.ToUInt32(block, 20);
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
            var cv2 = new CODEVIEW_HEADER { VSize = Ext.SizeOfImage, TimeDateStamp = TimeDate2, byteGuid = bytes2, Age = age2, aGuid = gid2, Sig = s2, PdbName = str2 };
            if (str2.Contains(".") && str2.Contains(".pdb"))
                sec.Name = str2.Substring(0, str2.IndexOf(".pdb") + 4).ToLower();
            else
                sec.Name = str2.ToLower();

            if (sec.Name == "ntkrnlmp.pdb")
                sec.Name = "ntoskrnl.exe";

            sec.DebugDetails = cv2;
            return cv2;
        }

        #region Memory Accessors 

        public bool WriteMemory<T>(long VA, T[] Data)
        {
            byte[] byteArr = null;
            if (Data is byte[])
                byteArr = Data as byte[];
            else if (Data is long[])
            {
                byteArr = new byte[Data.Length * 8];
                Buffer.BlockCopy(Data, 0, byteArr, 0, byteArr.Length);
            }
            else
                return false;

            var hw = MemAccess.VirtualToPhysical(CR3Value, VA);

            if (!hw.Valid)
                return false;

            var file_block_offset = MemAccess.OffsetToMemIndex(hw.NextTable_PFN);
            var FileAddr = file_block_offset + (VA & 0xfff);

            using (var writer = new FileStream(MemAccess.IOFile, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
            {
                writer.Seek(FileAddr, SeekOrigin.Begin);
                writer.Write(byteArr, 0, byteArr.Length);
            }
            return true;
        }

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
            bool GoodRead = false;
            var data = VGetBlock(VA, ref GoodRead);
            if (!GoodRead)
                return -1;

            return BitConverter.ToInt64(data, (int)(VA & 0xfff));
        }

        public ulong GetULongValue(long VA)
        {
            var data = VGetBlock((long)VA);
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
            return VGetBlock(VA, ref GotData);
        }

        public byte[] VGetBlock(long VA, ref bool GotData)
        {
            byte[] rv = new byte[PAGE_SIZE];

            var _va = VA & ~0xfff;

            HARDWARE_ADDRESS_ENTRY hw;
            if (vmcs == null)
                hw = MemAccess.VirtualToPhysical(CR3Value, _va);
            else
                hw = MemAccess.VirtualToPhysical(vmcs.EPTP, CR3Value, _va);

            MemAccess.GetPageForPhysAddr(hw, ref rv, ref GotData);
            if (!GotData)
                return null;

            return rv;
        }

        void ExpandoChanged(object sender, PropertyChangedEventArgs e)
        {
            var myDict = ((IDictionary<string, object>)sender);

            if (e.PropertyName.Equals("Value"))
            {
                // VA in this process, we set this strictly so we know it's a long
                var Address = (long)myDict["vAddress"];

                // the value to write (opaque)
                var NewValue = myDict["Value"];

                // SymType will tell us how to serialize NewValue
                var SymType = myDict["TypeName"] as String;

                // ObjectType is the full struct.member.field information
                var ObjectType = myDict["MemberName"] as String;

                var TypeLength = (ulong) myDict["Length"];

                if (Vtero.VerboseLevel > 1)
                {
                    WriteColor(ConsoleColor.Black, ConsoleColor.Green,
                    $"Writing {NewValue} to Object {ObjectType} MemberType {SymType} address: [{Address:X}]");
                    WxColor(ConsoleColor.White, ConsoleColor.Black, "");
                }

                using (var fsAccess = new FileStream(MemAccess.IOFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                {
                    byte[] byteArr = null;
                    byte[] testArr = new byte[PAGE_SIZE];

                    // why not read the data in and make sure we see what we think we should see?
                    var hw = MemAccess.VirtualToPhysical(CR3Value, Address);
                    if (!hw.Valid)
                        return;

                    var i = (int) Address & 0xfff;

                    var file_block_offset = MemAccess.OffsetToMemIndex(hw.NextTable_PFN);
                    var FileAddr = file_block_offset + i;
                    fsAccess.Seek(file_block_offset, SeekOrigin.Begin);
                    fsAccess.Read(testArr, 0, testArr.Length);

                    // seraialize byteArr
                    if (!string.IsNullOrWhiteSpace(SymType) && SymType.Equals("_UNICODE_STRING"))
                    {
                        int len = testArr[((Address - 0x10) & 0xfff)];
                        var newStr = NewValue as String;

                        if (newStr.Length > len)
                            WriteColor(ConsoleColor.Black, ConsoleColor.Yellow, $"new string{newStr.Length} is longer than the original{len}, consider something smaller next time, writing anyway!");

                        byteArr = Encoding.Unicode.GetBytes(newStr);
                    }
                    // a Null symtype mean's were a basic type where length is the size of the raw bytes (long,int,short,byte)
                    // this should include bit's also since the caller should be expected to just clobber the bits :)
                    else if (string.IsNullOrWhiteSpace(SymType))
                    {
                        if (myDict.ContainsKey("BitPosition"))
                        {
                            var bitPos = (uint)(myDict["BitPosition"]);
                            int BitsToSet = (int)NewValue << (int)bitPos;

                            var mask = 1U;
                            for (int x = (int)TypeLength - 1; x > 0; x--)
                            {
                                mask = mask << 1;
                                mask |= 1;
                            }
                            var new_mask = mask << (int)bitPos;
                            uint inv_mask = ~mask;

                            testArr[i] = (byte)((new_mask & (BitsToSet & 0xff)) | (testArr[i] & inv_mask));
                            byteArr = new byte[1] { testArr[i] };
                        }
                        else
                        {
                            switch (TypeLength)
                            {
                                case 8:
                                    byteArr = BitConverter.GetBytes(((long)NewValue));
                                    break;
                                case 4:
                                    byteArr = BitConverter.GetBytes(((int)NewValue));
                                    break;
                                case 2:
                                    byteArr = BitConverter.GetBytes(((short)NewValue));
                                    break;
                                case 1:
                                    byteArr = new byte[] { (byte)NewValue };
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    // if were still null that mean's were likely an array type of bytes
                    // let's just hope for the best
                    if (byteArr == null)
                    {
                        if ((NewValue as byte[]) != null)
                            byteArr = NewValue as byte[];
                        else if ((NewValue as string) != null)
                            byteArr = Encoding.ASCII.GetBytes(NewValue as string);
                        else if ((NewValue as int[]) != null)
                        {
                            var intArr = NewValue as int[];
                            byteArr = new byte[intArr.Length * 4];
                            Buffer.BlockCopy(intArr, 0, byteArr, 0, byteArr.Length);
                        }
                        else if ((NewValue as long[]) != null)
                        {
                            var longArr = NewValue as long[];
                            byteArr = new byte[longArr.Length * 4];
                            Buffer.BlockCopy(longArr, 0, byteArr, 0, byteArr.Length);
                        }
                    }

                    // if not then oh well, add more native type support (LARGE_INT etc..).
                    if (byteArr == null)
                        return;

                    fsAccess.Seek(FileAddr, SeekOrigin.Begin);
                    fsAccess.Write(byteArr, 0, byteArr.Length);
                }
            }
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
            bool GotSomeData = true;
            // offset to index
            long startIndex = (VA & 0xfff) / 8;
            long count = 512 - startIndex;
            // get data
            var block = VGetBlockLong(VA, ref GotData);

            // adjust into return array 
            var rv = new long[count + 512];
            Array.Copy(block, startIndex, rv, 0, count);

            // allow for failure of second block
            VA += 4096;
            var block2 = VGetBlockLong(VA, ref GotSomeData);
            Array.Copy(block2, 0, rv, count, 512);

            return rv;
        }

        public long[] GetVirtualLong(long VA)
        {
            return GetVirtualLongLen(VA, PAGE_SIZE);
        }
        public long[] GetVirtualLongLen(long VA, int len = 4096)
        {
            long VAlign = (VA + 0xfff) & ~0xfff;
            long startIndex = VA & 0xfff;
            long FirstPageCount = VAlign - VA;
            if (VA + len < VA + FirstPageCount)
                FirstPageCount = len;

            var rv = new long[len/8];
            var block = VGetBlockLong(VA);
            if (block == null) return null;

            // align the returned buffer to start precisely at the VA requested
            Array.Copy(block, startIndex/8, rv, 0, FirstPageCount/8);
            var done = FirstPageCount;

            // if we have done more than requested quick return
            if (done >= len)
                return rv;

            // we should be aligned to a page size now
            VA += done;
            // keep going until we satisfy the amount requested
            do
            {
                var block2 = VGetBlockLong(VA);
                var copy_cnt = len - done < 4096 ? (len - done) / 8 : 512;
                Array.Copy(block2, 0, rv, done/8, copy_cnt);
                done += 512 * 8;
                VA += PAGE_SIZE;
            } while (done < len);
            return rv;
        }

        public ulong[] GetVirtualULong(ulong VA)
        {
            // offset to index
            ulong startIndex = (VA & 0xfff) / 8;
            long count = 512 - (long)startIndex;
            // get data
            var block = VGetBlockLong((long)VA);

            // adjust into return array 
            var rv = new ulong[count + 512];
            Array.Copy(block, (long)startIndex, rv, 0, count);

            VA += 4096;
            var block2 = VGetBlockLong((long)VA);
            Array.Copy(block2, 0, rv, count, 512);

            return rv;
        }


        /// <summary>
        /// This is byte aligned
        /// </summary>
        /// <param name="VA"></param>
        /// <returns></returns>
        public byte[] GetVirtualByte(long VA)
        {
            long startIndex = VA & 0xfff;
            long count = PAGE_SIZE - startIndex;
            var rv = new byte[count + PAGE_SIZE];

            var block = VGetBlock(VA);
            if (block == null)
                return rv;

            Array.Copy(block, startIndex, rv, 0, count);
            VA += PAGE_SIZE;
            var block2 = VGetBlock(VA);
            if (block2 != null)
                Array.Copy(block2, 0, rv, count, PAGE_SIZE);
            return rv;
        }

        public byte[] GetVirtualByteLen(long VA, int len = PAGE_SIZE)
        {
            long VAlign = (VA + 0xfff) & ~0xfff;
            long startIndex = VA & 0xfff;
            long FirstPageCount = VAlign - VA;
            if (VA + len < VA + FirstPageCount)
                FirstPageCount = len;

            var rv = new byte[len];

            var block = VGetBlock(VA);
            if (block == null)
                return rv;

            // align the returned buffer to start precisely at the VA requested
            Array.Copy(block, startIndex, rv, 0, FirstPageCount);
            var done = FirstPageCount;

            // if we have done more than requested quick return
            if (done >= len)
                return rv;

            // we should be aligned to a page size now
            VA += done;
            // keep going until we satisfy the amount requested
            do
            {
                var block2 = VGetBlock(VA);
                var copy_cnt = len - done < PAGE_SIZE ? (len - done) : PAGE_SIZE;
                Array.Copy(block2, 0, rv, done, copy_cnt);
                VA += PAGE_SIZE;
                done += PAGE_SIZE;
            } while (done < len);

            return rv;
        }
        #endregion

        [ProtoIgnore]
        public Mem MemAccess { get; set; }
        [ProtoIgnore]
        public string ShortName { get { if (vmcs != null) return $"{OSFileName}-eptp[{vmcs.EPTP:X}]-dtb[{CR3Value:X}]-pid[{ProcessID}]"; return $"{OSFileName}-dtb[{CR3Value:x}]-pid[{ProcessID:x}]"; } }

        public override string ToString() => $"Process PID [{ProcessID,10}] CR3 [{CR3Value,16:X12}] Path [{OSPath,50}]";    // Type [{PageTableType,12}] VMCS [{vmcs,16}]";

        public int CompareTo(object obj)
        {
            int vi = 0;
            if (obj is DetectedProc)
            {
                DetectedProc dp = obj as DetectedProc;
                if (vmcs != null || dp.vmcs != null)
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

        private bool disposedValue = false;
        public void Dispose(bool disposing)
        {
            if (!disposedValue && disposing)
            {
                if (MemAccess != null)
                    MemAccess.Dispose();
                MemAccess = null;

                if (HDB != null)
                    HDB.Dispose();
                HDB = null;

                if (vmcs != null)
                    vmcs.Dispose();
                vmcs = null;

                if (CandidateList != null)
                    foreach (var c in CandidateList)
                        c.Dispose();

                CandidateList = null;
            }

            foreach (var addr in Sections)
                DebugHelp.SymUnloadModule64(ID.GetHashCode(), (ulong)addr.Key);

            disposedValue = true;
        }
        ~DetectedProc()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }


    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class VMCS : IDisposable
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

        public void Dispose()
        {
            if(dp != null)
                ((IDisposable)dp).Dispose();
            dp = null;
        }
    }

}
