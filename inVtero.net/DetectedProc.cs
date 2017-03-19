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
        public MemSection KernelSection;


        public dynamic xStructInfo(string Struct, long Address, int minLen = 4096, string Module = "ntkrnlmp")
        {
            MemSection pdb = null;

            if (Module == "ntkrnlmp" && KernelSection != null)
                pdb = KernelSection;
            else
            {
                var pdbPaths = from files in Sections.Values
                               where files.DebugDetails != null &&
                               !string.IsNullOrWhiteSpace(files.DebugDetails.PDBFullPath) &&
                               files.DebugDetails.PDBFullPath.ToLower().Contains(Module.ToLower())
                               select files;

                pdb = pdbPaths.FirstOrDefault();
                KernelSection = pdb;
            }

            long[] memRead = null;
            if (Address != 0)
                memRead = GetVirtualLongLen(Address, minLen);

            var rv = sym.xStructInfo(pdb.DebugDetails.PDBFullPath, Struct, memRead, GetVirtualByte, GetVirtualLong);
            rv.SelfAddr = Address;

            return rv;
        }

        public dynamic xStructInfo(string Struct, long[] memRead = null, string Module = "ntkrnlmp")
        {
            MemSection pdb = null;

            if (Module == "ntkrnlmp" && KernelSection != null)
                pdb = KernelSection;
            else
            {
                var pdbPaths = from files in Sections.Values
                               where files.DebugDetails != null &&
                               !string.IsNullOrWhiteSpace(files.DebugDetails.PDBFullPath) &&
                               files.DebugDetails.PDBFullPath.ToLower().Contains(Module.ToLower())
                               select files;

                pdb = pdbPaths.FirstOrDefault();
                KernelSection = pdb;
            }
            if(sym == null)
                sym = Vtero.TryLoadSymbols(ID.GetHashCode(), pdb.DebugDetails, pdb.VA.Address);
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

        public Tuple<String, ulong, ulong>[] MatchSymbols(string Match, string Module = "ntkrnlmp")
        {
           List<Tuple<String, ulong, ulong>> rv = new List<Tuple<string, ulong, ulong>>();
            foreach (var sec in Sections)
                if (sec.Value.DebugDetails != null &&
                    !string.IsNullOrWhiteSpace(sec.Value.DebugDetails.PDBFullPath) && 
                    Path.GetFileNameWithoutExtension(sec.Value.DebugDetails.PDBFullPath).ToLower().Contains(Path.GetFileNameWithoutExtension(Module).ToLower()) || string.IsNullOrWhiteSpace(Module))
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
                sym = Vtero.TryLoadSymbols(ID.GetHashCode(), ms.DebugDetails, ms.VA.Address);
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
        public VirtualScanner ScanAndLoadModules(string OnlyModule = "ntkrnlmp.pdb", bool OnlyLarge = true, bool IncludeKernelSpace = true, bool OnlyValid = true, bool IncludeData = false, bool DoExtraHeaderScan = true)
        {
            const int LARGE_PAGE_SIZE = 1024 * 1024 * 2;
            var curr = 0;
            PageTable.AddProcess(this, new Mem(MemAccess));
            //var cnt = PT.FillPageQueue(OnlyLarge, IncludeKernelSpace);

            var KVS = new VirtualScanner(this, new Mem(MemAccess), DoExtraHeaderScan);

            // single threaded worked best so far 
            //Parallel.For(0, cnt, (i, loopState) => x
            foreach (var range in PT.FillPageQueue(OnlyLarge, IncludeKernelSpace, OnlyValid, IncludeData))
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
                            if (Vtero.VerboseLevel > 1)
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
                //    return;e
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
        List<Tuple<long, long[]>> ThreadStacks;
        List<Tuple<long, long[]>> UserThreadStacks;

        public void LoadThreads()
        {
            if (EThreadPtr == 0)
                return;

            ThreadStacks = new List<Tuple<long, long[]>>();
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
            var memRead = GetVirtualLong(etr);
            do
            {
                _ETHR_ADDR = memRead[ThreadOffsetOf / 8];
                if (_ETHR_ADDR == EThreadPtr)
                    return;

                var ID = memRead[cidOffsetOf / 8];
                var StackLimit = memRead[sbLimitOf / 8];
                var CurrentUse = memRead[CurrKerUseOffsetOf / 8];
                var len = (int)(CurrentUse - StackLimit);

                ThreadStacks.Add(Tuple.Create<long, long[]>(ID, GetVirtualLongLen(StackLimit, len)));

                // read out user space info
                var teb_tib_read = memRead[tebOffsetOf / 8];
                memRead = GetVirtualLong(teb_tib_read);

                var UserLim = memRead[userStackLimitOffsetOf / 8];
                var UserBase = memRead[userStackBaseOffsetOf / 8];
                var userLen = (int) (UserBase - UserLim);

                UserThreadStacks.Add(Tuple.Create<long, long[]>(ID, GetVirtualLongLen(UserLim, userLen)));

                memRead = GetVirtualLong(_ETHR_ADDR - ThreadOffsetOf);
            } while (_ETHR_ADDR != EThreadPtr);

            // at this point we habe ThreadStacks saved and can scan for RoP badness
            // also need to scan the TEB for TEB base/limit and add those ranges for user space roppers
        }

        public void ListVad(long AddressRoot = 0)
        {
            if (AddressRoot == 0)
                return;
            try
            {
                var memRead = GetVirtualLong(AddressRoot);
                var mmvad = xStructInfo("_MMVAD", memRead);
                long StartingVPN = 0, EndingVPN = 0;

                bool IsExec = false;
                if (mmvad.Dictionary.ContainsKey("Core"))
                {
                    if ((mmvad.Core.u.VadFlags.Protection.Value & 2) != 0)
                    {
                        IsExec = true;
                        StartingVPN = (mmvad.Core.StartingVpnHigh.Value << 32) | mmvad.Core.StartingVpn.Value;
                        EndingVPN = (mmvad.Core.EndingVpnHigh.Value << 32) | mmvad.Core.EndingVpn.Value;
                    }
                }
                else
                {
                    if ((mmvad.u.VadFlags.Protection.Value & 2) != 0)
                    {
                        IsExec = true;
                        StartingVPN = (mmvad.u.StartingVpnHigh.Value << 32) | mmvad.u.StartingVpn.Value;
                        EndingVPN = (mmvad.u.EndingVpnHigh.Value << 32) | mmvad.u.EndingVpn.Value;
                    }

                }

                long StartingAddress = StartingVPN << MagicNumbers.PAGE_SHIFT;
                long Length = (EndingVPN - StartingVPN) * MagicNumbers.PAGE_SIZE;
                if (IsExec)
                {
                    var subsect = xStructInfo("_SUBSECTION", mmvad.Subsection.Value);
                    var control_area = xStructInfo("_CONTROL_AREA", subsect.ControlArea.Value);
                    var segment = xStructInfo("_SEGMENT", control_area.Segment.Value);
                    if (control_area.FilePointer.Value != 0)
                    {
                        var file_pointer = xStructInfo("_FILE_OBJECT", control_area.FilePointer.Value & -16);
                        //print "Mapped File: " + file_pointer.FileName.Value
                        String FileName = file_pointer.FileName.Value;

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
                    }
                }
                if (mmvad.Dictionary.ContainsKey("Core"))
                {
                    ListVad(mmvad.Core.VadNode.Left.Value);
                    ListVad(mmvad.Core.VadNode.Right.Value);
                }
                else
                {
                    ListVad(mmvad.LeftChild.Value);
                    ListVad(mmvad.RightChild.Value);
                }
            } catch(Exception all)
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
            foreach(var pte in execPages)
                codeRanges.TryAdd(pte.VA.Address, pte.VA.Address + (pte.PTE.LargePage ? MagicNumbers.LARG_PAGE_SIZE : MagicNumbers.PAGE_SIZE));

            // Walk Vad and inject into 'sections'
            // scan VAD data to additionally bind 
            ListVad(VadRootPtr);

            // Dig all threads
            if (DoStackCheck)
            {
                LoadThreads();
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
                    foreach (var kernelRange in ThreadStacks)
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

                // validate checkPtrs pointers here
                // TODO: group pointers so we can minimize page reads
                foreach (var ptr in checkPtrs)
                {
                    var idx = ptr & 0xfff;
                    if (idx < 10)
                        continue;

                    // every pointer needs to be a function start
                    // or a properly call/ret pair
                    var ptrTo = VGetBlock(ptr);
                    //BYTE* bp = (BYTE*)RefFramePtr;

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
                        WriteColor(ConsoleColor.Cyan, $"Stack pointer is wild {ptr:x}");
                        var cs = Capstone.Dissassemble(ptrTo, ptrTo.Length, (ulong) (ptr & -4096));
                        for(int i=0; i < cs.Length; i++)
                        {
                            if(cs[i].insn.address == (ulong) ptr)
                            {
                                WriteColor(ConsoleColor.Yellow, $"{cs[i - 1].insn.address:x} {cs[i - 1].insn.bytes[0]:x} {cs[i - 1].insn.mnemonic} {cs[i - 1].insn.operands}");
                                WriteColor(ConsoleColor.Yellow, $"{cs[i].insn.address:x} {cs[i].insn.bytes[0]:x} {cs[i].insn.mnemonic} {cs[i].insn.operands}");
                            }
                        }




                    }
                }
            }

            // find section's with no "Module"
            foreach (var sec in Sections.Values)
            {
                if(sec.Module == null)
                {
                    var test = GetVirtualByte(sec.VadAddr);
                    var ext = Extract.IsBlockaPE(test);
                    sec.Module = ext;
                }
            }

        }


        public void DumpProc(string Folder, bool IncludeData = false, bool KernelSpace = true, bool OnlyExec = true)
        {
            //// TODO: BOILER PLATE check perf of using callbacks 
            PageTable.AddProcess(this, new Mem(MemAccess));
            var cnt = PT.FillPageQueue(false, KernelSpace);

            Folder = Folder + Path.DirectorySeparatorChar.ToString();
            Directory.CreateDirectory(Folder);

            long ContigSizeState = 0, curr = 0;
            // single threaded worked best so far 
            //Parallel.For(0, cnt, (i, loopState) => x
            foreach (var range in PT.FillPageQueue(false, KernelSpace))
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
            var cv2 = new CODEVIEW_HEADER { VSize = (int)Ext.SizeOfImage, TimeDateStamp = TimeDate2, byteGuid = bytes2, Age = age2, aGuid = gid2, Sig = s2, PdbName = str2 };
            if (str2.Contains(".") && str2.Contains(".pdb"))
                sec.Name = str2.Substring(0, str2.IndexOf(".pdb") + 4).ToLower();
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
            if (done >= len)
                return rv;

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
            long count = 512 - (long)startIndex;
            // get data
            var block = VGetBlockLong((long)VA);

            // adjust into return array 
            var rv = new long[count + 512];
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
            if (block2 != null)
                Array.Copy(block2, 0, rv, count, 4096);
            return rv;
        }
        #endregion

        [ProtoIgnore]
        public Mem MemAccess { get; set; }
        [ProtoIgnore]
        public string ShortName { get { if (vmcs != null) return $"{vmcs.EPTP:X}-{CR3Value:X}"; return $"{CR3Value:X}"; } }

        public override string ToString() => $"Process CR3 [{CR3Value:X12}] Path [{OSPath}] True Offset [{TrueOffset:X12}] Diff [{Diff:X12}] Type [{PageTableType}] VMCS [{vmcs}]";

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

        public void Dispose()
        {
            foreach (var addr in Sections)
                DebugHelp.SymUnloadModule64(ID.GetHashCode(), (ulong)addr.Key);
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
