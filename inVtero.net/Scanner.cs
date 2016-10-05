// Shane.Macaulay @IOActive.com Copyright (C) 2013-2015

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

using inVtero.net.Support;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static inVtero.net.UnsafeHelp;
using static System.Console;
using ProtoBuf;
using static inVtero.net.Misc;

namespace inVtero.net
{
    /// <summary>
    /// Scanner is the initial entry point into inVtero, the most basic and primary functionality
    /// 
    /// Scanner is a file based scanning class
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class Scanner
    {
        // for diagnostic printf's
        int MAX_LINE_WIDTH = Console.WindowWidth;

        // using bag since it has the same collection interface as List
        [ProtoIgnore]
        public ConcurrentDictionary<long, DetectedProc> DetectedProcesses;
        [ProtoIgnore]
        public DetectedProc[] ScanForVMCSset;

        [ProtoIgnore]
        public uint HexScanDword;
        [ProtoIgnore]
        public ulong HexScanUlong;
        [ProtoIgnore]
        public bool Scan64;
        [ProtoIgnore]
        public List<long> FoundValueOffsets;

        #region class instance variables
        public string Filename;
        public long FileSize;
        [ProtoIgnore]
        public ConcurrentBag<VMCS> HVLayer;
        public bool DumpVMCSPage;

        List<MemoryRun> Gaps;
        [ProtoIgnore]
        List<Func<long, bool>> CheckMethods;
        PTType scanMode;
        public PTType ScanMode
        {
            get { return scanMode; }
            set
            {
                scanMode = value;

                CheckMethods.Clear();

                if ((value & PTType.GENERIC) == PTType.GENERIC)
                    CheckMethods.Add(Generic);

                if ((value & PTType.Windows) == PTType.Windows)
                    CheckMethods.Add(Windows);

                if ((value & PTType.HyperV) == PTType.HyperV)
                    CheckMethods.Add(HV);

                if ((value & PTType.FreeBSD) == PTType.FreeBSD)
                    CheckMethods.Add(FreeBSD);

                if ((value & PTType.OpenBSD) == PTType.OpenBSD)
                    CheckMethods.Add(OpenBSD);

                if ((value & PTType.NetBSD) == PTType.NetBSD)
                    CheckMethods.Add(NetBSD);

#if TESTING
                if ((value & PTType.VALUE) == PTType.VALUE)
                    CheckMethods = null;
#endif

                if ((value & PTType.LinuxS) == PTType.LinuxS)
                    CheckMethods.Add(LinuxS);

                if ((value & PTType.VMCS) == PTType.VMCS)
                    CheckMethods.Add(VMCS);
            }
        }

#endregion

        Scanner()
        {
            DetectedProcesses = new ConcurrentDictionary<long, DetectedProc>();
            HVLayer = new ConcurrentBag<VMCS>();
            FileSize = 0;
            Gaps = new List<MemoryRun>();
            CheckMethods = new List<Func<long, bool>>();
            FoundValueOffsets = new List<long>();
        }

        public Scanner(string InputFile) : this()
        {
            Filename = InputFile;
        }

        public bool HexScan(long offset, long[] ValueBlock, int ValueReadCount)
        {
            if (Scan64)
                for (int i = 0; i < ValueReadCount; i++)
                {
                    if ((ulong)ValueBlock[i] == HexScanUlong)
                    {
                        long xoff = offset + (i * 8);
                        WriteColor($"Found Hex data @{offset} + {i * 8}");
                        FoundValueOffsets.Add(xoff);
                        return true;
                    }
                }
            else
                for (int i = 0; i < ValueReadCount; i++)
                {
                    if ((uint)(ValueBlock[i] & 0xffffffff) == HexScanDword)
                    {
                        long xoff = offset + (i * 8);

                        WriteColor($"Found Hex ({HexScanDword:x8}) data OFFSET {offset:X16} + {(i * 8):X} @{(offset + (i * 8)):X} i={i}");
                        WriteColor($"{ValueBlock[i]:X16} : {ValueBlock[i + 1]:X16} : {ValueBlock[i + 2]:X16} : {ValueBlock[i + 3]:X16}");
                        WriteColor($"{ValueBlock[i + 4]:X16} : {ValueBlock[i + 5]:X16} : {ValueBlock[i + 6]:X16} : {ValueBlock[i + 7]:X16}");
                        FoundValueOffsets.Add(xoff);
                        return true;
                    }
                    else if ((uint)(ValueBlock[i] >> 32) == HexScanDword)
                    {
                        long xoff = offset + (i * 8) + 4;
                        WriteColor($"Found Hex ({HexScanDword:x8}) data OFFSET {offset:X16} + {(i * 8):X} @{(offset + (i * 8)):X}");
                        WriteColor($"{ValueBlock[i]:X16} : {ValueBlock[i + 1]:X16} : {ValueBlock[i + 2]:X16} : {ValueBlock[i + 3]:X16}");
                        WriteColor($"{ValueBlock[i + 4]:X16} : {ValueBlock[i + 5]:X16} : {ValueBlock[i + 6]:X16} : {ValueBlock[i + 7]:X16}");
                        FoundValueOffsets.Add(xoff);
                        return true;
                    }
                }
            return false;
        }


        /// <summary>
        /// The VMCS scan is based on the LINK pointer, abort code and CR3 register
        /// We  later isolate the EPTP based on constraints for that pointer
        /// </summary>
        /// <param name="xoffset"></param>
        /// <returns>true if the page being scanned is a candidate</returns>
        public bool VMCS(long xoffset)
        {
            var RevID = (REVISION_ID)(block[0] & 0xffffffff);
            var Acode = (VMCS_ABORT)((block[0] >> 32) & 0x7fffffff);

            var KnownAbortCode = false;
            var KnownRevision = false;
            var Candidate = false;
            var LinkCount = 0;
            var Neg1 = -1;

            if (ScanForVMCSset == null)
                throw new NullReferenceException("Entered VMCS callback w/o having found any VMCS, this is a second pass Func");

            // this might be a bit micro-opt-pointless ;)
            //Parallel.Invoke(() =>
            //{
            KnownRevision = typeof(REVISION_ID).GetEnumValues().Cast<REVISION_ID>().Any(x => x == RevID);
            //}, () =>
            //{
            KnownAbortCode = typeof(VMCS_ABORT).GetEnumValues().Cast<VMCS_ABORT>().Any(x => x == Acode);
            //});

            // TODO: Link pointer may not always be needed, evaluate removing this constraint
            // Find a 64bit value for link ptr
            for (int l = 0; l < block.Length; l++)
            {
                if (block[l] == Neg1)
                    LinkCount++;

                // too many
                if (LinkCount > 32)
                    return false;
            }
            // Currently, we expect to have 1 Link pointer at least
            if (LinkCount == 0 || !KnownAbortCode)
                return false;

            // curr width of line to screen
            Candidate = false;
            Parallel.For(0, ScanForVMCSset.Length, (v) =>
            {
                var ScanFor = ScanForVMCSset[v];

                for (int check = 1; check < block.Length; check++)
                {
                    if (block[check] == ScanFor.CR3Value && Candidate == false)
                    {
                        var OutputList = new List<long>();
                        StringBuilder sb = null, sbRED = null;
                        byte[] shorted = null;
                        var curr_width = 0;

                        if (Vtero.VerboseOutput)
                        {
                            sb = new StringBuilder();
                            // reverse endianness for easy reading in hex dumps/editors
                            shorted = BitConverter.GetBytes(block[check]);
                            Array.Reverse(shorted, 0, 8);
                            var Converted = BitConverter.ToUInt64(shorted, 0);

                            sbRED = new StringBuilder();
                            sbRED.Append($"Hypervisor: VMCS revision field: {RevID} [{((uint)RevID):X8}] abort indicator: {Acode} [{((int)Acode):X8}]{Environment.NewLine}");
                            sbRED.Append($"Hypervisor: {ScanFor.PageTableType} CR3 found [{ScanFor.CR3Value:X16})] byte-swapped: [{Converted:X16}] @ PAGE/File Offset = [{xoffset:X16}]");
                        }

                        for (int i = 0; i < block.Length; i++)
                        {
                            var value = block[i];

                            var eptp = new EPTP(value);

                            // any good minimum size? 64kb?
                            if (block[i] > 0
                            && block[i] < FileSize
                            && eptp.IsFullyValidated()
                   //         && EPTP.IsValid(eptp.aEPTP) && EPTP.IsValid2(eptp.aEPTP) && EPTP.IsValidEntry(eptp.aEPTP)
                            && !OutputList.Contains(block[i]))
                            {
                                Candidate = true;
                                OutputList.Add(block[i]);

                                if (Vtero.VerboseOutput)
                                {
                                    var linefrag = $"[{i}][{block[i]:X16}] ";

                                    if (curr_width + linefrag.Length > MAX_LINE_WIDTH)
                                    {
                                        sb.Append(Environment.NewLine);
                                        curr_width = 0;
                                    }
                                    sb.Append(linefrag);
                                    curr_width += linefrag.Length;
                                }

                            }
                        }
                        if (Candidate && Vtero.VerboseOutput)
                        {
                            WColor(ConsoleColor.Red, ConsoleColor.Black, sbRED.ToString().PadRight(WindowWidth));
                            WColor(ConsoleColor.DarkGreen, ConsoleColor.Black, sb.ToString().PadRight(WindowWidth));
                        }

                        // most VMWare I've scanned comes are using this layout
                        // we know VMWare well so ignore any other potential candidates // TODO: Constantly Verify assumption's 
                        if (RevID == REVISION_ID.VMWARE_NESTED && OutputList.Contains(block[14]))
                        {
                            var vmcsFound = new VMCS { dp = ScanFor, EPTP = block[14], gCR3 = ScanFor.CR3Value, Offset = xoffset };
                            HVLayer.Add(vmcsFound);
                        }
                        else
                            foreach (var entry in OutputList)
                                HVLayer.Add(new VMCS { dp = ScanFor, EPTP = entry, gCR3 = ScanFor.CR3Value, Offset = xoffset });
                    }
                }
            });
            return Candidate;
        }

        long[] LinuxSFirstPage;
        List<long[]> LinuxSFirstPages = new List<long[]>();

        /// <summary>
        /// The LinuxS check is a single pass state preserving scanner
        /// 
        /// This was created using kernel 3.19 as a baseline.  More to follow.
        /// 
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool LinuxS(long offset)
        {
            var Candidate = false;
            var group = -1;

            // The main observation on kern319 is the given set below of must-have offsets that are identical and 0x7f8 which is unique per process
            // Next is the behavior that uses entries in 2 directions from top down and bottom up 
            // i.e. 0x7f0 0x0 are the next expected values.
            // All others would be unset in the top level / base page
            //
            // Kernel should have only the magnificent entries
            // memcmp 0 ranges 8-7f0, 800-880, 888-c88, c98-e88, e90-ea0, ea8-ff0
            // after first (likely kernel) page table found, use it's lower 1/2 to validate other detected page tables
            // Linux was found (so far) to have a consistent kernel view.
            var kern319 = new Dictionary<int, bool> { [0x7f8] = false, [0x880] = true, [0xc90] = true, [0xe88] = true, [0xea0] = true, [0xff0] = true, [0xff8] = true };

            var Profiles = new List<Dictionary<int, bool>>();

            if (((block[0xFF] & 0xfff) == 0x067) &&
               ((block[0x110] & 0xfff) == 0x067) &&
               ((block[0x192] & 0xfff) == 0x067) &&
               ((block[0x1d1] & 0xfff) == 0x067) &&
               ((block[0x1d4] & 0xfff) == 0x067) &&
               ((block[0x1fe] & 0xfff) == 0x067) &&
               ((block[0x1ff] & 0xfff) == 0x067) 

               // this is the largest block of 0's 
               // just do this one to qualify
               //IsZero(block, 8, 0xe0)
               )

            if (
                    /*IsZero(block, 8,     0xE0) &&
                IsZero(block, 0x100, 0x10) &&*/
                IsZero(block, 0x111, 0x80) &&
                IsZero(block, 0x193, 0x3e) &&
                IsZero(block, 0x1D2, 0x02) &&
                IsZero(block, 0x1D5, 0x29))
            {
                // before we catalog this entry, check to see if we can put it in a group
                for (int i = 0; i < LinuxSFirstPages.Count(); i++)
                    if (EqualBytesLongUnrolled(block, LinuxSFirstPages[i], 0x100))
                        group = i;

                // if we haven't found anything yet, setup first page
                if (LinuxSFirstPage == null)
                {
                    LinuxSFirstPage = block;
                    LinuxSFirstPages.Add(block);
                    group = 0;
                }

                // load DP 
                var dp = new DetectedProc { CR3Value = offset, FileOffset = offset, Diff = 0, Mode = 2, Group = group, PageTableType = PTType.LinuxS };
                for (int p = 0; p < 0x200; p++)
                    if (block[p] != 0)
                        dp.TopPageTablePage.Add(p, block[p]);

                if (Vtero.VerboseOutput)
                    WriteColor(ConsoleColor.Cyan, dp.ToString());

                DetectedProcesses.TryAdd(offset, dp);
                Candidate = true;
            }
            return Candidate;
        }

        /// <summary>
        /// TODO: NetBSD needs some analysis
        /// Will add more later, this check is a bit noisy, consider it alpha
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool NetBSD(long offset)
        {
            var Candidate = false;

            //var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[255] & 0xFFFFFFFFF000);
            var diff = offset - shifted;


            if (((block[511] & 0xf3) == 0x63) && ((0x63 == (block[320] & 0xf3)) || (0x63 == (block[256] & 0xf3))))
            {
                if (((block[255] & 0xf3) == 0x63) && (0 == (block[255] & 0x7FFF000000000000)))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.NetBSD };
                        for (int p = 0; p < 0x200; p++)
                        {
                            if (block[p] != 0)
                                dp.TopPageTablePage.Add(p, block[p]);
                        }

                        DetectedProcesses.TryAdd(offset, dp);
                        if (Vtero.VerboseOutput)
                            WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, dp.ToString());
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }

        /*   OpenBSD /src/sys/arch/amd64/include/pmap.h
#define L4_SLOT_PTE		255
#define L4_SLOT_KERN		256
#define L4_SLOT_KERNBASE	511
#define L4_SLOT_DIRECT		510
        */
        /// <summary>
        /// Slightly better check then NetBSD so I guess consider it beta!
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool OpenBSD(long offset)
        {
            var Candidate = false;

            //var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[255] & 0xFFFFFFFFF000);
            var diff = offset - shifted;

            if (((block[510] & 0xf3) == 0x63) && (0x63 == (block[256] & 0xf3)) && (0x63 == (block[254] & 0xf3)))
            {
                if (((block[255] & 0xf3) == 0x63) && (0 == (block[255] & 0x7FFF000000000000)))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.OpenBSD };
                        for (int p = 0; p < 0x200; p++)
                        {
                            if (block[p] != 0)
                                dp.TopPageTablePage.Add(p, block[p]);
                        }

                        DetectedProcesses.TryAdd(offset, dp);
                        if (Vtero.VerboseOutput)
                            WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, dp.ToString());
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }

        /// <summary>
        /// The FreeBSD check for process detection is good
        /// Consider it release quality ;) 
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool FreeBSD(long offset)
        {
            var Candidate = false;

            //var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[0x100] & 0xFFFFFFFFF000);
            var diff = offset - shifted;

            if (((block[0] & 0xff) == 0x67) && (0x67 == (block[0xff] & 0xff)))
            {
                if (((block[0x100] & 0xff) == 0x63) && (0 == (block[0x100] & 0x7FFF000000000000)))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.FreeBSD };
                        for (int p = 0; p < 0x200; p++)
                        {
                            if (block[p] != 0)
                                dp.TopPageTablePage.Add(p, block[p]);
                        }

                        DetectedProcesses.TryAdd(offset, dp);
                        if (Vtero.VerboseOutput)
                            WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, dp.ToString());
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }
        /// <summary>
        /// Naturally the Generic checker is fairly chatty but at least you can use it
        /// to find unknowns, we could use some more tunable values here to help select the
        /// best match, I currently use the value with the lowest diff, which can be correct
        /// 
        /// This will find a self pointer in the first memory run for a non-sparse memory dump.
        /// After you locate the kernel in this first range, determine the memory run topology,
        /// and then you can extract/identify the remaining entries.
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool Generic(long offset)
        {
            var Candidate = false;
            //var offset = CurrWindowBase + CurrMapBase;
            long bestShift = long.MaxValue, bestDiff = long.MaxValue;
            var bestOffset = long.MaxValue;
            var i = 0x1ff;

            if (((block[0] & 0xff) == 0x63) || (block[0] & 0xfdf) == 0x847)
            {
                do
                {
                    if (((block[i] & 0xff) == 0x63 || (block[i] & 0xff) == 0x67))
                    {
                        // we disqualify entries that have these bits configured
                        // 111 1111 1111 1111 0000 0000 0000 0000 0000 0000 0000 0000 0000 0100 1000 0000
                        // 
                        if ((block[i] & 0x7FFF000000000480) == 0)
                        {
                            var shifted = (block[i] & 0xFFFFFFFFF000);

                            if (shifted != 0 && shifted < FileSize)
                            {
                                var diff = offset - shifted;

                                if (diff < bestDiff)
                                {
                                    bestShift = shifted;
                                    bestDiff = diff;
                                    bestOffset = offset;
                                }

                                var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.GENERIC };

                                // BUGBUG: Need to K-Means this or something cluster values to help detection of processes in sparse format
                                // this could be better 
                                if (shifted == offset)
                                {
                                    for (int p = 0; p < 0x200; p++)
                                    {
                                        if (block[p] != 0)
                                            dp.TopPageTablePage.Add(p, block[p]);
                                    }

                                    DetectedProcesses.TryAdd(offset, dp);
                                    if (Vtero.VerboseOutput)
                                        WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, dp.ToString());
                                    Candidate = true;
                                }
                            }
                        }
                    }
                    i--;
                } while (i > 0xFF && !Candidate);
            }
            // maybe some kernels keep more than 1/2 system memory 
            // wouldn't that be a bit greedy though!?
            return Candidate;
        }

        /// <summary>
        /// In some deployments Hyper-V was found to use a configuration as such
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool HV(long offset)
        {
            var Candidate = false;

            //var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[0x1fe] & 0xFFFFFFFFF000);
            var diff = offset - shifted;

            // detect mode 2, 2 seems good for most purposes and is more portable
            // maybe 0x3 is sufficient
            if (shifted != 0 && ((block[0] & 0xfff) == 0x063) && ((block[0x1fe] & 0xff) == 0x63 || (block[0x1fe] & 0xff) == 0x67) && block[0x1ff] == 0)
            {
                // we disqualify entries that have these bits configured
                // 111 1111 1111 1111 0000 0000 0000 0000 0000 0000 0000 0000 0000 0100 1000 0000
                // 
                if (((ulong)block[0x1fe] & 0xFFFF000000000480) == 0)
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.HyperV };
                        for (int p = 0; p < 0x200; p++)
                        {
                            if (block[p] != 0)
                                dp.TopPageTablePage.Add(p, block[p]);
                        }

                        DetectedProcesses.TryAdd(offset, dp);
                        if (Vtero.VerboseOutput)
                            WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, dp.ToString());
                        Candidate = true;
                    }
                }
            }
            return Candidate;
        }

        /// <summary>
        /// This is the same check as the earlier process detection code from CSW and DefCon
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public bool Windows(long offset)
        {
            var Candidate = false;

            // pre randomized kernel 10.16 anniversario edition
            const int SELF_PTR = 0x1ed;

            //var offset = CurrWindowBase + CurrMapBase;
            var shifted = (block[SELF_PTR] & 0xFFFFFFFFF000);
            var diff = offset - shifted;

            // detect mode 2, 2 seems good for most purposes and is more portable
            // maybe 0x3 is sufficient
            if (((block[0] & 0xfdf) == 0x847) && ((block[SELF_PTR] & 0xff) == 0x63 || (block[SELF_PTR] & 0xff) == 0x67))
            {
                // we disqualify entries that have these bits configured
                //111 1111 1111 1111 0000 0000 0000 0000 0000 0000 0000 0000 0000 0100 1000 0000
                if ((block[0x1ed] & 0x7FFF000000000480) == 0)
                {
#if MODE_1
                    if (!SetDiff)
                    {
                        FirstDiff = diff;
                        SetDiff = true;
                    }
#endif
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 2, PageTableType = PTType.Windows };
                        for (int p = 0; p < 0x200; p++)
                        {
                            if (block[p] != 0)
                                dp.TopPageTablePage.Add(p, block[p]);
                        }

                        DetectedProcesses.TryAdd(offset, dp);
                        if (Vtero.VerboseOutput)
                            WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, dp.ToString());
                        Candidate = true;
                    }
                }
            }
            // mode 1 is implemented to hit on very few supported bits
            // developing a version close to this that will work for Linux
#region MODE 1 IS PRETTY LOOSE
#if MODE_1
            else
                /// detect MODE 1, we can probably get away with even just testing & 1, the valid bit
                //if (((block[0] & 3) == 3) && (block[0x1ed] & 3) == 3)		
                if ((block[0] & 1) == 1 && (block[0xf68 / 8] & 1) == 1)
            {
                // a possible kernel first PFN? should look somewhat valid... 
                if (!SetDiff)
                {
                    // I guess we could be attacked here too, the system kernel could be modified/hooked/bootkit enough 
                    // we'll see if we need to analyze this in the long run
                    // the idea of mode 1 is a very low bit-scan, but we also do not want to mess up FirstDiff
                    // these root entries are valid for all win64's for PTE/hyper/session space etc.
                    if ((block[0xf78 / 8] & 1) == 1 && (block[0xf80 / 8] & 1) == 1 && (block[0xff8 / 8] & 1) == 1 && (block[0xff0 / 8] == 0))
                    {
                        // W/O this we may see some false positives 
                        // however can remove if you feel aggressive
                        if (diff < FileSize && (offset > shifted ? (diff + shifted == offset) : (diff + offset == shifted)))
                        {
                            FirstDiff = diff;
                            SetDiff = true;
                        }
                    }
                }

                if (SetDiff &&
                    !(FirstDiff != diff) &&
                     (shifted < (FileSize + diff)
                     //|| shifted != 0
                     ))
                {
                    if (!DetectedProcesses.ContainsKey(offset))
                    {
                        var dp = new DetectedProc { CR3Value = shifted, FileOffset = offset, Diff = diff, Mode = 1, PageTableType = PTType.Windows };

                        DetectedProcesses.TryAdd(offset, dp);
                        WriteColor(dp);

                        Candidate = true;
                    }
                }
            }
#endif
#endregion
            return Candidate;
        }

        // scanner related
        //static long offset;
        static long CurrMapBase;
        static long CurrWindowBase;
        static long mapSize = (64 * 1024 * 1024);
        static long[] block = new long[512];
        static long[][] buffers = { new long[512], new long[512] };
        static int filled = 0;

        /// <summary>
        /// A simple memory mapped scan over the input provided in the constructor
        /// </summary>
        /// <param name="ExitAfter">Optionally stop checking or exit early after this many candidates.  0 does not exit early.</param>
        /// <returns></returns>
        public int Analyze(int ExitAfter = 0)
        {
            CurrWindowBase = 0;
            mapSize = (64 * 1024 * 1024);

            if (File.Exists(Filename))
            {
                using (var fs = new FileStream(Filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var mapName = Path.GetFileNameWithoutExtension(Filename) + DateTime.Now.ToBinary().ToString("X16");
                    using (var mmap =
                        MemoryMappedFile.CreateFromFile(fs,
                        mapName,
                        0,
                        MemoryMappedFileAccess.Read,
                        null,
                        HandleInheritability.Inheritable,
                        false))
                    {
                        if (FileSize == 0)
                            FileSize = new FileInfo(Filename).Length;

                        while (CurrWindowBase < FileSize)
                        {
                            using (var reader = mmap.CreateViewAccessor(CurrWindowBase, mapSize, MemoryMappedFileAccess.Read))
                            {
                                CurrMapBase = 0;
                                reader.ReadArray(CurrMapBase, buffers[filled], 0, 512);

                                while (CurrMapBase < mapSize)
                                {
                                    var offset = CurrWindowBase + CurrMapBase;

                                    // next page, may be faster with larger chunks but it's simple to view 1 page at a time
                                    CurrMapBase += 4096;

                                    block = buffers[filled];
                                    filled ^= 1;

#pragma warning disable HeapAnalyzerImplicitParamsRule // Array allocation for params parameter
                                    Parallel.Invoke(() =>
                                    Parallel.ForEach<Func<long, bool>>(CheckMethods, (check) =>
                                    {

                                        check(offset);

                                    }), () =>
                                    {
                                        if (CurrMapBase < mapSize)
                                            UnsafeHelp.ReadBytes(reader, CurrMapBase, ref buffers[filled]);
                                    }
                                    );
                                    if (ExitAfter > 0 && (ExitAfter == DetectedProcesses.Count() || FoundValueOffsets.Count() >= ExitAfter))
                                        return DetectedProcesses.Count();

                                    var progress = Convert.ToInt32((Convert.ToDouble(CurrWindowBase) / Convert.ToDouble(FileSize) * 100.0) + 0.5);
                                    if (progress != ProgressBarz.Progress)
                                        ProgressBarz.RenderConsoleProgress(progress);
                                }
                            } // close current window

                            CurrWindowBase += CurrMapBase;

                            if (CurrWindowBase + mapSize > FileSize)
                                mapSize = FileSize - CurrWindowBase;
                        }
                    }
                } // close map
            } // close stream
            return DetectedProcesses.Count();
        }

        static IEnumerable<long> MapScanFile(String File, long From, int ScanData, int Count)
        {
            List<long> rv = new List<long>();

            // TODO: These streams should be persistent across these calls right?
            // TODO: This path is only 1 time and pretty infrequent so far though 
            using (var fs = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var mapName = Path.GetFileNameWithoutExtension(File) + From.ToString("X16");
                using (var mmap =
                    MemoryMappedFile.CreateFromFile(fs, mapName, 0, MemoryMappedFileAccess.Read,
                    null, HandleInheritability.Inheritable, false))
                {
                    using (var reader = mmap.CreateViewAccessor(From, Count * 4, MemoryMappedFileAccess.Read))
                    {
                        var LocatedScanTarget = UnsafeHelp.ScanBytes(reader, ScanData, Count);
                        if (LocatedScanTarget.Count() > 0)
                        {
                            foreach (var ioff in LocatedScanTarget)
                            {
                                var target = From + ioff;

                                //WriteColor($"Found input @ {(target):X}");
                                rv.Add(target);
                                yield return target;
                            }
                        }
                    }

                }
            }
            yield break;
        }


        public IEnumerable<long> BackwardsValueScan(int ExitAfter = 0)
        {
            if (FileSize == 0)
                FileSize = new FileInfo(Filename).Length;

            // each processor will ValueReadCount
            long ReadSize = 1024 * 1024 * 8;
            var ValueReadCount = (int)ReadSize / 4;
            var RevMapSize = ReadSize;

            var ShortFirstChunkSize = (int)(FileSize & (ReadSize - 1));
            var ShortFirstChunkBase = FileSize - ShortFirstChunkSize;

            if (ShortFirstChunkSize != 0)
            {
                var found = MapScanFile(Filename, ShortFirstChunkBase, (int)HexScanDword, ShortFirstChunkSize / 4);
                foreach (var offset in found)
                    yield return offset;
            }

            var RevCurrWindowBase = FileSize - ShortFirstChunkSize;

            RevCurrWindowBase -= RevMapSize;
            var ChunkCount = (FileSize / RevMapSize) + 1;

            bool StopRunning = false;

            long localOffset = ShortFirstChunkBase - ReadSize;

            for (long i = ChunkCount; i > 0; i--)
            {
                // testing if to For.Parallel this inner loop
                //for (int j = 0; j < Environment.ProcessorCount; j++)
                //{


                if (!StopRunning)
                {

                    if(Vtero.VerboseLevel > 1)
                        WriteColor($"Scanning From {localOffset:X} To {(localOffset + ReadSize):X} bytes");

                    var results = MapScanFile(Filename, localOffset, (int)HexScanDword, ValueReadCount);

                    foreach (var offset in results)
                        yield return offset;

                    if (ExitAfter > 0 && FoundValueOffsets.Count() >= ExitAfter)
                        StopRunning = true;

                    CurrWindowBase += (1 * ReadSize);
                    var progress = Convert.ToInt32((Convert.ToDouble(CurrWindowBase) / Convert.ToDouble(FileSize) * 100.0) + 0.5);
                    if (progress != ProgressBarz.Progress)
                        ProgressBarz.RenderConsoleProgress(progress);

                    //}

                    localOffset -= RevMapSize;
                    if (localOffset < 0 && !StopRunning)
                    {
                        localOffset = 0;
                        StopRunning = true;

                    }
                }
            }
            //}
            yield break;
        }

    }
}
