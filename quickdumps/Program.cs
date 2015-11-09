// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// Shane.Macaulay@IOActive.com (c) copyright 2014,2015 all rights reserved. GNU GPL License
//  
// Version 2.1-Post-RuxCon-DefCon-CanSecWest! thanks conferences for allowing people to do something not related to dayjobs!!!
//  + Fixed few bugs after the conference's
//  + Works as VMI insteads of single OS process detection
//  + Easier to use & find EPTP
//  + Ported to BSD families -- in terms of functional fbsd/obsd/nbsd (i.e. nbsd is a bit cranky, need to work on that one ;)
//  + Parallized some of the operation if your runtime is concurrent (serial versions still around for lame runtimes)
//  + CR3 dumping
// 
//  TODO:   * PERF!
//              - memory mapper should improve with windowing larger sizes (basic single page maps currently)
//              - pre-cache full tables in one shot (don't traverse V2gP2hV every time, 24 read's per load)
//              - testing against other tools (ensure dump is accurate & best performing ;)
//          
//          * BlockWatch server intergration - Eliminate gaps in your memory forensic process. 
//              - Isolate known code from unknown/untrusted code in memory. e.g. 99%+ of resident code can be securely identified (based on cryptographic secure hashes 192bit+)
//              - (If your not verifying the code in your memory dumps, you really don't know what's in them do you? -- that string that say's ntdll.dll cant lie right!! :)
//              - Delocate memory based on hosted .reloc files (don't you want to memory dumps that match disk files?!?!)
//              - Match dumped binaries to known secure hashes (who want's to dissassemble/analyze ntdll when you dont have too!)
//              
//          * Test/Support open .net runtimes Rosylin and such on other platforms
//              - Now that WCF is open, it's a sinch to connect to our web services
//             
//
using inVtero.net;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace quickdumps
{
    // demo of inVtero !!!
    public class Pogram
    {
        static Stopwatch Timer;
        static ConsoleColor Backg, Foreg;

        public static void Main(string[] args)
        {
            var Checkers = new List<Func<bool>>();

            #region fluff

            var Version = PTType.UNCONFIGURED;
            string Filename = null;

            if (args.Length == 0 || args.Length > 2)
            {
                Console.WriteLine("inVtero FileName [win|fbsd|obsd|nbsd|!]");
                Console.WriteLine("\"inVtero FileName winfbsd\"  (e.g. Run FreeBSD and Windows together)");
                return;
            }

            Filename = args[0];
            var detect = new Scanner(Filename);

            if (args.Length > 1)
            {
                var spec = args[1].ToLower();

                if (spec.Contains("win"))
                    Version |= PTType.Windows;
                if (spec.Contains("fbsd"))
                    Version |= PTType.FreeBSD;
                if (spec.Contains("obsd"))
                    Version |= PTType.OpenBSD;
                if (spec.Contains("nbsd"))
                    Version |= PTType.NetBSD;
                if (spec.Contains("!"))
                    Version |= PTType.ALL;
            }
            else
                Version = PTType.ALL;

            Backg = Console.BackgroundColor;
            Foreg = Console.ForegroundColor;
            Console.CancelKeyPress += Console_CancelKeyPress;
            AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.BackgroundColor = ConsoleColor.White;

            if ((Version & PTType.Windows) == PTType.Windows)
                Checkers.Add(detect.Windows);

            if ((Version & PTType.FreeBSD) == PTType.FreeBSD)
                Checkers.Add(detect.FreeBSD);

            if ((Version & PTType.OpenBSD) == PTType.OpenBSD)
                Checkers.Add(detect.OpenBSD);

            if ((Version & PTType.NetBSD) == PTType.NetBSD)
                Checkers.Add(detect.NetBSD);
            #endregion
            // basic perf checking
            Timer = Stopwatch.StartNew();

            var procCount = detect.Analyze(Checkers);

            #region page table/CR3 progress report

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.BackgroundColor = ConsoleColor.Yellow;
            Console.Write($"{procCount} candiate process page tables. Time so far: {Timer.Elapsed}");
            PrintRate((ulong)detect.FileSize, Timer.Elapsed);

            if (procCount < 3)
            {
                Console.WriteLine("Seems like a fail.  See if this is Linux or something that a different detection technique is needed? :(");
                return;
            }
            Console.BackgroundColor = ConsoleColor.White;
            #endregion

#if Host_Get_Proc_Mem
            var addr = (ulong)0x402000;
            bool pass = false;
            // TEST: find fbsd process space
            foreach (var pi in detect.DetectedProcesses)
            {
                if (pi.Value.PageTableType != PTType.FreeBSD)
                    continue;

                using (var memAxs = new Mem(Filename))
                {
                    var page = memAxs.GetVirtualPage<ulong>(pi.Value.CR3Value, addr, ref pass);
                    if (pass && page != null)
                    {
                        for(int j=0; j < 6; j++)
                        {
                            Console.WriteLine($"{page[j]:X16} ");
                        }
                    }


                    
                }
            }
#endif

#region blighering
            // second pass
            // with the page tables we aquired, locate candidate VMCS pages in the format
            // [31-bit revision id][abort indicator]
            // the page must also have at least 1 64bit value which is all set (-1)
            // Root-HOST CR3 will have uniform diff
            // unless an extent based dump image is input, some .DMP variations
            // TODO: Add support for extent based inputs
            // Guest VMCS will contain host CR3 & guest CR3 (hCR3 & gCR3)
            // sometimes CR3 will be found in multiple page tables, e.g. system process or SMP 
            // if I have more than 1 CR3 from different file_offset, just trim them out for now
            // future may have a reason to isolate based on original location
#endregion

            Checkers.Clear();
            Checkers.Add(detect.VMCS);
#if Serial
            detect.VMCSScanSet = (from dp in detect.DetectedProcesses.Values
                                  group dp by dp.CR3Value into CR3Masters
                                  select new KeyValuePair<ulong, DetectedProc>(CR3Masters.Key, CR3Masters.First()));
#else
            detect.VMCSScanSet = (from dp in detect.DetectedProcesses.Values
                                  group dp by dp.CR3Value into CR3Masters
                                  select new KeyValuePair<ulong, DetectedProc>(CR3Masters.Key, CR3Masters.First())).AsParallel();
#endif
            var VMCSCount = detect.Analyze(Checkers);
            Timer.Stop();

#region VMCS page detection
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.BackgroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"{VMCSCount} candiate VMCS pages. Time to process: {Timer.Elapsed}");

            Console.Write($"Data scanned: {detect.FileSize:N}");
            PrintRate((ulong)(detect.FileSize * 2), Timer.Elapsed);

            //
            // TODO:PageTable.cs
            //          + group/associate CR3's which belong together and are under the control of a given EPTP
            //              + can group by identifying shared kernel PTE entries e.g. all processes & kernel share most significant kernel entries
            //          + Cache tables into internal/peformance representation
            //              + PreLoad EPTP references into direct addresses
            //      Dumper.cs
            //          + Dump available pages into filesystem 
            //          + Group by permission's and contigious regions
            //
            #region BASIC TEST
            if (detect.HVLayer.Count > 0)
            {
                var Success = false;
                foreach(var hv in detect.HVLayer)
                {
                    Console.WriteLine(Environment.NewLine + "TEST:TEST Try dumping 0x7ffab822c000 ");
                    using (var memAxs = new Mem(Filename))
                    {

                        // guest virtual-physical CR3 address into host physical-physical address
                        //var gpaCR3 = memAxs.VirtualToPhysical(hv.EPTP, hv.gCR3, ref Success);
                        //var data = memAxs.GetHyperPage<HARDWARE_ADDRESS_ENTRY>(hv.EPTP, hv.gCR3, 0xfffff800a8e72000, ref Success);
                        //var gvalue = memAxs.VirtualToPhysical(hv.EPTP, hv.gCR3, 0xffffe001820c1740, ref Success);

                        //Console.WriteLine("Extracting mapped data");

                        //var data = memAxs.GetPageForPhysAddr<ulong>(gvalue.PTE);
                        //if (data != null && Success)
                        //{
                        //    for (int i = 0; i < data.Length; i++)
                        //        Console.Write($"{data[i]:X16} ");
                        //}

                        //var gvalue = memAxs.VirtualToPhysical(hv.EPTP, hv.gCR3, 0xffffe001820c1740, ref Success);
                        // attempt to use a user space address and non-kernel process
                        var k32 = (ulong)0x7ff7f89d1000;
                        foreach (var p in detect.DetectedProcesses)
                        {
                            if (p.Value.PageTableType != PTType.Windows)
                                continue;

                            if (p.Value.CR3Value != 0x27e3000)
                                continue;

                            var hPA = memAxs.VirtualToPhysical(hv.EPTP, p.Value.CR3Value, k32, ref Success);
                            if (Success)
                            {
                                var data = memAxs.GetPageForPhysAddr<ulong>(hPA.PTE);
                                if (data != null)
                                {
                                    for (int i = 0; i < data.Length; i++)
                                        Console.Write($"{data[i]:X16} ");
                                }
                            }
                        }
                    }
                }
            }
            #endregion
            #endregion

            Console.ForegroundColor = Foreg;
            Console.BackgroundColor = Backg;
            return;
        }
#region Utilities
        private static void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            Console.ForegroundColor = Foreg;
            Console.BackgroundColor = Backg;
        }
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.ForegroundColor = Foreg;
            Console.BackgroundColor = Backg;
        }

        static void PrintRate(ulong siz, TimeSpan t)
        {
            if (t.Seconds > 0)
            {
                var cnt = (ulong)(siz / (ulong)t.Seconds);

                if (cnt > 1024 * 1024)
                    Console.WriteLine($" rate: {(cnt / (1024 * 1024)):N3} MB/s");
                else if (cnt > 1024)
                    Console.WriteLine($" rate: {(cnt / 1024):N3} kb/s");
                else
                    Console.WriteLine($" rate: {cnt:N3} bp/s");
            }
            else
                Console.WriteLine(" rate: INSTANTLY!");
        }
#endregion
    }
}
