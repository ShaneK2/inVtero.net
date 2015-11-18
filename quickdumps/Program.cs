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
// TODO:PageTable.cs
//          + group/associate CR3's which belong together and are under the control of a given EPTP
//              + can group by identifying shared kernel PTE entries e.g. all processes & kernel share most significant kernel entries
//          + Cache tables into internal/peformance representation
//              + PreLoad EPTP references into direct addresses
//      Dumper.cs
//          + Dump available pages into filesystem 
//          + Group by permission's and contigious regions
//

using inVtero.net;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProtoBuf;
using static System.Console;

namespace quickdumps
{
    // demo of inVtero !!!
    public class Program
    {
        static Stopwatch Timer;

        public static void Main(string[] args)
        {
            #region fluff
            var Version = PTType.UNCONFIGURED;
            string Filename = null;

            if (args.Length == 0 || args.Length > 2)
            {
                WriteLine("inVtero FileName [win|fbsd|obsd|nbsd|!]");
                WriteLine("\"inVtero FileName winfbsd\"  (e.g. Run FreeBSD and Windows together)");
                return;
            }
            try {
                Filename = args[0];

                if (args.Length > 1)
                {
                    var spec = args[1].ToLower();

                    if (spec.Contains("gen"))
                        Version |= PTType.GENERIC;
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

                var vtero = new Vtero(Filename);

                Vtero.VerboseOutput = true;
                
                CancelKeyPress += Console_CancelKeyPress;
                AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;
                ForegroundColor = ConsoleColor.Cyan;

                #endregion

                // basic perf checking
                Timer = Stopwatch.StartNew();

                var procCount = vtero.ProcDetectScan(Version);

                #region page table/CR3 progress report
                ForegroundColor = ConsoleColor.Blue;
                BackgroundColor = ConsoleColor.Yellow;

                var msg = $"{procCount} candiate process page tables. Time so far: {Timer.Elapsed}, second pass starting.";

                Write(msg);

                WriteLine(PrintRate(vtero.FileSize, Timer.Elapsed));
                BackgroundColor = ConsoleColor.Black;
                ForegroundColor = ConsoleColor.Cyan;
                if (procCount < 3)
                {
                    WriteLine("Seems like a fail.  See if this is Linux or something that a different detection technique is needed? :(");
                    return;
                }
                //BackgroundColor = ConsoleColor.White;
                #endregion
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
                // future may have a reason to isolate based on original locationAG
                #endregion

                var VMCSCount = vtero.VMCSScan();

                //Timer.Stop();

                #region VMCS page detection
                ForegroundColor = ConsoleColor.Blue;
                BackgroundColor = ConsoleColor.Yellow;


                WriteLine($"{VMCSCount} candiate VMCS pages. Time to process: {Timer.Elapsed}");
                Write($"Data scanned: {vtero.FileSize:N}");

                // second time 
                WriteLine("Second pass done. " + PrintRate(vtero.FileSize * 2, Timer.Elapsed));
                BackgroundColor = ConsoleColor.Black;
                ForegroundColor = ConsoleColor.Cyan;

                #region TEST
                WriteLine("grouping and joinging all memory");
                vtero.GroupAS();
                //vtero.ExtrtactAddressSpaces();
                vtero.DumpFailList();

                WriteLine($"Final analysis compleated, address spaces extracted. {Timer.Elapsed} {PrintRate(vtero.FileSize * 3, Timer.Elapsed)}");

                #endregion
                #endregion
            } catch (Exception ex)
            {
                Write("Error in processing, likely need to adjust run/gaps. ");
                Write(ex.ToString());
                WriteLine((ex.InnerException == null ? "." : ex.InnerException.ToString()));
            }
            finally {
                ResetColor();
            }
            return;
        }
#region Utilities
        private static void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            ResetColor();
        }
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            ResetColor();
        }

        static string PrintRate(long siz, TimeSpan t)
        {
            string rv = string.Empty;
            if (t.Seconds > 0)
            {
                var cnt = siz * 1.00 / t.Seconds;

                if (cnt > 1024 * 1024)
                    rv = $" rate: {(cnt / (1024 * 1024)):F3} MB/s";
                else if (cnt > 1024)
                    rv = $" rate: {(cnt / 1024):F3} kb/s";
                else
                    rv = $" rate: {cnt:F3} bp/s";
            }
            else
                rv = " rate: INSTANTLY!?!?";

            return rv;
        }
#endregion
    }
}
