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

// Shane.Macaulay@IOActive.com (c) copyright 2014,2015 all rights reserved. GNU GPL License
//  
// Version 2.1-Post-RuxCon-DefCon-CanSecWest! thanks conferences for allowing people to do something not related to day jobs!!!
//  + Fixed few bugs after the conference's
//  + Works as VMI instead of single OS process detection
//  + Easier to use & find EPTP
//  + Ported to BSD families -- in terms of functional fbsd/obsd/nbsd (i.e. nbsd is a bit cranky, need to work on that one ;)
//  + Parallelized some of the operation if your runtime is concurrent (serial versions still around for lame run times)
//  + CR3 dumping
// 
//  TODO:   * PERF!
//              - memory mapper should improve with windowing larger sizes (basic single page maps currently)
//              - pre-cache full tables in one shot (don't traverse V2gP2hV every time, 24 reads per load)
//              - testing against other tools (ensure dump is accurate & best performing ;)
//          
//          * BlockWatch server integration - Eliminate gaps in your memory forensic process. 
//              - Isolate known code from unknown/untrusted code in memory. e.g. 99%+ of resident code can be securely identified (based on cryptographic secure hashes 192bit+)
//              - (If your not verifying the code in your memory dumps, you really don't know what's in them do you? -- that string that says ntdll.dll cant lie right!! :)
//              - Delocate memory based on hosted .reloc files (don't you want to memory dumps that match disk files?!?!)
//              - Match dumped binaries to known secure hashes (who wants to disassemble/analyze ntdll when you dont have too!)
//              
//          ~~* Test/Support open .net runtime Roselyn and such on other platforms (done see Reloc)~~
//              ~~- Now that WCF is open, it's a cinch to connect to our web services~~
//
//          * Memory run detection
//              - Validate top level page references and auto extend for raw, still tbd bitmap dmp for Windows
//
//
// TODO:PageTable.cs
//~~          + group/associate CR3's which belong together and are under the control of a given EPTP
//              + can group by identifying shared kernel PTE entries e.g. all processes & kernel share most significant kernel entries (done) ~~
//          + Cache tables into internal/performance representation
//              + PreLoad EPTP references into direct addresses
//      Dumper.cs
//          + Dump available pages into file system 
//          + Group by permission's and contiguous regions
//

using ProtoBuf;
using inVtero.net;
using System;
using System.IO;
using System.Diagnostics;
using static System.Console;
using System.Globalization;
using System.Linq;

namespace quickdumps
{
    // demo of inVtero !!!
    public class Program
    {
        static Stopwatch Timer;

        static void PrintHelp()
        {
            WriteLine("inVtero FileName [win|lin|fbsd|obsd|nbsd|gen|-vmcs|!]");
            WriteLine("\"inVtero FileName winfbsd\"  (will run FreeBSD and Windows together)");
            WriteLine("\"inVtero FileName !-obsd-nbsd\" (will run all scanners except for OpenBSD and NetBSD)");    
            WriteLine("Using -* should disable that scanner, you can not enable only a VMCS scan since VMCS EPTP detection requires a prior scan.");
        }

        public static void Main(string[] args)
        {
            #region fluff
            var Version = PTType.UNCONFIGURED;
            var Filename = string.Empty;
            var SkipVMCS = false;
            var Is64Scan = false;
            uint valuI = 0;
            ulong valuL = 0;

            if (args.Length < 1)
            {
                PrintHelp();
                return;
            }
            try {
                Filename = args[0];

                if (!File.Exists(Filename))
                {
                    PrintHelp();
                    return;
                }

                if (args.Length > 1)
                {
                    var spec = args[1].ToLower();

                    if (spec.Contains("win"))
                        Version |= PTType.Windows;
                    if (spec.Contains("hv"))
                        Version |= PTType.HyperV;
                    if (spec.Contains("lin"))
                        Version |= PTType.LinuxS;
                    if (spec.Contains("fbsd"))
                        Version |= PTType.FreeBSD;
                    if (spec.Contains("obsd"))
                        Version |= PTType.OpenBSD;
                    if (spec.Contains("nbsd"))
                        Version |= PTType.NetBSD;
                    if (spec.Contains("gen"))
                        Version |= PTType.GENERIC;
                    if (spec.Contains("value"))
                        Version |= PTType.VALUE;

                    if (spec.Contains("!"))
                        Version |= PTType.ALL;

                    if (spec.Contains("-vmcs"))
                        SkipVMCS = true;

                    if (spec.Contains("-obsd"))
                        Version = Version & ~PTType.OpenBSD;
                    if (spec.Contains("-nbsd"))
                        Version = Version & ~PTType.NetBSD;
                    if (spec.Contains("-fbsd"))
                        Version = Version & ~PTType.FreeBSD;
                    if (spec.Contains("-lin"))
                        Version = Version & ~PTType.LinuxS;
                    if (spec.Contains("-hv"))
                        Version = Version & ~PTType.HyperV;
                    if (spec.Contains("-win"))
                        Version = Version & ~PTType.Windows;
                }
                else
                    Version = PTType.ALL;
#if TESTING
                if((Version & PTType.VALUE) == PTType.VALUE)
                {
                    bool Parsed = false;
                    do
                    {
                        if(args.Length < 2)
                        {
                            WriteLine($"Specify value");
                            return;
                        }

                        Parsed = uint.TryParse(args[2],NumberStyles.HexNumber, CultureInfo.CurrentCulture, out valuI);
                        if (!Parsed)
                        {
                            Parsed = ulong.TryParse(args[2], NumberStyles.HexNumber, CultureInfo.CurrentCulture, out valuL);
                            if (Parsed)
                                Is64Scan = true;
                            else {
                                WriteLine($"Unable to parse input {args[2]}");
                                return;
                            }
                        }
                        else
                            valuL = (ulong)valuI;

                    } while (!Parsed);
                }
#endif
                Vtero vtero = new Vtero();

                var saveStateFile = $"{Filename}.inVtero.net";

                if (File.Exists(saveStateFile))
                {
                    WriteLine("Found save state, (l)oad or (d)iscard?");
                    var todo = ReadKey();
                    if (todo.Key != ConsoleKey.D)
                    {
                        vtero = vtero.CheckpointRestoreState(saveStateFile);
                        vtero.OverRidePhase = true;
                    }
                    else
                        File.Delete(saveStateFile);
                }

                if(vtero.Phase < 2)
                    vtero = new Vtero(Filename);

                Vtero.VerboseOutput = true;
                
                CancelKeyPress += Console_CancelKeyPress;
                AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;
                ForegroundColor = ConsoleColor.Cyan;

#endregion
                Timer = Stopwatch.StartNew();

#if TESTING
                if ((Version & PTType.VALUE) == PTType.VALUE)
                {
                    var off = vtero.ScanValue(Is64Scan, valuL, 0);
                    
                    WriteLine(FormatRate(vtero.FileSize, Timer.Elapsed));
                    using (var dstream = File.OpenRead(vtero.MemFile))
                    {
                        using (var dbin = new BinaryReader(dstream))
                        {
                            foreach (var xoff in off)
                            {
                                WriteLine($"Checking Memory Descriptor @{(xoff + 28):X}");
                                if (xoff > vtero.FileSize)
                                {
                                    WriteLine($"offset {xoff:X} > FileSize {vtero.FileSize:X}");
                                    continue;
                                }

                                dstream.Position = xoff + 28;
                                var MemRunDescriptor = new MemoryDescriptor();
                                MemRunDescriptor.NumberOfRuns = dbin.ReadInt64();
                                MemRunDescriptor.NumberOfPages = dbin.ReadInt64();

                                Console.WriteLine($"Runs: {MemRunDescriptor.NumberOfRuns}, Pages: {MemRunDescriptor.NumberOfPages} ");

                                if (MemRunDescriptor.NumberOfRuns < 0 || MemRunDescriptor.NumberOfRuns > 32)
                                {
                                    continue;
                                }
                                for (int i = 0; i < MemRunDescriptor.NumberOfRuns; i++)
                                {
                                    var basePage = dbin.ReadInt64();
                                    var pageCount = dbin.ReadInt64();

                                    MemRunDescriptor.Run.Add(new MemoryRun() { BasePage = basePage, PageCount = pageCount });
                                }
                                WriteLine($"MemoryDescriptor {MemRunDescriptor}");
                            }
                        }
                    }
                    WriteLine("Finished VALUE scan.");
                    return;
                }
                if ((Version & PTType.VALUE) == PTType.VALUE)
                    return;
#endif
                    // basic perf checking
               Timer = Stopwatch.StartNew();

                var procCount = vtero.ProcDetectScan(Version);

#region page table/CR3 progress report
                ForegroundColor = ConsoleColor.Blue;
                BackgroundColor = ConsoleColor.Yellow;

                var msg = $"{procCount} candidate process page tables. Time so far: {Timer.Elapsed}, second pass starting.";

                Write(msg);

                WriteLine(FormatRate(vtero.FileSize, Timer.Elapsed));
                BackgroundColor = ConsoleColor.Black;
                ForegroundColor = ConsoleColor.Cyan;
                if (procCount < 3)
                {
                    WriteLine("Seems like a fail. Try generic scanning or implement a state scan like LinuxS");
                    return;
                }
                //BackgroundColor = ConsoleColor.White;
                #endregion
                #region blighering
                // second pass
                // with the page tables we acquired, locate candidate VMCS pages in the format
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

                if (!SkipVMCS)
                {
                    var VMCSCount = vtero.VMCSScan();

                    //Timer.Stop();

                    #region VMCS page detection
                    ForegroundColor = ConsoleColor.Blue;
                    BackgroundColor = ConsoleColor.Yellow;


                    WriteLine($"{VMCSCount} candidate VMCS pages. Time to process: {Timer.Elapsed}");
                    Write($"Data scanned: {vtero.FileSize:N}");

                    // second time 
                    WriteLine($"Second pass done. {FormatRate(vtero.FileSize * 2, Timer.Elapsed)}");
                    BackgroundColor = ConsoleColor.Black;
                    ForegroundColor = ConsoleColor.Cyan;

                    #region TEST
                    // each of these depends on a VMCS scan/pass having been done at the moment
                    WriteLine("grouping and joining all memory");

                    // After this point were fairly functional
                    vtero.GroupAS();

                    // sync-save state so restarting is faster
                    if (!File.Exists(saveStateFile))
                    {
                        Write($"Saving checkpoint... ");
                        saveStateFile = vtero.CheckpointSaveState();
                        WriteLine(saveStateFile);
                    }


                    int i = 1;
                    DetectedProc dp = null;
                    while(dp == null)
                        dp = vtero.GetKernelRangeFromGroup(i++);


                    // Scan for kernel 
                    // NT kernel may be in 0xFFFFF80000000 to 0xFFFFF8800000 range
                    long KernVAStart = 0xF80000000000;
                    long KernVAEnd = KernVAStart + 0x8000000000;


                    var modules_in_range = vtero.ModuleScan(dp, null, KernVAStart, KernVAEnd);


                    // Extract Address Spaces verifies the linkages between
                    // process<->CR3<->EPTP(if there is one)
                    // and that they are functional
                    //var vetted = vtero.ExtrtactAddressSpaces(null, null, Version);

                    ForegroundColor = ConsoleColor.Green;
                    WriteLine($"{Environment.NewLine}Final analysis completed, address spaces extracted. {Timer.Elapsed} {FormatRate(vtero.FileSize * 3, Timer.Elapsed)}");

                    // do a test dump
                    // extract & dump could be done at the same time
                    vtero.DumpASToFile();

                    if (Vtero.VerboseOutput)
                        vtero.DumpFailList();
                }
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

        static string FormatRate(long siz, TimeSpan t)
        {
            var rv = string.Empty;
            if (t.Seconds > 0)
            {
                var cnt = siz * 1.00 / t.TotalSeconds;

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
