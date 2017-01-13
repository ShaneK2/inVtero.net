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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using inVtero.net;
using inVtero.net.Support;
using static System.Console;
using static inVtero.net.Misc;
using System.IO;
using System.Diagnostics;
using PowerArgs;
using ConsoleUtils;

namespace inVtero.net.ConsoleUtils
{
    public class Scan
    {
        public static Vtero Scanit(ConfigOptions co)
        {
            bool SkipVMCS = (co.VersionsToEnable & PTType.VMCS) != PTType.VMCS;
            var Filename = co.FileName;

            co.VersionsToEnable = co.VersionsToEnable & ~PTType.VMCS;

            // allocate now so that we can un-serialize or keep an instance
            Vtero vtero = new Vtero();

            // this instance is temporally used for loading state
            // i.e. don't set properties or fields here

            var saveStateFile = $"{Filename}.inVtero.net";

            if (File.Exists(saveStateFile))
            {
                if (!co.IgnoreSaveData)
                {
                    vtero = vtero.CheckpointRestoreState(saveStateFile);
                    if(vtero == null)
                    {
                        WriteColor(ConsoleColor.Red, "ERROR IN SERIALIZER");
                        return null;
                    }

                    vtero.OverRidePhase = true;
                }
                else
                    File.Delete(saveStateFile);
            }

            if (vtero.Phase < 2)
                vtero = new Vtero(Filename);

            if (!vtero.OverRidePhase)
            {
                Mem.InitMem(co.FileName, vtero.MRD);
                ProgressBarz.BaseMessage = new ConsoleString("First pass, looking for processes");
                ForegroundColor = ConsoleColor.Cyan;
#if TESTING
            Timer = Stopwatch.StartNew();

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
            }
            // basic perf checking
            QuickOptions.Timer = Stopwatch.StartNew();
                
            var procCount = vtero.ProcDetectScan(co.VersionsToEnable);

            if (!vtero.OverRidePhase)
            {
                if (co.VerboseLevel > 1)
                    WriteColor(ConsoleColor.Blue, ConsoleColor.Black, $"{procCount} candidate process page tables. Time so far: {QuickOptions.Timer.Elapsed}, second pass starting. {QuickOptions.FormatRate(vtero.FileSize, QuickOptions.Timer.Elapsed)}");
                if (procCount < 3)
                {
                    WriteColor(ConsoleColor.Red, "Seems like a fail. Try generic scanning or implement a state scan like LinuxS");
                    return null;
                }
            }
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

            if (SkipVMCS)
            {
                if (!vtero.OverRidePhase)
                    vtero.GroupAS();

                if (co.VerboseLevel > 1)
                    WriteColor(ConsoleColor.Yellow, "Skipping VMCS scan (as requested).");
            }
            else
            {
                ProgressBarz.BaseMessage = new ConsoleString("Second pass, correlating for VMCS pages");

                var VMCSCount = vtero.VMCSScan();
                //Timer.Stop();

                if (!vtero.OverRidePhase)
                {
                    WriteColor(ConsoleColor.Blue, ConsoleColor.Yellow, $"{VMCSCount} candidate VMCS pages. Time to process: {QuickOptions.Timer.Elapsed}, Data scanned: {vtero.FileSize:N}");

                    // second time 
                    WriteColor(ConsoleColor.Blue, ConsoleColor.Yellow, $"Second pass done. {QuickOptions.FormatRate(vtero.FileSize * 2, QuickOptions.Timer.Elapsed)}");

                    // each of these depends on a VMCS scan/pass having been done at the moment
                    WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, "grouping and joining all memory");
                }
                // After this point were fairly functional
                vtero.GroupAS();
            }
            // sync-save state so restarting is faster
            if (!File.Exists(saveStateFile))
            {
                if(Vtero.VerboseLevel > 0)
                    Write($"Saving checkpoint... ");
                saveStateFile = vtero.CheckpointSaveState();
                WriteColor(ConsoleColor.White, saveStateFile);
            }
            Console.CursorVisible = true;
            return vtero;
        }
    }
}
