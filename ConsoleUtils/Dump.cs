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
using static System.Console;
using static inVtero.net.Misc;
using inVtero.net;
using System.Collections.Concurrent;
using Reloc;
using PowerArgs;
using ConsoleUtils;
using inVtero.net.ConsoleUtils;

namespace inVtero.net
{

    public class Dump
    {
        public Dump()
        { }


        public static void DumpIt(Vtero vtero, ConfigOptions co, DumpOptions dmpo)
        {
            var Version = vtero.Version;

            Mem.InitMem(co.FileName, vtero.MRD);

            // Extract Address Spaces verifies the linkages between
            // process<->CR3<->EPTP(if there is one)
            // and that they are functional

            var vetted = vtero.ExtrtactAddressSpaces(null, null, Version);

            // leaving this in as an example maybe? ;)

            //WriteLine("enter a group ID: ");
            //input = ReadLine();
            //int Grp = int.Parse(input);
            //WriteLine("enter a process ID: ");
            //input = ReadLine();
            //long procID = long.Parse(input, NumberStyles.HexNumber);
            //var proc = (from procz in vtero.ASGroups[Grp]
            //            where procz.CR3Value == procID
            //            select procz).First();
            //int i = 1;
            //DetectedProc dp = proc;
            //while(dp == null)
            //    dp = vtero.GetKernelRangeFromGroup(i++);


            // Scan for kernel 
            // NT kernel may be in 0xFFFFF80000000 to 0xFFFFF8800000 range
            long KernVAStart = 0xF80000000000;
            long KernVAEnd = KernVAStart + (0x8000000000 - 0x1000);
            string input = string.Empty;
            var Detections = new Dictionary<long, Extract>();
            DetectedProc LikelyKernel = null;
            bool Decoded = false;
            // were doing this in nested loops to brute force our way past any errors
            // but only need the first set of detections per group

            foreach (var grpz in vtero.ASGroups)
            {
                foreach (var vm in vtero.VMCSs.Values)
                {
                    WriteColor(ConsoleColor.White, $"Group ID: {grpz.Key}");
                    foreach (var p in grpz.Value)
                    {
                        WriteLine($"Proc: {p.CR3Value:X}");
                        Detections = Detections.Concat(
                            vtero.ModuleScan(p, KernVAStart, KernVAEnd).Where(x => !Detections.ContainsKey(x.Key)))
                            .ToDictionary(x => x.Key, x => x.Value);

                        if (Detections.Count() > 0)
                        {
                            LikelyKernel = p;

                            if (vm.EPTP == 0)
                                p.vmcs = null;
                            else
                                p.vmcs = vm;

                            // scan for kernel
                            foreach (var detected in Detections)
                            {
                                WriteColor(ConsoleColor.Green, $"Attempting to parse detected PE module loaded @ {detected.Key:X}");
                                WriteColor(ConsoleColor.Cyan, detected.Value.ToString());

                                if (detected.Value.ToString().Contains("POOLCODE"))
                                {
                                    WriteColor(ConsoleColor.White, "Likely Kernel analyzing for CV data");
                                    var cv_data = vtero.ExtractCVDebug(LikelyKernel, detected.Value, detected.Key);

                                    if (cv_data != null)
                                    {
                                        var sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
                                        if (string.IsNullOrWhiteSpace(sympath))
                                            sympath = "SRV*http://msdl.microsoft.com/download/symbols";

                                        if (vtero.TryLoadSymbols(LikelyKernel, detected.Value, cv_data, detected.Key, sympath))
                                            Decoded = vtero.GetKernelDebuggerData(LikelyKernel, detected.Value, cv_data, sympath);
                                    }
                                }
                            }
                        }
                        if (Decoded) break;
                    }
                    if (Decoded) break;
                }
                if (Decoded) break;
            }
            ForegroundColor = ConsoleColor.Green;
            WriteLine($"{Environment.NewLine}Final analysis completed, address spaces extracted. {QuickOptions.Timer.Elapsed} {QuickOptions.FormatRate(vtero.FileSize * 3, QuickOptions.Timer.Elapsed)}");

            // do a test dump
            // extract & dump could be done at the same time

            if(!dmpo.ListOnly)
                vtero.DumpASToFile();

            //if (Vtero.VerboseOutput)
                //vtero.DumpFailList();
            
            return;
        }
    }
}
