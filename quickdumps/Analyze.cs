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
using static inVtero.net.Misc;
using static System.Console;
using Reloc;
using System.Collections.Concurrent;
using ConsoleUtils;

namespace inVtero.net
{
   
    public class Analyze
    {
        public Analyze() { }

        public static void DumpDetected(Vtero vtero, DetectedProc p, long VAStart = 0, long VAEnd = 0xffffffff0000)
        {
            var mods = vtero.ModuleScan(p, VAStart, VAEnd);

            // BUGBUG: TODO: Refactor the threadlocal stuff seems were re-entrant unsafe :(
            //Parallel.ForEach(mods, (detected) =>
            //{
            foreach (var detected in mods)
            {
                var cv_data = vtero.ExtractCVDebug(p, detected.Value, detected.Key);

                if (cv_data != null)
                {
                    var sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
                    if (string.IsNullOrWhiteSpace(sympath))
                        sympath = "SRV*http://msdl.microsoft.com/download/symbols";

                    if (vtero.TryLoadSymbols(p, detected.Value, cv_data, detected.Key, sympath))
                        vtero.GetKernelDebuggerData(p, detected.Value, cv_data, sympath);

                }
            }
            //});
        }

        /// <summary>
        /// Initial testing/prototype
        /// Detect/download all binaries in all AS
        /// </summary>
        /// <param name="ops"></param>
        /// <param name="vtero"></param>
        public void StartAnalyze(AnalyzeOptions ops, Vtero vtero)
        {
            long VAStart = 0;
            long VAEnd = VAStart + (0x8000000000 - 0x1000);
            string input = string.Empty;
            var GloalView = new ConcurrentDictionary<DetectedProc, ConcurrentDictionary<long, Extract>>();

            vtero.MemAccess = Mem.InitMem(vtero.MemFile, vtero.MRD);

            if (vtero.VMCSs.Count < 1)
            {
                foreach (var p in vtero.FlattenASGroups)
                {
                    DumpDetected(vtero, p);
                }
                // scan bare metal
                // Parallel.ForEach(vtero.Processes, (p) =>
                //{
                //    WriteColor(ConsoleColor.Cyan, $"Scanning for modules addressable by: {p}");
                //    DumpDetected(vtero, p);
                //});
            }
            else
            foreach (var grpz in vtero.ASGroups)
            {
                foreach (var vm in vtero.VMCSs.Values)
                {
                    WriteColor(ConsoleColor.White, $"Group ID: {grpz.Key}");
                    foreach (var p in grpz.Value)
                    {
                        DumpDetected(vtero, p);
                    }
                }
            }
        }
    }
}
