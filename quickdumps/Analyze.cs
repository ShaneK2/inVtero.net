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
            /*
            var mods = vtero.ModuleScan(p, 3, VAStart, VAEnd);

            //Parallel.ForEach(mods, (detected) =>
            //{
            foreach (var detected in p.Sections)
            {
                var cv_data = vtero.ExtractCVDebug(p, detected.Value);

                if (cv_data != null)
                {
                    var sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
                    if (string.IsNullOrWhiteSpace(sympath))
                        sympath = "SRV*http://msdl.microsoft.com/download/symbols";

                    // TODO: fix this or not?  
                    //if(Vtero.TryLoadSymbols(p.ID.GetHashCode(), cv_data, detected.Key))
                    //    vtero.KernelProc = p;
                }
            }
            //});
            */
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
