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
using System.Collections.Generic;
using System.Linq;
using System.Collections.Concurrent;
using Reloc;
using System.Text;
using System.Runtime.InteropServices;
using inVtero.net.ConsoleUtils;
using static inVtero.net.Misc;
using System.Threading.Tasks;

namespace inVtero.net
{
    public class quickdumps
    {
        PTType OS { get; set; }

        public static int Main(string[] args)
        {
            try
            {
                List<string> FullArgs = new List<string>(args);

                CancelKeyPress += Console_CancelKeyPress;
                AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;

                if (Environment.GetEnvironmentVariable("TERM") == null)
                    Environment.SetEnvironmentVariable("TERM", "ANSI");

                WriteColor(ConsoleColor.Cyan, "QuickDumps is an IronPython shell.");
                WriteColor(ConsoleColor.Cyan, "use dir() help() and the python language.");
                var pch = new PythonConsoleHost();

                FullArgs.Add("-i");
                FullArgs.Add("-O");

                if (File.Exists("Analyze.py"))
                {
                    Write("Analyze.py has been injected, ");
                    ForegroundColor = ConsoleColor.Green;
                    Write("test()");
                    ForegroundColor = ConsoleColor.Cyan;
                    Write(" is the default method that will digest memory dump files from the ");
                    ForegroundColor = ConsoleColor.Green;
                    Write("MemList");

                    WriteColor(ConsoleColor.Cyan, " array.");  
                    FullArgs.Add("Analyze.py");
                }


                FullArgs.Add("-X:FullFrames");
                FullArgs.Add("-X:TabCompletion");
                FullArgs.Add("-X:ColorfulConsole");

                ForegroundColor = ConsoleColor.White;
                pch.Run(FullArgs.ToArray());
            }
            catch (Exception ex)
            {
                Write("Error in processing, likely need to adjust run/gaps. ");
                Write(ex.ToString());
                WriteLine((ex.InnerException == null ? "." : ex.InnerException.ToString()));
            }
            finally
            {
                ResetColor();
            }
            return 0;
        }

        private static void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            ResetColor();
        }
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            ResetColor();
        }
    }
}
