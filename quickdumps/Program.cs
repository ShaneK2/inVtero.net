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
using System.Collections.Generic;
using System.Linq;
using System.Collections.Concurrent;
using Reloc;
using System.Text;
using System.Runtime.InteropServices;
using inVtero.net.ConsoleUtils;
using static inVtero.net.Misc;
using PowerArgs;
using PowerArgs.Cli;
using System.Threading.Tasks;

namespace inVtero.net
{
    // demo of inVtero !!!
    /*[ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling, ShowTypeColumn = true, ShowPossibleValues = true),
        TabCompletion(Indicator = "> ", REPL = true, HistoryToSave = 1000)]  // ,CompletionSourceType = typeof(ItemNameCompletion), 
    [ArgExample("Dump -f filename", "dumps"), ArgExample("scan", "-f filename scan's memory")]
   */
    public class quickdumps
    {
        #region inactive
        private class OSPicker : ISmartTabCompletionSource
        {
            public OSPicker()
            {
                
            }

            public bool TryComplete(TabCompletionContext context, out string completion)
            {
                var allRemotes = new List<string>
                {
                    "windows",
                    "hyperv",
                    "linux",
                    "freebsd",
                    "openbsd",
                    "netbsd",
                    "generic",
                    "all",
                    "vmcs"
                };

                var list = allRemotes.Where(r => r.StartsWith(context.CompletionCandidate.ToLower(), StringComparison.InvariantCultureIgnoreCase))
                    .Select(r => ContextAssistSearchResult.FromString(r))
                    .ToList();

                completion = list.FirstOrDefault().RichDisplayText.StringValue;
                return !string.IsNullOrWhiteSpace(completion);
            }
        }

        //[ArgActionMethod, ArgumentAwareTabCompletion(typeof(PTType)),
        //    ArgDescription("OS Support to enable"),
        //    ArgContextualAssistant(typeof(OSPicker)),
        //    DefaultValue("Windows")]
        PTType OS { get; set; }
        #endregion
        /*
        [ArgActionMethod, ArgDescription("Run scan")]
        public void scan(ScanOptions oo)

        {
            CliHelper cli = new CliHelper();

            var scanit = new Scan();

            vtero = scanit.Scanit(oo);

            return;
        }

        [ArgActionMethod, ArgDescription("Run default dump routine")]
        public void dump(DumpOptions oo)
        {
            var ops = new DumpOptions();

            vtero = new Vtero();

            var saveStateFile = $"{ops.Global.FileName }.inVtero.net";
            if (File.Exists(saveStateFile))
            {
                vtero = vtero.CheckpointRestoreState(saveStateFile);
                vtero.OverRidePhase = true;
            }

            // TODO: fail when no state

            Timer = Stopwatch.StartNew();

            //var dumper = new Dumper(vtero, string.Empty, null);

            //dumper.DumpIt();
            return;
        }

        [ArgActionMethod, ArgDescription("Run default analyze routine")]
        public void analyze(AnalyzeOptions ops)
        {

            if (!string.IsNullOrWhiteSpace(FileName))
                ops.Global.FileName = FileName;

            vtero = new Vtero();

            var saveStateFile = $"{ops.Global.FileName}.inVtero.net";
            if (File.Exists(saveStateFile))
            {
                vtero = vtero.CheckpointRestoreState(saveStateFile);
                vtero.OverRidePhase = true;
            }

            Mem.InitMem(ops.Global.FileName, null, vtero.DetectedDesc);

            var analyzer = new Analyze();

            Timer = Stopwatch.StartNew();
            analyzer.StartAnalyze(ops, vtero);

            return;
        }
        */



        public static int Main(string[] args)
        {
            try
            {
                CancelKeyPress += Console_CancelKeyPress;
                AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;

                RunCLIREPL._Main(args);

                var p = new quickdumps();
                



                /*

                // I wanted a flexible syntax that I didn't know how to (yet) attribute with CommandLine 2.0beta :\
                if (args.Length > 1 && File.Exists(args[0]))
                {
                    p.FileName = args[0];
                    var tmp = new string[args.Length-1];
                    Array.Copy(args, 1, tmp, 0, args.Length - 1);
                    args = tmp;
                }

                var parser = new Parser(with => with.EnableDashDash = true);

                return CommandLine.Parser.Default.ParseArguments<ScanOptions, DumpOptions, AnalyzeOptions>(args)
                    .MapResult(
                      (ScanOptions opts) => p.InitialPhaseScans(opts),
                      (DumpOptions opts) => p.DoDumping(opts),
                      (AnalyzeOptions opts) => p.DoAnalyze(opts),
                      errs => 1);
                      */
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


        #region Utilities
       
        private static void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            ResetColor();
        }
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            ResetColor();
        }


        #endregion
    }

    public class ScanTypeScanTypeCompletionSource : SimpleTabCompletionSource
    {
        public ScanTypeScanTypeCompletionSource() : base(new string[] {
            "Windows",
            "HyperV",
            "FreeBSD",
            "OpenBSD",
            "NetBSD",
            "HyperV", 
            "Linux",
            "Generic",
            "ALL",
            "VMCS"

        })
        {
            this.MinCharsBeforeCyclingBegins = 0;
        }
    }
}
