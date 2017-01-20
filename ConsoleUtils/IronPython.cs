using System;
using System.Collections.Generic;

using Microsoft.Scripting.Hosting;
using Microsoft.Scripting.Hosting.Providers;
using Microsoft.Scripting.Hosting.Shell;

using IronPython.Hosting;
using IronPython.Runtime;
using Microsoft.Scripting;

namespace inVtero.net.ConsoleUtils
{
    public class PythonConsoleHost : ConsoleHost
    {
        ScriptEngine EngineCtx;
        CommandLine CmdCtx;
        PythonOptionsParser OptionsCtx;

        public PythonConsoleHost()
        {
        }

        protected override Type Provider
        {
            get { return typeof(PythonContext); }
        }

        protected override CommandLine CreateCommandLine()
        {
            CmdCtx = new PythonCommandLine();
            return CmdCtx;
        }

        protected override OptionsParser CreateOptionsParser()
        {
            OptionsCtx = new PythonOptionsParser();
            return OptionsCtx;
        }

        protected override ScriptRuntimeSetup CreateRuntimeSetup()
        {
            var srs = ScriptRuntimeSetup.ReadConfiguration();
            foreach (var langSetup in srs.LanguageSetups)
            {
                if (langSetup.FileExtensions.Contains(".py"))
                {
                    langSetup.Options["SearchPaths"] = new string[0];
                }
            }
            return srs;
        }

        protected override IConsole CreateConsole(ScriptEngine engine, CommandLine commandLine, ConsoleOptions options)
        {
            var pyoptions = (PythonConsoleOptions)options;
            return new SuperConsole(commandLine, true);
        }

        protected override void ParseHostOptions(string[] args)
        {
            // Python doesn't want any of the DLR base options.
            foreach (string s in args)
            {
                Options.IgnoredArgs.Add(s);
            }
        }

        protected override void ExecuteInternal()
        {

            base.ExecuteInternal();
        }

        public static void RunREPL(string []Args)
        {
            if (Environment.GetEnvironmentVariable("TERM") == null)
            {
                Environment.SetEnvironmentVariable("TERM", "ANSI");
            }

            var pch = new PythonConsoleHost();
            pch.Run(Args);
        }

    }

}
