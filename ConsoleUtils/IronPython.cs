using System;
using System.Collections.Generic;

using Microsoft.Scripting.Hosting;
using Microsoft.Scripting.Hosting.Providers;
using Microsoft.Scripting.Hosting.Shell;

using IronPython.Hosting;
using IronPython.Runtime;


namespace inVtero.net.ConsoleUtils
{
    public class PythonConsoleHost : ConsoleHost
    {

        protected override Type Provider
        {
            get { return typeof(PythonContext); }
        }

        protected override CommandLine CreateCommandLine()
        {
            return new PythonCommandLine();
        }

        protected override OptionsParser CreateOptionsParser()
        {
            return new PythonOptionsParser();
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
            var pc = HostingHelpers.GetLanguageContext(Engine) as PythonContext;
            pc.SetModuleState(typeof(ScriptEngine), Engine);
            base.ExecuteInternal();
        }

        /// <summary>
        /// Runs the console.
        /// </summary>
        public void RunConsole(string[] Args)
        {

            List<string> moreArgs = Args == null ? new List<string>() : new List<string>(Args);

            moreArgs.Add("-X:FullFrames");
            moreArgs.Add("-X:TabCompletion");
            moreArgs.Add("-X:ColorfulConsole");

            this.Run(moreArgs.ToArray());
        }

        public static void RunREPL(string []Args)
        {
            if (Environment.GetEnvironmentVariable("TERM") == null)
            {
                Environment.SetEnvironmentVariable("TERM", "ANSI");
            }
            new PythonConsoleHost().RunConsole(Args);
        }
    }

}
