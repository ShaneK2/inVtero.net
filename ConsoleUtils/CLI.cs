using PowerArgs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Console;
using inVtero.net;
using inVtero.net.ConsoleUtils;
using System.IO;

namespace inVtero.net.ConsoleUtils
{
    [ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling), 
        TabCompletion(typeof(ItemNameCompletion), 
        REPLWelcomeMessage = "inVtero.net happy hunting, type a command.  Use \"help\" and when specifying a list use \",\" as a list separator and quit will exit.",
        REPL = true, HistoryToSave = 100)]
    public class CLI
    {
        // Library classes
        Vtero vtero;
        // Configuration info
        ConfigOptions option = new ConfigOptions();

        public CLI() {
            if (option == null) option = new ConfigOptions();

            option.VersionsToEnable = PTType.Windows | PTType.FreeBSD | PTType.VMCS | PTType.HyperV;

        }

        [StickyArg, ArgExistingFile
        ArgShortcut("-f"), 
        ArgDescription("Input .VMEM or .DMP (additionally any arbitrary non-extant based memory dump, e.g. .RAW, /dev/mem)")]
        public string MemoryDump { get
            { return option.FileName; }
            set {
                if (string.IsNullOrWhiteSpace(value))
                    return;

                //var action = Args.ParseAction<CLI>(new string[] { "-f", });

                var curr = PowerArgs.StickyArg.HookContext.Current.ArgumentValue = value;
                option.FileName = value; } }


        [ArgActionMethod, ArgDescription("Dump results of scan into contagious virtual regions ")]
        public void dump(DumpOptions argz)
        {

            DumpOptions dOptions = argz;

            if(argz == null)
            {
                ArgUsage.GetStyledUsage<DumpOptions>().Write();
                return;
            }

            if (option.IgnoreSaveData)
            {
                ConsoleString.WriteLine("No save state available or requested to ignore, scan first before dumping.", ConsoleColor.Yellow, ConsoleColor.Black);
                return;
            }

            if(vtero == null)
                vtero = Scan.Scanit(option);
          
             Dump.DumpIt(vtero, option, dOptions);
        }

        [ArgActionMethod, ArgDescription("start IronPython REPL")]
        public void python(string[] Args)
        {
            PythonConsoleHost.RunREPL(Args);
        }

        [ArgActionMethod, ArgDescription("Initial scanning action (required step will save a cache of data & may be skipped after)")]
        public void scan()
        {
            vtero = Scan.Scanit(option);
        }

        [ArgActionMethod, ArgDescription("config will dump the current state of the configuration object.")]
        [ArgExample("config", "dump config state (not command history)", Title = "dump state")]
        [ArgExample("config history", "dump config state and command history", Title = "dump state")]
        [ArgExample("config reset", "resets the basic config state (not command history)", Title = "reset configuration")]
        [ArgExample("config reset history", "resets the config state and command history.", Title = "reset configuration")]
        public void config([DefaultValue(""), ArgDescription("set true to ")] string reset, [DefaultValue(""), ArgDescription("will dump history or clear")] string history)
        {
            // dump info
            if (reset.StartsWith("his") || string.IsNullOrWhiteSpace(reset))
            {
                ConsoleString.WriteLine(option, ConsoleColor.White);
                var tc = (typeof(CLI).GetCustomAttributes(typeof(TabCompletion), true)[0] as TabCompletion);

                if(!File.Exists(tc.HistoryFileNameInternal) || new FileInfo(tc.HistoryFileNameInternal).Length <= 1)
                    ConsoleString.WriteLine($"History file {tc.HistoryFileNameInternal} contains no data. (check permissions)", ConsoleColor.Yellow);

                if(!string.IsNullOrWhiteSpace(history) || reset.StartsWith("his"))
                    foreach (var line in File.ReadAllLines(tc.HistoryFileNameInternal))
                        ConsoleString.WriteLine(line, ConsoleColor.White);
            } else if(reset.Equals("reset")) {
                option = null;

                if(history.StartsWith("hist"))
                    (typeof(CLI).GetCustomAttributes(typeof(TabCompletion), true)[0] as TabCompletion).ClearHistory();

                option = new ConfigOptions();
                MemoryDump = null;

                ConsoleString.WriteLine("done clearing data");
            }
        }

        [ArgActionMethod, ArgDescription("Set can be used to change default settings")]
        [ArgExample("set -f \"c:\\temp\\memory.dmp\"", "An alias that allows setting the default arguments so you don't need to specify them in every command")]
        public void set()
        { }

        [StickyArg, ArgDescription("If set, overwrite any found save state data.")]
        public bool IgnoreSaveData { get { return option.IgnoreSaveData; }
            set { option.IgnoreSaveData = value; } }

        [ArgDescription("Set supported Scanning modes")]
        public PTType ScanMode { get { return option.VersionsToEnable; } set { option.VersionsToEnable = value; } }

        public enum OutputMode
        {
            [ArgDescription("Don't output anything (except for the list command)")]
            Off = 0,
            [ArgDescription("Output minimal info")]
            Minimal = 1,
            [ArgDescription("Output every single detail")]
            Verbose = 2,
        }

        [DefaultValue(OutputMode.Minimal), ArgDescription("Determines the verbosity of the output")]
        public OutputMode Output { get { return (OutputMode)option.VerboseLevel; } set {
                option.VerboseLevel = (int)value;
                Vtero.VerboseLevel = (int)value;


                if (value >= OutputMode.Minimal)
                {
                    Vtero.VerboseOutput = true;
                    option.VerboseOutput = true;
                }
        } }

        [ArgActionMethod, OmitFromUsageDocs, ArgDescription("Displays the help")]
        public void Help()
        {
            ArgUsage.GenerateUsageFromTemplate<CLI>().Write();
        }
    }
    public class RunCLIREPL
    {
        public static void _Main(string[] args)
        {
            //Console.Clear(); 
            // reset to a good position
            //if (Console.CursorTop >= (Console.WindowHeight + Console.WindowTop - 1))
            //    WriteLine($"{Environment.NewLine}{Environment.NewLine}{Environment.NewLine}");

            Args.InvokeAction<CLI>(args);
        }
    }

    public class ItemNameCompletion : SimpleTabCompletionSource
    { 
        // The lambda that is sent to the base constructor will ensure that we get tab completion
        // on the REPL command line for items that are in the list at the time of execution.
        public ItemNameCompletion() : base(() => { return new[] { "help", "quit", "scan", "dump", "set", "config", "history", "reset" }; })
        {
            MinCharsBeforeCyclingBegins = 0;
        }
    }

    public class Items
    {
        [ArgPosition(1), ArgRequired, ArgDescription("Comma separated names of the items to operate on")]
        public List<string> Values { get; set; }
    }


    public class SingleItemArgs
    {
        [ArgPosition(1), ArgRequired, ArgDescription("The textual value of the item")]
        public string Value { get; set; }
    }

}
