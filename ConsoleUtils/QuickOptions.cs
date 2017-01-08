using PowerArgs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleUtils
{
    // demo of inVtero !!!
    [ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling, 
        ShowTypeColumn = true, 
        ShowPossibleValues = true),
        TabCompletion(Indicator = "> ", 
        REPL = true, 
        HistoryToSave = 1000)]
    [ArgExample("Dump -f filename", "dumps"), ArgExample("scan", "-f filename scan's memory")]
    public class QuickOptions 
    {
        [ArgShortcut("-f"), ArgEnforceCase, StickyArg, ArgExistingFile, ArgIgnoreCase(IgnoreCase = false)]
        public string FileName { get; set; }

        [HelpHook, ArgShortcut("-?")]
        public bool Help { get; set; }

        [ArgShortcut("-x"), ArgDescription("Overwrite any save state files (*.inVtero.net)")]
        public bool OverwriteSaveState { get; set; }

        public enum OutputMode
        {
            [ArgDescription("Don't output anything (except for the list command)")]
            Off = 0,
            [ArgDescription("Output minimal info")]
            Minimal = 1,
            [ArgDescription("Output every single detail")]
            Verbose = 2,
        }

        [DefaultValue(OutputMode.Minimal), ArgDescription("Determines the verbosity of the output"), ArgShortcut("-v")]
        public OutputMode Output { get; set; }

        public static string FormatRate(long siz, TimeSpan t)
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
        public static Stopwatch Timer;
        public static List<string> Items = new List<string>();
    }

        /*
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
        [ArgumentAwareTabCompletion(typeof(PTType)),
            ArgDescription("OS Support to enable"),
            ArgContextualAssistant(typeof(OSPicker)),
            PowerArgs.DefaultValue("Windows")]
        public PTType OS { get; set; }
    public class ItemNameCompletion : SimpleTabCompletionSource
    {
        // The lambda that is sent to the base constructor will ensure that we get tab completion
        // on the REPL command line for items that are in the list at the time of execution.
        public ItemNameCompletion() : base(() => { return QuickOptions.Items; })
        {
            MinCharsBeforeCyclingBegins = 0;
        }
    }
    */
}