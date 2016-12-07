using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PowerArgs;

namespace ConsoleUtils
{
    //[Verb("analyze", HelpText = "analyze physical memory image and report state.")]
    public class AnalyzeOptions
    {
        public QuickOptions Global;

        [ArgShortcut("-n"), ArgDescription("folder/directory to save outputs when extracting binaries")]
        public bool PEScan { get; set; }

        [ArgShortcut("-k"), ArgDescription("Only scan kernel")]
        public bool KernelOnly { get; set; }
    }
}