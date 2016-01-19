using PowerArgs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleUtils
{
    public class DumpOptions 
    {
        public QuickOptions Global;

        [ArgShortcut("-s"), ArgEnforceCase, ArgDescription("Download/use symbols to improve dumps. (uses environment symbol path _NT_SYMBOL_PATH")]
        public bool SymbolLoading { get; set; }

        [ArgShortcut("-y"), ArgEnforceCase, ArgDescription("Dump memory that is executable.")]
        public bool DumpExecOnly { get; set; }

        [ArgShortcut("-W"), ArgDescription("Dump memory that is Read|Write.")]
        public bool DumpRWOnly { get; set; }

        [ArgShortcut("-T"), ArgDescription("Terminate execution after, do not enter interactive mode.")]
        public bool Terminate { get; set; }

        [ArgShortcut("-D"), ArgDescription("Delocate memory when dumping")]
        public bool DeLocate { get; set; }

        [ArgShortcut("-L"), ArgDescription("List possible ranges")]
        public bool ListOnly { get; set; }
            
        [ArgDescription("Process Identifier to dump from")]
        public string PID { get; set; }

        [ArgShortcut("-VMCS"), ArgDescription("hyperVisor Identifier to use for the VMCS.")]
        public long VID { get; set; }

        [ArgDescription("EPTP Page, can usually be auto-detected from VMCS, but if there are a lot of confusing candidates specify here.")]
        public long EPTP { get; set; }
    }
}
