using PowerArgs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleUtils
{

    public enum OutputMode
    {
        [ArgDescription("Don't output anything (except for the list command)")]
        Off = 0,
        [ArgDescription("Output minimal info")]
        Minimal = 1,
        [ArgDescription("Output every single detail")]
        Verbose = 2,
    }

    public class BaseOptions
    {
        //[ArgShortcut("-Folder"), ArgEnforceCase, ArgDescription("folder/directory to save outputs when extracting binaries"), ArgExistingDirectory, ArgIgnoreCase(false)]
        //public string OutputFolder { get; set; }

    }
}
