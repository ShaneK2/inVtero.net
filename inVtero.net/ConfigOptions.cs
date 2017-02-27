using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Environment;

namespace inVtero.net
{
    public class ConfigOptions
    {
        public string FileName {get;set;}

        public bool IgnoreSaveData { get; set; }

        public bool ForceSingleFlatMemRun { get; set; }
        
        public PTType VersionsToEnable { get; set; }

        public int VerboseLevel { get; set; }

        public bool VerboseOutput { get; set; }

        public override string ToString()
        {
            return $"\t(-f) FileName = [{FileName}]{NewLine}" +
                $"\t(-i) Ignore saved data = {IgnoreSaveData}{NewLine}" +
                $"\t(-e) EnabledScans = {VersionsToEnable}{NewLine}" +
                $"\t(-v) Verbose = {VerboseOutput}, (-l) level {VerboseLevel}{NewLine}";
        }
    }
}
