using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace inVtero.net.Hashing
{
    /// <summary>
    /// Take an input and create a hash request for verification
    /// </summary>
    public class Hasher
    {

    }

    public class MetaData
    {
        public XElement RequestDetails;

        public string ProcessName;
        public string RegionName; // ="ntdll.dll"
        public string SectionName; // =".text" 
        public int PID;
        public long Length; // block aligned  = "FD000";
        public long VirtualSize; // byte len ="FCA37"
        public int StartOff; // "1000"
        public long ImageBase; // ="779E0000" 
        public long RelocatedBase; // ="ff000000"
        public uint TimeDateStamp; // ="54504B0D" 
        public uint DirectoryTableBase0; // = "1AA000"
    }
}
