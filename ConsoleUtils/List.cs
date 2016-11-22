using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net.ConsoleUtils
{
    public class List
    {
        public static void ListIt(Vtero vtero, ConfigOptions co)
        {
            var Version = vtero.Version;

            Mem.InitMem(co.FileName, vtero.MRD);


        }
    }
}
