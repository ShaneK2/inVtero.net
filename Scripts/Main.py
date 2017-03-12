import clr,sys
import System


clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")
clr.AddReferenceToFileAndPath("inVteroUI.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from inVteroUI import *
from System.IO import Directory, File, FileInfo, Path
from System import Environment, String, Console, ConsoleColor
from System import Text
from System.Diagnostics import Stopwatch

import Analyze
import CloudLeech

from Analyze import *
from CloudLeech import *

# BELOW LIST IS USED BY "test()" method. 
MemList = [
#"c:\\work\\R.RAW",
#"c:\\temp\\win2k8R264bit-Snapshot5.vmsn",
#"C:\\Users\\files\\VMs\\Windows Server 2008 x64 Standard\\Windows Server 2008 x64 Standard-ef068a0c.vmem",
#"c:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows 7 x64 ULT-360b98e6.vmem",
#"c:\\temp\\win10.64.xendump",
"C:\\Users\\files\\VMs\\Windows 1511\\Windows 1511-1b05a6a0.vmem",
#"c:\\temp\\2012R2.debug.MEMORY.DMP",
#"c:\\temp\\server2016.xendump",
#"c:\\temp\\2012R2.xendump",
#"c:\\temp\\10 ENT 1607-Snapshot1.vmem",
#"c:\\temp\\Windows Development-6d08357c.vmem",
#"c:\\temp\\MEMORY.4g.DMP",
#"c:\\temp\memory.64GB.dmp"
#"d:\\users\\files\\vms\\Windows Server 2016\\Windows Server 2016-02431799.vmem",
#"d:\\users\\files\\vms\\RED-Windows 10 x64\\RED-Windows 10 x64-0f643564.vmem"
]
i=1
print "\nConfigured input files (for test() method); "
for line in MemList:
    print '{0} {1}'.format(i, line)
    i+=1








