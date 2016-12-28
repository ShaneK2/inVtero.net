import clr

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *

copts = ConfigOptions()

# do not regenerate scan data every time
copts.IgnoreSaveData = True
#copts.FileName = "D:\\Users\\files\\VMs\\Windows Server 2016 TP5\\Windows Server 2016 TP5-16da3812.vmem"
copts.FileName = "d:\\temp\\ubuntu.16.10.xendump"
copts.VersionsToEnable = PTType.LinuxS
# PTType.VMCS | PTType.FreeBSD | PTType.Windows | PTType.HyperV | PTType.GENERIC
copts.VerboseLevel = 1
copts.VerboseOutput = True

vtero = Scan.Scanit(copts)


