import clr

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *

copts = ConfigOptions()

# do not regenerate scan data every time
copts.IgnoreSaveData = False
copts.FileName = "D:\\Users\\files\\VMs\\10-ENT-1607\\10 ENT 1607-bbbe109e.vmem"
copts.VersionsToEnable = PTType.VMCS | PTType.FreeBSD | PTType.Windows | PTType.HyperV | PTType.GENERIC
copts.VerboseLevel = 1
copts.VerboseOutput = True

vtero = Scan.Scanit(copts)


