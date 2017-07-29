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





#rv = fl.FileChecker("c:\\temp\\advapi32.dll.text", True)
#for f in fl.DirectoryChecker("C:\\Users\\files\\VMs\\Windows 10 x64-PRO-1703\\Windows 10 x64-PRO-1703-40599dd1.vmem.dumped.2", "*.text", 128):
#    if f.Item2 < 100.0:
#        print f.Item1 + " " + f.Item2.ToString("N3") 
#        # This will print the index at whitch the missing data is
#        #for index in range(0, f.Item3.Count):
#        #    if f.Item3[index] == False:
#        #        print " miss @ 0x" + (index * 128).ToString("X"),
#for f in fl.DirectoryChecker("C:\\temp\\", "FileSyncShell64.dll.text", 128):
#    if f.Item2 < 100.0:
#        print f.Item1 + " " + f.Item2.ToString("N3") 
#        for index in range(0, f.Item3.Count):
#            if f.Item3[index] == False:
#                print " miss @ 0x" + (index * 128).ToString("X"),
