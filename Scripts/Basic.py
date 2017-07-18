#
#
# To debug you can try like so;
# ipy64 -X:TabCompletion -X:ShowClrExceptions -X:PrivateBinding -X:PassExceptions -X:FullFrames -X:Frames -X:ExceptionDetail -D
#
#

import clr

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from inVtero.net.Support import Strings
from System.Text.RegularExpressions import RegEx



# turn off progress bar if it's too noisy
#Support.ProgressBarz.DisableProgressBar = True
# text progress
#Support.ProgressBarz.TextInfo = True
# Basic option handling
copts = ConfigOptions()

# do not regenerate scan data every time
# !!if you have _STALE_ data try changing this to True!!! (normally False is going to save time)
## currently the save state is missing for a few fields
copts.IgnoreSaveData = True
#proc.GetUValue(0xfffff80104a86000)
#copts.FileName = "c:\\temp\\memory.dmp"
copts.FileName = "c:\\temp\\MC.dmp"   
#copts.FileName = "c:\\temp\\win10.64.xendump"
#copts.FileName = "C:\\Users\\files\\VMs\\Windows 1511\\Windows 1511-1b05a6a0.vmem"
# support scanning for these targets
# use PTType.VMCS when your suspect VM's or nested VM/hypervisors in use
# PTType can also include HyperV, FreeBSD, OpenBSD, NetBSD and Linux
copts.VersionsToEnable = PTType.Windows 
# for many formats MemGaps can be derived from header data
#copts.ForceScanMemGaps = True
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

vtero = Vtero(copts.FileName)

check = 0x01AA
fs_offset = vtero.MemAccess.OffsetToMemIndex(check) / 4096
print "check " + check.ToString("X") + " is at " + fs_offset.ToString("X")
delta = check - fs_offset
print "delta " + delta.ToString("X")

check = 0x102846
fs_offset = vtero.MemAccess.OffsetToMemIndex(check) / 4096
print "check " + check.ToString("X") + " is at " + fs_offset.ToString("X")
delta = check - fs_offset
print "delta " + delta.ToString("X")
