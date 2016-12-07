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
copts.FileName = "d:\\temp\\2012R2.debug.MEMORY.DMP"   
copts.VersionsToEnable = PTType.Windows
# support scanning for these targets
# use PTType.VMCS when your suspect VM's or nested VM/hypervisors in use
# PTType can also include HyperV, FreeBSD, OpenBSD, NetBSD and Linux
copts.VersionsToEnable = PTType.Windows 
# for many formats MemGaps can be derived from header data
#copts.ForceScanMemGaps = True
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

mem = Mem.Instance;


proc = vtero.FlattenASGroups[0]
CollectKernel = True
pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)
print "Process %s, ranges %d, entries %d" % (proc.ShortName, ranges.Count, pt.EntriesParsed)





#for range in ranges:
#    print f.write(range.Key.ToString() + "\t" + range.Value.ToString() + "\n")

proc.GetUValue(0xfffff80176688000)

# blah test stuff
#

#proc.GetUValue(0xFFFFF80268674000)
#proc.GetUValue(0xfffff80104a86000)
