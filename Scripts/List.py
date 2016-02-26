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
Support.ProgressBarz.DisableProgressBar = True
# text progress
Support.ProgressBarz.TextInfo = True

# Basic option handling
copts = ConfigOptions()

# do not regenerate scan data every time
# !!if you have _STALE_ data try changing this to True!!! (normally False is going to save time)
copts.IgnoreSaveData = True
copts.FileName = "c:\\temp\\memory.dmp"
# support scanning for these targets
copts.VersionsToEnable = PTType.VMCS | PTType.FreeBSD | PTType.Windows | PTType.HyperV
copts.VerboseOutput = True
copts.VerboseLevel = 1

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

mem = Mem.Instance;

newdir = Directory.CreateDirectory(copts.FileName + ".dumped")

SetGroup = set()
#Vtero.DiagOutput = True

for proc in vtero.FlattenASGroups:
    print "%d %s" % (proc.ASGroup, proc)
    # Optimize out kernel ranges if you want here, slight possibility of missing things ;)
    CollectKernel = (proc.ASGroup not in SetGroup) and SetGroup.Count < 1
    print "Scan kernel? %s" % CollectKernel
    # attach page table to process
    #vtero.ExtrtactAddressSpaces(None, None, copts.VersionsToEnable)
    #pt = proc.PT
    pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
    if pt and pt.Root and pt.Root.Entries and pt.Root.Entries.SubTables:
        ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)    
        print "Process %s, ranges %d, entries %d" % (proc.ShortName, ranges.Count, pt.EntriesParsed)
        for range in ranges:
            if range.Value.PTE.Valid:
                outFile = vtero.WriteRange(range.Key, range.Value, "%s\\%s-" % (newdir.FullName, proc.ShortName), mem)
                if proc.ASGroup not in SetGroup:
                    SetGroup.add(proc.ASGroup)

