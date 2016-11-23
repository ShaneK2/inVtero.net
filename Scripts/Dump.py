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

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = True
copts.FileName = "d:\\temp\\2012R2.DMP"   
copts.VersionsToEnable = PTType.Windows 
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

# Global
mem = Mem.Instance

proc = vtero.FlattenASGroups[0]
CollectKernel = True
pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)
print "Process %s, ranges %d, entries %d" % (proc.ShortName, ranges.Count, pt.EntriesParsed)
    
newdir = copts.FileName + ".dumped"
topDir = Directory.CreateDirectory(newdir)
Vtero.DiagOutput = False
BareMetalGroup = -1

# At least on Windows the kernel may be in here 2x with the "idle" process
# It should be safe to remove dupes
for proc in vtero.FlattenASGroups:  
    currProcBase = newdir + "\\Group-" + proc.ASGroup.ToString() + "-Process-" + proc.CR3Value.ToString("X")
    if Directory.Exists(currProcBase):
        continue
    pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
    # only one time get Kernel
    CollectKernel = False
    # If we are good to go with PT traversal 
    if pt and pt.Root and pt.Root.Entries and pt.Root.Entries.SubTables:
        ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)
        # Were ready to go with a process & set of ranges
        print "Process %s, ranges %d, entries %d" % (proc.ShortName, ranges.Count, pt.EntriesParsed)
        for entry in ranges:
            if not Directory.Exists(currProcBase):
                dirz = Directory.CreateDirectory(currProcBase)
            #for entry in ranges:
                #print "VA: " + entry.Value.VA.ToString()
                #print "PTE: " + entry.Value.PTE.ToString()
            # Dump ranges into a process specific directory
            outFile = vtero.WriteRange(entry.Key, entry.Value, "%s\\%s-" % (currProcBase, proc.ShortName), mem)

