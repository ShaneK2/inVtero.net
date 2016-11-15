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
copts.FileName = "c:\\temp\\2.xendump"
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
#newdir = copts.FileName + ".dumped"
#topDir = Directory.CreateDirectory(newdir)
#SetGroup = set()
#Vtero.DiagOutput = True
#BareMetalGroup = -1

proc = vtero.FlattenASGroups[0]
CollectKernel = True
pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)
print "Process %s, ranges %d, entries %d" % (proc.ShortName, ranges.Count, pt.EntriesParsed)

proc.GetUValue(0xFFFFF80268674000)
proc.GetUValue(0xfffff80104a86000)

#
#for proc in vtero.FlattenASGroups:
#    currProcBase = newdir + "\\Group-" + proc.ASGroup.ToString() + "-Process-" + proc.CR3Value.ToString("X")
    # By default wipe out any stale stuff
#    if Directory.Exists(currProcBase):
#        Directory.Delete(currProcBase, True)
#    print "%d %s" % (proc.ASGroup, proc)
    # Optimize out kernel ranges if you want here, slight possibility of missing things ;)
#    CollectKernel = (proc.ASGroup not in SetGroup) and SetGroup.Count < 1
    #print "Scan kernel? %s" % CollectKernel
    #pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
    # If we are good to go with PT traversal 
    #if pt and pt.Root and pt.Root.Entries and pt.Root.Entries.SubTables:
        #ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)
        # Make sure we have a range
  #      if ranges.Count == 0:
  #          proc.vmcs = None
  #          pt = PageTable.AddProcess(proc, mem, CollectKernel, 4)
            # if no range we try a bit harder on bare metal
  #          ranges = PageTable.Flatten(pt.Root.Entries.SubTables, 4)
        # Assign the current group as a known group so we do not continue to redundantly dump kernel ranges
        # possibly continue to attempt dumping only kernel ranges which are not mapped into other processes
        # also where the PFN != previous mapped PFN
        #if proc.ASGroup not in SetGroup:
        #    SetGroup.add(proc.ASGroup)
        # Were ready to go with a process & set of ranges
 #       print "Process %s, ranges %d, entries %d" % (proc.ShortName, ranges.Count, pt.EntriesParsed)
 #       for entry in ranges:
 #           print "VA: " + entry.Value.VA.ToString()
 #           print "PTE: " + entry.Value.PTE.ToString()
            #if entry.Value.VA == 0xFFFFF80268674000:
            #    print "Found something!"

            #if range.Value.PTE.Valid:
            #if range.Key.Address == 0xfffff80104a86000:
            #    print "range: " + range.Key.Address.ToString("X")
            #if not Directory.Exists(currProcBase):
            #    dirz = Directory.CreateDirectory(currProcBase)
            # Dump ranges into a process specific directory
            #outFile = vtero.WriteRange(range.Key, range.Value, "%s\\%s-" % (currProcBase, proc.ShortName), mem)



