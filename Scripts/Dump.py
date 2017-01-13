import clr,sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = "d:\\temp\\2012R2.debug.MEMORY.DMP"   
copts.VersionsToEnable = PTType.Windows
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

# since we are not ignoring SaveData, this just get's our state from
vtero = Scan.Scanit(copts)

# Global
mem = Mem.Instance
CollectKernel = True
newdir = copts.FileName + ".dumped"
topDir = Directory.CreateDirectory(newdir)
Vtero.DiagOutput = False

# At least on Windows the kernel may be in here 2x with the "idle" process
# It should be safe to remove dupes
for proc in vtero.FlattenASGroups:  
    currProcBase = newdir + "\\Group-" + proc.ASGroup.ToString() + "-Process-" + proc.CR3Value.ToString("X")
    if Directory.Exists(currProcBase):
        continue
    Directory.CreateDirectory(currProcBase)
    # only one time get Kernel
    entries = vtero.DumpProc(currProcBase + "\\", proc, False, CollectKernel)
    CollectKernel = False
    print "Dumped Process %s, entries %d" % (proc.ShortName, entries)
    # use Reloc.Delocate.DeLocateFile to repair a dumped section into a block that matches disk representation 
    # this allows for secure hash validation of memory blocks

