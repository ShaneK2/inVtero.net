import clr
import sys
clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = "c:\\temp\\server2016.xendump"   
copts.VersionsToEnable = PTType.GENERIC
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

# since we are not ignoring SaveData, this just get's our state from
vtero = Scan.Scanit(copts)

# Global
CollectKernel = True
newdir = copts.FileName + ".dumped"
topDir = Directory.CreateDirectory(newdir)
Vtero.DiagOutput = False

proc_arr = vtero.Processes.ToArray()
low_proc = proc_arr[0]
for proc in proc_arr:
    if proc.CR3Value < low_proc.CR3Value:
        low_proc = proc

proc = low_proc
print "Assumed Kernel Proc: " + proc.ToString()
vtero.KernelProc = proc
proc.MemAccess = Mem(vtero.MemAccess)

# by default this will scan for kernel symbols 
kvs = proc.ScanAndLoadModules()
vtero.KVS = kvs
#apply some setup
kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff
Console.ForegroundColor = ConsoleColor.Cyan
print "kernel build: " + kMinorVer.ToString()
# Use dynamic typing to walk EPROCES 
logicalList = vtero.WalkProcList(proc)
# At least on Windows the kernel may be in here 2x with the "idle" process
# It should be safe to remove dupes
entries = 0
for proc in proc_arr:  
    currProcBase = newdir + "\\" + proc.OSFileName + " PID[" + proc.ProcessID.ToString() + "] CR3[" + proc.CR3Value.ToString("X") + "]"
    if Directory.Exists(currProcBase):
        continue
    dir = Directory.CreateDirectory(currProcBase)
    # only one time get Kernel view 
    # TODO: Implment PFN bitmap so we dump each PFN exactially once
    proc.MemAccess = Mem(vtero.MemAccess)
    proc.KernelSection = vtero.KernelProc.KernelSection 
    entries = proc.DumpProc(currProcBase + "\\", False, CollectKernel)
    CollectKernel = False
    print "Dumped Process %s, size %d" % (proc.ShortName, entries*4096)
    entries = 0
    # use Reloc.Delocate.DeLocateFile to repair a dumped section into a block that matches disk representation 
    # this allows for secure hash validation of memory blocks

