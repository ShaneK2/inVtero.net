import clr
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System.Diagnostics import Stopwatch
from softwareunion import *

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = "c:\\temp\\server2016.xendump"   
copts.VersionsToEnable = PTType.GENERIC
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

TotalRunTime = Stopwatch.StartNew()

# since we are not ignoring SaveData, this just get's our state from
vtero = Scan.Scanit(copts)

# Global
CollectKernel = False
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
if vtero.KVS is None:
    kvs = proc.ScanAndLoadModules()
    vtero.KVS = kvs
    vtero.CheckpointSaveState()
else:
    proc.LoadSymbols()
#apply some setup

kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff
Console.ForegroundColor = ConsoleColor.Cyan
print "kernel build: " + kMinorVer.ToString()
# Use dynamic typing to walk EPROCES 
logicalList = vtero.WalkProcList(proc)

# At least on Windows the kernel may be in here 2x with the "idle" process
# It should be safe to remove dupes
vtero.MemAccess.MapViewSize = 128 * 1024
entries = 0
#vtero.KernelProc.InitSymbolsForVad()

target = open(copts.FileName + ".hashSet", 'w')

for proc in proc_arr:  
    # only one time get Kernel view 
    # TODO: Implment PFN bitmap so we dump each PFN exactially once
    proc.MemAccess = Mem(vtero.MemAccess)
    proc.KernelSection = vtero.KernelProc.KernelSection 
    #proc.CopySymbolsForVad(vtero.KernelProc)
    hashes = proc.HashGenBlocks(CollectKernel)
    target.write("\nHash set for process: " + proc.OSFileName + " PID[" + proc.ProcessID.ToString() + "] CR3[" + proc.CR3Value.ToString("X") + "] " + hashes.Length.ToString() + " total hashes generated\n\n" )
    for hash in hashes:
        target.write("0x" + hash.Item1.ToString("X") + "\t" + hash.Item3.ToString() + "\t(" + hash.Item2 + ")\n")

target.close()
print "Done! Total runtime: " + TotalRunTime.Elapsed.ToString()
