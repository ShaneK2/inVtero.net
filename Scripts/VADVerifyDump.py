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
from System import Environment, String, Console, ConsoleColor
from inVtero.net.Hashing import *

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = True
copts.FileName = "C:\\Users\\files\\VMs\\Windows 10 x64-PRO-1703\\Windows 10 x64-PRO-1703-40599dd1.vmem"   
#copts.FileName = "C:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows7.vmem"
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
Vtero.VerboseLevel = 0

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
else:
    proc.LoadSymbols()

kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff
Console.ForegroundColor = ConsoleColor.Cyan
print "kernel build: " + kMinorVer.ToString()

Vtero.VerboseLevel = 2
vtero.HashAllProcs("C:\\temp\\inVtero.net\\iv.DB", "c:\\temp\\inVtero.net\Relocs", 1024*1024*1024*16, True);

print "Done! Total runtime: " + TotalRunTime.Elapsed.ToString()

##
## This is the Python version of vtero.HashAllProcs
##

# Use dynamic typing to walk EPROCES 
#logicalList = vtero.WalkProcList(proc)

#vtero.MemAccess.MapViewSize = 128 * 1024
#vtero.KernelProc.InitSymbolsForVad()
#db = HashDB("C:\\temp\\iv.DB", "c:\\temp\\reloc", 1024*1024*1024*4)
#fl = FileLoader(db)

#for proc in proc_arr:  
#    if proc.CR3Value == vtero.KernelProc.CR3Value:
#        CollectKernel = True
#    else:
#        CollectKernel = False
#    valid = 0
#    proc.HDB = db
#    proc.MemAccess = Mem(vtero.MemAccess)
#    proc.KernelSection = vtero.KernelProc.KernelSection  
#    proc.CopySymbolsForVad(vtero.KernelProc)
#    proc.ID = vtero.KernelProc.ID
#    hashes = proc.VADHash(CollectKernel, True, True, True)
#    fl.HashLookup(proc.HashRecords)
#    if proc.HashRecords is not None:
#        rate = proc.HashRecordRate()
#        if rate == 100.0:
#            Console.ForegroundColor = ConsoleColor.Green
#        else:
#            Console.ForegroundColor = ConsoleColor.Yellow
#        print proc.ToString() + " Validated to " + rate.ToString("N3")
#    else:
#        print "Error in performing hash lookup!!!"
#    #print "*** PID [" + proc.ProcessID.ToString() + "] " + Path.GetFileName(proc.OSFileName) + " ***"
#    if proc.HashRecords is not None and proc.HashRecords.Length > 0:
#        for h in proc.HashRecords:
#            for r in h.Regions:
#                if r.PercentValid != 100.0:
#                    print r.ToString()
    




        #valid = db.BitmapScan(hashes)


#hashes = proc.HashGenBlocks(CollectKernel, True)
    #target.write("\nHash set for process: " + proc.OSFileName + " PID[" + proc.ProcessID.ToString() + "] CR3[" + proc.CR3Value.ToString("X") + "] " + hashes.Length.ToString() + " total hashes generated\n\n" )  + "] Len [" + (h.Address[idx].Count*4096).ToString("X") + "] "
#    for hash in hashes:
#        if db.GetIdxBit(hash.Index):
#            FoundBit += 1
#        else:
#            NoBit += 1

#valid = h.Validated
#            checkedCnt = h.Total
#            if checkedCnt != 0:
#                percent = valid * 100.0 / checkedCnt
#                for idx in h.GetSegments():
            