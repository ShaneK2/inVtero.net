import clr
import sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from inVtero.net.Hashing import *

from System.IO import Directory, File, FileInfo, Path
from System.Diagnostics import Stopwatch
from System import Environment, String, Console, ConsoleColor
from System.Text import Encoding

MemoryDump = "C:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows 7 x64 ULT-360b98e6.vmem"

###
#
#  You have to set AllowWrite to enable write-back support for dynamic objects
#  This is a safety measure so nothing changes under the hood by mistake
#  Vtero.VerboseLevel 2+ will write detailed information when write's occur
#
###
Vtero.AllowWrite = True

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = MemoryDump
copts.VersionsToEnable = PTType.GENERIC
copts.VerboseOutput = False
copts.VerboseLevel = 0
# Vtero options are global
Vtero.DiagOutput = False
# perform full page scan
# this scans the input in it's entirety and set's up 
# the basis for traversing memory appropiatly as the CPU would
# through the page table (including nested) 
vtero = Scan.Scanit(copts)
proc_arr = vtero.Processes.ToArray()
low_proc = proc_arr[0]
for proc in proc_arr:
    if proc.CR3Value < low_proc.CR3Value:
        low_proc = proc

proc = low_proc
print "Assumed Kernel Proc: " + proc.ToString()
vtero.KernelProc = proc
proc.MemAccess = Mem(vtero.MemAccess)
    
# Here we bring up symbol support to the Windows Kernel
# if we have a save state we skip the scan and directly load it
if vtero.KVS is None:
    kvs = proc.ScanAndLoadModules()
    vtero.KVS = kvs
else:
    proc.LoadSymbols()

# having the kernel build info displayed mean's were good to go
kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff
Console.ForegroundColor = ConsoleColor.Cyan
print "Kernel build: " + kMinorVer.ToString()

psHead = proc.GetSymValueLong("PsActiveProcessHead")
x = proc.xStructInfo("_EPROCESS")
ProcListOffsetOf = x.ActiveProcessLinks.Flink.OffsetPos
_EPROC = proc.xStructInfo("_EPROCESS", psHead - ProcListOffsetOf)
print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] " + _EPROC.SeAuditProcessCreationInfo.ImageFileName.Name.Value

xaddr = _EPROC.ActiveProcessLinks.Flink.Value - ProcListOffsetOf
_EPROC = proc.xStructInfo("_EPROCESS", xaddr)
print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] " + _EPROC.SeAuditProcessCreationInfo.ImageFileName.Name.Value

Vtero.VerboseLevel = 2


            
# if you want to write bytes, send bytes
#_EPROC.ImageFileName.Value = Encoding.ASCII.GetBytes("asdf3")

# string will get converted for you automatically 
#_EPROC.ImageFileName.Value = "string"