
# MemoryDump is the file we are going to analyze
# Walk detected page tables, logical OS EPROC and more through dynamic language runtime (IronPython)
# Automagically works for XEN, VMWARE, many .DMP versions and RAW!
#
# NO PROFILE CONFIG OR ANYTHING FOR ALL WINDOWS OS!
#
# make sure to have dia registered do "regsvr32 c:\\windows\system32\msdia120.dll"
#
# you also want symsrv.dll and dbghelp.dll in the current folder =)
#
# Play with the PTType and stuff for nested hypervisors =)
#
# DLR reflected DIA symbols through physical memory
#

MemoryDump = "d:\\temp\\Windows 1511-Snapshot1.vmem"   

import clr,sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System import Environment, String

sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")
if String.IsNullOrWhiteSpace(sympath):
    sympath = "SRV*http://msdl.microsoft.com/download/symbols"

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = MemoryDump
copts.VersionsToEnable = PTType.GENERIC
# To get some additional output 
copts.VerboseOutput = False
copts.VerboseLevel = 1
Vtero.VerboseOutput = False
Vtero.DiagOutput = False
Vtero.DisableProgressBar = True

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

proc_arr = vtero.Processes.ToArray()
low_proc = proc_arr[0]
for proc in proc_arr:
    if proc.CR3Value < low_proc.CR3Value:
        low_proc = proc

proc = low_proc

# if we have save state we can skip this entirely
if vtero.KVS is None or vtero.KVS.Artifacts is None:
    #this thing is pretty expensive right now :(
    #at least it's threaded for you
    vtero.ModuleScan(proc)

vtero.CheckpointSaveState()

for detected in vtero.KVS.Artifacts:
    cv_data = vtero.ExtractCVDebug(proc, detected.Value, detected.Key)
    if cv_data is not None:
        if vtero.TryLoadSymbols(proc, detected.Value, cv_data, detected.Key, sympath):
            vtero.GetKernelDebuggerData(proc, detected.Value, cv_data, sympath)

vtero.CheckpointSaveState()

logicalList = vtero.WalkProcList(proc)

print "Physical Proc Count: " + proc_arr.Count.ToString()
for pproc in proc_arr:
    print pproc

print "Logical Proc Count: " + logicalList.Count.ToString()

for proc in logicalList:
    print proc.ImagePath + " : " + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + " : " + proc.VadRoot.ToString("X") +  " : " + proc.UniqueProcessId.ToString("X") 


for proc in logicalList:
    found=False
    for hwproc in proc_arr:
        if proc.Dictionary["Pcb.DirectoryTableBase"] == hwproc.CR3Value:
            found=True
    if found == False:
        print "can not match " + proc.ImagePath

