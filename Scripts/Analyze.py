
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

MemoryDump = "C:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows 7 x64 ULT-360b98e6.vmem"   
import clr,sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System import Environment, String, Console, ConsoleColor
from System.Diagnostics import Stopwatch

MemoryDumpSize = FileInfo(MemoryDump).Length

sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")
if String.IsNullOrWhiteSpace(sympath):
    sympath = "SRV*http://msdl.microsoft.com/download/symbols"

# Basic option handling
# This script can be pretty chatty to stdout 
# 
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = MemoryDump
copts.VersionsToEnable = PTType.Windows
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1
Vtero.VerboseOutput = True
Vtero.DiagOutput = True

runTime = Stopwatch.StartNew()

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

proc_arr = vtero.Processes.ToArray()
low_proc = proc_arr[0]
for proc in proc_arr:
    if proc.CR3Value < low_proc.CR3Value:
        low_proc = proc

proc = low_proc

swModScan = Stopwatch.StartNew()
# if we have save state we can skip this entirely
if vtero.KVS is None or vtero.KVS.Artifacts is None:
    #this thing is pretty expensive right now :(
    #at least it's threaded for you
    vtero.ModuleScan(proc)
    print "Module Scan time: " + swModScan.Elapsed.ToString()

vtero.CheckpointSaveState()

# Symbol scan using GUID & DWORD methods
# If you can't match symbols you can use other API for most goals
for detected in vtero.KVS.Artifacts:
    cv_data = vtero.ExtractCVDebug(proc, detected.Value, detected.Key)
    if cv_data is not None:
        if vtero.TryLoadSymbols(proc, detected.Value, cv_data, detected.Key, sympath):
            vtero.GetKernelDebuggerData(proc, detected.Value, cv_data, sympath)

vtero.CheckpointSaveState()

# Use dynamic typing to walk EPROCES 
logicalList = vtero.WalkProcList(proc)

print "Physical Proc Count: " + proc_arr.Count.ToString()
for pproc in proc_arr:
    print pproc

print "Logical Proc Count: " + logicalList.Count.ToString()

for proc in logicalList:
    if proc.Dictionary.ContainsKey("VadRoot.BalancedRoot.RightChild"):
        proc.VadRoot = proc.Dictionary["VadRoot.BalancedRoot.RightChild"]
    print proc.ImagePath + " : " + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + " : " + proc.VadRoot.ToString("X") +  " : " + proc.UniqueProcessId.ToString("X") 


Console.ForegroundColor = ConsoleColor.Green;
print "Green text is OK++"
print "checking that all logical processes exist in the physical list."
# Miss list mostly bad for yellow printing  
for proc in logicalList:
    found=False
    for hwproc in proc_arr:
        if proc.Dictionary["Pcb.DirectoryTableBase"] == hwproc.CR3Value:
            found=True
    if found == False:
        Console.ForegroundColor = ConsoleColor.Yellow;
        if proc.VadRoot == 0:
            Console.ForegroundColor = ConsoleColor.Green;
        print "Logical miss for " + proc.ImagePath + " : " + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + " : " + proc.VadRoot.ToString("X") +  " : " + proc.UniqueProcessId.ToString("X") 

print "Checking that all physical processes exist in the logical list"
for hwproc in proc_arr:
    Found=False
    for proc in logicalList:
        if proc.Dictionary["Pcb.DirectoryTableBase"] == hwproc.CR3Value:
            found=True
    if found == False:
        Console.ForegroundColor = ConsoleColor.Yellow;
        if proc.VadRoot == 0:
            Console.ForegroundColor = ConsoleColor.Green;
            print "An expected, ",
        print "physical miss for " + proc.ImagePath + " : " + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + " : " + proc.VadRoot.ToString("X") +  " : " + proc.UniqueProcessId.ToString("X") 
 
print "TOTAL RUNTIME: " + runTime.Elapsed.ToString() + " (seconds), INPUT DUMP SIZE: " + MemoryDumpSize.ToString("N") + " bytes."
print "SPEED: " + ((MemoryDumpSize / 1024) / ((runTime.ElapsedMilliseconds / 1000)+1)).ToString("N0") + " KB / second  (all phases aggregate time)"
print "ALL DONE... Please explore!"