
# MemoryDump is the file we are going to analyze
# Walk detected page tables, logical OS EPROC and more through dynamic language runtime (IronPython)
# Automagically works for XEN, VMWARE, many .DMP versions and RAW!
#
# NO PROFILE CONFIG OR ANYTHING FOR ALL WINDOWS OS!
#
# YOU DO NEED TO HAVE SYMBOLS CONFIGURED.
# IF A GUID IS NOT FOUND, FIND IT MAY BE ON THE SYM CD WHICH IS NOT ON THE SERVER
#
# DLR reflected DIA symbols through physical memory
# make sure to have dia registered do "regsvr32 c:\\windows\system32\msdia120.dll"
# you also want symsrv.dll and dbghelp.dll in the current folder =)
#
# Play with the PTType and stuff for nested hypervisors =) (PTTYPE VMCS)
#
#MemoryDump = "C:\\Users\\files\\VMs\\Windows Server 2008 x64 Standard\\Windows Server 2008 x64 Standard-ef068a0c.vmem"   
#MemoryDump = "C:\\Users\\files\\VMs\\Windows 1511\\Windows.1511.vmem"   
#MemoryDump = "d:\\temp\\2012R2.debug.MEMORY.DMP"
#MemoryDump = "d:\\temp\\server2016.xendump"
#MemoryDump = "c:\\temp\\win10.64.xendump"
MemoryDump = "c:\\temp\\2012R2.xendump"
#MemoryDump = "D:\\Users\\files\\VMs\\10-ENT-1607\\10 ENT 1607-Snapshot1.vmem"
#MemoryDump = "D:\\Users\\files\\VMs\\Windows Development\\Windows Development-6d08357c.vmem"

import clr,sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System import Environment, String, Console, ConsoleColor
from System import Text
from System.Diagnostics import Stopwatch

MemoryDumpSize = FileInfo(MemoryDump).Length

# This code fragment can be removed but it's a reminder you need symbols working
sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")
if String.IsNullOrWhiteSpace(sympath):
    sympath = "SRV*http://msdl.microsoft.com/download/symbols"

# Basic option handling
# This script can be pretty chatty to stdout 
# 
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = MemoryDump
copts.VersionsToEnable = PTType.GENERIC
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
    #it's an optimized kernel scan at this time
    likelyKernelModules = vtero.ModuleScan(proc)
    print "Module Scan time: " + swModScan.Elapsed.ToString()

vtero.CheckpointSaveState()

# this initial pass for module scan should only be for Kernel
for section in proc.Sections:
    vtero.ExtractCVDebug(proc, section)
    if section.DebugDetails is not None:
        if vtero.TryLoadSymbols(section.DebugDetails, section.VA.Address, sympath) == True:
            vtero.KernelProc = proc

# Symbol scan using GUID & DWORD methods
# If you can't match symbols you can use other API for most goals
# BUGBUG: weird bug you have to run this twice, not a big deal since we
# do get past a checkpoint.  Need to review protobuf code around here
#for detected in vtero.KVS.Artifacts:
#    cv_data = vtero.ExtractCVDebug(proc, detected.Value, detected.Key)
#    if cv_data is not None:
#        if vtero.TryLoadSymbols(cv_data, detected.Key, sympath):
#            vtero.GetKernelDebuggerData(proc, detected.Value, cv_data, sympath)

vtero.CheckpointSaveState()

# Use dynamic typing to walk EPROCES 
logicalList = vtero.WalkProcList(proc)

print "Physical Proc Count: " + proc_arr.Count.ToString()
for pproc in proc_arr:
    print pproc

if logicalList is not None:
    print "Logical Proc Count: " + logicalList.Count.ToString()
    for proc in logicalList:
        # This is due to a structure member name change pre win 8
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

# Get detected symbol file to use for loaded vtero
symFile = ""
for section in vtero.KernelProc.Sections:
    if section.DebugDetails.PDBFullPath.Contains("ntkrnlmp"):
        symFile = section.DebugDetails.PDBFullPath

# This one is recursive down a tree
def ListVAD(VadRoot):
    if VadRoot == 0:
        return
    pMMVadArr = vtero.KernelProc.GetVirtualLong(VadRoot)
    mmvad = vtero.SymForKernel.xStructInfo(symFile,"_MMVAD", pMMVadArr)
    IsExec = False
    # This is to support 7 and earlier kernels
    if mmvad.Dictionary.ContainsKey("Core"):
        if mmvad.Core.u.VadFlags.Protection.Value & 2 != 0:
            IsExec = True
    else:
        # TODO: Double check this one! 
        if mmvad.u.VadFlags.Protection.Value & 2 != 0:
            IsExec = True
    # Check VAD Flags for execute permission before we spend time looking at this entry
    if IsExec:
        subsect = vtero.SymForKernel.xStructInfo(symFile,"_SUBSECTION", vtero.KernelProc.GetVirtualLong(mmvad.Subsection.Value))
        control_area = vtero.SymForKernel.xStructInfo(symFile,"_CONTROL_AREA", vtero.KernelProc.GetVirtualLong(subsect.ControlArea.Value))
        segment = vtero.SymForKernel.xStructInfo(symFile,"_SEGMENT", vtero.KernelProc.GetVirtualLong(control_area.Segment.Value))
        # look for file pointer
        if control_area.FilePointer.Value != 0:
            file_pointer = vtero.SymForKernel.xStructInfo(symFile,"_FILE_OBJECT", vtero.KernelProc.GetVirtualLong(control_area.FilePointer.Value & -16))
            fileNameByteArr = vtero.KernelProc.GetVirtualByte(file_pointer.FileName.Buffer.Value)
            fileNameString = Text.Encoding.Unicode.GetString(fileNameByteArr).Split('\x00')[0]
            print "Mapped File: " + fileNameString 
    # Core is the more recent kernels
    if mmvad.Dictionary.ContainsKey("Core"):
        ListVAD(mmvad.Core.VadNode.Left.Value)
        ListVAD(mmvad.Core.VadNode.Right.Value)
    else:
        ListVAD(mmvad.LeftChild.Value)
        ListVAD(mmvad.RightChild.Value)

# Here we walk another LIST_ENTRY
def WalkETHREAD(eThreadHead):
    typedef = vtero.SymForKernel.xStructInfo(symFile,"_ETHREAD")
    ThreadOffsetOf = typedef.ThreadListEntry.OffsetPos
    _ETHR_ADDR = eThreadHead
    while True:
        memRead = vtero.KernelProc.GetVirtualLong(_ETHR_ADDR - ThreadOffsetOf)
        _ETHREAD = vtero.SymForKernel.xStructInfo(symFile,"_ETHREAD", memRead)
        print "Thread [" + _ETHREAD.Cid.UniqueThread.Value.ToString("X") + "] BASE", 
        print "[0x" + _ETHREAD.Tcb.StackBase.Value.ToString("X") + "] LIMIT [0x" + _ETHREAD.Tcb.StackLimit.Value.ToString("X") + "]"
        _ETHR_ADDR = memRead[ThreadOffsetOf / 8]
        if _ETHR_ADDR == eThreadHead:
            return

def WalkModules(ModLinkHead):
    ImagePath = ""
    _LDR_DATA_ADDR = ModLinkHead
    while True:
        memRead = vtero.KernelProc.GetVirtualLong(_LDR_DATA_ADDR)
        _LDR_DATA = vtero.SymForKernel.xStructInfo(symFile,"_LDR_DATA_TABLE_ENTRY", memRead)
        ImagePathPtr = memRead[(_LDR_DATA.FullDllName.OffsetPos+8) / 8]
        if ImagePathPtr != 0:
            ImagePathArr =  vtero.KernelProc.GetVirtualByte(ImagePathPtr)
            ImagePath = Text.Encoding.Unicode.GetString(ImagePathArr).Split('\x00')[0]
        else:
            ImagePath = ""
        print "Loaded Base: 0x" + _LDR_DATA.DllBase.Value.ToString("x") + " Length: 0x" + _LDR_DATA.SizeOfImage.Value.ToString("x8") + " \t Module: " + ImagePath
        _LDR_DATA_ADDR = memRead[0]
        if _LDR_DATA_ADDR == ModLinkHead:
            return

# Example of walking process list
def WalkProcListExample():
    #
    #  WALK KERNEL 
    #
    print "Walking Kernel modules..."
    pModuleHead = vtero.GetSymValueLong(vtero.KernelProc,"PsLoadedModuleList")
    WalkModules(pModuleHead)
    # Get a typedef 
    print "Walking Kernel processes..."
    x = vtero.SymForKernel.xStructInfo(symFile,"_EPROCESS")
    ProcListOffsetOf = x.ActiveProcessLinks.Flink.OffsetPos
    ImagePath = ""
    psHead = vtero.GetSymValueLong(vtero.KernelProc,"PsActiveProcessHead")
    _EPROC_ADDR = psHead
    while True:
        memRead = vtero.KernelProc.GetVirtualLong(_EPROC_ADDR - ProcListOffsetOf)
        _EPROC = vtero.SymForKernel.xStructInfo(symFile,"_EPROCESS", memRead)
        # prep and acquire memory for strings
        # TODO: We should scan structures for UNICODE_STRING automatically since extracting them is something * wants
        ImagePtrIndex = _EPROC.SeAuditProcessCreationInfo.ImageFileName.OffsetPos / 8
        ImagePathPtr = memRead[ImagePtrIndex];
        if ImagePathPtr != 0:
            ImagePathArr =  vtero.KernelProc.GetVirtualByte(ImagePathPtr + 0x10)
            ImagePath = Text.Encoding.Unicode.GetString(ImagePathArr).Split('\x00')[0]
        else:
            ImagePath = ""
        _EPROC_ADDR = memRead[ProcListOffsetOf / 8]
        print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] EXE [" + ImagePath + "]",
        print " CR3/DTB [" + _EPROC.Pcb.DirectoryTableBase.Value.ToString("X") + "] VADROOT [" + _EPROC.VadRoot.Value.ToString("X") + "]"
        if _EPROC.VadRoot.Value != 0:
            ListVAD(_EPROC.VadRoot.Value)
        if _EPROC.ThreadListHead.Value != 0:
            WalkETHREAD(_EPROC.ThreadListHead.Value)
        if _EPROC_ADDR == psHead:
            return
            
