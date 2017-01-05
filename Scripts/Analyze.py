
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
# NtBuildNumber == kernel version
#

MemList = [
#"C:\\Users\\files\\VMs\\Windows Server 2008 x64 Standard\\Windows Server 2008 x64 Standard-ef068a0c.vmem",
#"c:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows 7 x64 ULT-360b98e6.vmem",
#"C:\\Users\\files\\VMs\\Windows 1511\\Windows.1511.vmem",
#"d:\\temp\\2012R2.debug.MEMORY.DMP",
#"d:\\temp\\server2016.xendump",
#"c:\\temp\\win10.64.xendump",
#"c:\\temp\\2012R2.xendump",
#"D:\\Users\\files\\VMs\\10-ENT-1607\\10 ENT 1607-Snapshot1.vmem",
"D:\\Users\\files\\VMs\\10-ENT-1607\\10 ENT 1607-bbbe109e.vmem",
#"D:\\Users\\files\\VMs\\Windows Development\\Windows Development-6d08357c.vmem"
]

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

TotalSizeAnalyzed = 0
Vtero.VerboseOutput = True
Vtero.DiagOutput = False
Vtero.VerboseLevel = 1

# This code fragment can be removed but it's a reminder you need symbols working
sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")
if String.IsNullOrWhiteSpace(sympath):
    sympath = "SRV*http://msdl.microsoft.com/download/symbols"

def ScanDump(MemoryDump):
    MemoryDumpSize = FileInfo(MemoryDump).Length
    # Basic option handling
    # This script can be pretty chatty to stdout 
    copts = ConfigOptions()
    copts.IgnoreSaveData = False
    copts.FileName = MemoryDump
    copts.VersionsToEnable = PTType.GENERIC
    # To get some additional output 
    copts.VerboseLevel = 0
    # Check StopWatch
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
    print "Assumed Kernel Proc: " + proc.ToString()
    vtero.KernelProc = proc
    vtero.CheckpointSaveState()
    proc.MemAccess = Mem(vtero.MemAccess)
    swModScan = Stopwatch.StartNew()
    # by default this will scan for kernel symbols 
    if vtero.KVS is None or vtero.KVS.Artifacts is None:
        kvs = proc.ScanAndLoadModules()
        vtero.KVS = kvs
        vtero.CheckpointSaveState()
    else:
        proc.LoadSymbols()
    kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff
    print "kernel minor version " + kMinorVer.ToString()
    # Use dynamic typing to walk EPROCES 
    logicalList = vtero.WalkProcList(proc)
    print "Physical Proc Count: " + proc_arr.Count.ToString()
    #for pproc in proc_arr:
    #    print pproc
    if logicalList is not None:
        print "Logical Proc Count: " + logicalList.Count.ToString()
        for proc in logicalList:
            # This is due to a structure member name change pre win 8
            if proc.Dictionary.ContainsKey("VadRoot.BalancedRoot.RightChild"):
                proc.VadRoot = proc.Dictionary["VadRoot.BalancedRoot.RightChild"]
            print proc.ImagePath + " : " + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + " : " + proc.VadRoot.ToString("X") +  " : " + proc.UniqueProcessId.ToString("X") 
        Console.ForegroundColor = ConsoleColor.Green;
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
                    print "An expected, ",
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
    print "PART RUNTIME: " + runTime.Elapsed.ToString() + " (seconds), INPUT DUMP SIZE: " + MemoryDumpSize.ToString("N") + " bytes."
    print "SPEED: " + ((MemoryDumpSize / 1024) / ((runTime.ElapsedMilliseconds / 1000)+1)).ToString("N0") + " KB / second  (all phases aggregate time)"
    return vtero

# Check StopWatch
TotalRunTime = Stopwatch.StartNew()
TotalSizeAnalyzed = 0

for MemoryDump in MemList:
    print " ++++++++++++++++++++++++++++++ ANALYZING INPUT [" + MemoryDump + "] ++++++++++++++++++++++++++++++ "
    if not File.Exists(MemoryDump):
        print "Can not find dump to analyze: " + MemoryDump
        continue
    vtero = ScanDump(MemoryDump)
    TotalSizeAnalyzed += vtero.FileSize
    print " ++++++++++++++++++++++++++++++ DONE WITH INPUT [" + MemoryDump + "] ++++++++++++++++++++++++++++++ "

print "TOTAL RUNTIME: " + TotalRunTime.Elapsed.ToString() + " (seconds), TOTAL DATA ANALYZED: " + TotalSizeAnalyzed.ToString("N") + " bytes."
print "SPEED: " + ((TotalSizeAnalyzed / 1024) / ((TotalRunTime.ElapsedMilliseconds / 1000)+1)).ToString("N0") + " KB / second  (all phases aggregate time)"
print "ALL DONE... Please explore!"


# This one is recursive down a tree
def ListVAD(proc, VadRoot):
    if VadRoot == 0:
        return
    pMMVadArr = proc.GetVirtualLong(VadRoot)
    mmvad = proc.xStructInfo("_MMVAD", pMMVadArr)
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
        subsect = proc.xStructInfo("_SUBSECTION", proc.GetVirtualLong(mmvad.Subsection.Value))
        control_area = proc.xStructInfo("_CONTROL_AREA", proc.GetVirtualLong(subsect.ControlArea.Value))
        segment = proc.xStructInfo("_SEGMENT", proc.GetVirtualLong(control_area.Segment.Value))
        # look for file pointer
        if control_area.FilePointer.Value != 0:
            file_pointer = proc.xStructInfo("_FILE_OBJECT", proc.GetVirtualLong(control_area.FilePointer.Value & -16))
            print "Mapped File: " + file_pointer.FileName.Value 
    # Core is the more recent kernels
    if mmvad.Dictionary.ContainsKey("Core"):
        ListVAD(proc, mmvad.Core.VadNode.Left.Value)
        ListVAD(proc, mmvad.Core.VadNode.Right.Value)
    else:
        ListVAD(proc, mmvad.LeftChild.Value)
        ListVAD(proc, mmvad.RightChild.Value)

# Here we walk another LIST_ENTRY
def WalkETHREAD(proc, eThreadHead):
    typedef = proc.xStructInfo("_ETHREAD")
    ThreadOffsetOf = typedef.ThreadListEntry.OffsetPos
    _ETHR_ADDR = eThreadHead
    while True:
        memRead = proc.GetVirtualLong(_ETHR_ADDR - ThreadOffsetOf)
        _ETHREAD = proc.xStructInfo("_ETHREAD", memRead)
        print "Thread [" + _ETHREAD.Cid.UniqueThread.Value.ToString("X") + "] BASE", 
        print "[0x" + _ETHREAD.Tcb.StackBase.Value.ToString("X") + "] LIMIT [0x" + _ETHREAD.Tcb.StackLimit.Value.ToString("X") + "]"
        _ETHR_ADDR = memRead[ThreadOffsetOf / 8]
        if _ETHR_ADDR == eThreadHead:
            return

def WalkModules(proc, ModLinkHead, Verbose):
    modlist = []
    _LDR_DATA_ADDR = ModLinkHead
    while True:
        memRead = proc.GetVirtualLong(_LDR_DATA_ADDR)
        _LDR_DATA = proc.xStructInfo("_LDR_DATA_TABLE_ENTRY", memRead)
        if Verbose:
            print "Loaded Base: 0x" + _LDR_DATA.DllBase.Value.ToString("x") + " Length: 0x" + _LDR_DATA.SizeOfImage.Value.ToString("x8") + " \t Module: " + _LDR_DATA.FullDllName.Value
        modlist.append(_LDR_DATA)
        _LDR_DATA_ADDR = memRead[0]
        if _LDR_DATA_ADDR == ModLinkHead:
            return modlist


def hives(proc):
    _HIVE_HEAD_ADDR = proc.GetSymValueLong("CmpHiveListHead")
    _HIVE_ADDR = _HIVE_HEAD_ADDR 
    typedef = proc.xStructInfo("_CMHIVE")
    hiveOffsetOf = typedef.HiveList.OffsetPos
    Path = ""
    while True:
        memRead = proc.GetVirtualLongLen(_HIVE_ADDR - hiveOffsetOf, typedef.Length)
        _HIVE2 = proc.xStructInfo("_CMHIVE", memRead)
        if _HIVE2.Hive.Signature.Value != 0xffbee0bee0:
            return
        print "next Hive Signature [" + _HIVE2.Hive.Signature.Value.ToString("x") + "] path: " + _HIVE2.HiveRootPath.Value
        _HIVE_ADDR = memRead[hiveOffsetOf/ 8]
        if _HIVE_HEAD_ADDR == _HIVE_ADDR:
            return

 
# Example of walking process list
def WalkProcListExample(proc):
    #
    #  WALK KERNEL 
    #
    print "Walking Kernel modules..."
    pModuleHead = proc.GetSymValueLong("PsLoadedModuleList")
    WalkModules(proc, pModuleHead, True)
    # Get a typedef 
    print "Walking Kernel processes..."
    x = proc.xStructInfo("_EPROCESS")
    ProcListOffsetOf = x.ActiveProcessLinks.Flink.OffsetPos
    ImagePath = ""
    psHead = proc.GetSymValueLong("PsActiveProcessHead")
    _EPROC_ADDR = psHead
    while True:
        memRead = proc.GetVirtualLong(_EPROC_ADDR - ProcListOffsetOf)
        _EPROC = proc.xStructInfo("_EPROCESS", memRead)
        ImagePath = _EPROC.SeAuditProcessCreationInfo.ImageFileName.Name.Value;
        # prep and acquire memory for strings
        _EPROC_ADDR = memRead[ProcListOffsetOf / 8]
        print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] EXE [" + ImagePath + "]",
        print " CR3/DTB [" + _EPROC.Pcb.DirectoryTableBase.Value.ToString("X") + "] VADROOT [" + _EPROC.VadRoot.Value.ToString("X") + "]"
        #print "PEB: " + _EPROC.Peb.Ldr
        if _EPROC.VadRoot.Value != 0:
            ListVAD(proc, _EPROC.VadRoot.Value)
        #if _EPROC.ThreadListHead.Value != 0:
        #    WalkETHREAD(proc, _EPROC.ThreadListHead.Value)
        if _EPROC_ADDR == psHead:
            return
            
