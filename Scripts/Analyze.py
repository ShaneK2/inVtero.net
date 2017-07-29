
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
# make sure to have dia registered do "regsvr32 c:\\windows\system32\msdia140.dll"
# you also want symsrv.dll and dbghelp.dll in the current folder =)
#
# Play with the PTType and stuff for nested hypervisors =) (PTTYPE VMCS)
#
# NtBuildNumber == kernel version
#
import clr,sys
import System
clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")
from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from inVtero.net.Hashing import *
from System.IO import Directory, File, FileInfo, Path
from System import Environment, String, Console, ConsoleColor
from System import Text
from System.Diagnostics import Stopwatch
from List import *

print "\n\n\tCurrent directory [" + Directory.GetCurrentDirectory() + "]"

# This script can be pretty chatty to stdout, configure various output here
Vtero.VerboseOutput = True
Vtero.DiagOutput = False
Vtero.VerboseLevel = 1
Vtero.DisableProgressBar = True

# More option handling for each file 
copts = ConfigOptions()
copts.IgnoreSaveData = True
copts.VersionsToEnable = PTType.GENERIC 
copts.VerboseLevel = 1
# in the case of some dump tools (ENCASE) use this option 
#copts.ForceSingleFlatMemRun = True


# This code fragment can be removed but it's a reminder you need symbols working
sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")
if String.IsNullOrWhiteSpace(sympath):
    sympath = "SRV*http://msdl.microsoft.com/download/symbols"

hwmiss = []

def ScanDump(MemoryDump, copts):
    MemoryDumpSize = FileInfo(MemoryDump).Length
    copts.FileName = MemoryDump
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
    #vtero.CheckpointSaveState()
    proc.MemAccess = Mem(vtero.MemAccess)
    #swModScan = Stopwatch.StartNew()
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
        Console.ForegroundColor = ConsoleColor.Green
        print "checking that all logical processes exist in the physical list."
        # Miss list mostly bad for yellow printing  
        for proc in logicalList:
            found=False
            for hwproc in proc_arr:
                if proc.Dictionary["Pcb.DirectoryTableBase"] == hwproc.CR3Value:
                    found=True
                    #print "Found logical proc[" + hwproc.CR3Value.ToString("X") + "] in physical array"
            if found == False:
                Console.ForegroundColor = ConsoleColor.Yellow
                if proc.VadRoot == 0:
                    Console.ForegroundColor = ConsoleColor.Green
                    print "An expected, ",
                print "Logical miss for " + proc.ImagePath + " : " + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + " : " + proc.VadRoot.ToString("X") +  " : " + proc.UniqueProcessId.ToString("X") 
        print "Checking that all physical processes exist in the logical list"
        for hwproc in proc_arr:
            found=False
            for proc in logicalList:
                if proc.Dictionary["Pcb.DirectoryTableBase"] == hwproc.CR3Value:
                    found=True
                    #print "Found physical proc[" + proc.Dictionary["Pcb.DirectoryTableBase"].ToString("X") + "] in logical array"
            if found == False:
                Console.ForegroundColor = ConsoleColor.Yellow
                hwmiss.append(hwproc)
                print "physical miss for " + hwproc.ToString()
    Console.ForegroundColor = ConsoleColor.White
    print "PART RUNTIME: " + runTime.Elapsed.ToString() + " (seconds), INPUT DUMP SIZE: " + MemoryDumpSize.ToString("N") + " bytes."
    print "SPEED: " + ((MemoryDumpSize / 1024) / ((runTime.ElapsedMilliseconds / 1000)+1)).ToString("N0") + " KB / second  (all phases aggregate time)"
    return vtero

# This one is recursive down a tree
def ListVAD(proc, VadRoot):
    if VadRoot == 0:
        return
    #pMMVadArr = proc.GetVirtualLong(VadRoot)
    mmvad = proc.xStructInfo("_MMVAD", VadRoot)
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
        subsect = proc.xStructInfo("_SUBSECTION", mmvad.Subsection.Value)
        control_area = proc.xStructInfo("_CONTROL_AREA", subsect.ControlArea.Value)
        #segment = proc.xStructInfo("_SEGMENT", control_area.Segment.Value)
        # look for file pointer
        if control_area.FilePointer.Value != 0:
            file_pointer = proc.xStructInfo("_FILE_OBJECT", control_area.FilePointer.Value & -16)
            print "Mapped File: " + file_pointer.FileName.Value 
        else:
            print "Mapped anonymous memory " + mmvad.Core.StartingVpn.Value.ToString("x")
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
    print "top reading thread " + _ETHR_ADDR.ToString("x") + "-" + ThreadOffsetOf.ToString("x") + "=" + (_ETHR_ADDR - ThreadOffsetOf).ToString("X")
    _ETHREAD = proc.xStructInfo("_ETHREAD", _ETHR_ADDR - ThreadOffsetOf)
    while True:
        print "Thread [" + _ETHREAD.Cid.UniqueThread.Value.ToString("X") + "] BASE", 
        print "[0x" + _ETHREAD.Tcb.StackBase.Value.ToString("X") + "] LIMIT [0x" + _ETHREAD.Tcb.StackLimit.Value.ToString("X") + "]"
        _ETHR_ADDR = _ETHREAD.ThreadListEntry.Value
        if _ETHR_ADDR == eThreadHead:
            return
        _ETHREAD = proc.xStructInfo("_ETHREAD", _ETHR_ADDR - ThreadOffsetOf)
        print "top reading thread " + _ETHR_ADDR.ToString("x") + "-" + ThreadOffsetOf.ToString("x") + "=" + (_ETHR_ADDR - ThreadOffsetOf).ToString("X")


def WalkModules(proc, ModLinkHead, Verbose):
    modlist = []
    _LDR_DATA_ADDR = ModLinkHead
    while True:
        _LDR_DATA = proc.xStructInfo("_LDR_DATA_TABLE_ENTRY", _LDR_DATA_ADDR)
        if Verbose:
            print "Loaded Base: 0x" + _LDR_DATA.DllBase.Value.ToString("x") + " EntryPoint: 0x" + _LDR_DATA.EntryPoint.Value.ToString("x") + " Length: 0x" + _LDR_DATA.SizeOfImage.Value.ToString("x8") + " \t Module: " + _LDR_DATA.FullDllName.Value
        modlist.append(_LDR_DATA)
        _LDR_DATA_ADDR = _LDR_DATA.InLoadOrderLinks.Flink.Value
        if _LDR_DATA_ADDR == ModLinkHead:
            return modlist


def WalkList(proc, type, ptr, head, offsetOf, typeLen):
    while ptr != head:
        if ptr == None or ptr == 0:
            ptr = head
        yield proc.xStructInfo(type, ptr - offsetOf, typeLen)

# Walk registry hives
def hives(proc):
    h = WalkList(p, "_CMHIVE", _HIVE_HEAD_ADDR, hiveOffsetOf)
    for x in h:
        print "HiveRootPath: " + x.Obj.HiveRootPath.Value
        print "FileUserName: " + x.Obj.FileUserName.Value

# YaraRules = "c:\\temp\\yara\\index.yar"
# Do a parallel Yara Scan
def YaraAll(YaraRules, vtero):
    Vtero.VerboseLevel = 1
    Vtero.DiagOutput = False
    dumptime = Stopwatch.StartNew()
    yall = vtero.YaraAll(YaraRules, True, False)
    print "elapsed " + dumptime.Elapsed.ToString()
    return yall

def QuickSetup(MemoryDump, IgnoreSave = False):
    # Basic option handling
    copts = ConfigOptions()
    copts.IgnoreSaveData = IgnoreSave
    copts.FileName = MemoryDump
    copts.VersionsToEnable = PTType.GENERIC
    copts.VerboseOutput = False
    copts.VerboseLevel = 0
    # Vtero options are global
    Vtero.DiagOutput = False
    Vtero.VerboseLevel = 0
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
    logicalList = vtero.WalkProcList(vtero.KernelProc)
    return vtero

#########################################################################
# search symbols like this
# SymList(proc, "*POOL*")
# pretty print symbols matching string
#########################################################################
def SymList(proc, MatchString):
    for match in proc.MatchSymbols(MatchString):
        print match.Item1 + " @ 0x" + match.Item2.ToString("x")
 
def dt(dynObj):
    print dynObj.TypeName,
    print " len: 0x" + dynObj.Length.ToString("x")
    for member in dynObj.Dictionary.Keys:
        pyMember = getattr(dynObj, member, None)
        print "  +0x" + pyMember.OffsetPos.ToString("x"),
        currName = pyMember.MemberName.split(".")
        print currName[currName.Count-1] + "\t\t:",
        bitPos = getattr(pyMember, "BitPosition", None)
        bitCnt = getattr(pyMember, "BitCount", None)
        if bitPos is not None:
            print "Pos " + bitPos.ToString() + ", " + bitCnt.ToString() + " Bits",
        prop = getattr(pyMember, "IsPtr", None)
        if prop:
            print "*",
            ptrType = getattr(pyMember, "PtrTypeName", None) 
            if ptrType is not None:
                print ptrType,
        arrCnt = getattr(pyMember, "ArrayCount", None)
        if arrCnt is not None:
            print "[" + arrCnt.ToString() + "] ",
            arrType = getattr(pyMember, "ArrayMemberType", None)
            if arrType is not None:
                print arrType,
            print " member len(" + pyMember.ArrayMemberLen.ToString() + ")",
        typName = getattr(pyMember, "TypeName", None)
        if typName is not None:
            print typName,
        value = getattr(pyMember, "ConstValue", None)
        if value is not None:
            print "0x" + value.ToString("x"),
        print " len(0x" + pyMember.Length.ToString("x") + ")",
        if dynObj.Dictionary[member] is not None:
            print " = 0x" + dynObj.Dictionary[member].ToString("x")
        else:
            print " "



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
    _EPROC = proc.xStructInfo("_EPROCESS", psHead - ProcListOffsetOf)
    while True:
        # Deeply hidden value in _EPROCESS to find full path!! ;)
        ImagePath = _EPROC.SeAuditProcessCreationInfo.ImageFileName.Name.Value
        print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] EXE [" + ImagePath + "]",
        # Nice to see members
        print " CR3/DTB [" + _EPROC.Pcb.DirectoryTableBase.Value.ToString("X") + "] VADROOT [" + _EPROC.VadRoot.Value.ToString("X") + "]"
        # Walk VAD & look for +X file mapped entries
        if _EPROC.VadRoot.Value != 0:
            ListVAD(proc, _EPROC.VadRoot.Value)
        # Depending on Thr Count this takes too long
        #if _EPROC.ThreadListHead.Value != 0:
        #    WalkETHREAD(proc, _EPROC.ThreadListHead.Value)
        # We read this 2x, simply readability ? =)
        _EPROC_ADDR = _EPROC.ActiveProcessLinks.Flink.Value
        if _EPROC_ADDR == psHead:
            return
        _EPROC = proc.xStructInfo("_EPROCESS", _EPROC_ADDR - ProcListOffsetOf)
            
vtero = None

def test(MemList):
    TotalRunTime = Stopwatch.StartNew()
    TotalSizeAnalyzed = 0
    for MemoryDump in MemList:
        print " ++++++++++++++++++++++++++++++ ANALYZING INPUT [" + MemoryDump + "] ++++++++++++++++++++++++++++++ "
        if not File.Exists(MemoryDump):
            print "Can not find dump to analyze: " + MemoryDump
            continue
        copts.FileName = MemoryDump
        vtero = ScanDump(MemoryDump, copts)
        TotalSizeAnalyzed += vtero.FileSize
        print " ++++++++++++++++++++++++++++++ DONE WITH INPUT [" + MemoryDump + "] ++++++++++++++++++++++++++++++ "
    print " ++++++++++++++++++++++++++++++ ALL DONE... Please explore! ++++++++++++++++++++++++++++++"
    print "TOTAL RUNTIME: " + TotalRunTime.Elapsed.ToString() + " (seconds), TOTAL DATA ANALYZED: " + TotalSizeAnalyzed.ToString("N") + " bytes."
    print "SPEED: " + ((TotalSizeAnalyzed / 1024) / ((TotalRunTime.ElapsedMilliseconds / 1000)+1)).ToString("N0") + " KB / second  (all phases aggregate time)"
    return vtero







