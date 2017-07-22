import clr
import sys
from sys import argv
import Analyze
clr.AddReferenceToFileAndPath("inVtero.net.dll")

from inVtero.net import *
from System.IO import Directory, File, FileInfo, Path
from System.Diagnostics import Stopwatch
from Analyze import QuickSetup

# p.ScanAndLoadModules("") for hal/ntos
# p.ScanAndLoadModules("", False) 

# Not finished, extract / handle NT object directory 
def DumpObj(o):
    oHdr = p.xStructInfo("_OBJECT_HEADER")
    TypeIndexTable = p.GetSymValueLong("ObTypeIndexTable")
    ObjHeaderAddr = o - oHdr.Body.OffsetPos
    oHdr = p.xStructInfo("_OBJECT_HEADER", ObjHeaderAddr)
    typeIdx = getattr(oHdr, "TypeIndex", None)
    #if typeIdx.Value is not None:
    #    ObjectTypeIndex = oHdr.TypeIndex
    #    print "do cookie " + typeIdx.Value.ToString()
    #else:
    #print oHdr.Type.Name

def Objects(p):
    RootDirectoryObject = p.GetSymValueLong("ObpRootDirectoryObject")
    HeaderCookie = p.GetSymValueLong("ObHeaderCookie")
    ObDir = p.xStructInfo("_OBJECT_DIRECTORY", RootDirectoryObject)
    for i in range(0, 37):
        entry = ObDir.HashBuckets.Value[i]
        oList = p.xStructInfo("_OBJECT_DIRECTORY_ENTRY", entry)
        while oList.ChainLink.vAddress != 0:
            DumpObj(oList.Object.Value)
            oList = p.xStructInfo("_OBJECT_DIRECTORY_ENTRY", oList.ChainLink.Value)

# Parsing for IDT / GDT
# there's actually more than one table, it's per CPU this isnt reading them out yet
def DescriptorTables(p):
    numProcs = p.GetSymValueLong("KeNumberProcessors") & 0xff
    pcrbDef = p.xStructInfo("_KPRCB")
    pcrDef = p.xStructInfo("_KPCR")
    kintDef = p.xStructInfo("_KINTERRUPT")
    firstPRCBAddress = p.GetSymValueLong("KiProcessorBlock")
    KPRCB = p.xStructInfo("_KPRCB", firstPRCBAddress, pcrbDef.Length)
    KPCR = p.xStructInfo("_KPCR", firstPRCBAddress & ~0xfff, pcrDef.Length)
    idt = p.xStructInfo("_KIDTENTRY64", KPCR.IdtBase.Value, 0x10)
    for i in range(0, 256):
        nextIdt = KPCR.IdtBase.Value+(i*0x10)
        entryidt = p.xStructInfo("_KIDTENTRY64", nextIdt, 0x10)
        isrAddr = (entryidt.OffsetHigh.Value & 0x0fffffff) << 32 | entryidt.OffsetMiddle.Value << 16 | entryidt.OffsetLow.Value
        kInt =  p.xStructInfo("_KINTERRUPT", isrAddr - kintDef.DispatchCode.OffsetPos, kintDef.Length)
        if kInt.Type.Value == 22:
            print "Routine Address: " + kInt.ServiceRoutine.Value.ToString("x") + " [" + p.GetSymName(kInt.ServiceRoutine.Value) + "]" + " type: " + kInt.Type.Value.ToString()
            print "List Entry: " + kInt.InterruptListEntry.Flink.Value.ToString("x")
    gdt = p.xStructInfo("_KGDTENTRY64", KPCR.GdtBase.Value, 0x10)
    for g in range(0, 256):
        gdt = p.xStructInfo("_KGDTENTRY64", KPCR.GdtBase.Value+(g*0x10), 0x10)
        Entry = (gdt.BaseUpper.Value & 0x0fffffff) << 32 | (gdt.Bytes.BaseHigh.Value << 24) | (gdt.Bytes.BaseMiddle.Value << 16) | gdt.BaseLow.Value;
        print "GDT: " + Entry.ToString("x") 

# Dump the SSDT
def ssdt(p):
    kMinorVer = p.GetSymValueLong("NtBuildNumber") & 0xffff
    KiServiceTable = p.GetSymValueLong("KeServiceDescriptorTable")
    KiServiceLimit = p.GetSymValueLong("KiServiceLimit") & 0xffffffff
    ntosBase = p.GetSymValueLong("PsNtosImageBase")
    ntosEnd = p.GetSymValueLong("PsNtosImageEnd")
    ntosLen = ntosEnd - ntosBase
    Address = KiServiceTable
    for i in range(0, KiServiceLimit/8):
        Offset = p.GetUIntValue(Address) 
        if kMinorVer < 6000:
            Offset = Offset & ~0xf
        else:
            Offset = Offset >> 4
        ServiceAddress = KiServiceTable + Offset
        print "ServiceDescriptor entry: " + ServiceAddress.ToString("x") + " [" + p.GetSymName(ServiceAddress) + "]"
        Address = Address + 8
        # dissassemble with capstone
        if ServiceAddress > ntosEnd or ServiceAddress < ntosBase:
            print "ServiceDescriptor is out of kernel bounds! " + ServiceAddress.ToString("x")
