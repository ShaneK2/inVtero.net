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

PtrToStructure = Marshal.PtrToStructure.Overloads[IntPtr, Type]
#dissassemble proc & entrypoint
def dis(p, EntryPoint, len=128):
    bytes = p.GetVirtualByteLen(EntryPoint, len)
    #setup Capstone to find instruction to patch
    insnHandle = clr.Reference[IntPtr]()
    disHandle = clr.Reference[IntPtr]()
    csopen = Capstone.cs_open(Capstone.cs_arch.CS_ARCH_X86, Capstone.cs_mode.CS_MODE_64, disHandle)
    # intel diss
    csopt = Capstone.cs_option(disHandle.Value, 1, 1)
    # detail mode
    csopt = Capstone.cs_option(disHandle.Value, 2, 3)
    count = Capstone.cs_disasm(disHandle.Value, bytes, len, EntryPoint, 0, insnHandle)
    #print "capstone count = " + count.ToString()    
    curr = 0
    insn = Capstone.cs_insn()
    detail = Capstone.cs_detail()
    BuffOffset = insnHandle.ToInt64()
    insn_size = Marshal.SizeOf(insn)
    PatchAddr = 0
    NopCnt = 0
    Console.ForegroundColor = ConsoleColor.Green
    #find the last jne
    while curr < count:
        InsnPointer = IntPtr(BuffOffset)
        cs = PtrToStructure(InsnPointer, Capstone.cs_insn)
        print "[" + cs.address.ToString("x") + "] (" + p.GetSymName(cs.address)  + ") [" + cs.bytes[0].ToString("x") +"] " + cs.mnemonic + " " + cs.operands
        curr += 1
        BuffOffset += insn_size
    # clean up Capstone 
    Capstone.cs_close(disHandle)
    Capstone.cs_free(insnHandle.Value, count)
    Console.ForegroundColor = ConsoleColor.Yellow