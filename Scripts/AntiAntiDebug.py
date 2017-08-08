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

#MemoryDump = "C:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows 7 x64 ULT-360b98e6.vmem"

MemoryDump = "D:\\Users\\files\\VMs\\Windows Server 2016\\Windows Server 2016-02431799.vmem"

###
#
#  You have to set AllowWrite to enable write-back support for dynamic objects
#  This is a safety measure so nothing changes under the hood by mistake
#  Vtero.VerboseLevel 2+ will write detailed information when write's occur
#
###
Vtero.AllowWrite = True

vtero = QuickSetup(MemoryDump)



## having the kernel build info displayed mean's were good to go
#kMinorVer = proc.GetSymValueLong("NtBuildNumber") & 0xffff
#Console.ForegroundColor = ConsoleColor.Cyan
#print "Kernel build: " + kMinorVer.ToString()

#psHead = proc.GetSymValueLong("PsActiveProcessHead")
#x = proc.xStructInfo("_EPROCESS")
#ProcListOffsetOf = x.ActiveProcessLinks.Flink.OffsetPos
#_EPROC = proc.xStructInfo("_EPROCESS", psHead - ProcListOffsetOf)
#print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] " + _EPROC.SeAuditProcessCreationInfo.ImageFileName.Name.Value

xaddr = _EPROC.ActiveProcessLinks.Flink.Value - ProcListOffsetOf
_EPROC = proc.xStructInfo("_EPROCESS", xaddr)
print "Process ID [" + _EPROC.UniqueProcessId.Value.ToString("X") + "] " + _EPROC.SeAuditProcessCreationInfo.ImageFileName.Name.Value

#Vtero.VerboseLevel = 2


            
# if you want to write bytes, send bytes
#_EPROC.ImageFileName.Value = Encoding.ASCII.GetBytes("asdf3")

# string will get converted for you automatically 
#_EPROC.ImageFileName.Value = "string"