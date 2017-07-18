#
# Demo of how to pool scan with python CLI
# Most of this converted from windbg module from https://github.com/fishstiqz/poolinfo
#
#
import clr
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System.Diagnostics import Stopwatch
from System import Environment, String, Console, ConsoleColor
from inVtero.net.Hashing import *
from inVtero.net.Support import Strings
from System.Text.RegularExpressions import Regex, RegexOptions
from System.Text import Encoding

FileName = "C:\\temp\\server2016.xendump"   

vtero = QuickSetup(FileName)

p = vtero.KernelProc

# lots of lookaside's for pool data if we want to get tehm
#_LOOKASIDE_LIST_EX @ 0x0
#_NPAGED_LOOKASIDE_LIST @ 0x0
#_PAGED_LOOKASIDE_LIST @ 0x0
#_PP_LOOKASIDE_LIST @ 0x0
#_PP_NPAGED_LOOKASIDE_NUMBER @ 0x0
#_GENERAL_LOOKASIDE @ 0x0
#_GENERAL_LOOKASIDE_POOL @ 0x0
#_ALPC_COMPLETION_PACKET_LOOKASIDE @ 0x0
#_ALPC_COMPLETION_PACKET_LOOKASIDE_ENTRY @ 0x0
#_HEAP_LOOKASIDE @ 0x0

NPPoolDescs = []
PPoolDescs = []
PoolDescs = []

# get typedefs mostly for length checks
POOL_DESC = p.xStructInfo("_POOL_DESCRIPTOR")
pcrbDef = p.xStructInfo("_KPRCB")
POOL_HEAD = p.xStructInfo("_POOL_HEADER")
#ExpSessionPoolLookaside

# Processor control block info is handy
KPRCB = p.xStructInfo("_KPRCB", p.GetSymValueLong("KiProcessorBlock"), pcrbDef.Length)

numProcs = p.GetSymValueLong("KeNumberProcessors") & 0xff

# Paged Pool info
NumPaged  = p.GetSymValueLong("ExpNumberOfPagedPools") + 1
kDescList  = p.GetSymValueLong("ExpPagedPoolDescriptor")
for x in range(0, numProcs):
    PPoolDescs.append(p.xStructInfo("_POOL_DESCRIPTOR", kDescList + (x*8)))

# NonPaged Pools follow CPU count

kNonPDescList = p.GetSymValueLong("ExpNonPagedPoolDescriptor")
kVectorBase = p.GetSymValueLong("PoolVector")
for x in range(0, numProcs):
    NPPoolDescs.append(p.xStructInfo("_POOL_DESCRIPTOR", kNonPDescList + (x*8)))

cnt = 0
runTime = Stopwatch.StartNew()
###
# "strings" like functionality (UNICODE/UTF8/ASCII) modes/regex
###
#regx = Regex("\w{5,}", RegexOptions.Compiled)
#for s in Strings.SimpleRegex(regx, vtero.KernelProc):
#    print s.Item1.ToString("X") + " " + s.Item2
#    cnt += 1

###
# This is a full address space search
###
#find = "Vad "
#for addr in Strings.ByteScan(Encoding.ASCII.GetBytes(find), vtero.KernelProc, 4):
#    cnt += 1
#    print addr.ToString("X")

print runTime.Elapsed.ToString()
print "found: " + cnt.ToString()

