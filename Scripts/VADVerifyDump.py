import clr
import sys
from sys import argv

import Analyze

clr.AddReferenceToFileAndPath("inVtero.net.dll")

from inVtero.net import *
from System.Diagnostics import Stopwatch
from System import Environment, String, ConsoleColor
from System.IO import File
from inVtero.net.Hashing import MetaDB

from Analyze import QuickSetup

#testFile = "C:\\Users\\files\\VMs\\Windows 10 x64-PRO-1703\\Windows 10 x64-PRO-1703-40599dd1.vmem"
#testFile = "d:\\Users\\files\\VMs\\Windows Server 2016\\Windows Server 2016-02431799.vmem"
#testFile = "C:\\Users\\files\\VMs\\Windows Server 2008 x64 Standard\\Windows Server 2008 x64 Standard-ef068a0c.vmem"

#testFile = "C:\\Users\\files\\VMs\\Windows 10 x64-PRO-1703\\Windows 10 x64-PRO-1703-40599dd1.vmem"
#testFile = "C:\\Users\\files\\VMs\\MSEdge.Win10_preview.VMWare\\MSEdge - Win10_preview-411af900.vmem"
#testFile = "C:\\Users\\files\\VMs\\MSEdge.Win10.RS2.VMWare\\MSEdge - Win10_preview\\MSEdge - Win10_preview-e70efcb2.vmem"
testFile = "c:\\temp\\minidump.dmp"
print "Scanning input: " + testFile

TotalRunTime = Stopwatch.StartNew()
aBufferCount = 60000000

# local we have insane size capability
mdb = MetaDB("c:\\temp\\inVtero.net", 256, 1024*1024*1024*16, aBufferCount)
#cloud is 4096 for now
#mdb = MetaDB("c:\\temp\\inVtero.net", 4096, 1024*1024*1024*16, aBufferCount)

mdb.cLoader.MaxBatchParallel = 200

vtero = QuickSetup(testFile)

Vtero.VerboseLevel = 1

# default hash lookup scan
#vtero.HashAllProcs(mdb)
#
# This is bitmap mode
#vtero.HashAllProcs(mdb, True, False)
# setup cloud scan, using the 256 byte block size specified in the MetaDB instance
vtero.HashAllProcs(mdb, False, True)

print "Done! Total runtime: " + TotalRunTime.Elapsed.ToString()


