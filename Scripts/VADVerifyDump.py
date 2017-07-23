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

testFile = "C:\\Users\\files\\VMs\\Windows 10 x64-PRO-1703\\Windows 10 x64-PRO-1703-40599dd1.vmem"
#testFile = "C:\\Users\\files\\VMs\\Windows 7 x64 ULT\\Windows 7 x64 ULT-360b98e6.vmem"
#testFile = "C:\\Users\\files\\VMs\\Windows 1511\\Windows 1511-1b05a6a0.vmem"

print "Scanning input: " + testFile

TotalRunTime = Stopwatch.StartNew()
aBufferCount = 60000000

mdb = MetaDB("c:\\temp\\inVtero.net", 1024*1024*1024*16, 64, aBufferCount)

vtero = QuickSetup(testFile, False)

Vtero.VerboseLevel = 1
vtero.HashAllProcs(mdb, False)

print "Done! Total runtime: " + TotalRunTime.Elapsed.ToString()
