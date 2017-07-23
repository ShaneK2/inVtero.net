import clr
import sys
from sys import argv

clr.AddReferenceToFileAndPath("inVtero.net.dll")

from inVtero.net import *
from System.IO import Directory, File, FileInfo, Path
from System.Diagnostics import Stopwatch
from inVtero.net.Hashing import *


importFolder = "e:\\"

Vtero.VerboseLevel = 1
aBufferCount = 175000000

mdb = MetaDB("c:\\temp\\inVtero.net", 1024*1024*1024*16, 64, aBufferCount)

fl = mdb.Loader
fl.LoadFromPath(importFolder)

mdb.Save()




#rv = fl.FileChecker("c:\\temp\\advapi32.dll.text", True)
#for f in fl.DirectoryChecker("C:\\Users\\files\\VMs\\Windows 10 x64-PRO-1703\\Windows 10 x64-PRO-1703-40599dd1.vmem.dumped.2", "*.text", 128):
#    if f.Item2 < 100.0:
#        print f.Item1 + " " + f.Item2.ToString("N3") 
#        # This will print the index at whitch the missing data is
#        #for index in range(0, f.Item3.Count):
#        #    if f.Item3[index] == False:
#        #        print " miss @ 0x" + (index * 128).ToString("X"),
#for f in fl.DirectoryChecker("C:\\temp\\", "FileSyncShell64.dll.text", 128):
#    if f.Item2 < 100.0:
#        print f.Item1 + " " + f.Item2.ToString("N3") 
#        for index in range(0, f.Item3.Count):
#            if f.Item3[index] == False:
#                print " miss @ 0x" + (index * 128).ToString("X"),
