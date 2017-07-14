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
from inVtero.net.Hashing import *

Vtero.VerboseLevel = 1
aBufferCount = 50000000
db = HashDB("C:\\temp\\iv.DB", "c:\\temp\\reloc", 1024*1024*1024*2)
fl = FileLoader(db, 128)
fl.BufferCount = aBufferCount 

fl.LoadFromPath("f:\\")

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


## Load the DB, min hash size for inputs is 64
## The size is stored in the DB from the min block
## i.e. here "64" is the min block size so 64 = 0
## 128 = 1, 256 = 2, 512 = 3, 1024 = 4, 2048 = 5 & 4096 = 6
##BufferCount = 5000000

##fl = FileLoader(db, 128, BufferCount)

## How many entrier per DB buffer write (keep it under 200Million or else .NET has issues)
## 10M is enough for most deployments
#fl.LoadFromPath("f:\\")

print fl.LoadExceptions.Count.ToString() + " File load exceptions encountered."


