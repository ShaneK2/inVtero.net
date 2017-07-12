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
TotalRunTime = Stopwatch.StartNew()

db = HashDB("C:\\temp\\iv.DB", "c:\\temp\\reloc", 1024*1024*1024*2)

# Load the DB, min hash size for inputs is 64
# The size is stored in the DB from the min block
# i.e. here "64" is the min block size so 64 = 0
# 128 = 1, 256 = 2, 512 = 3, 1024 = 4, 2048 = 5 & 4096 = 6
fl = FileLoader(db, 64)

# How many entrier per DB buffer write (keep it under 200Million or else .NET has issues)
# 10M is enough for most deployments
fl.BufferCount = 10000000
fl.LoadFromPath("z:\\")

print "Done! Total runtime: " + TotalRunTime.Elapsed.ToString()
