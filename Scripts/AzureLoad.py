import clr
import sys
from sys import argv

clr.AddReferenceToFileAndPath("inVtero.net.dll")

from inVtero.net import *
from System.IO import Directory, File, FileInfo, Path
from System.Diagnostics import Stopwatch
from inVtero.net.Hashing import *

importFolders = "e:\\"

Vtero.VerboseLevel = 1
# 50 million is default
#aBufferCount = 50000000

# The full prototype
#public MetaDB(string WorkingDir, int minHashSize = 0, long DBSize = 0, int loadBufferCount = 50000000, string NewInfoString = null)

# This will make sure we create a new DB set the hash size to 4096 (largest really you can make)
#mdb = MetaDB("c:\\temp\\inVtero.net", 4096,  1024*1024*1024*16, aBufferCount)

# if you already have a DB setup you can get away with this
mdb = MetaDB("c:\\temp\\inVtero.net", 4096)

cl = mdb.cLoader

# depending on upload throughput tune this
cl.MaxBatchParallel = 20
cl.LoadFromPath(importFolders)

mdb.Save()

