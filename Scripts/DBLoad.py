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
aBufferCount = 100000000

mdb = MetaDB("c:\\temp\\inVtero.net", 256, 1024*1024*1024*16, aBufferCount)
fl = mdb.Loader

fl.LoadFromPath(importFolders, False)

mdb.Save()

