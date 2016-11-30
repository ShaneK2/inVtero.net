#
#
# To debug you can try like so;
# ipy64 -X:TabCompletion -X:ShowClrExceptions -X:PrivateBinding -X:PassExceptions -X:FullFrames -X:Frames -X:ExceptionDetail -D
#
#

import clr,sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")
clr.AddReferenceToFileAndPath("quickdumps.exe")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = "d:\\temp\\win10.64.nodebug.xendump"   
copts.VersionsToEnable = PTType.GENERIC 
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

print "last arg = " + sys.argv.pop()

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

# Global
mem = Mem.Instance

CollectKernel = True
Vtero.DiagOutput = False

ao = AnalyzeOptions()

analyzer = Analyze()
Support.ProgressBarz.DisableProgressBar = True
analyzer.StartAnalyze(ao, vtero)