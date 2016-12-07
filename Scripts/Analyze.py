import clr,sys

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System import Environment

sympath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")
if string.IsNullOrWhiteSpace(sympath):
    sympath = "SRV*http://msdl.microsoft.com/download/symbols"

# Basic option handling
copts = ConfigOptions()
copts.IgnoreSaveData = False
copts.FileName = "d:\\temp\\2012R2.xendump"   
copts.VersionsToEnable = PTType.Windows
# To get some additional output 
copts.VerboseOutput = True
copts.VerboseLevel = 1

# since we are not ignoring SaveData, this just get's our state from
# the underlying protobuf, pretty fast
vtero = Scan.Scanit(copts)

Vtero.DiagOutput = True

proc = vtero.FlattenASGroups[0]

#this thing is pretty expensive right now :(
#at least it's threaded for you
mods = vtero.ModuleScan(proc);

for detected in mods:
    cv_data = vtero.ExtractCVDebug(proc, detected.Value, detected.Key)
    if cv_data is not None:
        if vtero.TryLoadSymbols(proc, detected.Value, cv_data, detected.Key, sympath):
            vtero.GetKernelDebuggerData(proc, detected.Value, cv_data, sympath)
