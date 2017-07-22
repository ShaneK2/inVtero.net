#
#
# To debug you can try like so;
# ipy64 -X:TabCompletion -X:ShowClrExceptions -X:PrivateBinding -X:PassExceptions -X:FullFrames -X:Frames -X:ExceptionDetail -D
#
#

import clr

clr.AddReferenceToFileAndPath("inVtero.net.dll")
clr.AddReferenceToFileAndPath("inVtero.net.ConsoleUtils.dll")

from inVtero.net import *
from inVtero.net.ConsoleUtils import *
from System.IO import Directory, File, FileInfo, Path
from System import ConsoleColor, Console, Environment


# Display Symbols
def ds(p, addr, len=128, maxWid = 72):
    if Console.WindowWidth-4 < maxWid:
        maxWid = Console.WindowWidth-4
    words = p.GetVirtualLongLen(addr, len)
    len = len / 8
    curr = 0
    while curr < len:
        Misc.WxColor(ConsoleColor.White, ConsoleColor.Black, VIRTUAL_ADDRESS(addr+(curr*8)).xStr + " ")
        Misc.WxColor(ConsoleColor.Green, ConsoleColor.Black, words[curr].ToString("x16") + " ")
        Misc.WxColor(ConsoleColor.Cyan, ConsoleColor.Black, "[" +  p.GetSymName(words[curr]) + "]")
        curr = curr+1
        Console.Write(Environment.NewLine);

# Display quadwords
def dq(p, addr, len=128, maxWid = 72):
    if Console.WindowWidth-4 < maxWid:
        maxWid = Console.WindowWidth-4
    words = p.GetVirtualLongLen(addr, len)
    len = len / 8
    curr = 0
    while curr < len:
        Misc.WxColor(ConsoleColor.White, ConsoleColor.Black, VIRTUAL_ADDRESS(addr+(curr*8)).xStr + " ")
        while curr < len and Console.CursorLeft < maxWid:
            Misc.WxColor(ConsoleColor.Green, ConsoleColor.Black, words[curr].ToString("x16") + " ")
            curr = curr+1
        Console.Write(Environment.NewLine);

# Display bytes
def db(p, addr, len=128, maxWid = 64):
    if Console.WindowWidth-4 < maxWid:
        maxWid = Console.WindowWidth-4
    words = p.GetVirtualByteLen(addr, len)
    curr = 0
    while curr < len:
        Misc.WxColor(ConsoleColor.White, ConsoleColor.Black, VIRTUAL_ADDRESS(addr+curr).xStr + " ")
        while curr < len and Console.CursorLeft < maxWid:
            Misc.WxColor(ConsoleColor.Green, ConsoleColor.Black, words[curr].ToString("x2") + " ")
            curr = curr+1
        Console.Write(Environment.NewLine);




