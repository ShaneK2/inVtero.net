using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using inVtero.net;
using static inVtero.net.Misc;

namespace inVtero.net.Support
{
    public class Heaps
    {
        uint Signature = 0xffeeffee;
        DetectedProc p;

        public List<dynamic> HEAPS;

        public Heaps(DetectedProc P)
        {
            p = P;
            HEAPS = new List<dynamic>();
        }

        public long InitHeaps(bool ScanAll = false)
        {
            var nonExec = from s in p.Sections
                          where !s.Value.IsExec
                          select s;
            var heDef = p.xStructInfo("_HEAP_ENTRY");
            var heLen = (int) heDef.Length;
            long rv = 0, currSize;
            foreach (var s in nonExec)
            {
                var block = p.VGetBlockLong(s.Key);
                var h = p.xStructInfo("_HEAP", block);
                if(h.SegmentSignature.Value == Signature)
                {
                    WriteColor(ConsoleColor.Green, $"Found a heap @ {s.Key:x}");
                    HEAPS.Add(h);

                    if (ScanAll)
                    {
                        long cookie = block[(h.Encoding.OffsetPos / 8) + 1];
                        var FirstEntry = block[h.FirstEntry.OffsetPos / 8];
                        var LastEntry = block[h.LastValidEntry.OffsetPos / 8];

                        var currEntry = FirstEntry;
                        do
                        {
                            var currBlock = p.GetVirtualLongLen(currEntry, heLen);
                            currBlock[1] ^= cookie;

                            currSize = (currBlock[1] & 0xffff) << 4;
                            currEntry += currSize;
                            rv += currSize;
                        } while (currEntry < LastEntry && currSize != 0);
                    }  
                }
            }
            return rv;
        }

    }
}
