using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using inVtero.net;
using System.Linq;

namespace inVtero.net.Support
{
    public class Strings
    {
        public Strings() { }

        public static IEnumerable<Tuple<ulong, string>> SimpleRegex(Regex re, DetectedProc dp, bool MatchAscii = true, bool MatchUTF16 = false, bool MatchUTF8 = false)
        {
            byte[] block4k = new byte[MagicNumbers.PAGE_SIZE];
            byte[] block2MB = new byte[MagicNumbers.LARGE_PAGE_SIZE];
            string s = string.Empty;
            MatchCollection mc = null;

            dp.MemAccess.ResetDumpBitmap();

            foreach(var entry in dp.PT.FillPageQueue(false, true, true, false))
            {
                if (dp.MemAccess.IsDumpedPFN(entry.PTE))
                    continue;
                dp.MemAccess.SetDumpedPFN(entry.PTE);

                bool GotData = false;
                byte[] block = entry.PTE.LargePage ? block2MB : block4k;

                dp.MemAccess.GetPageForPhysAddr(entry.PTE, ref block, ref GotData);

                if (!GotData 
                    || UnsafeHelp.IsZeroPage(block) == 0
                    || UnsafeHelp.IsFFFPage(block) == 0)
                    continue;

                if (MatchAscii)
                {
                    s = Encoding.ASCII.GetString(block, 0, block.Length);
                    mc = re.Matches(s);
                    foreach (Match m in mc)
                        yield return Tuple.Create<ulong, string>(entry.VA.FullAddr+(uint)m.Index, m.Value);
                }
                if (MatchUTF16)
                {
                    s = Encoding.Unicode.GetString(block, 0, block.Length);
                    mc = re.Matches(s);
                    foreach (Match m in mc)
                        yield return Tuple.Create<ulong, string>(entry.VA.FullAddr + (uint)m.Index, m.Value);
                }
                if (MatchUTF8)
                {
                    s = Encoding.UTF8.GetString(block, 0, block.Length);
                    mc = re.Matches(s);
                    foreach (Match m in mc)
                        yield return Tuple.Create<ulong, string>(entry.VA.FullAddr + (uint)m.Index, m.Value);
                }
            }
            yield break;
        }

        public static IEnumerable<ulong> ByteScan(Byte[] ToFind, DetectedProc dp, int align = 1, int MaxCount = 0)
        {
            byte[] block4k = new byte[MagicNumbers.PAGE_SIZE];
            byte[] block2MB = new byte[MagicNumbers.LARGE_PAGE_SIZE];
            string s = string.Empty;

            foreach (var entry in dp.PT.FillPageQueue(false, true, true, false))
            {
                bool GotData = false;
                byte[] block = entry.PTE.LargePage ? block2MB : block4k;

                dp.MemAccess.GetPageForPhysAddr(entry.PTE, ref block, ref GotData);

                if (!GotData)
                    continue;

                int i = 0;
                do
                {
                    i = block.SearchBytes(ToFind, i, align);
                    if (i < 0)
                        break;

                    var VA = (entry.VA.FullAddr + (uint)i);

                    yield return VA;

                    i += ToFind.Length;

                } while (i <= (block.Length-ToFind.Length));
            }
            yield break;
        }
    }
}
