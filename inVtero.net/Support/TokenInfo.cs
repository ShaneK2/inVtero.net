using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static inVtero.net.Misc;
using static System.Console;

namespace inVtero.net.Support
{
    public class TokenInfo
    {
        internal class Privilege
        {
            public string Name;
            public long Address;
            public int Value;
            public override string ToString() { return $"{Name} - {Value}"; }
        }

        static List<Privilege> PrivilegeSet;

        public static void InitFromKernel(DetectedProc p)
        {
            PrivilegeSet = new List<Privilege>();

            //build list of privs 
            foreach (var priv in p.MatchSymbols("Se*Privilege", "ntkrnlmp"))
            {
                var addr = (long)priv.Item2;
                var val = p.GetByteValue(addr);
                var nfo = new Privilege() { Name = priv.Item1, Address = (long)priv.Item2, Value = val};
                PrivilegeSet.Add(nfo);
            }
        }

        public static void Token(DetectedProc p, long TokenAddress = 0)
        {
            if (PrivilegeSet == null || PrivilegeSet.Count < 1)
                InitFromKernel(p);

            long TokenToDump = TokenAddress;
            if (TokenToDump == 0)
                TokenToDump = p.EProc.Token;
            
            // check all processes primary token's
            var tok = p.xStructInfo("_TOKEN", TokenToDump);

            // find enabled address
            var enabled = (long) tok.Privileges.Enabled.Value;

            WxColor(ConsoleColor.Cyan, ConsoleColor.Black, $"{p.ShortName} Enabled Privileges: ");
            foreach (var priv in PrivilegeSet)
            {
                if(((enabled >> priv.Value) & 1) != 0)
                    WriteLine($"{priv.Name, 8}");
            }
            Write(Environment.NewLine);

        }
    }
}
