using System;
using System.Collections.Generic;
using Dia2Lib;
using static System.Console;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Linq;

namespace Dia2Sharp
{
    public class Sym
    {
        public static IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;
        IDiaSession Session = null;

        public static Sym Initalize(String SymPath, DebugHelp.SymOptions Options = DebugHelp.SymOptions.SYMOPT_DEBUG)
        {
            DebugHelp.SymSetOptions(Options);

            if(string.IsNullOrWhiteSpace(SymPath))
                SymPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
                if (string.IsNullOrWhiteSpace(SymPath))
                    SymPath = "SRV*http://msdl.microsoft.com/download/symbols";

            bool symStatus = DebugHelp.SymInitialize(hCurrentProcess, SymPath, false);
            if (!symStatus)
                WriteLine($"symbol status  {symStatus}:  {new Win32Exception(Marshal.GetLastWin32Error()).Message }");

            DebugHelp.SymSetOptions(DebugHelp.SymOptions.SYMOPT_DEBUG);
            return new Sym();
        }

        void CollectCompileDetails(IDiaSymbol detail, String ModName, String BlockName)
        {
            string Language = string.Empty, Platform = string.Empty;
            var lang = detail.language;
            var plat = detail.platform;

            switch (lang)
            {
                case 0: Language = "C"; break;
                case 1: Language = "C++"; break;
                case 2: Language = "Linked DLL/Import"; break;
                case 3: Language = "Fortran"; break;
                case 4: Language = "MASM"; break;
                case 5: Language = "Pascal"; break;
                case 6: Language = "ILASM"; break;
                case 7: Language = "MSIL"; break;
                case 8: Language = "HLSL"; break;
                case 9: Language = "Resource Data"; break;
                case 10: Language = "PGO Data (performance guided opt)"; break;
                case 11: Language = "Managed C#"; break;
                default: Language = "Other / Not hookable"; break;
            }

            if (plat > 2 && plat < 8)
                Platform = "x86";
            if (plat == 0xD0)
                Platform = "x64";
            else
                Platform = "Unsupported";

            WriteLine($"Language: {Language} / {Platform}");
        }

        void FuncCollectSym(IDiaSymbol Detail, uint tag, String ModName, String BlockName)
        {
            IDiaEnumSymbols EnumSymbols = null;
            IDiaSymbol Symbol = null;
            List<string> Args = new List<string>();
            uint childrenFetched = 0;

            ForegroundColor = ConsoleColor.Green;

            if (Detail == null || string.IsNullOrWhiteSpace(Detail.name))
                return;

            //WriteLine($"{Detail.undecoratedName} ({Detail.name}) Length: {Detail.length} RVA: {Detail.targetRelativeVirtualAddress} VA: {Detail.targetVirtualAddress}");

            Detail.findChildren(SymTagEnum.SymTagNull, null, 0, out EnumSymbols);
            do
            {
                //EnumSymbols.Next(1, out Symbol, out childrenFetched);
                //if (Symbol == null || string.IsNullOrEmpty(Symbol.name))
                //    continue;

                Symbol = Detail;

                if (Symbol.type != null)
                    Args.Add(Symbol.type.name);
                //else
                //    WriteLine($"{Symbol.undecoratedName} ({Symbol.name}) @ {Symbol.virtualAddress:X} Length: {Symbol.length} ");

            } while (childrenFetched == 1);
        }

        void ClassCollectSym(IDiaSymbol Detail)
        {
            IDiaEnumSymbols EnumSymbols = null;
            IDiaSymbol Symbol = null;
            List<string> Args = new List<string>();
            uint childrenFetched = 0;

            ForegroundColor = ConsoleColor.Yellow;

            if (Detail == null || string.IsNullOrWhiteSpace(Detail.name))
                return;

            //WriteLine($"{Detail.undecoratedName} ({Detail.name}) Length: {Detail.length} RVA: {Detail.targetRelativeVirtualAddress} VA: {Detail.targetVirtualAddress}");

            Detail.findChildren(SymTagEnum.SymTagNull, null, 0, out EnumSymbols);
            do
            {
                EnumSymbols.Next(1, out Symbol, out childrenFetched);
                if (Symbol == null || string.IsNullOrEmpty(Symbol.name))
                    continue;

                if (Symbol.type != null)
                    Args.Add(Symbol.type.name);
                //  else
                //      WriteLine($"{Symbol.undecoratedName} ({Symbol.name}) @ {Symbol.virtualAddress:X} Length: {Symbol.length} ");

            } while (childrenFetched == 1);
        }

        /// <summary>
        /// Perform full symbol walk scanning for a struct/member position and length
        /// 
        /// TODO: make safe for type collisions in other pdb's
        /// </summary>
        /// <param name="PDBFile">d:\dev\symbols\ntkrnlmp.pdb\DD08DD42692B43F199A079D60E79D2171\ntkrnlmp.pdb</param>
        /// <param name="Struct">_EPROCESS</param>
        /// <param name="Member">Pcb.DirectoryTableBase</param>
        /// <returns>Tuple of Position & Length </returns>

        public Tuple<int, int> StructMemberInfo(string PDBFile, string Struct, string Member)
        {
            IDiaSymbol Master = null;
            IDiaEnumSymbols EnumSymbols = null;
            uint compileFetched = 0;

            var result = from symx in StructInfo
                         where symx.Key.EndsWith(Member)
                         select symx;

            if (result.Count() > 0)
                return result.First().Value;

            var foo = new DiaSource();
            foo.loadDataFromPdb(PDBFile);
            foo.openSession(out Session);
            if (Session == null)
                return null;

            Session.findChildren(Session.globalScope, SymTagEnum.SymTagNull, Struct, 0, out EnumSymbols);
            do
            {
                EnumSymbols.Next(1, out Master, out compileFetched);
                if (Master == null)
                    continue;
#if DEBUGX
                Console.ForegroundColor = ConsoleColor.White;
                WriteLine($"Dumping Type [{Master.name}] Len [{Master.length}]");
#endif
                if (!StructInfo.ContainsKey(Master.name))
                    StructInfo.Add(Master.name, Tuple.Create<int, int>(0, (int)Master.length));

                DumpStructs(Master, Master.name, Struct, 0);
            } while (compileFetched == 1);

            var resultx = (from symx in StructInfo
                           where symx.Key.EndsWith(Member)
                           select symx).FirstOrDefault();

            return resultx.Value;
        }

        public Dictionary<string, Tuple<int, int>> StructInfo = new Dictionary<string, Tuple<int, int>>();

        void DumpStructs(IDiaSymbol Master, string preName, string Search, int CurrOffset)
        {
            IDiaSymbol Sub = null;
            IDiaEnumSymbols Enum2 = null;
            uint compileFetched = 0;

            Master.findChildren(SymTagEnum.SymTagNull, null, 0, out Enum2);
            do
            {
                if (Enum2 == null)
                    break;

                Enum2.Next(1, out Sub, out compileFetched);
                if (Sub == null)
                    continue;

                var sType = Sub.type;
                var typeName = sType.name;
                var currName = $"{preName}.{Sub.name}";
                int Pos = CurrOffset + Sub.offset;

#if DEBUGX
                ForegroundColor = ConsoleColor.Cyan;
                WriteLine($"Pos = [{Pos}] Name = [{currName}] Len [{sType.length}], Type [{typeName}]");
#endif
                if (!StructInfo.ContainsKey(currName))
                    StructInfo.Add(currName, Tuple.Create<int, int>(Pos, (int)sType.length));
#if DEBUGX
                ForegroundColor = ConsoleColor.Green;
                WriteLine($"Type [{typeName}] Len [{sType.length}]");
#endif
                DumpStructs(sType, currName, typeName, Pos);

            } while (compileFetched == 1);
        }

    }
}
