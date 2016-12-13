using System;
using System.Collections.Generic;
using Dia2Lib;
using static System.Console;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Linq;
using System.Dynamic;

namespace Dia2Sharp
{
    public class Sym
    {
        public static IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;
        public Dictionary<string, Tuple<int, int>> StructInfo = new Dictionary<string, Tuple<int, int>>();

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

        public dynamic xStructInfo(string PDBFile, string Struct, long[] memRead = null)
        {
            dynamic Info = null;
            IDiaSymbol Master = null;
            IDiaEnumSymbols EnumSymbols = null;
            IDiaSession Session;
            uint compileFetched = 0;

            var foo = new DiaSource();
            foo.loadDataFromPdb(PDBFile);
            foo.openSession(out Session);
            if (Session == null)
                return null;
            // 10 is regex
            Session.globalScope.findChildren(SymTagEnum.SymTagNull, Struct, 10, out EnumSymbols);
            do
            {
                EnumSymbols.Next(1, out Master, out compileFetched);
                if (Master == null)
                    continue;
#if DEBUGX
                Console.ForegroundColor = ConsoleColor.White;
                WriteLine($"Dumping Type [{Master.name}] Len [{Master.length}]");
#endif
                Info = new ExpandoObject();
                Info.TypeName = Master.name;
                Info.Length = Master.length;
                //StructInfo.Add(Master.name, Info); // Tuple.Create<int, int>(0, (int)Master.length));

                xDumpStructs(Info, Master, Master.name, 0, memRead);
            } while (compileFetched == 1);

            return Info;
        }

        dynamic xDumpStructs(dynamic Info, IDiaSymbol Master, string preName, int CurrOffset, long[] memRead = null)
        {
            var IInfo = (IDictionary<string, object>)Info;

            IDiaSymbol Sub = null;
            IDiaEnumSymbols Enum2 = null;
            uint compileFetched = 0;

            Master.findChildren(SymTagEnum.SymTagNull, null, 10, out Enum2);
            do
            {
                if (Enum2 == null)
                    break;

                Enum2.Next(1, out Sub, out compileFetched);
                if (Sub == null)
                    continue;

                dynamic zym = new ExpandoObject();
                var Izym = (IDictionary<string, object>)zym;

                var master = zym.InstanceName = Master.name;
                var sType = Sub.type;
                var typeName = zym.TypeName = sType.name;
                var currName = zym.MemberName = $"{preName}.{Sub.name}";
                int Pos = CurrOffset + Sub.offset;

                zym.Tag = (SymTagEnum)Sub.symTag;
                zym.Length = sType.length;
                zym.OffsetPos = Pos;

                if (memRead != null)
                {
                    var defName = "Value";
                    switch (sType.length)
                    {
                        case 4:
                            var ival = memRead == null ? 0 : (int)(memRead[Pos / 8] & 0xffffffffff);
                            Izym.Add(defName, ival);
                            break;
                        case 2:
                            var sval = memRead == null ? 0 : (short)(memRead[Pos / 8] & 0xffffff);
                            Izym.Add(defName, sval);
                            break;
                        case 1:
                            var bval = memRead == null ? 0 : (byte)(memRead[Pos / 8] & 0xff);
                            Izym.Add(defName, bval);
                            break;
                        default:
                            var lval = memRead == null ? 0 : memRead[Pos / 8];
                            Izym.Add(defName, lval);
                            break;
                    }
                }
                // This is a pointer really, so type.type... of course!
                var TypeType = sType.type;
                var TypeTypeTag = sType.symTag;
                if ((SymTagEnum)TypeTypeTag == SymTagEnum.SymTagPointerType)
                {
                    zym.IsPtr = true;
                    if (TypeType != null && !string.IsNullOrWhiteSpace(TypeType.name))
                        zym.PtrTypeName = TypeType.name;
                } else
                    xDumpStructs(zym, sType, currName, Pos, memRead);
#if DEBUGX
                ForegroundColor = ConsoleColor.Cyan;
                WriteLine($"Pos = [{Pos:X}] Name = [{currName}] Len [{sType.length}], Type [{typeName}], ThisStruct [{master}]");
#endif

                if (IInfo.ContainsKey(Sub.name))
                    continue;

                IInfo.Add(Sub.name, zym);

                //Pos += (int)sType.length;
            } while (compileFetched == 1);
            return null;
        }

        public dynamic GetStruct(String Name, long[] memRead = null)
        {
            var typeDefs = from typeDef in StructInfo
                           where typeDef.Key.StartsWith(Name)
                           select typeDef;

            dynamic strukt = new ExpandoObject();
            var IDstrukt = (IDictionary<string, object>)strukt;

            // kludge 
            var staticDict = new Dictionary<string, object>();
            strukt.Dictionary = staticDict;

            foreach (var def in typeDefs)
            {
                // custom types are not fitted this way
                // we just recuse into basic types
                if (def.Value.Item2 > 8)
                    continue;

                // TODO: make recursive and expand on this dynamic object foo.bar working etc...
                var defName = def.Key.Substring(Name.Length + 1); //.Replace('.', '_');

                switch (def.Value.Item2)
                {
                    case 4:
                        var ival = memRead == null ? 0 : (int)(memRead[def.Value.Item1 / 8] & 0xffffffffff);
                        staticDict.Add(defName, ival);
                        IDstrukt.Add(defName, ival);
                        break;
                    case 2:
                        var sval = memRead == null ? 0 : (short)(memRead[def.Value.Item1 / 8] & 0xffffff);
                        staticDict.Add(defName, sval);
                        IDstrukt.Add(defName, sval);
                        break;
                    case 1:
                        var bval = memRead == null ? 0 : (byte)(memRead[def.Value.Item1 / 8] & 0xff);
                        staticDict.Add(defName, bval);
                        IDstrukt.Add(defName, bval);
                        break;
                    default:
                        var lval = memRead == null ? 0 : memRead[def.Value.Item1 / 8];
                        staticDict.Add(defName, lval);
                        IDstrukt.Add(defName, lval);
                        break;
                }
            }
            return strukt;
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
            IDiaSession Session;
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
                DumpStructs(sType, currName, typeName, Pos);

            } while (compileFetched == 1);
        }
    }
}
