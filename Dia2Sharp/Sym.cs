// Copyright(C) 2017 Shane Macaulay smacaulay@gmail.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.If not, see<http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using dia;
using static System.Console;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Linq;
using System.Dynamic;
using System.Text;
using System.Collections.Concurrent;

namespace Dia2Sharp
{
    public class Sym
    {
        public static ConcurrentQueue<string> Errors = new ConcurrentQueue<string>();

        // These are added to the type's as meta data to allow things like memory editing
        const string defName = "Value";
        const string defAddr = "vAddress";

        public static Dictionary<string, Tuple<int, int>> StructInfo = new Dictionary<string, Tuple<int, int>>();

        public static long Handle = Process.GetCurrentProcess().GetHashCode();
        static Sym()
        {
            Initalize(Handle, null);
        }

        public static Sym Initalize(long Handle, String SymPath, DebugHelp.SymOptions Options = DebugHelp.SymOptions.SYMOPT_UNDNAME)
        {
            DebugHelp.SymSetOptions(Options);

            if (string.IsNullOrWhiteSpace(SymPath))
                SymPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
            if (string.IsNullOrWhiteSpace(SymPath))
                SymPath = "SRV*http://msdl.microsoft.com/download/symbols";

            bool symStatus = DebugHelp.SymInitialize(Handle, SymPath, false);
            if (!symStatus)
                Errors.Enqueue($"symbol status  {symStatus}:  {new Win32Exception(Marshal.GetLastWin32Error()).Message }");

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

        public static dynamic xStructInfo(
            string PDBFile,
            string Struct,
            long vAddress = 0,
            long[] memRead = null,
            Func<long, int, byte[]> GetMem = null,
            Func<long, int, long[]> GetMemLong = null,
            PropertyChangedEventHandler ExpandoChanged = null
            )
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

            Session.loadAddress = (ulong) vAddress;

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
                Info.vAddress = vAddress;

                //StructInfo.Add(Master.name, Info); // Tuple.Create<int, int>(0, (int)Master.length));
                xDumpStructs(Info, Master, Master.name, 0, vAddress, memRead, GetMem, GetMemLong, ExpandoChanged);

                if (ExpandoChanged != null)
                    ((INotifyPropertyChanged)Info).PropertyChanged +=
                        new PropertyChangedEventHandler(ExpandoChanged);

            } while (compileFetched == 1);


            return Info;
        }

        /// <summary>
        /// Method for native type reflection into DLR
        /// TODO: Perf check + handle .Dictionary references
        /// </summary>
        /// <param name="Info"></param>
        /// <param name="Master"></param>
        /// <param name="preName"></param>
        /// <param name="CurrOffset"></param>
        /// <param name="memRead"></param>
        /// <returns></returns>
        public static dynamic xDumpStructs(
            dynamic Info,
            IDiaSymbol Master,
            string preName,
            int CurrOffset,
            long vAddress = 0,
            long[] memRead = null,
            Func<long, int, byte[]> GetMem = null,
            Func<long, int, long[]> GetMemLong = null,
            PropertyChangedEventHandler ExpandoChanged = null
            )
        {
            var IInfo = (IDictionary<string, object>)Info;
            var InfoDict = new Dictionary<string, object>();
            Info.Dictionary = InfoDict;
            long lvalue = 0;
            ulong Length = 0, memberLen = 0;
            string memberName = string.Empty;

            IDiaSymbol Sub = null;
            IDiaEnumSymbols Enum2 = null;
            IDiaSymbol TypeType;
            SymTagEnum TypeTypeTag;

            uint compileFetched = 0;

            Master.findChildren(SymTagEnum.SymTagNull, null, 10, out Enum2);
            do
            {
                if (Enum2 == null) break;

                Enum2.Next(1, out Sub, out compileFetched);
                if (Sub == null) continue;

                dynamic zym = new ExpandoObject();
                var Izym = (IDictionary<string, object>)zym;
                var staticDict = new Dictionary<string, object>();
                zym.Dictionary = staticDict;

                var master = zym.InstanceName = Master.name;
                var sType = Sub.type;
                var typeName = sType.name;
                var currName = $"{preName}.{Sub.name}";

                // LocIsConstant
                if (Sub.locationType == 0xA)
                    zym.ConstValue = Sub.value;

                int Pos = CurrOffset + Sub.offset;

                zym.TypeName = typeName;
                zym.MemberName = currName;

                zym.Tag = (SymTagEnum)Sub.symTag;
                Length = sType.length;
                zym.Length = Length;

                zym.OffsetPos = Pos;
                zym.vAddress = vAddress + Pos;

                // bitfield
                if (Sub.locationType == 6)
                {
                    zym.BitPosition = Sub.bitPosition;
                    zym.BitCount = Sub.length;
                }
                if (SymTagEnum.SymTagArrayType == (SymTagEnum)sType.symTag)
                {
                    TypeType = sType.type;

                    memberLen = TypeType.length;
                    memberName = TypeType.name;

                    zym.ArrayCount = Length / memberLen;
                    zym.ArrayMemberLen = memberLen;
                    zym.ArrayMemberType = memberName;
                }

                bool KeepRecur = true;
                if (memRead != null)
                {
                    bool captured = false;
                    lvalue = memRead == null ? 0 : memRead[Pos / 8];

                    // TODO: Handles/OBJECT_FOO/_ETC...

                    if (String.Equals("_UNICODE_STRING", typeName) && GetMem != null)
                    {
                        // since we deref'd this struct manually don't follow 
                        KeepRecur = false;
                        string strVal = "";
                        var DataOffset = (Pos + 8) / 8;
                        // get address from our offset
                        var StringAddr = memRead[DataOffset];
                        if (StringAddr != 0)
                        {
                            var strLen = (short)lvalue & 0xffff;

                            var strByteArr = GetMem(StringAddr, strLen + 2);

                            strVal = Encoding.Unicode.GetString(strByteArr, 0, strLen);
                        }
                        // update new address for double deref
                        zym.vAddress = StringAddr;
                        Izym.Add(defName, strVal);
                        staticDict.Add(currName, lvalue);

                    }
                    else
                    {
                        // bittable types
                        // TODO: GUID
                        // 6 is a bitfield
                        if (Sub.locationType == 6)
                        {
                            var mask = 1U;
                            var BitsLen = Sub.length;
                            zym.BitCount = BitsLen;

                            var subOff = Sub.offset;

                            for (int x = (int)BitsLen - 1; x > 0; x--)
                            {
                                mask = mask << 1;
                                mask |= 1;
                            }
                            var new_mask = mask << (int)Sub.bitPosition << (subOff * 8);

                            lvalue &= new_mask;

                            // move lvalue to bitposition 0 
                            // saves having todo this every time we evaluate Value
                            lvalue = lvalue >> (int)Sub.bitPosition >> (subOff * 8);
                            captured = true;
                        }
                        else
                        {
                            var shift = (Pos % 8 * 8);
                            switch (sType.length)
                            {
                                case 8:
                                    captured = true;
                                    break;
                                case 4:
                                    lvalue = (lvalue >> shift) & 0xffffffff;
                                    captured = true;
                                    break;
                                case 2:
                                    lvalue = (lvalue >> shift) & 0xffff;
                                    captured = true;
                                    break;
                                case 1:
                                    lvalue = (lvalue >> shift) & 0xff;
                                    captured = true;
                                    break;
                                default:
                                    break;
                            }
                            // were dealing with some sort of array or weird sized type not nativly supported (yet, e.g. GUID)
                            // if we start with a _ we are going to be descending recursivly into this type so don't extract it here
                            // this is really for basic type array's or things' were not otherwise able to recursivly extract
                            if (!captured && (SymTagEnum.SymTagArrayType == (SymTagEnum)sType.symTag))
                            {
                                int BytesReadRoom = 0, len = 0;
                                if (memberLen == 1 || memberLen > 8)
                                {
                                    byte[] barr = new byte[sType.length];
                                    BytesReadRoom = (memRead.Length * 8) - Pos;
                                    len = BytesReadRoom > barr.Length ? barr.Length : BytesReadRoom;
                                    Buffer.BlockCopy(memRead, Pos, barr, 0, len);

                                    Izym.Add(defName, barr);
                                    staticDict.Add(currName, barr);
                                }
                                else if (memberLen == 4)
                                {
                                    int arrLen = (int)Length / (int)memberLen;
                                    int[] iarr = new int[arrLen];
                                    BytesReadRoom = (memRead.Length * 8) - Pos;
                                    len = BytesReadRoom > (int)Length ? (int)Length : BytesReadRoom;
                                    Buffer.BlockCopy(memRead, Pos, iarr, 0, len);

                                    Izym.Add(defName, iarr);
                                    staticDict.Add(currName, iarr);
                                }
                                else
                                {
                                    int arrLen = (int)Length / (int)memberLen;
                                    long[] larr = new long[arrLen];
                                    BytesReadRoom = (memRead.Length * 8) - Pos;
                                    len = BytesReadRoom > (int)Length ? (int)Length : BytesReadRoom;
                                    Buffer.BlockCopy(memRead, Pos, larr, 0, len);

                                    Izym.Add(defName, larr);
                                    staticDict.Add(currName, larr);
                                }
                            }
                        }
                        if (captured)
                        {
                            Izym.Add(defName, lvalue);
                            staticDict.Add(currName, lvalue);
                        }
                    }
                }

                // This is a pointer really, so type.type... of course!
                if (KeepRecur)
                {
                    TypeType = sType.type;
                    TypeTypeTag = (SymTagEnum)sType.symTag;
                    if (TypeTypeTag == SymTagEnum.SymTagPointerType)
                    {
                        zym.IsPtr = true;
                        if (TypeType != null && !string.IsNullOrWhiteSpace(TypeType.name))
                        {
                            zym.PtrTypeName = TypeType.name;

                            // only recuse non-recursive ptr types
                            if (TypeType.name.Equals("_OBJECT_NAME_INFORMATION"))
                            {
                                long[] deRefArr = null;
                                // do second deref here
                                // the location to read is our offset pos data
                                if (GetMemLong != null)
                                {
                                    deRefArr = GetMemLong(lvalue, 0x20);
                                }
                                xDumpStructs(zym, TypeType, currName, 0, vAddress + Pos, deRefArr, GetMem, GetMemLong, ExpandoChanged);
                            }
                        }
                    }
                    else
                        xDumpStructs(zym, sType, currName, Pos, vAddress + Pos, memRead, GetMem, GetMemLong, ExpandoChanged);
                }
#if DEBUGX
                ForegroundColor = ConsoleColor.Cyan;
                WriteLine($"Pos = [{Pos:X}] Name = [{currName}] Len [{sType.length}], Type [{typeName}], ThisStruct [{master}]");
#endif


                // Length comes up a lot in struct's and conflicts with the ExpandoObject 
                // so remap it specially
                var AddedName = Sub.name;
                if (AddedName.ToLower().Equals("value"))
                    AddedName = "ValueMember";
                if (AddedName.ToLower().Equals("length"))
                    AddedName = "LengthMember";
                if (IInfo.ContainsKey(AddedName))
                    continue;


                IInfo.Add(AddedName, zym);
                InfoDict.Add(AddedName, lvalue);

                if (ExpandoChanged != null)
                    ((INotifyPropertyChanged)zym).PropertyChanged += ExpandoChanged;

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

        public static Tuple<int, int> StructMemberInfo(string PDBFile, string Struct, string Member)
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


        static void DumpStructs(IDiaSymbol Master, string preName, string Search, int CurrOffset)
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

        public static Tuple<String, ulong, ulong> FindSymByAddress(ulong Address, String PDBFile, ulong LoadAddr = 0)
        {
            Tuple<string, ulong, ulong> rv = null;
            IDiaSession Session;
            IDiaSymbol Sym;
            IDiaEnumSymbolsByAddr pEnumAddr;

            var foo = new DiaSource();
            foo.loadDataFromPdb(PDBFile);
            foo.openSession(out Session);
            if (Session == null)
                return rv;

            Session.loadAddress = LoadAddr;

            Session.getSymbolsByAddr(out pEnumAddr);
            if (pEnumAddr == null)
                return rv;

            Sym = pEnumAddr.symbolByVA(Address);
            if (Sym == null)
                return rv;

            rv = new Tuple<string, ulong, ulong>(Sym.name, Sym.virtualAddress, Sym.length);

            return rv;
        }

        public static List<Tuple<String, ulong, ulong>> MatchSyms(String Match, String PDBFile, ulong LoadAddr = 0)
        {
            List<Tuple<String, ulong, ulong>> rv = new List<Tuple<string, ulong, ulong>>();
            IDiaSession Session;
            IDiaEnumSymbols EnumSymbols = null;
            IDiaSymbol Master = null;
            uint compileFetched = 0;

            var foo = new DiaSource();
            foo.loadDataFromPdb(PDBFile);
            foo.openSession(out Session);
            if (Session == null)
                return rv;
            // 10 is regex
            Session.globalScope.findChildren(SymTagEnum.SymTagNull, Match, 10, out EnumSymbols);

            if (Session == null)
                return rv;

            Session.loadAddress = LoadAddr;

            var GlobalScope = Session.globalScope;

            var tot = EnumSymbols.count;
            do
            {
                EnumSymbols.Next(1, out Master, out compileFetched);
                if (Master == null)
                    continue;

                var len = Master.length;

                rv.Add(Tuple.Create<String, ulong, ulong>(Master.name, Master.virtualAddress, len));
#if DEBUGX
                ForegroundColor = ConsoleColor.White;
                WriteLine($"Name = [{Master.name}] VA = {Master.virtualAddress}");
#endif
            } while (compileFetched == 1);

            return rv;
        }
    }
}
