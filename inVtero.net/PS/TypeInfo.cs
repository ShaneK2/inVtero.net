#if FALSE || NETSTANDARD2_0
using inVtero.net;
using inVtero.net.ConsoleUtils;
using inVtero.net.Hashing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Management.Automation;
using static inVtero.net.Misc;
using Reloc;
using Dia2Sharp;
using System.Dynamic;
using Newtonsoft.Json;
using static System.Console;

namespace inVteroCore.PS
{
    [Cmdlet(VerbsData.ConvertTo, "TypeInfo")]
    [OutputType(typeof(string))]
    public class ANSIC : Cmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "Any PE that may have typedef's"), Alias("I")]
        public string InputFile { get; set; }

        [Parameter(Mandatory = false, HelpMessage = "Optionally, part or all of the name of the type"), Alias("T"), PSDefaultValue(Help = "Use wild cards", Value = "*") ]
        public string TypeName { get; set; }
        public dynamic TypeInfos { get => typeInfos; set => typeInfos = value; }

        Extract Info;
        CODEVIEW_HEADER cvh = CODEVIEW_HEADER.Init();
        dynamic typeInfos = null;

        protected override void BeginProcessing()
        {

#if DEBUG
            WriteColor("starting up");
#endif
            MiniSection ms = MiniSection.Empty;
            string SymFileName = string.Empty;
            var buff = new byte[4096];

            using (var fs = File.OpenRead(InputFile))
            {
                fs.Read(buff, 0, 4096);

                Info = Extract.IsBlockaPE(buff);
                if (Info == null)
                    return;

                var block = new byte[28];
                var debugBlockAddr = Info.Directories[(int)PEDirectory.Debug].Item1;
                for (int i = 0; i < Info.NumberOfSections; i++)
                {
                    if (debugBlockAddr >= Info.Sections[i].VirtualAddress && debugBlockAddr < (Info.Sections[i].VirtualAddress + Info.Sections[i].VirtualSize))
                    {
                        ms = Info.Sections[i];
                        break;
                    }
                }
                fs.Position = ms.RawFilePointer + (debugBlockAddr - ms.VirtualAddress);

                fs.Read(block, 0, block.Length);
                var TimeDate2 = BitConverter.ToUInt32(block, 4);
                if (TimeDate2 != Info.TimeStamp & Vtero.VerboseOutput )
                {
                    WriteColor(ConsoleColor.Yellow, "Unable to lock on to CV data.");
                    return;
                }

                cvh.TimeDateStamp = TimeDate2;
                cvh.Type = TypeName;

                cvh.VSize = Info.SizeOfImage;
                var CVLocation = BitConverter.ToUInt32(block, 20);
                var PointerToRawData = BitConverter.ToUInt32(block, 24);

                // Advance to the debug section where we may find the code view info
                //var _va = VA + RawData;
                var blockCV = new byte[64];
                fs.Position = ms.RawFilePointer + (CVLocation - ms.VirtualAddress); 
                fs.Read(blockCV, 0, 64);

                cvh.Sig = blockCV[0];
                cvh.byteGuid = new byte[16];
                Array.ConstrainedCopy(blockCV, 4, cvh.byteGuid, 0, 16);
                cvh.aGuid = new Guid(cvh.byteGuid);
                // after GUID
                cvh.Age = blockCV[20];

                // char* at end
                var str2 = Encoding.Default.GetString(blockCV, 24, 32).Trim();
                if (str2.Contains(".") && str2.Contains(".pdb"))
                    SymFileName = str2.Substring(0, str2.IndexOf(".pdb") + 4);
                else
                    SymFileName = str2;

                cvh.PdbName = SymFileName;
            }
        }


        protected override void ProcessRecord()
        {
            string emitBasicTypeInfo(long OfVarLen)
            {
                switch (OfVarLen)
                {
                    case 8: return("unsigned __int64 ");
                    case 4: return("unsigned __int32 ");
                    case 2: return("unsigned __int16 "); 
                    case 1: return("unsigned __int8  ");
                }
                return string.Empty;
            }
            (string Line, int TypeStop, int NameStop) MakeMemberLine(string name, dynamic MetaInfo, IDictionary<string, dynamic> typeMembers, int TypePad = 0)
            {
                (string Line, int TypeStop, int NameStop) rv = (string.Empty, 0, 0);

                var line = new StringBuilder();
                try
                {
                    var IMetaInfo = MetaInfo as IDictionary<string, object>;

                    // type of the member
                    var size = (int)MetaInfo.Length;
                    if (!IMetaInfo.ContainsKey("IsPtr") &&
                        string.IsNullOrWhiteSpace(IMetaInfo["TypeName"] as string ?? string.Empty) &&
                        !IMetaInfo.ContainsKey("ArrayMemberType"))
                        line.Append(emitBasicTypeInfo(size));
                    else
                    {
                        if (IMetaInfo.ContainsKey("IsPtr"))
                        {
                            if (IMetaInfo.ContainsKey("PtrTypeName"))
                                line.Append($"{MetaInfo.PtrTypeName} *");
                            else
                                line.Append("void *");
                        }
                        else if (IMetaInfo.ContainsKey("ArrayMemberLen"))
                        {
                            if (!string.IsNullOrWhiteSpace(MetaInfo.ArrayMemberType))
                                line.Append($"{MetaInfo.ArrayMemberType} ");
                            else
                                line.Append(emitBasicTypeInfo(MetaInfo.ArrayMemberLen));
                        }
                        else
                            line.Append($"{MetaInfo.TypeName} ");
                    }
                    rv.TypeStop = line.Length;
                    if (TypePad > 0)
                        while (line.Length < TypePad)
                            line.Append(' ');

                    // name of the member
                    line.Append($"{name}");

                    // bitfields & arrays :)
                    if (IMetaInfo.ContainsKey("BitCount"))
                        line.Append($":{ MetaInfo.BitCount}");
                    else if (IMetaInfo.ContainsKey("ArrayCount"))
                        line.Append($"[{MetaInfo.ArrayCount}]");

                    line.Append(';');
                    rv.NameStop = line.Length;

                }
                catch (Exception ex) { line.Append($"// CRITICAL ERROR: REPORT THIS!!!! {ex});"); }

                rv.Line = line.ToString();
                return rv;
            }
            
            if (string.IsNullOrWhiteSpace(cvh.PdbName))
                return;

            if (Vtero.VerboseOutput)
                WriteColor($"Contacting server for data from {cvh}");

            var tInfo = SymAPI.TypeDef(TypeName, cvh).GetAwaiter();

            var json = tInfo.GetResult();
            var converter = new Newtonsoft.Json.Converters.ExpandoObjectConverter();
            TypeInfos = JsonConvert.DeserializeObject<List<ExpandoObject>>(json, converter);

            foreach (var typeInfo in TypeInfos)
            {
                bool Bug = false;
                var typeMembers = typeInfo as IDictionary<string, dynamic>;
                // this Dictionary contain's the origional typeinfo before we added metadata 
                var SymNames = (IDictionary<string, dynamic>)typeInfo.Dictionary;

                // we iterate the struct 2x due to prettyprint needs
                int maxWidth = 0, maxTypeWidth = 0;
                foreach (var name in SymNames.Keys)
                {
                    var MetaInfo = typeMembers[name] as dynamic;
                    var lineInfo = MakeMemberLine(name, MetaInfo, typeMembers);

                    if (lineInfo.Line.Length > maxWidth)
                        maxWidth = lineInfo.Line.Length;
                    if (lineInfo.TypeStop > maxTypeWidth)
                        maxTypeWidth = lineInfo.TypeStop;
                }

                if ((typeInfo.TypeName as string).StartsWith("<un"))
                {
                    Bug = true;
                    WriteLine("/* !TODO: Fix for this declaration");
                }

                var structHdr = $"typedef struct {typeInfo.TypeName}";
                if (structHdr.Length > maxWidth)
                    maxWidth = structHdr.Length;

                Write(structHdr.PadRight(maxWidth+10));
                // meta
                Write($"\t// total length {typeInfo.Length:x6}{Environment.NewLine}{{{Environment.NewLine}");

                foreach (var name in SymNames.Keys)
                {
                    var MetaInfo = typeMembers[name] as dynamic;

                    var line = $"{MakeMemberLine(name, MetaInfo, typeMembers, maxTypeWidth).Line}";

                    // this is like a enum/bitfield that belongs to the previous type that was
                    // typed as a basic type
                    if (line.StartsWith("<unnamed"))
                        continue;

                    // meta info
                    var meta = $"// +0x{MetaInfo.OffsetPos:x6} len(0x{MetaInfo.Length:x6}) ";

                    Write($"  {line.PadRight(maxWidth + 10)} {meta}"); 

                    // fine end of line
                    Console.WriteLine();
                }
                var shortStructName = (typeInfo.TypeName as string).Substring(1);

                WriteLine($"}} {shortStructName}, *P{shortStructName};{Environment.NewLine}");
                if (Bug)
                    WriteLine("***/");
            }
        }

        protected override void EndProcessing()
        {
            WriteLine("Done");
        }

        protected override void StopProcessing()
        {
            WriteLine("Abort");
        }
    }
}

#endif