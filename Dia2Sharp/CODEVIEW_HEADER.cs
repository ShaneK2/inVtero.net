using ProtoBuf;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static System.Console;

namespace Dia2Sharp
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class CODEVIEW_HEADER
    {
        public static CODEVIEW_HEADER Init(IEnumerable<KeyValuePair<string, string>> entries)
        {
            string GUID = string.Empty;
            string age = string.Empty;
            string PDB = string.Empty;
            string sig = string.Empty;
            string name = string.Empty;
            string vsize = string.Empty;
            string symAddr = string.Empty;
            string typeName = string.Empty;
            string timeStamp = string.Empty;
            string baseVaddr = string.Empty;

            foreach (var entry in entries)
            {
                var key = entry.Key.ToLower();
                switch (key)
                {
                    case "age": age = entry.Value; break;
                    case "sig": sig = entry.Value; break;
                    case "pdb": PDB = entry.Value; break;
                    case "guid": GUID = entry.Value; break;
                    case "name": name = entry.Value; break;
                    case "vsize": vsize = entry.Value; break;
                    case "type": typeName = entry.Value; break;
                    case "symaddr": symAddr = entry.Value; break;
                    case "baseva": baseVaddr = entry.Value; break;
                    case "timedate": timeStamp = entry.Value; break;
                    default: break;
                }
            }
            return Init(name, PDB, symAddr, typeName, baseVaddr, vsize, age, sig, timeStamp, GUID);
        }


        public static CODEVIEW_HEADER Init(
            string name = null,
            string pdb = null,
            string symaddr = null,
            string typename = null,
            string baseva = null,
            string vsize = null,
            string age = null,
            string sig = null,
            string timestamp = null,
            string guid = null
            )
        {
            bool parsed = false;
            var cv = new CODEVIEW_HEADER();

            cv.Name = name;
            cv.PdbName = pdb;
            cv.Type = typename;
            cv.BaseVA = ParseUlong(baseva, ref parsed);
            cv.SymAddr = ParseUlong(symaddr, ref parsed);
            cv.VSize = ParseUint(vsize, ref parsed);
            cv.Age = ParseUint(age, ref parsed);
            cv.Sig = ParseUint(sig, ref parsed);
            cv.TimeDateStamp = ParseUint(timestamp, ref parsed);
            cv.aGuid = Guid.Parse(guid);
            return cv;
        }

        static ulong ParseUlong(string intStr, ref bool parsed)
        {
            ulong rv = 0;
            var parse = intStr.Trim(new char[] { '\"', '\'', '?', '&', '=', '.', ',' });
            if (parse.Contains("x"))
                parse = parse.Substring(parse.IndexOf("x") + 1);

            if (!ulong.TryParse(parse, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out rv))
                if (!ulong.TryParse(parse, out rv))
                    parsed = false;
                else
                    parsed = true;
            else
                parsed = true;

            return rv;
        }

        static uint ParseUint(string intStr, ref bool parsed)
        {
            uint rv = 0;
            var parse = intStr.Trim(new char[] { '\"', '\'', '?', '&', '=', '.', ',' });
            if (parse.Contains("x"))
                parse = parse.Substring(parse.IndexOf("x") + 1);

            if (!uint.TryParse(parse, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out rv))
                if (!uint.TryParse(parse, out rv))
                    parsed = false;
                else
                    parsed = true;
            else
                parsed = true;

            return rv;
        }

        public override string ToString() => $"{PdbName}-{aGuid:N}-{TimeDateStamp:x}-{Age:X1}-{BaseVA:X}-{VSize:X}";

        public uint Age;
        public uint Sig;
        public uint TimeDateStamp;
        public Guid aGuid;
        public byte[] byteGuid;
        public string Name;
        public string PdbName;
        public string Type;
        public ulong SymAddr;
        public ulong BaseVA;
        public uint VSize;

        // This field is determined through a call to SymFindFileInPath/Ex from the above info 
        public string PDBFullPath;
    }

    public class CODEVIEW
    {
        public static bool TryLoadSymbols(long Handle, CODEVIEW_HEADER cv_data, long BaseVA, bool Verbose = false)
        {
            ulong KernRange = 0xffff000000000000;

            // sign extend BaseVA for kernel ranges
            if ((BaseVA & 0xf00000000000) != 0)
                BaseVA |= (long)KernRange;

            return TryLoadSymbols(Handle, cv_data, (ulong) BaseVA, Verbose);
        }

        /// <summary>
        /// We use sympath environment variable
        /// </summary>
        /// <param name="cv_data"></param>
        /// <param name="BaseVA"></param>
        /// <param name="SymPath"></param>
        /// <returns></returns>
        public static bool TryLoadSymbols(long Handle, CODEVIEW_HEADER cv_data, ulong BaseVA, bool Verbose = false)
        {
#if NETSTANDARD2_0
            cv_data.PDBFullPath = $"NET_BINDING-{cv_data}";
            return true;
#else

            var symStatus = false;
            if (string.IsNullOrWhiteSpace(cv_data.PdbName))
                return symStatus;

            var sym = Sym.Initalize(Handle, null, DebugHelp.SymOptions.SYMOPT_UNDNAME);

            if (!sym && Verbose)
                Sym.Errors.Enqueue($"Can not initialize symbols for ${Handle}, error:  {new Win32Exception(Marshal.GetLastWin32Error()).Message }");


            StringBuilder sbx = new StringBuilder(1024);
            StringBuilder sbName = new StringBuilder(cv_data.PdbName.Substring(0, cv_data.PdbName.IndexOf(".pdb")+4));

            uint three = 0;
            var flags = DebugHelp.SSRVOPT_GUIDPTR;
            symStatus = DebugHelp.SymFindFileInPathW(Handle, null, sbName, ref cv_data.aGuid, cv_data.Age, three, flags, sbx, IntPtr.Zero, IntPtr.Zero);
            //// try twice, just in case
            if (!symStatus)
                symStatus = DebugHelp.SymFindFileInPathW(Handle, null, sbName, ref cv_data.aGuid, cv_data.Age, three, flags, sbx, IntPtr.Zero, IntPtr.Zero);

            if (!symStatus)
            {
                if(Verbose)
                    Sym.Errors.Enqueue($" Symbol locate returned {symStatus}: {new Win32Exception(Marshal.GetLastWin32Error()).Message }, attempting less precise request.");

                flags = DebugHelp.SSRVOPT_DWORDPTR;
                var refBytes = BitConverter.GetBytes(cv_data.TimeDateStamp);
                GCHandle pinnedArray = GCHandle.Alloc(refBytes, GCHandleType.Pinned);
                IntPtr pointer = pinnedArray.AddrOfPinnedObject();

                symStatus = DebugHelp.SymFindFileInPathW(Handle, null, sbName, pointer, cv_data.VSize, three, flags, sbx, IntPtr.Zero, IntPtr.Zero);
                pinnedArray.Free();
                if (!symStatus && Verbose)
                    Sym.Errors.Enqueue($" Find Symbols returned value: {symStatus}:[{sbx.ToString()}]");
            }
            if (symStatus)
            {
                var symLoaded = DebugHelp.SymLoadModuleEx(Handle, IntPtr.Zero, sbx.ToString(), null, BaseVA, cv_data.VSize, IntPtr.Zero, 0);
                if (symLoaded == 0 && Verbose)
                    Sym.Errors.Enqueue($"Symbols file located @ {sbx.ToString()} yet load Failed: [{new Win32Exception(Marshal.GetLastWin32Error()).Message }]");

                cv_data.PDBFullPath = sbx.ToString();
            }

            return symStatus;
#endif
        }
    }
}
