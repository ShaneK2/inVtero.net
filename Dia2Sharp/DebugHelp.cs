using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

// TODO: use that github project that Microsoft released the PDB info which makes life a lot easier? :) never heard that b4!

namespace Dia2Sharp
{
    public unsafe class DebugHelp
    {
        public const int SSRVOPT_DWORD = 0x0002;
        public const int SSRVOPT_DWORDPTR = 0x004;
        public const int SSRVOPT_GUIDPTR = 0x0008;
       

        [Flags]
        public enum SymFlag : uint
        {
            VALUEPRESENT = 0x00000001,
            REGISTER = 0x00000008,
            REGREL = 0x00000010,
            FRAMEREL = 0x00000020,
            PARAMETER = 0x00000040,
            LOCAL = 0x00000080,
            CONSTANT = 0x00000100,
            EXPORT = 0x00000200,
            FORWARDER = 0x00000400,
            FUNCTION = 0x00000800,
            VIRTUAL = 0x00001000,
            THUNK = 0x00002000,
            TLSREL = 0x00004000,
        }

        [Flags]
        public enum SymTagEnum : uint
        {
            Null,
            Exe,
            Compiland,
            CompilandDetails,
            CompilandEnv,
            Function,
            Block,
            Data,
            Annotation,
            Label,
            PublicSymbol,
            UDT,
            Enum,
            FunctionType,
            PointerType,
            ArrayType,
            BaseType,
            Typedef,
            BaseClass,
            Friend,
            FunctionArgType,
            FuncDebugStart,
            FuncDebugEnd,
            UsingNamespace,
            VTableShape,
            VTable,
            Custom,
            Thunk,
            CustomType,
            ManagedType,
            Dimension
        };
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SYMBOL_INFO
        {
            public uint SizeOfStruct;
            public uint TypeIndex;
            public ulong Reserved1;
            public ulong Reserved2;
            public uint Reserved3;
            public uint Size;
            public ulong ModBase;
            public SymFlag Flags;
            public ulong Value;
            public long Address;
            public uint Register;
            public uint Scope;
            public SymTagEnum Tag;
            public int NameLen;
            public int MaxNameLen;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
            public string Name;
        }

        [Flags]
        public enum SymCallbackActions
        {
            CBA_DEBUG_INFO = 0x10000000,
            CBA_DEFERRED_SYMBOL_LOAD_CANCEL = 0x00000007,
            CBA_DEFERRED_SYMBOL_LOAD_COMPLETE = 0x00000002,
            CBA_DEFERRED_SYMBOL_LOAD_FAILURE = 0x00000003,
            CBA_DEFERRED_SYMBOL_LOAD_PARTIAL = 0x00000020,
            CBA_DEFERRED_SYMBOL_LOAD_START = 0x00000001,
            CBA_DUPLICATE_SYMBOL = 0x00000005,
            CBA_EVENT = 0x00000010,
            CBA_READ_MEMORY = 0x00000006,
            CBA_SET_OPTIONS = 0x00000008,
            CBA_SRCSRV_EVENT = 0x40000000,
            CBA_SRCSRV_INFO = 0x20000000,
            CBA_SYMBOLS_UNLOADED = 0x00000004,
        }

        [Flags]
        public enum SymOptions : uint
        {
            SYMOPT_ALLOW_ABSOLUTE_SYMBOLS = 0x00000800,
            SYMOPT_ALLOW_ZERO_ADDRESS = 0x01000000,
            SYMOPT_AUTO_PUBLICS = 0x00010000,
            SYMOPT_CASE_INSENSITIVE = 0x00000001,
            SYMOPT_DEBUG = 0x80000000,
            SYMOPT_DEFERRED_LOADS = 0x00000004,
            SYMOPT_DISABLE_SYMSRV_AUTODETECT = 0x02000000,
            SYMOPT_EXACT_SYMBOLS = 0x00000400,
            SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200,
            SYMOPT_FAVOR_COMPRESSED = 0x00800000,
            SYMOPT_FLAT_DIRECTORY = 0x00400000,
            SYMOPT_IGNORE_CVREC = 0x00000080,
            SYMOPT_IGNORE_IMAGEDIR = 0x00200000,
            SYMOPT_IGNORE_NT_SYMPATH = 0x00001000,
            SYMOPT_INCLUDE_32BIT_MODULES = 0x00002000,
            SYMOPT_LOAD_ANYTHING = 0x00000040,
            SYMOPT_LOAD_LINES = 0x00000010,
            SYMOPT_NO_CPP = 0x00000008,
            SYMOPT_NO_IMAGE_SEARCH = 0x00020000,
            SYMOPT_NO_PROMPTS = 0x00080000,
            SYMOPT_NO_PUBLICS = 0x00008000,
            SYMOPT_NO_UNQUALIFIED_LOADS = 0x00000100,
            SYMOPT_OVERWRITE = 0x00100000,
            SYMOPT_PUBLICS_ONLY = 0x00004000,
            SYMOPT_SECURE = 0x00040000,
            SYMOPT_UNDNAME = 0x00000002,
        };

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode)]
        public static extern bool SymInitialize(long hProcess, [MarshalAs(UnmanagedType.LPWStr)] string UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFindFileInPath(
            long hProcess,
            string SearchPath,
            [MarshalAs(UnmanagedType.LPWStr), In]  string FileName,
            IntPtr TimeDate,
            Int32 two,
            Int32 three,
            Int32 flags,
            [In, Out] StringBuilder filePath,
            IntPtr callback,
            IntPtr context);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFindFileInPathW(
            long hProcess,
            string searchPath,
            [MarshalAs(UnmanagedType.LPWStr), In] string fileName,
            ref Guid id,
            int two,
            int three,
            int flags,
            [In, Out] StringBuilder filepath,
            IntPtr findCallback,
            IntPtr context
            );


        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymEnumSymbols(long hProcess, ulong BaseOfDll, string Mask, PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IntPtr UserContext);
        public delegate bool PSYM_ENUMERATESYMBOLS_CALLBACK(ref SYMBOL_INFO pSymInfo, uint SymbolSize, IntPtr UserContext);

        public static bool EnumSyms(ref SYMBOL_INFO pSymInfo, uint SymbolSize, IntPtr UserContext)
        {
            Console.Out.WriteLine("Name: " + pSymInfo.Name);
            return true;

        }

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFromName(
            long hProcess,
            [MarshalAs(UnmanagedType.LPTStr)] string SymName,
            ref SYMBOL_INFO pSymInfo);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymSrvGetFileIndexesW(
            string filePath,
            ref Guid id,
            ref int val1,
            ref int val2,
            int flags);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitializeW(IntPtr hProcess, string UserSearchPath, [MarshalAs(UnmanagedType.Bool)] bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern ulong SymLoadModuleExW(
            long hProcess,
            IntPtr hFile,
            string ImageName,
            string ModuleName,
            ulong BaseOfDll,
            uint DllSize,
            void* Data,
            uint Flags
         );

        [DllImport("dbghelp.dll", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymUnloadModule64(
            long hProcess,
            ulong BaseOfDll);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetLineFromAddrW64(
            long hProcess,
            ulong Address,
            ref Int32 Displacement,
            ref IntPtr Line
        );

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFromAddrW(
            long hProcess,
            ulong Address,
            ref ulong Displacement,
            ref SYMBOL_INFO Symbol
        );
        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong SymLoadModuleEx(long hProcess, IntPtr hFile, string ImageName, string ModuleName, long BaseOfDll, int DllSize, IntPtr Data, int Flags);


        [DllImport("dbghelp.dll", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern SymOptions SymGetOptions();

        [DllImport("dbghelp.dll", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern SymOptions SymSetOptions(SymOptions SymOptions);
    }
}
