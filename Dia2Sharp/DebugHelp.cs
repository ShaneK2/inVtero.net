using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

// TODO: use that github project that Microsoft released the PDB info which makes life a lot easier? :) never heard that b4!

namespace Dia2Sharp
{
    public unsafe class DebugHelp
    {
        public const uint SSRVOPT_DWORD = 0x0002;
        public const uint SSRVOPT_DWORDPTR = 0x004;
        public const uint SSRVOPT_GUIDPTR = 0x0008;

        [Flags]
        public enum UnDname : uint
        {
            COMPLETE                 = 0x0000,  // Enable full undecoration
            NO_LEADING_UNDERSCORES   = 0x0001,  // Remove leading underscores from MS extended keywords
            NO_MS_KEYWORDS           = 0x0002,  // Disable expansion of MS extended keywords
            NO_FUNCTION_RETURNS      = 0x0004,  // Disable expansion of return type for primary declaration
            NO_ALLOCATION_MODEL      = 0x0008,  // Disable expansion of the declaration model
            NO_ALLOCATION_LANGUAGE   = 0x0010,  // Disable expansion of the declaration language specifier
            NO_MS_THISTYPE           = 0x0020,  // NYI Disable expansion of MS keywords on the 'this' type for primary declaration
            NO_CV_THISTYPE           = 0x0040,  // NYI Disable expansion of CV modifiers on the 'this' type for primary declaration
            NO_THISTYPE              = 0x0060,  // Disable all modifiers on the 'this' type
            NO_ACCESS_SPECIFIERS     = 0x0080,  // Disable expansion of access specifiers for members
            NO_THROW_SIGNATURES      = 0x0100,  // Disable expansion of 'throw-signatures' for functions and pointers to functions
            NO_MEMBER_TYPE           = 0x0200,  // Disable expansion of 'static' or 'virtual'ness of members
            NO_RETURN_UDT_MODEL      = 0x0400,  // Disable expansion of MS model for UDT returns
            DECODE_32_BIT            = 0x0800,  // Undecorate 32-bit decorated names
            NAME_ONLY                = 0x1000,  // Crack only the name for primary declaration;
                        //  return just [scope::]name.  Does expand template params
            NO_ARGUMENTS             = 0x2000,  // Don't undecorate arguments to function
            NO_SPECIAL_SYMS          = 0x4000,  // Don't undecorate special names = v-table, vcall, vector xxx, metatype, etc,

        };

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
            SLOT = 0x00008000,
            ILREL = 0x00010000,
            METADATA = 0x00020000,
            CLR_TOKEN = 0x00040000,
            NULL = 0x00080000,
            FUNC_NO_RETURN = 0x00100000,
            SYNTHETIC_ZEROBASE = 0x00200000,
            PUBLIC_CODE = 0x00400000,
            RESET = 0x80000000
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
            Dimension,
            CallSite,
            InlineSite,
            BaseInterface,
            VectorType,
            MatrixType,
            HLSLType,
            Caller,
            Callee,
            Export,
            HeapAllocationSite,
            CoffGroup,
            Max
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
        public enum SymOptions : UInt32
        {
            SYMOPT_CASE_INSENSITIVE          = 0x00000001,
            SYMOPT_UNDNAME                   = 0x00000002,
            SYMOPT_DEFERRED_LOADS            = 0x00000004,
            SYMOPT_NO_CPP                    = 0x00000008,
            SYMOPT_LOAD_LINES                = 0x00000010,
            SYMOPT_OMAP_FIND_NEAREST         = 0x00000020,
            SYMOPT_LOAD_ANYTHING             = 0x00000040,
            SYMOPT_IGNORE_CVREC              = 0x00000080,
            SYMOPT_NO_UNQUALIFIED_LOADS      = 0x00000100,
            SYMOPT_FAIL_CRITICAL_ERRORS      = 0x00000200,
            SYMOPT_EXACT_SYMBOLS             = 0x00000400,
            SYMOPT_ALLOW_ABSOLUTE_SYMBOLS    = 0x00000800,
            SYMOPT_IGNORE_NT_SYMPATH         = 0x00001000,
            SYMOPT_INCLUDE_32BIT_MODULES     = 0x00002000,
            SYMOPT_PUBLICS_ONLY              = 0x00004000,
            SYMOPT_NO_PUBLICS                = 0x00008000,
            SYMOPT_AUTO_PUBLICS              = 0x00010000,
            SYMOPT_NO_IMAGE_SEARCH           = 0x00020000,
            SYMOPT_SECURE                    = 0x00040000,
            SYMOPT_NO_PROMPTS                = 0x00080000,
            SYMOPT_OVERWRITE                 = 0x00100000,
            SYMOPT_IGNORE_IMAGEDIR           = 0x00200000,
            SYMOPT_FLAT_DIRECTORY            = 0x00400000,
            SYMOPT_FAVOR_COMPRESSED          = 0x00800000,
            SYMOPT_ALLOW_ZERO_ADDRESS        = 0x01000000,
            SYMOPT_DISABLE_SYMSRV_AUTODETECT = 0x02000000,
            SYMOPT_READONLY_CACHE            = 0x04000000,
            SYMOPT_SYMPATH_LAST              = 0x08000000,
            SYMOPT_DISABLE_FAST_SYMBOLS      = 0x10000000,
            SYMOPT_DISABLE_SYMSRV_TIMEOUT    = 0x20000000,
            SYMOPT_DISABLE_SRVSTAR_ON_STARTUP = 0x40000000,
            SYMOPT_DEBUG                     = 0x80000000
        };

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitialize(long hProcess, [MarshalAs(UnmanagedType.LPWStr), In] string UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFindFileInPathW(
            long hProcess,
            string SearchPath,
            [MarshalAs(UnmanagedType.LPWStr), In]  StringBuilder FileName,
            IntPtr TimeDate,
            UInt32 two,
            UInt32 three,
            UInt32 flags,
            [In, Out] StringBuilder filePath,
            IntPtr callback,
            IntPtr context);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFindFileInPathW(
            long hProcess,
            string searchPath,
            [MarshalAs(UnmanagedType.LPWStr), In] StringBuilder fileName,
            ref Guid id,
            UInt32 two,
            UInt32 three,
            UInt32 flags,
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

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFromName(
            long hProcess,
            [MarshalAs(UnmanagedType.LPWStr)] string SymName,
            ref SYMBOL_INFO pSymInfo);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymSrvGetFileIndexesW(
            string filePath,
            ref Guid id,
            ref int val1,
            ref int val2,
            int flags);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitializeW(IntPtr hProcess, string UserSearchPath, [MarshalAs(UnmanagedType.Bool)] bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
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

        [DllImport("dbghelp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymUnloadModule64(
            long hProcess,
            ulong BaseOfDll);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetLineFromAddrW64(
            long hProcess,
            ulong Address,
            ref Int32 Displacement,
            ref IntPtr Line
        );

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFromAddrW(
            long hProcess,
            ulong Address,
            ref ulong Displacement,
            ref SYMBOL_INFO Symbol
        );
        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong SymLoadModuleEx(long hProcess, IntPtr hFile, string ImageName, string ModuleName, ulong BaseOfDll, uint DllSize, IntPtr Data, uint Flags);


        [DllImport("dbghelp.dll", SetLastError = true)]
        public static extern SymOptions SymGetOptions();

        [DllImport("dbghelp.dll", SetLastError = true)]
        public static extern SymOptions SymSetOptions(SymOptions SymOptions);

        [DllImport("dbghelp.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public static extern bool SymGetSymbolFile([In, Optional]long hProcess, [In, Optional]string SymPath,
            [In] string ImageFile, [In] uint Type, [Out] StringBuilder SymbolFile, [In] UIntPtr cSymbolFile, [Out] StringBuilder DbgFile, [In] UIntPtr cDbgFile);
    }
}
