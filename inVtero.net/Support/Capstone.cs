using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace inVtero.net.Support
{ 
    [StructLayout(LayoutKind.Sequential)]
    public struct cs_insn
    {
        public uint id;
        public ulong address;
        public ushort size;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] bytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string mnemonic;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
        public string operands;
        public IntPtr detail;
    }
    /// Partial, only architecture-independent internal data
    [StructLayout(LayoutKind.Sequential)]
    public struct cs_detail
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
        public byte[] regs_read;
        public byte regs_read_count;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] regs_write;
        public byte regs_write_count;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] groups;
        public byte groups_count;
    }
    public enum cs_err : int
    {
        CS_ERR_OK = 0,    /// No error: everything was fine
		CS_ERR_MEM,       /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
		CS_ERR_ARCH,      /// Unsupported architecture: cs_open()
		CS_ERR_HANDLE,    /// Invalid handle: cs_op_count(), cs_op_index()
		CS_ERR_CSH,       /// Invalid csh argument: cs_close(), cs_errno(), cs_option()
		CS_ERR_MODE,      /// Invalid/unsupported mode: cs_open()
		CS_ERR_OPTION,    /// Invalid/unsupported option: cs_option()
		CS_ERR_DETAIL,    /// Information is unavailable because detail option is OFF
		CS_ERR_MEMSETUP,  /// Dynamic memory management uninitialized (see CS_OPT_MEM)
		CS_ERR_VERSION,   /// Unsupported version (bindings)
		CS_ERR_DIET,      /// Access irrelevant data in "diet" engine
		CS_ERR_SKIPDATA,  /// Access irrelevant data for "data" instruction in SKIPDATA mode
		CS_ERR_X86_ATT,   /// X86 AT&T syntax is unsupported (opt-out at compile time)
		CS_ERR_X86_INTEL, /// X86 Intel syntax is unsupported (opt-out at compile time)
	}
    public enum cs_arch : int
    {
        CS_ARCH_ARM = 0,      /// ARM architecture (including Thumb, Thumb-2)
		CS_ARCH_ARM64,        /// ARM-64, also called AArch64
		CS_ARCH_MIPS,         /// Mips architecture
		CS_ARCH_X86,          /// X86 architecture (including x86 & x86-64)
		CS_ARCH_PPC,          /// PowerPC architecture
		CS_ARCH_SPARC,        /// Sparc architecture
		CS_ARCH_SYSZ,         /// SystemZ architecture
		CS_ARCH_XCORE,        /// XCore architecture
		CS_ARCH_MAX,
        CS_ARCH_ALL = 0xFFFF, /// All architectures - for cs_support()
	}
    public enum cs_mode : int
    {
        CS_MODE_LITTLE_ENDIAN = 0,    /// little-endian mode (default mode)
		CS_MODE_ARM = 0,              /// 32-bit ARM
		CS_MODE_16 = 1 << 1,          /// 16-bit mode (X86)
		CS_MODE_32 = 1 << 2,          /// 32-bit mode (X86)
		CS_MODE_64 = 1 << 3,          /// 64-bit mode (X86, PPC)
		CS_MODE_THUMB = 1 << 4,       /// ARM's Thumb mode, including Thumb-2
		CS_MODE_MCLASS = 1 << 5,      /// ARM's Cortex-M series
		CS_MODE_V8 = 1 << 6,          /// ARMv8 A32 encodings for ARM
		CS_MODE_MICRO = 1 << 4,       /// MicroMips mode (MIPS)
		CS_MODE_MIPS3 = 1 << 5,       /// Mips III ISA
		CS_MODE_MIPS32R6 = 1 << 6,    /// Mips32r6 ISA
		CS_MODE_MIPSGP64 = 1 << 7,    /// General Purpose Registers are 64-bit wide (MIPS)
		CS_MODE_V9 = 1 << 4,          /// SparcV9 mode (Sparc)
		CS_MODE_BIG_ENDIAN = 1 << 31, /// big-endian mode
		CS_MODE_MIPS32 = CS_MODE_32,  /// Mips32 ISA (Mips)
		CS_MODE_MIPS64 = CS_MODE_64,  /// Mips64 ISA (Mips)
	}

    public static class Capstone
    {
        [DllImport("$DllPath")]
        public static extern cs_err cs_open(
            cs_arch arch,
            cs_mode mode,
            ref IntPtr handle);
        [DllImport("$DllPath")]
        public static extern UInt32 cs_disasm(
            IntPtr handle,
            byte[] code,
            int code_size,
            ulong address,
            int count,
            ref IntPtr insn);
        [DllImport("$DllPath")]
        public static extern bool cs_free(
            IntPtr insn,
            int count);
        [DllImport("$DllPath")]
        public static extern cs_err cs_close(
            ref IntPtr handle);
        [DllImport("$DllPath")]
        public static extern cs_err cs_option(
            IntPtr handle,
            int type,
            int value);
        [DllImport("$DllPath", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr cs_reg_name(
            IntPtr handle,
            uint reg_id);
        [DllImport("$DllPath")]
        public static extern int cs_version(
            uint major,
            uint minor);
    }
}
