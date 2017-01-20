// Shane.Macaulay @IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// Shane.Macaulay@IOActive.com (c) copyright 2014,2015,2016 all rights reserved. GNU GPL License

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ProtoBuf;
using static System.Console;
using inVtero.net.Support;
using inVtero.net.Specialties;

namespace inVtero.net
{
    public static class EnvLimits
    {
        public const int PageCacheMaxEntries = 100000;
        // more than 10Million page table entries in a single address space, somethings going on ?
        public const long MAX_PageTableEntriesToScan = 10 * 1000000; 
    }
 
    public static class MagicNumbers
    {
        public const int PAGE_SIZE = 0x1000;
        public const int KERNEL_PT_INDEX_START_USUALLY = 256;
        public const int PAGE_SHIFT = 12;
        public const long BAD_VALUE_READ = -0xbad00;
        public const long BAD_RUN_CONFIG_READ = -0xbad01;
        public const long PAGE_REQUESTED_IS_IN_RUN_GAP = -0xbad02;

        public static int[] Each { get { return new int[] { Windows_SelfPtr, FreeBSD_RecursiveEntry, OpenBSD_RecursiveEntry }; } }

        // Self ptr's not relevant after Win10 + 2016 update.
        public static long Windows_SelfAsVA = 0xFFFF6FB7DBEDF68;
        public static int Windows_SelfPtr          = 0x1ED;
        public static int FreeBSD_RecursiveEntry   = 0x100;
        public static int OpenBSD_RecursiveEntry   = 0xFF; // if this were Windows that would place the page table in the user range!  
        public static int NetBSD_RecursiveEntry    = 0xFF; // stop copying OpenBSD ;)! hehe

        public static long MinEPTPAddr = 0x32; // there is no rule about this but even if just not the zero page would cut the false positives down a lot
                                               // if you miss the EPTP reduce this to 0 or 1 ;)
                                               // I could/should probably write a EPTP detection similar to the Linux one 
    }

    public static class Misc
    {
        public static ulong RotL(ulong N, int S)
        {
            return ((N >> (~S)) >> 1) | (N << S);
        }
        public static ulong RotR(ulong N, int S)
        {
            return ((N << (~S)) << 1) | (N >> S);
        }

        public static void WriteColor(string var)
        {
            WriteLine(var);
        }
        public static void WriteColor(ConsoleColor ForeGround, string var)
        {
            if (ForegroundColor != ForeGround)
                ForegroundColor = ForeGround;
            WriteLine(var);
        }
        public static void WriteColor(ConsoleColor ForeGround, ConsoleColor BackGround, string var)
        {
            if (BackgroundColor != BackGround)
                BackgroundColor = BackGround;
            if (ForegroundColor != ForeGround)
                ForegroundColor = ForeGround;

            WriteLine(var.PadRight(var.Length % WindowWidth, ' '));
            WriteLine(var);
        }

        static void LowerBoundOutput()
        {
            const int BarHeight = 5;
            
            var MaxText = (WindowTop + WindowHeight - 1) - BarHeight;

            if (CursorTop >= MaxText)
            {
                BackgroundColor = ConsoleColor.Black;
                var newlines = CursorTop % MaxText;

                for (int i=0; i < newlines; i++)
                    WriteLine(" ".PadRight(WindowWidth));

                CursorTop = MaxText-1;
            }
            ProgressBarz.RenderConsoleProgress(ProgressBarz.Progress);
        }

        public static void WColor(ConsoleColor ForeGround, ConsoleColor BackGround, string var)
        {
            if (BackgroundColor != BackGround)
                BackgroundColor = BackGround;
            if (ForegroundColor != ForeGround)
                ForegroundColor = ForeGround;

            Write(var.PadRight(var.Length % WindowWidth, '\t'));
            LowerBoundOutput();
        }
    }


    #region Value Type addressing objects
    /// <summary>
    /// Using long for Virtual addresses
    /// </summary>
    [ProtoContract]
    public struct VIRTUAL_ADDRESS
    {
        [ProtoMember(800)]
        public long Address;
        public VIRTUAL_ADDRESS(long VA) { Address = VA; }

        public override string ToString() => $"VA: {((Address < 0 || Address > 0x7FFFFFFFFFFF) ? (ulong)Address | 0xffff000000000000 : (ulong)Address):X12}, PML4E {PML4:X3}, DPO:{DirectoryPointerOffset:X3}, DO:{DirectoryOffset:X3}, TO: {TableOffset:X3}, O: {Offset:X4}";

        public long Offset { get { return Address & 0xfff; } set { Address &= ~0xfffu; Address |= value; } }
        public long TableOffset { get { return (Address & 0x1ff000) >> 12; } set { Address &= ~0x1ff000; Address |= (value << 12); } }
        public long DirectoryOffset { get { return (Address & 0x3fe00000) >> 21; } set { Address &= ~0x3FE00000; Address |= (value << 21); } }
        public long DirectoryPointerOffset { get { return (Address & 0x7FC0000000) >> 30; } set { Address &= ~0x7FC0000000; Address |= (value << 30); } }
        // // only >> 36 since we & isolate the 9 bits we want and the lower 3 bits are not used to acquire PML4 page entry
        public long PML4 { get { return (Address & 0xff8000000000) >> 39; } set { Address &= ~0xFF8000000000; Address |= (value << 39); } }
        public long SignExtend
        {
            get { return (((Address >> 48) & 0xfffu) != 0 ? 0xffffu : 0); }
            // who gives a crap?
            set
            {
                return;
            }
        }

    }
    /// <summary>
    /// Maybe just use VIRTUAL_ADDRESS above, pretty much identical
    /// 
    /// EPT: PML4 table is located at the physical address specified in bits 51:12 of the EPTP
    ///         - PML4 entry is then selected from Bits 11:3 are bits 47:39 of the guest-physical address
    /// 
    /// Physical addresses as long
    /// </summary>
    public struct GUEST_PHYSICAL_ADDRESS
    {
        public long GPA;
        public GUEST_PHYSICAL_ADDRESS(long gPA) { GPA = gPA; }
        public long Offset { get { return GPA & 0xfff; } }
        public long PTE { get { return (GPA >> 12) & 0x1ff; } }
        public long PDE { get { return (GPA >> 21) & 0x1ff; } }
        public long PDPTE { get { return (GPA >> 30) & 0x1ff; } }
        public long PML4E { get { return (GPA >> 39) & 0x1ff; } }
    }

    [ProtoContract(ImplicitFields = ImplicitFields.AllFields)]
    public struct HARDWARE_ADDRESS_ENTRY : IComparable
    {
        [ProtoMember(99)]
        public long PTE; // should really be called 'value' or something

        public static readonly HARDWARE_ADDRESS_ENTRY MinAddr = new HARDWARE_ADDRESS_ENTRY(long.MinValue);
        public static readonly HARDWARE_ADDRESS_ENTRY MaxAddr = new HARDWARE_ADDRESS_ENTRY(long.MaxValue);

        public static implicit operator HARDWARE_ADDRESS_ENTRY(long x) => new HARDWARE_ADDRESS_ENTRY(x);
        public static implicit operator SLAT_ENTRY(HARDWARE_ADDRESS_ENTRY x) => new SLAT_ENTRY(x);
        public static implicit operator long (HARDWARE_ADDRESS_ENTRY x) => x.PTE;

        public static HARDWARE_ADDRESS_ENTRY operator +(HARDWARE_ADDRESS_ENTRY lh, long rh)
        {
            lh.PTE += rh;
            return lh;
        }
        public static HARDWARE_ADDRESS_ENTRY operator +(HARDWARE_ADDRESS_ENTRY lh, HARDWARE_ADDRESS_ENTRY rh)
        {
            lh.PTE += rh.PTE;
            return lh;
        }
        public override string ToString()
        {
            var sb = $"PTE:{PTE:X16} PFN:{PFN:X12} AO:{AddressOffset:X3} WS:{SoftwareWsIndex:X4} NX:{NoExecute} W:{Write} UN:{Unused} COW:{CopyOnWrite} G:{Global} LP:{LargePage} D:{Dirty} A:{Accessed} CD:{CacheDisable} WT:{WriteThrough} S|O{Owner} D1:{Dirty1} V:{Valid}";

            // I wish bool had a format specifier!
            var replacements = new List<Tuple<string, string>>() { Tuple.Create<string, string>("True", "+"), Tuple.Create<string, string>("False", "-") };
            replacements.ForEach(x => sb = sb.Replace(x.Item1, x.Item2));
            return sb.ToString();
        }

        public int CompareTo(object obj)
        {
            return PTE.CompareTo(obj);
        }

        public static bool IsBadEntry(HARDWARE_ADDRESS_ENTRY entry)
        {
            if (entry <= HARDWARE_ADDRESS_ENTRY.MinAddr + 2L || entry >= HARDWARE_ADDRESS_ENTRY.MaxAddr - 2L)
                return true;

            return false;
        }

        public HARDWARE_ADDRESS_ENTRY(long pte) { PTE = pte; }
        public bool Valid { get { return (PTE & 1) != 0; } set { if (value) PTE |= 1; else PTE &= ~1; } }
        public bool Dirty1 { get { return (PTE & 2) != 0; } }
        public bool Owner { get { return (PTE & 4) != 0; } }
        public bool WriteThrough { get { return (PTE & 8) != 0; } }
        public bool CacheDisable { get { return (PTE & 0x10) != 0; } }
        public bool Accessed { get { return (PTE & 0x20) != 0; } }
        public bool Dirty { get { return (PTE & 0x40) != 0; } }
        public bool LargePage { get { return (PTE & 0x80) != 0; } set { if (value) PTE |= 0x80; else PTE &= ~0x80; } }

        public bool Global { get { return (PTE & 0x100) != 0; } }
        public bool CopyOnWrite { get { return (PTE & 0x200) != 0; } }
        public bool Unused { get { return (PTE & 0x400) != 0; } }
        public bool Write { get { return (PTE & 0x800) != 0; } }
        public long PFN { get { return (PTE >> 12) & 0xFFFFFFFFFF; } } 
        public long SoftwareWsIndex { get { return (PTE >> 52) & 0x7ff; } }
        public bool NoExecute { get { return ((ulong) PTE & 0x8000000000000000) != 0; } }
        // NEXT is PFN << 12 since were adjusting back to phys address
        public long NextTableAddress {  get { return PTE & 0xFFFFFFFFFF000; } } // 40 bit address + Offset 12 bits = 52 phys linear address
        // Full 48 bit size
        public long NextTable_PFN { get { return (PTE >> 12) & 0xFFFFFFFFFF; } }
        // 2MB entries, should be very typical
        public long twoMB_PFN { get { return (PTE & 0xFFFFFFE00000) >> 21; } }
        // after >> 30 == 3FFFF tot 1GB pages 
        public long GB_PFN { get { return (PTE & 0xFFFFC0000000) >> 30; } }
        public long AddressOffset {  get { return PTE & 0xfff; } /*set { PTE = PTE &= ~0xfff; PTE |= value & 0xfff; } */ }
    }

    public struct SLAT_ENTRY
    {
        public long SLATEntry;
        public SLAT_ENTRY(HARDWARE_ADDRESS_ENTRY slat) { SLATEntry = slat.PTE; }
        public SLAT_ENTRY(long slat) { SLATEntry = slat; }
        public bool Read { get { return (SLATEntry & 1) != 0; } }
        public bool Write { get { return (SLATEntry & 2) != 0; } }
        public bool Execute { get { return (SLATEntry & 4) != 0; } }
        public long MemType { get { return (SLATEntry >> 3) & 0x7; } }
        public bool IgnorePAT { get { return (SLATEntry & 0x40) != 0; } }
        public bool LargePage { get { return (SLATEntry & 0x80) != 0; } }
        public bool Accessed { get { return (SLATEntry & 0x100) != 0; } }
        public bool Dirty { get { return (SLATEntry & 0x200) != 0; } }
        // 2MB entries, should be very typical
        public long twoMB_PFN { get { return (SLATEntry & 0xFFFFFFE00000) >> 21; } }
        // after >> 30 == 3FFFF tot 1GB pages 
        public long GB_PFN { get { return (SLATEntry & 0xFFFFC0000000) >> 30; } }
        // When this entry point's to another table, this is the phys address of that table
        public long SLAT_NextTable_PFN { get { return (SLATEntry >> 12) & 0xFFFFFFFFFF; } }
        public bool SuppressVE { get { return ((ulong) SLATEntry & 0x8000000000000000) != 0; } }
    }
    /// <summary>
    /// EPTP for SLAT configuration hypervisors
    /// 64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf
    /// Section 24.6.11
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public struct EPTP
    {
        public long aEPTP;
        public EPTP(long eptp) { aEPTP = eptp; }
        public EPT_MemType Type { get { return (EPT_MemType) (aEPTP & 0x7); } }
        public int PageWalkLen { get { return (int) (aEPTP >> 3) & 0x7; } } // 1 less than the length
        public bool EPT_AccessDirtyFlagBehaviour { get { return (aEPTP & 0x40) != 0; } }
        public bool ReservedFlagsSet { get { return ((ulong)aEPTP & 0xFFFF000000000F80) != 0; } }

        public long PML4_PFN { get { return (aEPTP >> 12) & 0xFFFFFFFFFF; } } // double check may just use PTE above
        public long PML4_PFN_Address { get { return aEPTP & 0xFFFFFFFFFF; } } // double check may just use PTE above

        public static bool IsValid(long SLATe) { return (SLATe & 0x7) != 0; }

        /// <summary>
        /// validates an EPTP 
        /// </summary>
        /// <returns></returns>
        public bool IsFullyValidated()
        {
            if ((Type & (EPT_MemType.UnCached | EPT_MemType.WriteBack)) != Type)
                return false;

            // can this happen?
            if (PageWalkLen > 3 || PageWalkLen <= 1)
                return false;

            if (ReservedFlagsSet)
                return false;

            if (PML4_PFN < MagicNumbers.MinEPTPAddr)
                return false;

            return true;
        }

        public static bool IsLargePDE(long SLATe)
        {
            // bits 29:12 must be 0
            // 51:48 must be 0
            if ((0xE0000001FF080 & (ulong)SLATe) != 0)
                return false;
            return true;
        }
        public static bool IsLargePDPTE(long SLATe)
        {
            // bits 29:12 must be 0
            // 51:48 must be 0
            if ((0xF00003FFFF080 & (ulong)SLATe) != 0)
                return false;
            return true;
        }
        public static bool IsValid2(long SLATe)
        {
            if ((0xF0000000000F8 & (ulong)SLATe) != 0)
                return false;
            return true;
        }
        
        public static bool IsValidEntry(long SLATe)
        {
            if ((0xF000000000007 & (ulong)SLATe) != 0)
                return false;
            return true;
        }

        public override string ToString() => $"Address:{PML4_PFN_Address:X12}, Type:{Type}, WalkLen:{PageWalkLen}, Valid:{IsValid(aEPTP)}, Valid2:{IsValid2(aEPTP)}, ValidEntry:{IsValidEntry(aEPTP)}, LargePDP:{IsLargePDPTE(aEPTP)}, LargePDE:{IsLargePDE(aEPTP)}";

    }
    #endregion
    #region Memory gap structs
    /// <summary>
    /// Runs allow for gaps in address space
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class MemoryRun
    {
        public long BasePage;
        public long PageCount;
        public long regionPPN;
        public long SkipCount;

        public override string ToString()
        {
            return $"BasePage: {BasePage:X12} PageCount: {PageCount:X12} PhysicalPageNumber {regionPPN:X12}";
        }
    }
    /// <summary>
    /// Setup one default memory run for the entire range
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class MemoryDescriptor
    {
        public long StartOfMemmory; // this object does not have to be a 1:1 to the native type
        public long NumberOfRuns;
        public long NumberOfPages;

        long maxAddressablePageNumber;

        [ProtoIgnore]
        public long MaxAddressablePageNumber { get {

                if (maxAddressablePageNumber != 0)
                    return maxAddressablePageNumber + (StartOfMemmory >> MagicNumbers.PAGE_SHIFT);

                maxAddressablePageNumber = Run.Count > 0 ? Run[Run.Count - 1].BasePage + Run[Run.Count - 1].PageCount : NumberOfPages;
                return maxAddressablePageNumber + (StartOfMemmory >> MagicNumbers.PAGE_SHIFT);
            } }
        public List<MemoryRun> Run;

        public MemoryDescriptor()
        {
            Run = new List<MemoryRun>();
        }

        public MemoryDescriptor(long MemSize, long BaseOffset) : this()
        {
            StartOfMemmory = BaseOffset;
            NumberOfPages = (MemSize / 4096) - BaseOffset / 4096;
            NumberOfRuns = 1;

            Run.Add(new MemoryRun { BasePage = 0, PageCount = NumberOfPages });
        }

        public MemoryDescriptor(long MemSize) : this()
        {
            NumberOfPages = MemSize / 4096;
            NumberOfRuns = 1;

            Run.Add(new MemoryRun { BasePage = 0, PageCount = NumberOfPages });
        }

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Number of Runs: 0x{NumberOfRuns:X} \t Pages: 0x{NumberOfPages:X}");
            for(int i=0; i < NumberOfRuns; i++)
                sb.AppendLine($"BasePage 0x{Run[i].BasePage:X} \t PageCount: 0x{Run[i].PageCount:X} ");

            return sb.ToString();
        }
    }
    #endregion
    #region Top Level classes
    
    #endregion
    #region Flags and Enum
    // 0 Is really what we expect
    // This may be different for virtualized implementations
    public enum VMCS_ABORT
    {
        NO_ABORT = 0,
        MCD_IN_EXIT = 0x500,
        TXT_SHUTDOWN = 0xd00,
        UNKNOWN_ABORT = 0x7fffffff
    }

    // From ReKall.  This is only for informational purposes
    // REVISION_ID is not used for any detection or matching
    public enum REVISION_ID : uint // Should correspond to VMX_BASIC_MSR
    {
        VMWARE_NESTED = 1,
        // KVM
        KVM_NESTED = 0x11e57ed0,
        // XEN
        XEN_NESTED = 0xda0400,
        // Intel VT-x microarchitectures.
        PENRYN = 0xd,
        NEHALEM = 0x0e,
        WESTMERE = 0xf,
        SANDYBRIDGE = 0x10,
        HASWELL = 0x12,
        UNKNOWN_REVISION = 0xffffffff
    }

    /// <summary>
    /// PTType configures the Scanner methods by setting ScanMode
    /// </summary>
    [Flags]
    public enum PTType : int
    {
        UNCONFIGURED = 0,
        Windows = 1,
        FreeBSD = 2,
        OpenBSD = 4,
        NetBSD = 8,
        HyperV = 0x10,
        LinuxS = 0x10000000,    // Jumping for Linux since this is now a state saving check
                                // LinuxS is still a single pass
        VALUE   = 0x20000000,   // Value Scan (i.e. scan for a dword or ulong)
        GENERIC = 0x40000000,   // Generic stateless
        ALL = int.MaxValue,
        VMCS = 0x8000000      // VMCS uses state also and also 2 pass
    }

    [Flags]
    public enum VAScanType : uint
    {
        UNDETERMINED    = 0,
        PE_FAST         = 1
    }


    [Flags]
    public enum EPT_MemType
    {
        UnCached        = 0,
        WriteCombine    = 1,
        INVALID         = 2,
        INVALID2        = 3,
        WriteThrough    = 4,
        WriteProtect    = 5,
        WriteBack       = 6
    }
    #endregion
}
