// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net
{
    public static class Typical_Offsets
    {
        public static int[] Each { get { return new int[] { Windows_SelfPtr, FreeBSD_RecursiveEntry, OpenBSD_RecursiveEntry }; } }

        public static int Windows_SelfPtr          = 0x1ED;
        public static int FreeBSD_RecursiveEntry   = 0x100;
        public static int OpenBSD_RecursiveEntry   = 0xFF; // if this were Windows that would place the page table in the user range!  
        public static int NetBSD_RecursiveEntry    = 0xFF; // stop copying OpenBSD ;)! hehe
    }


    public class AddressX
    {
        public VIRTUAL_ADDRESS VA;
        public HARDWARE_ADDRESS_ENTRY gPA;
        public HARDWARE_ADDRESS_ENTRY[] gTable;
        
        public HARDWARE_ADDRESS_ENTRY hPA;
        public HARDWARE_ADDRESS_ENTRY[] hPTable;
    }

    #region Value Type addressing objects
    public struct VIRTUAL_ADDRESS
    {
        public override string ToString() => $"Addr: {Address:X16}, PML4E {PML4:X4}, DirectoryPointerOffset:{DirectoryPointerOffset:X4}, DirectoryOffset:{DirectoryOffset:X4}, TableOffset: {TableOffset:X4}, Offset: {Offset:X4}";

        public ulong Address;
        public VIRTUAL_ADDRESS(ulong VA) { Address = VA; }
        public ulong Offset { get { return Address & 0xfff; } set { Address |= (value & 0xfff); } }
        public ulong TableOffset { get { return (Address & 0x1ff000) >> 9; } set { Address |= (value & 0x1ff000); } }
        public ulong DirectoryOffset { get { return (Address & 0x3fe00000) >> 18; }  set { Address |= (value & 0x3FE00000); } }
        public ulong DirectoryPointerOffset { get { return (Address & 0x7FC0000000) >> 27; } set { Address |= (value & 0x7FC0000000); } }
        public ulong PML4 { get { return (Address & 0xff8000000000) >> 36; } set { Address |= (value & 0xFF8000000000); } }
        public ulong SignExtend { get { return (ulong)(((Address >> 48) & 0xfff) != 0 ? 0xffff : 0); } set { Address |= (value & 0xffff00000000000); } }  // either 0 or 0xffff if any bits were set
    }
    /// <summary>
    /// Maybe just use VIRTUAL_ADDRESS above, pretty much identical
    /// 
    /// EPT: PML4 table is located at the physical address specified in bits 51:12 of the EPTP
    ///         - PML4 entry is then selected from Bits 11:3 are bits 47:39 of the guest-physical address
    /// </summary>
    public struct GUEST_PHYSICAL_ADDRESS
    {
        public ulong GPA;
        public GUEST_PHYSICAL_ADDRESS(ulong gPA) { GPA = gPA; }
        public ulong Offset { get { return GPA & 0xfff; } }
        public ulong PTE { get { return (GPA >> 12) & 0x1ff; } }
        public ulong PDE { get { return (GPA >> 21) & 0x1ff; } }
        public ulong PDPTE { get { return (GPA >> 30) & 0x1ff; } }
        public ulong PML4E { get { return (GPA >> 39) & 0x1ff; } }
    }

    public struct HARDWARE_ADDRESS_ENTRY
    {
        public ulong PTE; // should really be called 'value' or something

        public static readonly HARDWARE_ADDRESS_ENTRY MinAddr = new HARDWARE_ADDRESS_ENTRY(ulong.MinValue);
        public static readonly HARDWARE_ADDRESS_ENTRY MaxAddr = new HARDWARE_ADDRESS_ENTRY(ulong.MaxValue);

        public static implicit operator HARDWARE_ADDRESS_ENTRY(ulong x) => new HARDWARE_ADDRESS_ENTRY(x);
        public static implicit operator SLAT_ENTRY(HARDWARE_ADDRESS_ENTRY x) => new SLAT_ENTRY(x);
        public static implicit operator ulong (HARDWARE_ADDRESS_ENTRY x) => x.PTE;

        public static HARDWARE_ADDRESS_ENTRY operator +(HARDWARE_ADDRESS_ENTRY lh, ulong rh)
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
            return $"Addr: {PTE:X16}";
        }

        public HARDWARE_ADDRESS_ENTRY(ulong pte) { PTE = pte; }
        public bool Valid { get { return (PTE & 7) != 0; } }
        public bool Dirty1 { get { return (PTE & 2) != 0; } }
        public bool Owner { get { return (PTE & 4) != 0; } }
        public bool WriteThrough { get { return (PTE & 8) != 0; } }
        public bool CacheDisable { get { return (PTE & 0x10) != 0; } }
        public bool Accessed { get { return (PTE & 0x20) != 0; } }
        public bool Dirty { get { return (PTE & 0x40) != 0; } }
        public bool LargePage { get { return (PTE & 0x80) != 0; } }
        public bool Global { get { return (PTE & 0x100) != 0; } }
        public bool CopyOnWrite { get { return (PTE & 0x200) != 0; } }
        public bool Unused { get { return (PTE & 0x400) != 0; } }
        public bool Write { get { return (PTE & 0x800) != 0; } }
        public ulong PFN { get { return (PTE >> 12) & 0xFFFFFFFFF; } } // 36bit PFN in Windows :(?
        public ulong SoftwareWsIndex { get { return (PTE >> 52) & 0x7ff; } }
        public bool NoExecute { get { return (PTE & 0x8000000000000000) != 0; } }
        // NEXT is PFN << 12 since were adjusting back to phys address
        public ulong NextTableAddress {  get { return PTE & 0xFFFFFFFFFF000; } } // 40 bit address + Offset 12 bits = 52 phys linerar address
        // Full 48 bit size
        public ulong NextTable_PFN { get { return (PTE >> 12) & 0xFFFFFFFFFF; } }
        // 2MB entries, should be very typical
        public ulong twoMB_PFN { get { return (PTE & 0xFFFFFFE00000) >> 21; } }
        // after >> 30 == 3FFFF tot 1GB pages 
        public ulong GB_PFN { get { return (PTE & 0xFFFFC0000000) >> 30; } }
        public ulong AddressOffset {  get { return PTE & 0xfff; } }
    }

    public struct SLAT_ENTRY
    {
        public ulong SLATEntry;
        public SLAT_ENTRY(HARDWARE_ADDRESS_ENTRY slat) { SLATEntry = slat.PTE; }
        public SLAT_ENTRY(ulong slat) { SLATEntry = slat; }
        public bool Read { get { return (SLATEntry & 1) != 0; } }
        public bool Write { get { return (SLATEntry & 2) != 0; } }
        public bool Execute { get { return (SLATEntry & 4) != 0; } }
        public ulong MemType { get { return (SLATEntry >> 3) & 0x7; } }
        public bool IgnorePAT { get { return (SLATEntry & 0x40) != 0; } }
        public bool LargePage { get { return (SLATEntry & 0x80) != 0; } }
        public bool Accessed { get { return (SLATEntry & 0x100) != 0; } }
        public bool Dirty { get { return (SLATEntry & 0x200) != 0; } }
        // 2MB entries, should be very typical
        public ulong twoMB_PFN { get { return (SLATEntry & 0xFFFFFFE00000) >> 21; } }
        // after >> 30 == 3FFFF tot 1GB pages 
        public ulong GB_PFN { get { return (SLATEntry & 0xFFFFC0000000) >> 30; } }
        // When this entry point's to another table, this is the phys address of that table
        public ulong SLAT_NextTable_PFN { get { return (SLATEntry >> 12) & 0xFFFFFFFFFF; } }
        public bool SuppressVE { get { return (SLATEntry & 0x8000000000000000) != 0; } }
    }
    /// <summary>
    /// EPTP for SLAT configuration hypervisors
    /// </summary>
    public struct EPTP
    {
        public ulong aEPTP;
        public EPTP(ulong eptp) { aEPTP = eptp; }
        public EPT_MemType Type { get { return (EPT_MemType) (aEPTP & 0x7); } }
        public int PageWalkLen { get { return (int) (aEPTP >> 3) & 0x7; } } // 1 less than the length
        public bool EPT_AccessDirtyFlagBehaviour { get { return (aEPTP & 0x40) != 0; } }
        public ulong PML4_PFN { get { return (aEPTP >> 12) & 0xFFFFFFFFFF; } } // double check may just use PTE above
        public ulong PML4_PFN_Address { get { return aEPTP & 0xFFFFFFFFFF; } } // double check may just use PTE above
    }
    #endregion
    #region Memory gap structs
    /// <summary>
    /// Run's allow for gaps in address space
    /// </summary>
    public class MemoryRun
    {
        public ulong BasePage;
        public ulong PageCount;
    }
    /// <summary>
    /// Setup one default memory run for the entire range
    /// </summary>
    public class MemoryDescriptor
    {
        public int NumberOfRuns;
        public ulong NumberOfPages;
        public List<MemoryRun> Run;
        public MemoryDescriptor(ulong MemSize)
        {
            NumberOfPages = MemSize / 4096;
            NumberOfRuns = 1;

            Run = new List<MemoryRun>();
            Run.Add(new MemoryRun() { BasePage = 0, PageCount = NumberOfPages });
        }
    }
    #endregion
    #region Top Level classes
    public class DetectedProc
    {
        public int Group;

        public VMCS vmcs; // vmcs if available
        public PageTable PT;
        public ulong CR3Value;
        public ulong FileOffset;
        public long Diff;
        public int Mode; // 1 or 2
        public PTType PageTableType;

        public override string ToString() => $"Process CR3 = [{CR3Value:X16}] File Offset = [{FileOffset:X16}] Diff = [{Diff:X16}] ScanMode = [{Mode}] Type = [{PageTableType}]";
    }
    // TODO: enhance this in to something more useable
    public class VMCS
    {
        public DetectedProc dp; // which proc this came from

        public ulong gCR3_off;
        public ulong gCR3;
        public ulong hCR3_off;
        public ulong hCR3;
        public ulong EPTP;
        public ulong EPTP_off;
    }

    public class MemoryRange
    { }

    #endregion
    #region Flags and Enum
    // 0 Is really what we expect
    // This may be different for virtualized implmentations
    public enum VMCS_ABORT
    {
        NO_ABORT = 0,
        MCD_IN_EXIT = 0x500,
        TXT_SHUTDOWN = 0xd00,
        UNKNOWN_ABORT = 0x7fffffff
    }

    // From ReKall.  This is only for informational purposes
    // REVISION_ID is not used for any detection or matching
    public enum REVISION_ID : uint // Should corospond to VMX_BASIC_MSR
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
    [Flags]
    public enum PTType
    {
        UNCONFIGURED = 0,
        Windows = 1,
        FreeBSD = 2,
        OpenBSD = 4,
        NetBSD = 8,
        ALL = -1
    }
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
