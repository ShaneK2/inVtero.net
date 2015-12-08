// Shane.Macaulay@IOActive.com Copyright (C) 2013-2015

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


using ProtoBuf;
using System.Collections.Generic;

namespace inVtero.net
{
    [ProtoContract]
    public class DetectedProc
    {
        public DetectedProc()
        {
            TopPageTablePage = new Dictionary<int, long>();
        }
        [ProtoMember(1)]
        public int Group;
        [ProtoMember(2)]
        public VMCS vmcs;       // vmcs if available
        [ProtoMember(3)]
        public PageTable PT;    // extracted page table
        [ProtoMember(4)]
        public long CR3Value;
        [ProtoMember(5)]
        public long FileOffset;
        [ProtoMember(6)]
        public long Diff;
        [ProtoMember(7)]
        public int Mode; // 1 or 2
        [ProtoMember(8)]
        public PTType PageTableType;

        [ProtoMember(9)]
        public Dictionary<int, long> TopPageTablePage;

        [ProtoMember(10)]
        public int AddressSpaceID;

        public override string ToString() => $"Process CR3 [{CR3Value:X16}] File Offset [{FileOffset:X16}] Diff [{Diff:X16}] Type [{PageTableType}]";
    }


    [ProtoContract]
    public class VMCS
    {
        public VMCS()
        {
            //TopEPT = new Dictionary<int, HARDWARE_ADDRESS_ENTRY>();
        }

        [ProtoMember(1)]
        public DetectedProc dp; // which proc this came from
        [ProtoMember(2)]
        public long gCR3_off;
        [ProtoMember(3)]
        public long gCR3;
        [ProtoMember(4)]
        public long hCR3_off;
        [ProtoMember(5)]
        public long hCR3;
        [ProtoMember(6)]
        public long EPTP;
        [ProtoMember(7)]
        public long EPTP_off;

        //[ProtoMember(8)] // not really that usefull
        //public Dictionary<int, HARDWARE_ADDRESS_ENTRY> TopEPT;

        public override string ToString() => $"EPTP = [{new EPTP(this.EPTP)}]";
    }

}
