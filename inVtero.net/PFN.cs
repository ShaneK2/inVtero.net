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

using ProtoBuf;
using System.Collections.Generic;

namespace inVtero.net
{
    /// <summary>
    /// Basis for PFFN DB, generated first time loading the memory dump
    /// </summary>
    [ProtoContract]
    public class PFN
    {
        [ProtoMember(1)]
        public HARDWARE_ADDRESS_ENTRY PTE;  // Virtualized if we have SLATA or the real one for native
        public long PageFrameNumber;
        [ProtoMember(2)]
        public long VA;
        [ProtoMember(3)]
        public HARDWARE_ADDRESS_ENTRY PageTable;
        [ProtoMember(4)]
        public HARDWARE_ADDRESS_ENTRY SLAT;
        [ProtoMember(6)]
        public long PFNCount;
        [ProtoMember(5)]
        public Dictionary<VIRTUAL_ADDRESS, PFN> SubTables;
        [ProtoMember(6)]
        public long hostPTE;  // if we have SLAT and had the chance to de-virtualize, place the translated entry here

        public PFN() { PTE = long.MaxValue; }
        public PFN(long RawEntry, long va, long pageTable, long sLAT)
        {
            PTE = new HARDWARE_ADDRESS_ENTRY(RawEntry);

            // this is the key into bitmap, since were never going to get past 32bit PFN
            // figures to make it only uint
            PageFrameNumber = PTE.PFN;
            VA = va;

            PageTable.PTE = pageTable;
            SLAT.PTE = sLAT;
            SubTables = new Dictionary<VIRTUAL_ADDRESS, PFN>();
        }
        public PFN(long RawEntry, long va, long pageTable, long sLAT, long RAW_Translated)
            : this(RawEntry, va, pageTable, sLAT)
        {
            hostPTE = RAW_Translated;
        }
    }
}