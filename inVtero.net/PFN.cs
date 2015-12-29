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
using System.Linq;

namespace inVtero.net
{
    [ProtoContract]
    public class PageTableRoot
    {
        [ProtoMember(1)]
        public HARDWARE_ADDRESS_ENTRY CR3;
        [ProtoMember(2)]
        public HARDWARE_ADDRESS_ENTRY SLAT;

        // not really a basic PFN but contains all of the 
        // information that binds PFN<->PTE<->VA together
        [ProtoMember(3)]
        public PFN Entries;

        public long Count;
    }


    /// <summary>
    /// Basis for PFFN DB, generated first time loading the memory dump
    /// </summary>
    [ProtoContract]
    public class PFN
    {
        [ProtoMember(1)]
        public HARDWARE_ADDRESS_ENTRY PTE;  // Virtualized if we have SLAT address or the real one for native
        [ProtoMember(2)]
        public VIRTUAL_ADDRESS VA;
        [ProtoMember(3)]
        public Dictionary<VIRTUAL_ADDRESS, PFN> SubTables;


        public long PFNCount {
            get { return SubTables.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).SelectMany(z => z.Value.SubTables).LongCount(); }
        }

        public PFN() { SubTables = new Dictionary<VIRTUAL_ADDRESS, PFN>(); }
    }
}