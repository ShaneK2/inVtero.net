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
using System.Linq;
using ProtoBuf;

namespace inVtero.net
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class PageTableRoot
    {
        public HARDWARE_ADDRESS_ENTRY CR3;
        public HARDWARE_ADDRESS_ENTRY SLAT;

        // not really a basic PFN but contains all of the 
        // information that binds PFN<->PTE<->VA together
        public PFN Entries;

        public long Count;
    }


    /// <summary>
    /// Basis for PFFN DB, generated first time loading the memory dump
    /// </summary>
    [ProtoContract(AsReferenceDefault = false, ImplicitFields = ImplicitFields.AllPublic)]
    public class PFN
    {
        public HARDWARE_ADDRESS_ENTRY PTE;  // Virtualized if we have SLAT address or the real one for native
        
        public VIRTUAL_ADDRESS VA;
        public Dictionary<VIRTUAL_ADDRESS, PFN> SubTables;

        [ProtoIgnore]
        public long PFNCount {
            get { return SubTables.SelectMany(x => x.Value.SubTables).SelectMany(y => y.Value.SubTables).SelectMany(z => z.Value.SubTables).LongCount(); }
        }

        public PFN() { SubTables = new Dictionary<VIRTUAL_ADDRESS, PFN>(); }

        public override string ToString() => $"HW: {PTE}  SW: {VA}";
    }
}