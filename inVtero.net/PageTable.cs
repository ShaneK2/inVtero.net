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
using System.Collections.Concurrent;
using System.Collections.Specialized;
using System.Collections.ObjectModel;

namespace inVtero.net
{
    /// <summary>
    /// Maintain a cached representation of scanned results from analysis
    /// Group regions and address spaces
    /// 
    /// TODO: Enumerate and expose available virtual addresses for a given page table
    ///  - probably just do a recursive routine to desend/enum all available virtual addresses
    /// 
    /// TODO: Implment join-on-shared-kernel-spaces
    /// </summary>
    public class PageTable
    {



        static PageTable AddProcess(DetectedProc dp)
        {
            PageTable rv = new PageTable();

            // for a given dp, cache it's page tables into a local dictionary

            return rv;
        }

        HARDWARE_ADDRESS_ENTRY GetPTEntry(Mem memAccess, VIRTUAL_ADDRESS va, int Level)
        {
            HARDWARE_ADDRESS_ENTRY entry = HARDWARE_ADDRESS_ENTRY.MinAddr;

            //memAccess.GetValueAtPhysicalAddr<HARDWARE_ADDRESS_ENTRY>()


            return entry;
        }


        void FillAddresses(VIRTUAL_ADDRESS va, HARDWARE_ADDRESS_ENTRY[] Table, int Level)
        {


        }

    }
}
