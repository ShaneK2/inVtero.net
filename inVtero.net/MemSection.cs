// Copyright(C) 2017 Shane Macaulay smacaulay@gmail.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.If not, see<http://www.gnu.org/licenses/>.
using ProtoBuf;
using Reloc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net
{
    /// <summary>
    /// Initial idea is describe modules, pools or anything else (opaque mapped regions)
    /// 
    /// This should tie together PFN/PTE entries VA space and process objects sharable or otherwise.
    /// 
    /// Put the most trusted information here, i.e. from the page tables 
    /// Logically acquired details from PE modules will be available in the Extract class
    /// </summary>
    /// 
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class MemSection : IComparable
    {
        public string Name { get; set; }
        [ProtoIgnore]
        public ulong Address { get { return (ulong) VA.Address; } }
        public long Length { get; set; }

        public VIRTUAL_ADDRESS VA;

        public bool IsExec;

        public PFN Source;

        // Extract can contain sub lists (.text, .data) from PE data Module.SectionPosOffsets
        public Extract Module;

        // Per module debug support
        public CODEVIEW_HEADER DebugDetails;

        public string VadFile;
        public long VadLength;
        public long VadAddr; 

        // Often PE section data will overlap the MM system's protection scheme
        public List<MemSection> SubSections;

        public int CompareTo(object obj)
        {
            var other = obj as MemSection;
            if (other == null)
                return int.MaxValue;

            return other.VA.Address.CompareTo(VA.Address);
        }
    }
}
