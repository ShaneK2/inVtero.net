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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using ProtoBuf;

namespace inVtero.net.Specialties
{
    /// <summary>
    /// Default single memory run
    /// </summary>
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class BasicRunDetector : AMemoryRunDetector, IMemAwareChecking
    {
        bool SupportedStatus = true;
        
        public override bool IsSupportedFormat(Vtero vtero)
        {
            // use abstract implementation & scan for internal 
            LogicalPhysMemDesc = ExtractMemDesc(vtero);

            if (LogicalPhysMemDesc != null)
                PhysMemDesc = LogicalPhysMemDesc;

            // weather or not we find it set true
            return true;
        }

        public BasicRunDetector(string MemSourceFile)
        {
            MemFile = MemSourceFile;

            FileInfo fi = new FileInfo(MemFile);
            SupportedStatus = fi.Exists;

            PhysMemDesc = new MemoryDescriptor(fi.Length);
        }
        public BasicRunDetector()
        { }
    }
}
