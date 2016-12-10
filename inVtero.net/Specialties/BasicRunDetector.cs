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
