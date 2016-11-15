using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net.Specialties
{
    public interface IMemAwareChecking
    {
        MemoryDescriptor PhysMemDesc { get; set; }
        string vDeviceFile { get; set; }
        string MemFile { get; set; }

        bool IsSupportedFormat(Vtero vtero);


    }
}
