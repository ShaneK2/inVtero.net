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
    public class MemSection
    {
        public string Name;
        public VIRTUAL_ADDRESS VA;
        public long Length;

        public bool IsExec;


        // Extract can contain sub lists (.text, .data) from PE data Module.SectionPosOffsets
        public Extract Module;

        // Per module debug support
        public CODEVIEW_HEADER DebugDetails;

        // Often PE section data will overlap the MM system's protection scheme
        public List<MemSection> SubSections;
    }
}
