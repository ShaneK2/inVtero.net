using PowerArgs;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using inVtero.net;

namespace ConsoleUtils
{


    /// <summary>
    /// A memory region contains the information to perform 1 or more memory Virtual <-> Physical conversion mappings
    /// </summary>
    public class MemoryRegion
    {
        public VIRTUAL_ADDRESS Virtual { get; set; }
        public PFN Physical { get; set; }
    }

    /// <summary>
    /// Dump available data to disk
    /// Grouped by permission, process and VA space
    /// </summary>
    public class Dumper
    {
        Vtero Vtero;
        DetectedProc DP;
        String OutDir;


        // bring up a more concise api for dumping than the basic 
        // test dump we have now in inVtero.cs
        [ArgShortcut("-R"), ArgDescription("ranges to dump")]
        public List<MemoryRegion> SelectedRegions { get; }

        public Dumper(Vtero vtero, string outDir, DetectedProc dp, MemRangeArgs args)
        {
            Vtero = vtero;
            DP = dp;
            OutDir = outDir;

            SelectedRegions = args.Regions;
        }

        public void DumpIt()
        {
            foreach (var r in SelectedRegions)
                Vtero.WriteRange(r.Virtual, r.Physical, OutDir, DP.MemAccess);

        }

    }


    public class MemoryRegionSource : DbContext
    {
        public DbSet<MemoryRegion> Regions { get; set; }
    }

    public class MemRangeArgs
    {
        public string OrderBy { get; set; }
        [ArgShortcut("o-")]
        public string OrderByDescending { get; set; }
        public string Where { get; set; }
        public int Skip { get; set; }
        public int Take { get; set; }

        [Query(typeof(MemoryRegionSource))]
        [ArgIgnore]
        public List<MemoryRegion> Regions { get; set; }
    }

}
