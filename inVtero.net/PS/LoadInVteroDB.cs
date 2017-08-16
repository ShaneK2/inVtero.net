using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using inVtero.net;
using inVtero.net.Hashing;
using System.IO;


namespace inVtero.net.PS
{
    [Cmdlet(VerbsCommon.Add, "InVteroDB")]
    [OutputType(typeof(DirectoryInfo))]
    public class LoadInVteroDB : Cmdlet
    {
        [Parameter(Mandatory = true, Position = 0,
        HelpMessage = "Path to the folder where an inVterDB is located"), Alias("VF"),
        ValidateInVteroArgDB]
        public string VteroFolder { get; set; }


        [Parameter(Mandatory = true,
        HelpMessage = "The size of the blocks to use for importing to the DB.  The smaller sizes will take many more times larger DB and impact performace some but will be much better at locating fragments of data."), 
        ValidateSet("4096", "2048", "1024", "512", "256", "128", "64"), Alias("HS")]
        public int HashSize { get; set; }


        [Parameter(HelpMessage = "Make this as large as you can to improve performance, 1M is the smallest, 4G is the largest"), 
        ValidateRange(1000000, uint.MaxValue), Alias("Buf", "B")]
        public int BufferCount { get; set; }

        [Parameter(HelpMessage = "Meta information that will be logged to the MetaDB to help identify where the hash came from like 'Windows 10 Desktop' or 'Cloud Server'.")]
        public string InfoString { get; set; }

        [Parameter(HelpMessage = "By Default metadata is collected, however if you import a directory multiple times (maybe just one or 2 files were updated and your note sure what ones), set this to false and your meta table will not be polluted")]
        public bool MetaCollection { get; set; }

        [Parameter(Mandatory = true, 
            HelpMessage = "The folder to import your data from.  Typically a mounted virtual disk root x:\\ or z:\\updates"),
            Alias("I"),
            ValidateImportFolder]
        public string ImportFolder { get; set; }



        MetaDB mdb;

        protected override void BeginProcessing()
        {
            mdb = new MetaDB(VteroFolder, HashSize, 0, BufferCount);
        }

        protected override void ProcessRecord()
        {
            int[] LastPercents = new int[3] {-1,-1,-1};

            // setup callback
            mdb.Loader.ProgressDelegate = new Action<int, int , string, string>(
            (int PercentComplete, int Activity, string Status, string CurrentOp) =>
            { 
                if (LastPercents[Activity] != PercentComplete)
                {
                    var desc = string.Empty; 
                    switch (Activity)
                    {
                        case 0: desc = "Scanning filesystem for candidates (unknown estimate) 1% == 100 folders scanned."; break;
                        case 1: desc = $"Chunking into {BufferCount} database commit arrays (unknown estimate) 1% == 500 files imported."; break;
                        case 2: desc = "Chunk progress (accurate progress)"; break;
                        case 3: desc = "Commiting to database (unknown estimate) 1% == 100000 hash values."; break;
                        case 4: desc = "Commiting to database (accurate progress)."; break;
                        default: break;
                    }

                    var pr = new ProgressRecord(Activity, $"Stage: {Activity}", desc);
                    pr.PercentComplete = PercentComplete;
                    if (Activity > 0)
                        pr.ParentActivityId = Activity - 1;
                     
                    pr.CurrentOperation = desc;

                    if (CurrentOp == string.Empty)
                        pr.RecordType = ProgressRecordType.Completed;

                    WriteProgress(pr);
                }
                LastPercents[Activity] = PercentComplete;

            });

            

            mdb.Loader.LoadFromPath(ImportFolder, MetaCollection);

            /*
            ProgressRecord pr = new ProgressRecord(1, "Hashing file", "Importing to DB:");
            for (int i = 0; i < 100; i++)
            {
                pr.PercentComplete = i;
                WriteProgress(pr);
            }
            WriteObject("Done.");
            */
        }

        protected override void EndProcessing()
        {
            mdb.Save();
            WriteObject(new DirectoryInfo(ImportFolder));
        }

        protected override void StopProcessing()
        {
        }

        class ValidateInVteroArgDB: ValidateArgumentsAttribute
        {
            protected override void Validate(object arguments, EngineIntrinsics engineIntrinsics)
            {
                var apath = arguments as string;
                if(apath != null && !string.IsNullOrWhiteSpace(apath))
                {
                    if (Directory.Exists(apath) &&
                        File.Exists(Path.Combine(apath, "inVtero.DB")) &&
                        File.Exists(Path.Combine(apath, "MetaDB.XML")) &&
                        File.Exists(Path.Combine(apath, "inVtero.DB.bin")))
                        return;
                }
                throw new ValidationMetadataException($"Argument {arguments} does not specify a folder where an inVtero.net DB is located.");
            }
        }

        class ValidateImportFolder : ValidateArgumentsAttribute
        {
            protected override void Validate(object arguments, EngineIntrinsics engineIntrinsics)
            {
                var apath = arguments as string;
                if (apath != null && !string.IsNullOrWhiteSpace(apath))
                {
                    if (Directory.Exists(apath))
                        return;
                }
                throw new ValidationMetadataException($"Argument {arguments} does not specify a folder.");
            }
        }
    }
}
