using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using inVtero.net;
using inVtero.net.Hashing;
using System.IO;
using System.Globalization;

namespace inVtero.net.PS
{
    [Cmdlet(VerbsCommon.New, "InVteroDB")]
    [OutputType(typeof(DirectoryInfo))]
    public class NewInVteroDB : Cmdlet
    {
        [Parameter(Position = 0, Mandatory = true, HelpMessage = "The folder to hold the integrity DB, Bitmap, XML MetaData and relocation information"),
            Alias("VF")]
        public string VteroFolder { get; set; }

        [Parameter(Position = 0, Mandatory = true,
            HelpMessage = "The size of the DB, it must be pretty big >= 256M and be a power of 2, if you want to use really small blocks when you load this DB, reccomend 16G or more."),
        ValidateInVteroArgSize
            ]
        public long Size { get; set; }

        MetaDB mdb;

        protected override void BeginProcessing()
        {
            Vtero.VerboseOutput = false;
            Vtero.DiagOutput = false;
            Vtero.DisableProgressBar = true;

            mdb = new MetaDB(VteroFolder, 0, Size);
        }

        protected override void ProcessRecord()
        {
        }
         
        protected override void EndProcessing()
        {
            mdb.Save();
            WriteObject(new DirectoryInfo(VteroFolder));
        }

        protected override void StopProcessing()
        {
            Directory.Delete(VteroFolder, true);
        }

        class ValidateInVteroArgSize : ValidateArgumentsAttribute
        {
            protected override void Validate(object arguments, EngineIntrinsics engineIntrinsics)
            {
                ulong parsed = 0;
                var parse = arguments as string;
                if (parse != null && !string.IsNullOrWhiteSpace(parse))
                {
                    if (parse.Contains("x"))
                        parse = parse.Substring(parse.IndexOf("x") + 1);

                    if (!ulong.TryParse(parse, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out parsed))
                        if (!ulong.TryParse(parse, out parsed))
                            throw new ValidationMetadataException($"Argument {arguments} must be an number value and a power of 2.  You can specify hex values or regular.");
                }
            }
        }
    }
}
