using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.IO;
using System.Xml.Linq;
using System.Xml;
using System.Xml.Serialization;
using System.Collections.ObjectModel;
using System.Threading;

namespace inVtero.net.Hashing
{
    public class MetaDB
    {
        const string mdbName = "MetaDB.XML";
        const string hdbName = "inVtero.DB";
        const string bdbName = "inVtero.DB.bin";
        const string relocFolder = "Relocs";

        public string HDBName;
        public string MDBName;
        public string BDBName;
        public string RelocName;

        public int MinHashSize;
        public int LoadBufferCount;

        public HashDB HDB { get; }
        public FileLoader Loader;

        string RootFolder;
        public XElement mData;
        public XElement mRecords;

        XElement infoStrings;

        XDocument xDoc;
        

        int currHID;
        public int CurrHashID
        {
            get
            {
                return Interlocked.Increment(ref currHID);
            }
        }

        public void AddMetaInfoString(string Info)
        {
            var DupCheck = from each in infoStrings.Elements(ElementNames.xInfo)
                           where each.Attribute(AttributeNames.xValue).Value == Info
                           select each;

            if (DupCheck.Count() < 1)
                infoStrings.Add(new XElement(ElementNames.xInfo, Info));
        }
        public int AddFileInfo(string FilePath, string metaInfo)
        {
            var finfo = new FileInfo(FilePath);
            
            var entry = MetaItem.GenMetaDataEntry(finfo, 0, metaInfo);

            var rv = CurrHashID;
            entry.SetAttributeValue(AttributeNames.xHashID, rv);
            mRecords.Add(entry);
            return rv;
        }

        public MetaDB(string WorkingDir, long DBSize = 0, int minHashSize = 0, int loadBufferCount = 0, string NewInfoString = null)
        {
            RootFolder = WorkingDir;
            if (!Directory.Exists(RootFolder))
                Directory.CreateDirectory(RootFolder);

            MDBName = Path.Combine(RootFolder, mdbName);
            HDBName = Path.Combine(RootFolder, hdbName);
            BDBName = Path.Combine(RootFolder, bdbName);
            RelocName = Path.Combine(RootFolder, relocFolder);
            LoadBufferCount = loadBufferCount;

            if (File.Exists(MDBName))
                xDoc = XDocument.Load(MDBName);
            else
                xDoc = new XDocument(new XDeclaration("1.0", Encoding.Default.WebName, "yes"), new XElement(ElementNames.xRoot));

            mData = xDoc.Root;

            var currID = ((Int32?)mData.Attribute(AttributeNames.xNextHashID) ?? 0);
            if (currID == 0)
            {
                mData.SetAttributeValue(AttributeNames.xNextHashID, 1);
                currHID = 1;
            }
            else
                currHID = currID;

            if (mData.Element(ElementNames.xRecords) != null)
                mRecords = mData.Element(ElementNames.xRecords);
            else
            {
                mRecords = new XElement(ElementNames.xRecords);
                mData.Add(mRecords);
            }

            if (mData.Element(ElementNames.xMetaInfoStrings) != null)
                infoStrings = mData.Element(ElementNames.xMetaInfoStrings);
            else
            {
                infoStrings = new XElement(ElementNames.xMetaInfoStrings);
                mData.Add(infoStrings);
            }
            
            MinHashSize = minHashSize;
            HDB = new HashDB(MinHashSize, HDBName, RelocName, DBSize);
            Loader = new FileLoader(this, LoadBufferCount, NewInfoString);
        }

        public void Save()
        {
            Misc.WriteColor(ConsoleColor.Black, ConsoleColor.Cyan, $"CRITICAL: SAVING METADATA DATABASE!!! WAIT JUST A SECOND!");
            // TODO: find a faster dup check 
            HDB.Save();

            mData.SetAttributeValue(AttributeNames.xNextHashID, currHID);
            
            mData.Save(MDBName);
            Misc.WriteColor(ConsoleColor.Cyan, ConsoleColor.Black, $"Done. Commited {mData.Descendants().Count():N0} XML entries to disk.");
        }
    }

    public static class AttributeNames
    {
        public const string sNextHashID = "NextID";
        public static XName xNextHashID = sNextHashID;
        private const string sValue = "Value";
        public static XName xValue = sValue;
        private const string sRevision = "Revision";
        public static XName xRevision = sRevision;

        public const string sHashID = "HID";
        public static XName xHashID = sHashID;
        public const string sInfo = "Info";
        public static XName xInfo = sInfo;
    }

    public static class ElementNames
    {
        public const string sRoot = "inVtero";
        public static XName xRoot = sRoot;


        public const string sMetaData = "MD";
        public static XName xMetaData = sMetaData;
            
        public const string sFilenfo = "FileInfo";
        public static XName xFileInfo = sFilenfo;
        public const string sVerInfo = "VerInfo";
        public static XName xVerInfo = sVerInfo;
        private const string sMetaInfoStrings = "MetaInfoStrings";
        public static XName xMetaInfoStrings = sMetaInfoStrings;
        private const string sInfo = "Info";
        public static XName xInfo = sInfo;
        private const string sRecords = "Records";
        public static XName xRecords = sRecords;
    }
}
