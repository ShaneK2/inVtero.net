using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Diagnostics;
using System.IO;

namespace inVtero.net.Hashing
{
    public static class MetaItem
    {
        public static XElement GenMetaDataEntry(FileInfo File, long HashID = 0, string Info = null)
        {
            var fVerInfo = FileVersionInfo.GetVersionInfo(File.FullName);

            var check = new XElement(ElementNames.xMetaData,
                new XAttribute(xFullName, File.FullName),
                HashID != 0 ? null : new XAttribute(AttributeNames.xHashID, HashID),
                string.IsNullOrWhiteSpace(Info) ? null : new XAttribute(AttributeNames.xInfo, Info.GetHashCode().ToString("X")),
                File.GetXElement(),
                fVerInfo.GetXElement()
                );

            if (check.HasAttributes)
                return check;
            return null;
        }

        public static XElement GetXElement(this FileInfo f)
        {
            var check = new XElement(ElementNames.xFileInfo
                     , string.IsNullOrWhiteSpace(f.Name) ? null : new XAttribute(xName, f.Name)
                     , string.IsNullOrWhiteSpace(f.FullName) ? null : new XAttribute(xFullName, f.FullName)
                     , string.IsNullOrWhiteSpace(f.Extension) ? null : new XAttribute(xExtension, f.Extension)
                     , f.Exists ? new XAttribute(xExists, f.Exists) : null
                     , f.Length == 0 ? null : new XAttribute(xLength, f.Length)
                     , (int)f.Attributes == 0 ? null : new XAttribute(xAttributes, f.Attributes.ToString())
                     //, f.LastAccessTimeUtc == null ? null : new XAttribute(xLastAccessTimeUtc, f.LastAccessTimeUtc)
                     , f.LastWriteTimeUtc == null ? null : new XAttribute(xLastWriteTimeUtc, f.LastWriteTimeUtc)
                     , f.CreationTimeUtc == null ? null : new XAttribute(xCreationTimeUtc, f.CreationTimeUtc)
                     );
            if (check.HasAttributes)
                return check;
            return null;
        }

        public static bool IsDifferentInfo(XElement fInfo, FileInfo fi)
        {
            if (fInfo.Attribute(xName).Value != fi.Name) return false;
            if (fInfo.Attribute(xFullName).Value != fi.FullName) return false;
            if (((Int64?)fInfo.Attribute(xLength) ?? 0) != fi.Length) return false;
            if (fInfo.Attribute(xCreationTimeUtc).Value != fi.CreationTimeUtc.ToString()) return false;
            if (fInfo.Attribute(xLastWriteTimeUtc).Value != fi.LastWriteTime.ToString()) return false;
            return true;
        }

        public const string sName = "Name";
        public static XName xName = sName;
        public const string sLength = "Length";
        public static XName xLength = sLength;
        public const string sFullName = "FullName";
        public static XName xFullName = sFullName;
        public const string sExists = "Exists";
        public static XName xExists = sExists;
        public const string sExtension = "Extension";
        public static XName xExtension = sExtension;
        public const string sAttributes = "Attributes";
        public static XName xAttributes = sAttributes;
        public const string sCreationTimeUtc = "CreationTimeUtc";
        public static XName xCreationTimeUtc = sCreationTimeUtc;
        public const string sLastAccessTimeUtc = "LastAccessTimeUtc";
        public static XName xLastAccessTimeUtc = sLastAccessTimeUtc;
        public const string sLastWriteTimeUtc = "LastWriteTimeUtc";
        public static XName xLastWriteTimeUtc = sLastWriteTimeUtc;


        public static XElement GetXElement(this FileVersionInfo fvi)
        {
            var check = new XElement(ElementNames.xVerInfo
                   , fvi.FileBuildPart == 0 ? null : new XAttribute(xFileBuildPart, fvi.FileBuildPart)
                   , fvi.FileMajorPart == 0 ? null : new XAttribute(xFileMajorPart, fvi.FileMajorPart)
                   , fvi.FileMinorPart == 0 ? null : new XAttribute(xFileMinorPart, fvi.FileMinorPart)
                   , fvi.FilePrivatePart == 0 ? null : new XAttribute(xFilePrivatePart, fvi.FilePrivatePart)
                   , !fvi.IsDebug ? null : new XAttribute(xIsDebug, fvi.IsDebug)
                   , !fvi.IsPatched ? null : new XAttribute(xIsPatched, fvi.IsPatched)
                   , !fvi.IsPreRelease ? null : new XAttribute(xIsPreRelease, fvi.IsPreRelease)
                   , !fvi.IsPrivateBuild ? null : new XAttribute(xIsPrivateBuild, fvi.IsPrivateBuild)
                   , !fvi.IsSpecialBuild ? null : new XAttribute(xIsSpecialBuild, fvi.IsSpecialBuild)
                   , fvi.ProductBuildPart == 0 ? null : new XAttribute(xProductBuildPart, fvi.ProductBuildPart)
                   , fvi.ProductMajorPart == 0 ? null : new XAttribute(xProductMajorPart, fvi.ProductMajorPart)
                   , fvi.ProductMinorPart == 0 ? null : new XAttribute(xProductMinorPart, fvi.ProductMinorPart)
                   , fvi.ProductPrivatePart == 0 ? null : new XAttribute(xProductPrivatePart, fvi.ProductPrivatePart)
                   //, !string.IsNullOrWhiteSpace(fvi.FileName) ? new XAttribute(xFileName, fvi.FileName) : null
                   , !string.IsNullOrWhiteSpace(fvi.Comments) ? new XAttribute(xComments, fvi.Comments) : null
                   , !string.IsNullOrWhiteSpace(fvi.CompanyName) ? new XAttribute(xCompanyName, fvi.CompanyName) : null
                   , !string.IsNullOrWhiteSpace(fvi.FileDescription) ? new XAttribute(xFileDescription, fvi.FileDescription) : null
                   , !string.IsNullOrWhiteSpace(fvi.FileVersion) ? new XAttribute(xFileVersion, fvi.FileVersion) : null
                   , !string.IsNullOrWhiteSpace(fvi.InternalName) ? new XAttribute(xInternalName, fvi.InternalName) : null
                   , !string.IsNullOrWhiteSpace(fvi.Language) ? new XAttribute(xLanguage, fvi.Language) : null
                   , !string.IsNullOrWhiteSpace(fvi.LegalTrademarks) ? new XAttribute(xLegalTrademarks, fvi.LegalTrademarks) : null
                   , !string.IsNullOrWhiteSpace(fvi.LegalCopyright) ? new XAttribute(xLegalCopyright, fvi.LegalCopyright) : null
                   , !string.IsNullOrWhiteSpace(fvi.OriginalFilename) ? new XAttribute(xOriginalFilename, fvi.OriginalFilename) : null
                   , !string.IsNullOrWhiteSpace(fvi.PrivateBuild) ? new XAttribute(xPrivateBuild, fvi.PrivateBuild) : null
                   , !string.IsNullOrWhiteSpace(fvi.ProductVersion) ? new XAttribute(xProductVersion, fvi.ProductVersion) : null
                   , !string.IsNullOrWhiteSpace(fvi.SpecialBuild) ? new XAttribute(xSpecialBuild, fvi.SpecialBuild) : null
                   , !string.IsNullOrWhiteSpace(fvi.ProductName) ? new XAttribute(xProductName, fvi.ProductName) : null
                   );
            if (check.HasAttributes)
                return check;
            return null;
        }
        public const string sComments = "Comments";
        public static XName xComments = sComments;
        public const string sFileName = "FileName"; // should be in the parent element
        public static XName xFileName = sFileName;
        public const string sCompanyName = "CompanyName";
        public static XName xCompanyName = sCompanyName;
        public const string sFileBuildPart = "FileBuildPart";
        public static XName xFileBuildPart = sFileBuildPart;
        public const string sFileDescription = "FileDescription";
        public static XName xFileDescription = sFileDescription;
        public const string sFileMajorPart = "FileMajorPart";
        public static XName xFileMajorPart = sFileMajorPart;
        public const string sFileMinorPart = "FileMinorPart";
        public static XName xFileMinorPart = sFileMinorPart;
        public const string sFilePrivatePart = "FilePrivatePart";
        public static XName xFilePrivatePart = sFilePrivatePart;
        public const string sFileVersion = "FileVersion";
        public static XName xFileVersion = sFileVersion;
        public const string sInternalName = "InternalName";
        public static XName xInternalName = sInternalName;
        public const string sIsDebug = "IsDebug";
        public static XName xIsDebug = sIsDebug;
        public const string sIsPatched = "IsPatched";
        public static XName xIsPatched = sIsPatched;
        public const string sIsPreRelease = "IsPreRelease";
        public static XName xIsPreRelease = sIsPreRelease;
        public const string sIsPrivateBuild = "IsPrivateBuild";
        public static XName xIsPrivateBuild = sIsPrivateBuild;
        public const string sIsSpecialBuild = "IsSpecialBuild";
        public static XName xIsSpecialBuild = sIsSpecialBuild;
        public const string sLanguage = "Language";
        public static XName xLanguage = sLanguage;
        public const string sLegalCopyright = "LegalCopyright";
        public static XName xLegalCopyright = sLegalCopyright;
        public const string sLegalTrademarks = "LegalTrademarks";
        public static XName xLegalTrademarks = sLegalTrademarks;
        public const string sOriginalFilename = "OriginalFilename";
        public static XName xOriginalFilename = sOriginalFilename;
        public const string sPrivateBuild = "PrivateBuild";
        public static XName xPrivateBuild = sPrivateBuild;
        public const string sProductBuildPart = "ProductBuildPart";
        public static XName xProductBuildPart = sProductBuildPart;
        public const string sProductMajorPart = "ProductMajorPart";
        public static XName xProductMajorPart = sProductMajorPart;
        public const string sProductMinorPart = "ProductMinorPart";
        public static XName xProductMinorPart = sProductMinorPart;
        public const string sProductName = "ProductName";
        public static XName xProductName = sProductName;
        public const string sProductPrivatePart = "ProductPrivatePart";
        public static XName xProductPrivatePart = sProductPrivatePart;
        public const string sProductVersion = "ProductVersion";
        public static XName xProductVersion = sProductVersion;
        public const string sSpecialBuild = "SpecialBuild";
        public static XName xSpecialBuild = sSpecialBuild;
    }
}
