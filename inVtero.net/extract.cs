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
using System.Threading.Tasks;
using System.IO;
using System.Text;
using System.Diagnostics;
using static System.Console;
//using ProtoBuf;

namespace Reloc
{
    //[ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public struct MiniSection
    {
        public string Name;
        public uint VirtualSize; // size in memory
        public uint VirtualAddress; // offset to section base in memory (from ImageBase)
        public uint RawFileSize; // size on disk
        public uint RawFilePointer; // offset to section base on disk (from 0)
        //[ProtoIgnore]
        public bool IsExec { get { return (Characteristics & PECaricteristicFlags.Exec) != 0; } }
        //[ProtoIgnore]
        public bool IsCode { get { return (Characteristics & PECaricteristicFlags.Code) != 0; } }
        //[ProtoIgnore]
        public bool IsRead { get { return (Characteristics & PECaricteristicFlags.Read) != 0; } }
        //[ProtoIgnore]
        public bool IsWrite { get { return (Characteristics & PECaricteristicFlags.Write) != 0; } }
        //[ProtoIgnore]
        public bool IsShared { get { return (Characteristics & PECaricteristicFlags.Shared) != 0; } }
        //[ProtoIgnore]
        public bool IsDiscard { get { return (Characteristics & PECaricteristicFlags.Discardable) != 0; } }
        public PECaricteristicFlags Characteristics;

        public static MiniSection Empty;

        static MiniSection()
        {
            Empty.Name = string.Empty;
            Empty.Characteristics = 0;
            Empty.VirtualAddress = 0;
            Empty.RawFilePointer = 0;
            Empty.VirtualSize = 0;
            Empty.RawFileSize = 0;
        }

        public override string ToString()
        {
            return $"{Name} - VBase {VirtualAddress:X}:{VirtualSize:X} - File {RawFilePointer:X}:{RawFileSize:X} - R:{IsRead},W:{IsWrite},X:{IsExec},S:{IsShared},D:{IsDiscard}";
        }
    }

    public enum PEDirectory : int
    {
        Export,
        Import,
        Resource,
        Exception,
        Certificates,
        BaseRelocation,
        Debug,
        Architechture,
        GlobalPointer,
        ThreadStorage,
        LoadConfiguration,
        BoundImport,
        ImportAddressTable,
        DelayImport,
        ComNet,
        Reserved
    }

    // Extract compiles a local reloc set that can be used when dumping memory to recover identical files 
    //[ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class Extract
    {
        public int rID;

        public long VA;

        public static int NewCnt;
        public static int Verbose;
        public static bool OverWrite;

        public string FileName;
        public uint RelocPos;
        public uint RelocSize;
        public int CheckSumPos;
        public uint CheckSum;
        public uint ClrAddress;
        public uint ClrSize;
        public uint EntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public long ImageBaseOffset;
        public uint TimeStamp;
        public bool Is64;
        public uint SectionAlignment;
        public uint FileAlignment;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public ushort Characteristics;
        public ushort NumberOfSections;
        public bool IsCLR;
        // maybe ordered list would emit better errors for people
        public List<MiniSection> Sections;
        public List<Tuple<int, int>> Directories;

        public int BoundImprotLen;

        //[ProtoIgnore]
        public bool IsHighEntropy { get { return (Characteristics & 0x20) != 0; } }
        //[ProtoIgnore]
        public bool IsReloc { get { return (Characteristics & 0x40) != 0; } }
#if !TEST
        //[ProtoIgnore]
        public DeLocate ReReState;
#endif
        int secOff;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder($"{Environment.NewLine}**PE FILE** \t-\t-\t Date   [{TimeStamp:X8}]{Environment.NewLine}*Base*  \t-\t-\t Offset [{ImageBase:X16}] -\t Size [{SizeOfImage:X8}]{Environment.NewLine}");
            foreach (var s in Sections)
                sb.Append($"[{s.Name.PadRight(8)}] \t-\t-\t Offset [{s.VirtualAddress:X8}] \t-\t Size [{s.VirtualSize:X8}]{Environment.NewLine}");

            sb.AppendLine();
            return sb.ToString();
        }


        // Helper that delegates execution
        private static async Task CompileEachFileAsync(string path, string searchPattern, string SaveFolder, SearchOption searchOption, Func<string, string, Task> doAsync)
        {
            // Avoid blocking the caller for the initial enumerate call.
            await Task.Yield();

            var sw = Stopwatch.StartNew();

            // really need a simple exception swallowing filesystem walker, enumerations suck with exceptions !
            foreach (string file in Directory.EnumerateFiles(path, searchPattern, searchOption))
            {
                await doAsync?.Invoke(file, SaveFolder);
            }

            if (Verbose > 0)
                WriteLine($"processing time: {sw.Elapsed}");
        }

        public static Extract IsBlockaPE(byte[] block, int blockOffset = 0)
        {
            Extract extracted_struct = new Extract();

            if (block[blockOffset] != 0x4d || block[blockOffset + 1] != 0x5a)
                return null;

            var headerOffset = BitConverter.ToInt32(block, blockOffset + 0x3C);

            // bad probably
            if (headerOffset > 3000)
                return null;

            if (BitConverter.ToInt32(block, blockOffset + headerOffset) != 0x00004550)
                return null;

            var pos = blockOffset + headerOffset + 6;

            extracted_struct.NumberOfSections = BitConverter.ToUInt16(block, pos); pos += 2;
            extracted_struct.Sections = new List<MiniSection>();
            //pos += 2;

            extracted_struct.TimeStamp = BitConverter.ToUInt32(block, pos); pos += 4;
            pos += 8;
            extracted_struct.secOff = BitConverter.ToUInt16(block, pos); pos += 2;
            pos += 2;
            var magic = BitConverter.ToUInt16(block, pos); pos += 2;
            extracted_struct.Is64 = magic == 0x20b;
            // sizeofcode, sizeofinit, sizeofuninit, 
            pos += 14;
            extracted_struct.EntryPoint = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.BaseOfCode = BitConverter.ToUInt32(block, pos); pos += 4;

            if (extracted_struct.Is64)
            {
                // we wan't this to be page aligned to typical small page size
                extracted_struct.ImageBaseOffset = pos & 0xfff;
                extracted_struct.ImageBase = BitConverter.ToUInt64(block, pos); pos += 8;
            }
            else
            {
                // baseofdata
                pos += 4;
                // imagebase
                extracted_struct.ImageBaseOffset = pos & 0xfff;
                extracted_struct.ImageBase = BitConverter.ToUInt32(block, pos); pos += 4;
            }
            extracted_struct.SectionAlignment = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.FileAlignment = BitConverter.ToUInt32(block, pos); pos += 4;

            pos += 16;

            extracted_struct.SizeOfImage = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.SizeOfHeaders = BitConverter.ToUInt32(block, pos); pos += 4;
            // checksum
            extracted_struct.CheckSumPos = pos;
            extracted_struct.CheckSum = BitConverter.ToUInt32(block, pos); pos += 4;
            // subsys
            pos += 2;
            ///characteristics
            extracted_struct.Characteristics = BitConverter.ToUInt16(block, pos); pos += 2;

            // SizeOf/Stack/Heap/Reserve/Commit
            if (extracted_struct.Is64)
                pos += 32;
            else
                pos += 16;
            // LoaderFlags
            pos += 4;
            // NumberOfRvaAndSizes
            pos += 4;

            extracted_struct.Directories = new List<Tuple<int, int>>(16);
            // collect a list of all directories in a table
            for (int i = 0; i < 0x10; i++)
                extracted_struct.Directories.Add(Tuple.Create<int, int>(BitConverter.ToInt32(block, pos + (i * 8)), BitConverter.ToInt32(block, pos + (i * 8) + 4)));

            extracted_struct.ClrAddress = (uint)extracted_struct.Directories[0xf].Item1;
            extracted_struct.ClrSize = (uint)extracted_struct.Directories[0xf].Item2;

            if (extracted_struct.ClrAddress != 0)
                extracted_struct.IsCLR = true;

            var CurrEnd = extracted_struct.SizeOfHeaders;
            /// implicit section for header
            extracted_struct.Sections.Add(new MiniSection { VirtualSize = CurrEnd, RawFileSize = CurrEnd, RawFilePointer = 0, VirtualAddress = 0, Name = ".PEHeader", Characteristics = PECaricteristicFlags.Code });

            // get to sections
            pos = blockOffset + headerOffset + (extracted_struct.Is64 ? 0x108 : 0xF8);
            for (int i = 0; i < extracted_struct.NumberOfSections; i++)
            {
                /*var rawStr = BitConverter.ToString(block, pos, 8); */
                var rawStr = new String(
                    new char[8] { (char) block[pos], (char) block[pos + 1], (char) block[pos + 2], (char) block[pos + 3],
                    (char) block[pos + 4], (char) block[pos + 5], (char) block[pos + 6], (char) block[pos + 7] }); pos += 8;

                var secStr = new string(rawStr.Where(c => char.IsLetterOrDigit(c) || char.IsPunctuation(c)).ToArray());

                var Size = BitConverter.ToUInt32(block, pos); pos += 4;
                var Pos = BitConverter.ToUInt32(block, pos); pos += 4;
                var rawSize = BitConverter.ToUInt32(block, pos); pos += 4;
                var rawPos = BitConverter.ToUInt32(block, pos); pos += 0x10;
                var characteristic = (PECaricteristicFlags)  BitConverter.ToUInt32(block, pos); pos += 4;

                var currSecNfo = new MiniSection { VirtualSize = Size, VirtualAddress = Pos, RawFileSize = rawSize, RawFilePointer = rawPos, Name = secStr, Characteristics = characteristic };
                extracted_struct.Sections.Add(currSecNfo);

                if (Verbose > 2)
                    Write($" section [{secStr}] ");

                //optimize reloc for easy access
                if (secStr.StartsWith(@".reloc", StringComparison.Ordinal))
                {
                    extracted_struct.RelocSize = Size;
                    extracted_struct.RelocPos = Pos;
                }
            }

            return extracted_struct;
        }
#if !TEST
        // We don't really need a reloc folder if were wharehousing the whole binary anyhow
        public static RelocSection ExtractRelocData(string PE, string RelocBase = null, bool NoExtraRelocFolder = true)
        {
            using (var fs = new FileStream(PE, FileMode.Open, FileAccess.Read))
            {
                var buff = new byte[4096];

                fs.Read(buff, 0, 4096);

                var e = Extract.IsBlockaPE(buff);
                if (e == null)
                    return null;

                e.FileName = PE;
                if (e.RelocSize == 0)
                    return null;

                RelocSection rv = new RelocSection();

                int RelocPos = 0, RelocSize = 0;

                rv.FullPath = PE;
                rv.Name = Path.GetFileName(PE);

                rv.Is64 = e.Is64;
                rv.VirtualSize = e.SizeOfImage;
                rv.TimeStamp = e.TimeStamp;
                rv.OriginalBase = e.ImageBase;
                rv.OrigBaseOffset = (int)e.ImageBaseOffset;

                for (int i = 0; i < e.Sections.Count(); i++)
                {
                    if (e.Sections[i].Name == ".reloc")
                    {
                        RelocPos = (int)e.Sections[i].RawFilePointer;
                        RelocSize = (int)e.Sections[i].RawFileSize;
                        break;
                    }
                }
                if (RelocPos == 0 && RelocSize == 0)
                    return null;
                    
                rv.RelocSecOffset = RelocPos;
                rv.RelocLength = RelocSize;
                var readBuffer = new byte[RelocSize];

                if (RelocSize != 0)
                {
                    fs.Position = RelocPos;
                    fs.Read(readBuffer, 0, RelocSize);

                    if (!NoExtraRelocFolder && !string.IsNullOrWhiteSpace(RelocBase) && !File.Exists(rv.FullPath))
                    {
                        var relocDir = e.Is64 ? Path.Combine(RelocBase, "64") : Path.Combine(RelocBase, "32");
                        var sb = $"{Path.GetFileName(e.FileName)}-{e.ImageBase.ToString("X")}-{e.TimeStamp.ToString("X")}.reloc";
                        var outFile = Path.Combine(relocDir, sb);

                        using (FileStream stream = new FileStream(outFile, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                            stream.Write(readBuffer, 0, RelocSize);
                    }
                }
                rv.RawRelocBuffer = readBuffer;
                return rv;
            }
        }
#endif
        public bool GetDetails(Stream fs)
        {
            using (var binReader = new BinaryReader(fs))
            {
                if (fs.Length < 0x40)
                    return false;
                fs.Position = 0x3C;
                var headerOffset = binReader.ReadUInt32();

                if (headerOffset > fs.Length - 5)
                    return false;

                fs.Position = headerOffset;
                var signature = binReader.ReadUInt32();

                if (signature != 0x00004550)
                    return false;

                fs.Position += 2;
                NumberOfSections = binReader.ReadUInt16();

                Sections = new List<MiniSection>();

                TimeStamp = binReader.ReadUInt32();
                fs.Position += 8;
                secOff = binReader.ReadUInt16();
                fs.Position += 2;

                var magic = binReader.ReadInt16();
                Is64 = magic == 0x20b;
                if (Is64)
                {
                    fs.Position += 22;
                    ImageBaseOffset = fs.Position;
                    ImageBase = binReader.ReadUInt64();
                }
                else
                {
                    fs.Position += 26;
                    ImageBaseOffset = fs.Position;
                    ImageBase = binReader.ReadUInt32();
                }
                SectionAlignment = binReader.ReadUInt32();
                FileAlignment = binReader.ReadUInt32();
                fs.Position += 16;
                SizeOfImage = binReader.ReadUInt32();
                SizeOfHeaders = binReader.ReadUInt32();
                var CurrEnd = SizeOfHeaders;

                /// implicit section for header
                Sections.Add(new MiniSection { VirtualSize = 0x1000, RawFileSize = CurrEnd, RawFilePointer = 0, VirtualAddress = 0, Name = ".PEHeader", Characteristics = PECaricteristicFlags.Code });

                // get to sections
                fs.Position = headerOffset + (Is64 ? 0x108 : 0xF8);
                for (int i = 0; i < NumberOfSections; i++)
                {
                    var secName = binReader.ReadBytes(8);
                    var rawStr = Encoding.ASCII.GetString(secName);
                    var secStr = new string(rawStr.Where(c => char.IsLetterOrDigit(c) || char.IsPunctuation(c)).ToArray());

                    var Size = binReader.ReadUInt32();
                    var Pos = binReader.ReadUInt32();
                    var rawSize = binReader.ReadUInt32();
                    var rawPos = binReader.ReadUInt32();
                    fs.Position += 0xC;
                    var characteristic =  (PECaricteristicFlags)binReader.ReadUInt32();

                    var currSecNfo = new MiniSection { VirtualSize = Size, VirtualAddress = Pos, RawFileSize = rawSize, RawFilePointer = rawPos, Name = secStr, Characteristics = characteristic };
                    Sections.Add(currSecNfo);

                    if (Verbose > 2)
                        Write($" section [{secStr}] ");

                    if (secStr.StartsWith(@".reloc", StringComparison.Ordinal))
                    {
                        RelocSize = Size;
                        RelocPos = Pos;
                    }

                    fs.Position += 0x4;
                }
            }
            return true;
        }

        // slim PE 32/64 handling and collect required details we need for delocation
        // ImageBase, TimeDateStamp, bitness (64/32) and location/size of .reloc section
        public bool GetDetails()
        {
            bool rv = false;
            try
            {
                using (var fs = new FileStream(FileName, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
                {
                    GetDetails(fs);
                }
                rv = true;
            }
            catch (Exception ex)
            {
                if (Verbose > 0)
                    WriteLine($"Skipping file [{FileName}] due to error {ex.Message} : {ex.ToString()}.");

            }
            return rv;
        }

        public async Task<byte[]> GetBuffAsync()
        {
            byte[] readBuffer = null;
            var bytesRead = 0;
            try
            {
                using (var fileStream = File.OpenRead(FileName))
                {
                    readBuffer = new Byte[RelocSize];
                    fileStream.Position = RelocPos;
                    bytesRead = await fileStream.ReadAsync(readBuffer, 0, (int)RelocSize).ConfigureAwait(false);
                    return readBuffer;
                }
            }
            catch (Exception)
            {
                return readBuffer;
            }
        }
    }
    [Flags]
    public enum PECaricteristicFlags : uint
    {

        // same as IMAGE_SCN_ALIGN_1BYTE?
        NoPadding = 0x00000008,
        Code = 0x00000020,
        HasData = 0x00000040,
        HasBSS = 0x00000080,
        Other = 0x00000100,
        Comments = 0x00000200,
        COMDAT = 0x00001000,
        NoDeferSpeculativeExceptions = 0x00004000,
        GlobalRelative = 0x00008000,
        Purgable = 0x00020000,
        Locked = 0x00040000,
        PreLoad = 0x00080000,
        Align1 = 0x00100000,
        Align2 = 0x00200000,
        Align4 = 0x00300000,
        Align8 = 0x00400000,
        Align16 = 0x00500000,
        Align32 = 0x00600000,
        Align64 = 0x00700000,
        Align128 = 0x00800000,
        Align256 = 0x00900000,
        Align512 = 0x00A00000,
        Align1k = 0x00B00000,
        Align2k = 0x00C00000,
        Align4k = 0x00D00000,
        Align8k = 0x00E00000,
        RelocInfo = 0x01000000,
        Discardable = 0x02000000,
        NotCachable = 0x04000000,
        NotPageable = 0x08000000,
        Shared = 0x10000000,
        Exec = 0x20000000,
        Read = 0x40000000,
        Write = 0x80000000
    }
}