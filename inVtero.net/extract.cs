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
using ProtoBuf;

namespace Reloc
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public struct MiniSection
    {
        public string Name;
        public uint VirtualSize; // size in memory
        public uint VirtualAddress; // offset to section base in memory (from ImageBase)
        public uint RawFileSize; // size on disk
        public uint RawFilePointer; // offset to section base on disk (from 0)
        [ProtoIgnore]
        public bool IsExec { get { return (Characteristics & 0x20000000) != 0; } }
        [ProtoIgnore]
        public bool IsCode { get { return (Characteristics & 0x20000000) != 0; } }
        [ProtoIgnore]
        public bool IsRead { get { return (Characteristics & 0x40000000) != 0; } }
        [ProtoIgnore]
        public bool IsWrite { get { return (Characteristics & 0x80000000) != 0; } }
        [ProtoIgnore]
        public bool IsShared { get { return (Characteristics & 0x10000000) != 0; } }
        [ProtoIgnore]
        public bool IsDiscard { get { return (Characteristics & 0x02000000) != 0; } }
        public uint Characteristics;

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
    // Extract compiles a local reloc set that can be used when dumping memory to recover identical files 
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class Extract
    {
        public long VA;

        public static int NewCnt;
        public static int Verbose;
        public static bool OverWrite;

        public string FileName;
        public uint RelocPos;
        public uint RelocSize;
        public uint ImportDirPos;
        public uint ImportDirSize;
        public uint DebugDirPos;
        public uint DebugDirSize;
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
        public short NumberOfSections;
        public bool IsCLR;
        // maybe ordered list would emit better errors for people
        public List<MiniSection> Sections;
        
        public DeLocate ReReState;

        int secOff;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder($"{Environment.NewLine}**PE FILE** \t-\t-\t Date   [{TimeStamp:X8}]{Environment.NewLine}*DebugPos* \t-\t-\t Offset [{DebugDirPos:X8}] \t-\t Size [{DebugDirSize:X8}] {Environment.NewLine}*Base*  \t-\t-\t Offset [{ImageBase:X16}] -\t Size [{SizeOfImage:X8}]{Environment.NewLine}");
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

        /// Directory Async enumeration
        public static Task ScanDirectoryAsync(string Source, string Dest, string glob = "*", bool Recursive = false)
        {
            if (!Directory.Exists(Source))
            {
                WriteLine($"Can not find scan folder {Source} to import PE files from");
                return null;
            }
            else {

                WriteLine($"Scanning folder {Source} and saving relocs into {Dest}.");

                return CompileEachFileAsync(Source, glob, Dest, Recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly,
                        (f, g) => new Extract().ScanFile(f, g));
                // this exception handling not working well
                //.ContinueWith(t => {
                //    if (Verbose > 0)
                //        WriteLine($"{t.Exception.Message}. InnerException: {t.Exception.InnerExceptions}", );
            }
        }

        /// Perform scan/extract on a single file
        public async Task ScanFile(string name, string saveToFolder)
        {
            if (File.Exists(name))
            {
                FileName = name;
                if (GetDetails())
                {
                    if (RelocPos != 0 && RelocSize != 0)
                    {
                        if (Verbose > 1)
                            WriteLine($"processing [{name}]");

                        var sb = new StringBuilder(Path.GetFileName(name));
                        sb.Append("-");
                        sb.Append(ImageBase.ToString("X"));
                        sb.Append("-");
                        sb.Append(TimeStamp.ToString("X"));
                        sb.Append(".reloc");

                        var outFile = Path.Combine(saveToFolder, sb.ToString());
                        if (File.Exists(outFile) && !OverWrite)
                        {
                            if (Verbose > 0)
                            {
                                WriteLine($"{outFile} exists, skipping due to no over write setting.");
                                return;
                            }
                        }
                        //var readBuffer = GetBuffAsync().Result;
                        using (FileStream stream = new FileStream(outFile,
                            FileMode.CreateNew, FileAccess.Write, FileShare.None, (int)RelocSize, true))
                            await stream.WriteAsync(GetBuffAsync().Result, 0, (int)RelocSize);

                        NewCnt++;
                        if (Verbose > 0)
                            WriteLine($"extracted {name} relocation data into {outFile} size {RelocSize}");
                        return;
                    }
                }
                else
                    Debug.WriteLine($"Unable to find file: {FileName}");
            }
            return;
        }

        public static Extract IsBlockaPE(byte[] block, int blockOffset = 0)
        {
            Extract extracted_struct = new Extract();

            if (block[blockOffset] != 0x4d || block[blockOffset+1] != 0x5a)
                return null;

            var headerOffset = BitConverter.ToInt32(block, blockOffset+0x3C);

            // bad probably
            if (headerOffset > 3000)
                return null;

            if (BitConverter.ToInt32(block, blockOffset+headerOffset) != 0x00004550)
                return null;

            var pos = blockOffset + headerOffset + 6;

            extracted_struct.NumberOfSections = BitConverter.ToInt16(block, pos); pos += 2;
            extracted_struct.Sections = new List<MiniSection>();
            //pos += 2;

            extracted_struct.TimeStamp = BitConverter.ToUInt32(block, pos); pos += 4;
            pos += 8;
            extracted_struct.secOff = BitConverter.ToUInt16(block, pos); pos += 2;
            pos += 2;
            var magic = BitConverter.ToUInt16(block, pos); pos += 2;
            extracted_struct.Is64 = magic == 0x20b;

            if (extracted_struct.Is64)
            {
                pos += 14;
                extracted_struct.EntryPoint = BitConverter.ToUInt32(block, pos); pos += 4;
                extracted_struct.BaseOfCode = BitConverter.ToUInt32(block, pos); pos += 4;
                extracted_struct.ImageBaseOffset = pos;
                extracted_struct.ImageBase = BitConverter.ToUInt64(block, pos); pos += 8;
            }
            else
            {
                pos += 18;
                extracted_struct.EntryPoint = BitConverter.ToUInt32(block, pos); pos += 4;
                extracted_struct.BaseOfCode = BitConverter.ToUInt32(block, pos); pos += 4;
                extracted_struct.ImageBaseOffset = pos;
                extracted_struct.ImageBase = BitConverter.ToUInt32(block, pos); pos += 4;
            }
            extracted_struct.SectionAlignment = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.FileAlignment = BitConverter.ToUInt32(block, pos); pos += 4;

            pos += 16;

            extracted_struct.SizeOfImage = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.SizeOfHeaders = BitConverter.ToUInt32(block, pos); pos += 4;
            // checksum
            pos += 4;
            // subsys/characteristics
            pos += 4;
            // SizeOf/Stack/Heap/Reserve/Commit
            if (extracted_struct.Is64)
                pos += 32;
            else
                pos += 16;
            // LoaderFlags
            pos += 4;
            // NumberOfRvaAndSizes
            pos += 4;
            // 16 DataDirectory entries, each is 8 bytes 4byte VA, 4byte Size
            // we care about #6 since it's where we will find the GUID
            pos += 6 * 8;
            extracted_struct.DebugDirPos = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.DebugDirSize = BitConverter.ToUInt32(block, pos); pos += 4;
            // move to IAT directory
            pos += 5 * 8;
            extracted_struct.ImportDirPos = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.ImportDirSize = BitConverter.ToUInt32(block, pos); pos += 4;
            // move to "COM" directory (.net PE check)
            pos += 8;
            extracted_struct.ClrAddress = BitConverter.ToUInt32(block, pos); pos += 4;
            extracted_struct.ClrSize = BitConverter.ToUInt32(block, pos); pos += 4;
            if (extracted_struct.ClrAddress != 0)
                extracted_struct.IsCLR = true;

            var CurrEnd = extracted_struct.SizeOfHeaders;
            /// implicit section for header
            extracted_struct.Sections.Add(new MiniSection { VirtualSize = CurrEnd, RawFileSize = CurrEnd, RawFilePointer = 0, VirtualAddress = 0, Name = ".PEHeader", Characteristics = 0x20000000 });

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
                var characteristic = BitConverter.ToUInt32(block, pos); pos += 4;

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
                NumberOfSections = binReader.ReadInt16();

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
                Sections.Add(new MiniSection { VirtualSize = 0x1000, RawFileSize = CurrEnd, RawFilePointer = 0, VirtualAddress = 0, Name = ".PEHeader", Characteristics = 0x20000000 });

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
                    var characteristic = binReader.ReadUInt32();

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
}