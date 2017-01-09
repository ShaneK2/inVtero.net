// Shane.Macaulay @IOActive.com Copyright (C) 2013-2015

//Copyright(C) 2015 Shane Macaulay

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// Shane.Macaulay@IOActive.com (c) copyright 2014,2015,2016 all rights reserved. GNU GPL License

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
        public uint VirtualOffset; // offset to section base in memory (from ImageBase)
        public uint RawFileSize; // size on disk
        public uint RawFilePointer; // offset to section base on disk (from 0)

        public override string ToString()
        {
            return $"{Name} - VBase {VirtualOffset:X}:{VirtualSize:X} - File {RawFilePointer:X}:{RawFileSize:X}";
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
        public uint DebugDirPos;
        public uint DebugDirSize;
        public ulong ImageBase;
        public long ImageBaseOffset;
        public uint TimeStamp;
        public bool Is64;
        public uint SectionAlignment;
        public uint FileAlignment;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public short NumberOfSections;
        // maybe ordered list would emit better errors for people
        public List<MiniSection> SectionPosOffsets;

        int secOff;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder($"{Environment.NewLine}**PE FILE** \t-\t-\t Date   [{TimeStamp:X8}]{Environment.NewLine}*DebugPos* \t-\t-\t Offset [{DebugDirPos:X8}] \t-\t Size [{DebugDirSize:X8}] {Environment.NewLine}*Base*  \t-\t-\t Offset [{ImageBase:X16}] -\t Size [{SizeOfImage:X8}]{Environment.NewLine}");
            foreach (var s in SectionPosOffsets)
                sb.Append($"[{s.Name.PadRight(8)}] \t-\t-\t Offset [{s.VirtualOffset:X8}] \t-\t Size [{s.VirtualSize:X8}]{Environment.NewLine}");

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

        public static Extract IsBlockaPE(byte[] block)
        {
            Extract extracted_struct = new Extract();

            if (BitConverter.ToInt16(block, 0) != 0x5A4D)
                return null;

            var headerOffset = BitConverter.ToInt32(block, 0x3C);

            if (headerOffset > 3000)
            {
                // bad probably
                return null;
            }

            if (BitConverter.ToInt32(block, headerOffset) != 0x00004550)
                return null;

            var pos = headerOffset + 6;

            extracted_struct.NumberOfSections = BitConverter.ToInt16(block, pos); pos += 2;
            extracted_struct.SectionPosOffsets = new List<MiniSection>();
            //pos += 2;

            extracted_struct.TimeStamp = BitConverter.ToUInt32(block, pos); pos += 4;
            pos += 8;
            extracted_struct.secOff = BitConverter.ToUInt16(block, pos); pos += 2;
            pos += 2;
            var magic = BitConverter.ToUInt16(block, pos); pos += 2;
            extracted_struct.Is64 = magic == 0x20b;

            if (extracted_struct.Is64)
            {
                pos += 22;
                extracted_struct.ImageBaseOffset = pos;
                extracted_struct.ImageBase = BitConverter.ToUInt64(block, pos); pos += 8;
            }
            else
            {
                pos += 26;
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


            var CurrEnd = extracted_struct.SizeOfHeaders;
            /// implicit section for header
            extracted_struct.SectionPosOffsets.Add(new MiniSection { VirtualSize = 0x1000, RawFileSize = 0x400, RawFilePointer = 0, VirtualOffset = 0, Name = "PEHeader" });

            // get to sections
            pos = headerOffset + (extracted_struct.Is64 ? 0x108 : 0xF8);
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
                var rawPos = BitConverter.ToUInt32(block, pos); pos += 4;

                var currSecNfo = new MiniSection { VirtualSize = Size, VirtualOffset = Pos, RawFileSize = rawSize, RawFilePointer = rawPos, Name = secStr };
                extracted_struct.SectionPosOffsets.Add(currSecNfo);

                if (Verbose > 2)
                    Write($" section [{secStr}] ");

                if (secStr.StartsWith(@".reloc", StringComparison.Ordinal))
                {
                    extracted_struct.RelocSize = Size;
                    extracted_struct.RelocPos = Pos;
                }

                pos += 0x10;
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

                SectionPosOffsets = new List<MiniSection>();

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
                SectionPosOffsets.Add(new MiniSection { VirtualSize = 0x1000, RawFileSize = 0x400, RawFilePointer = 0, VirtualOffset = 0, Name = "PEHeader" });

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

                    var currSecNfo = new MiniSection { VirtualSize = Size, VirtualOffset = Pos, RawFileSize = rawSize, RawFilePointer = rawPos, Name = secStr };
                    SectionPosOffsets.Add(currSecNfo);

                    if (Verbose > 2)
                        Write($" section [{secStr}] ");

                    if (secStr.StartsWith(@".reloc", StringComparison.Ordinal))
                    {
                        RelocSize = Size;
                        RelocPos = Pos;
                    }

                    fs.Position += 0x10;
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