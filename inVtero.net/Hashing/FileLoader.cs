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
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using Reloc;
using static inVtero.net.Misc;
using System.Collections.Concurrent;
using System.Threading;
using inVtero.net;
using System.Threading.Algorithms;
using System.Diagnostics;

namespace inVtero.net.Hashing
{
    public class FileLoader
    {
        HashDB HDB;

        public string ScanExtensionsSpec = ":.EXE:.DLL:.SYS:.CPL:.OCX:.SCR:.DRV:.TSP:.MUI:";
        public string[] ScanExtensions;

        public string MaskedEntriesSpec = ":.MSI:.MSP:.PDB:.TDLOG:.VHD:.WIM:.DMP:.MSU:.LOG:.FON:.TTF:.TTC:FONTS:.WMV:.WAV:.CUR:.ANI:HIBERFIL.SYS:PAGEFILE.SYS:SWAPFILE.SYS:";
        public string[] MaskedEntries;

        public List<string> LoadExceptions = new List<string>();

        BlockingCollection<Extract> LoadList = new BlockingCollection<Extract>();

        bool DoneDirScan = false;
        bool DoneHashLoad = false;

        int MinHashSize;
        string DBFile;

        // A BILLION :)
        public int BufferCount = 1000 * 1000 * 500;
        const int PageSize = MagicNumbers.PAGE_SIZE;

        Func<HashLib.IHash> GetHP;

        public FileLoader() { }
        public FileLoader(HashDB hDB, int minHashSize, Func<HashLib.IHash> getHP = null)
        {
            var sep = new char[] { ':' };

            GetHP = getHP;
            if (GetHP == null)
                GetHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            HDB = hDB;
            DBFile = HDB.HashDBFile;

            MinHashSize = minHashSize;

            ScanExtensions = ScanExtensionsSpec.ToUpper().Split(sep, StringSplitOptions.RemoveEmptyEntries);
            MaskedEntries = MaskedEntriesSpec.ToUpper().Split(sep, StringSplitOptions.RemoveEmptyEntries);
        }

        Stopwatch GenerateSW;

        public void LoadFromPath(string Folder)
        {
            Parallel.Invoke(() =>
            {
                GenerateSW = Stopwatch.StartNew();
                RecursiveGenerate(Folder);
                DoneDirScan = true;
                WriteColor(ConsoleColor.Green, $"Finished FS load from {Folder} task time: {GenerateSW.Elapsed}");
            }, () => {
                HashToBuffers();
            });
            WriteColor(ConsoleColor.White, $"Total task runtime: {GenerateSW.Elapsed}");
        }

#region Compare Stuff
        public static IComparer<T> GetICompareer<T>(Comparison<T> comparer)
        {
            return new FunctorComparer<T>(comparer);
        }

        internal sealed class FunctorComparer<T> : IComparer<T>
        {
            // Fields
            private Comparer<T> c;
            private Comparison<T> comparison;

            // Methods
            public FunctorComparer(Comparison<T> comparison)
            {
                this.c = Comparer<T>.Default;
                this.comparison = comparison;
            }

            public int Compare(T x, T y)
            {
                return this.comparison(x, y);
            }
        }
        static ulong SortMask = 0;
        static int SortByDBSizeMask(HashRec x, HashRec y)
        {
            if (x.HashData == null)
            {
                if (y.HashData == null)
                    return 0;
                return 1;
            }
            else if (y.HashData == null)
                return -1;

            return (x.Index & SortMask) == (y.Index & SortMask) ? 0 : (x.Index & SortMask) > (y.Index & SortMask )? 1 : -1;
        }
#endregion

        void DumpBufToDisk()
        {
            var sw = Stopwatch.StartNew();
            long TotalDBWrites = 0;
            long TotalRequested = 0;
            do
            {
                sw.Stop();
                var ReadyHashes = ReadyQueue.Take();
                sw.Start();
                var hashArr = ReadyHashes.ToArray();
                SortMask = (ulong)HDB.DBSize - 1;
                
                ParallelAlgorithms.Sort<HashRec>(hashArr, GetICompareer<HashRec>(SortByDBSizeMask));

                var Count = hashArr.Count();
                TotalRequested += Count;

                if (Vtero.VerboseLevel >= 1)
                    WriteColor(ConsoleColor.Cyan, $"Hash entries to store: {Count:N0}");

                using (var fs = new FileStream(DBFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, PageSize*2))
                {
                    // we need 2 pages now since were block reading and we might pick a hash that start's scan
                    // at the very end of a page
                    byte[] buff = new byte[PageSize * 2];
                    byte[] zero = new byte[16];
                    int i = 0, firstIndex = 0, zeroIndex = 0;
                    bool WriteBack = false;

                    var DBEntriesMask = HDB.DBEntries - 1;

                    do
                    {
                        var Index = hashArr[i].Index;
                        // convert Index to PageIndex
                        var DBPage = (long)((Index & SortMask) & ~0xfffUL);

                        // find block offset for this hash
                        fs.Seek(DBPage, SeekOrigin.Begin);
                        fs.Read(buff, 0, PageSize * 2);
                        WriteBack = false;

                        do
                        {
                            // skip duplicates
                            if (i + 1 < Count
                                && hashArr[i].Index == hashArr[i + 1].Index)
                               //&& UnsafeHelp.UnsafeCompare(hashArr[i].HashData, hashArr[i + 1].HashData))
                            {
                                i++;
                                continue;
                            }
                            // were all done since the sort should of put these null entries at the end
                            while(i < Count && hashArr[i].HashData == null)
                                i++;
                            
                            if (i < Count)
                            {
                                // re-read Inxex since we could be on the inner loop
                                Index = hashArr[i].Index;
                                // Index inside of a page
                                var PageIndex = (int)Index & 0xfff;

                                // Hash to populate the DB with
                                var toWrite = hashArr[i].HashData;

                                // do we already have this hash from disk? 
                                firstIndex = buff.SearchBytes(toWrite, PageIndex, 16);
                                if (firstIndex < 0)
                                {
                                    zeroIndex = buff.SearchBytes(zero, PageIndex, 16);
                                    if (zeroIndex >= 0)
                                    {
                                        // we want the modified buffer to get written back
                                        WriteBack = true;
                                        // update buff with new hash entry for write back
                                        //Array.Copy(toWrite, 0, buff, zeroIndex, toWrite.Length);
                                        for (int j = zeroIndex, k = 0; j < zeroIndex + toWrite.Length; j++, k++)
                                            buff[j] = toWrite[k];

                                        TotalDBWrites++;

                                        // set to the origional index, shift down since were bit aligned
                                        HDB.SetIdxBit(Index);
                                    }
                                    else if (zeroIndex < 0)
                                    {
                                        var strerr = $"HASH TABLE SATURATED! YOU NEED TO MAKE THE DB LARGER!!";
                                        WriteColor(ConsoleColor.Red, strerr);
                                        throw new ApplicationException(strerr);
                                    }
                                }
                            }
                            i++;
                            
                            // continue to next entry if it's in the same block
                        } while (i < Count && (((hashArr[i].Index & SortMask) & ~0xfffUL) == (ulong)DBPage));

                        if (WriteBack)
                        {
                            // reset seek position
                            fs.Seek(DBPage, SeekOrigin.Begin);
                            // only write back 1 page if we can help it
                            fs.Write(buff, 0, PageSize * 2);
                        }

                        if (i % 100000 == 0 && sw.Elapsed.TotalSeconds > 0)
                            WriteColor(ConsoleColor.Cyan, $"DB commit entries: {i:N0} - per second {(i / sw.Elapsed.TotalSeconds):N0} ");

                    } while (i < Count);
                    WriteColor(ConsoleColor.Cyan, $"Buffer commited entries: {i:N0} - per second {(i / sw.Elapsed.TotalSeconds):N0} ");
                }
            } while (!DoneHashLoad || ReadyQueue.Count() > 0);

            WriteColor(ConsoleColor.Cyan, $"Finished DB write {TotalDBWrites:N0} NEW entries. Requsted {TotalRequested:N0} (reduced count reflects de-duplication). Task time: {sw.Elapsed}");
        }

        List<HashRec> Hashes = new List<HashRec>();
        BlockingCollection<List<HashRec>> ReadyQueue = new BlockingCollection<List<HashRec>>();

        void ExtractRelocData(Extract e)
        {
            if (e.RelocSize == 0)
                return;

            var relocDir = e.Is64 ? HDB.Reloc64Dir : HDB.Reloc32Dir;
            var sb = $"{Path.GetFileName(e.FileName)}-{e.ImageBase.ToString("X")}-{e.TimeStamp.ToString("X")}.reloc";
            var outFile = Path.Combine(relocDir, sb);

            if (File.Exists(outFile))
                return;

            byte[] readBuffer;

            using (var fileStream = File.OpenRead(e.FileName))
            {
                int RelocPos = 0, RelocSize=0;
                for(int i=0; i < e.Sections.Count(); i++)
                {
                    if(e.Sections[i].Name == ".reloc")
                    {
                        RelocPos = (int) e.Sections[i].RawFilePointer;
                        RelocSize = (int) e.Sections[i].RawFileSize;
                        break;
                    }
                }
                if (RelocSize != 0)
                {
                    readBuffer = new byte[RelocSize];
                    fileStream.Position = RelocPos;

                    fileStream.Read(readBuffer, 0, RelocSize);

                    using (FileStream stream = new FileStream(outFile,
                            FileMode.CreateNew, FileAccess.Write, FileShare.None, (int)RelocSize, true))
                        stream.Write(readBuffer, 0, (int)RelocSize);
                }
            }
        }

        long HashGenCnt = 0;
        void FillHashBuff()
        {
            int LoadedCnt = 0;
            Stopwatch sw = Stopwatch.StartNew();
            do
            {
                //Parallel.ForEach(LoadList, (hashFile) =>
                var hashFile = LoadList.Take();
                LoadedCnt++;
                //Interlocked.Increment(ref LoadedCnt);
                Parallel.Invoke(() =>
                {
                    ExtractRelocData(hashFile);
                }, () =>
                {
                    foreach (var ms in hashFile.Sections)
                    {
                        // ONLY hash CODE/EXEC file sections & not the headers
                        // we already loaded the header during the scan before we got here
                        if ((!ms.IsCode && !ms.IsExec) || ms.RawFilePointer == 0)
                            continue;

                        var fhtree = FractHashTree.CreateRecsFromFile(hashFile.FileName, ms, MinHashSize, GetHP);
                        Interlocked.Add(ref HashGenCnt, fhtree.Length);
                        Hashes.AddRange(fhtree);

                        if((LoadedCnt % 100) == 0 && sw.Elapsed.TotalSeconds > 0)
                            WriteColor(ConsoleColor.Green, $"HashGen: { (HashGenCnt / sw.Elapsed.TotalSeconds):N0} per second.");
                    }

                    if (Hashes.Count() > BufferCount)
                    {
                        WriteColor(ConsoleColor.Green, $"Filled queue past maximum (actual) {Hashes.Count():N0}, signaling readyqueue.");
                        WriteColor(ConsoleColor.Green, $"Loaded-Files/Generated-Hash-Values {LoadedCnt:N0}/{HashGenCnt:N0}.  HashGen: {(HashGenCnt/sw.Elapsed.TotalSeconds):N0} per second.");
                        ReadyQueue.Add(Hashes);
                        Hashes = new List<HashRec>();
                    }

                });
            } while (!DoneDirScan || LoadList.Count() > 0);

            ReadyQueue.Add(Hashes);
            WriteColor(ConsoleColor.Green, $"Final hash load finished {Hashes.Count():N0}, signaling readyqueue for DB commit. Task time: {sw.Elapsed}");
            WriteColor(ConsoleColor.Green, $"Loaded-Files/Generated-Hash-Values {LoadedCnt:N0}/{HashGenCnt:N0}.  HashGen: {(HashGenCnt / sw.Elapsed.TotalSeconds):N0} per second.");
            DoneHashLoad = true;
            Hashes = new List<HashRec>();
        }

        /// <summary>
        /// Set's up the FILL/SPILL into the big disk DB
        /// </summary>
        void HashToBuffers()
        {
            Parallel.Invoke(() => FillHashBuff(), () => DumpBufToDisk());
        }

        /// <summary>
        /// Pre-Screen files to find out if it's a binary we care about
        /// </summary>
        /// <param name="Path"></param>
        /// <returns></returns>
        Extract CheckFile(string Path)
        {
            Extract rv = null;
            byte[] block = new byte[PageSize];
            try
            {
                using (var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.Read, PageSize))
                {
                    fs.Read(block, 0, PageSize);
                    rv = Extract.IsBlockaPE(block);
                    if (rv != null)
                    {
                        // we mine as well hash it now since we already loaded the bytes
                        var fhtree = FractHashTree.CreateRecsFromMemory(block, MinHashSize, GetHP);
                        Interlocked.Add(ref HashGenCnt, fhtree.Length);

                        Hashes.AddRange(fhtree);

                        rv.FileName = Path;
                    }
                }
            }
            catch (Exception ex)
            {
                var FileCheckException = $"Skipping file [{Path}] due to error {ex.Message}.";
                LoadExceptions.Add(FileCheckException);

                if (Vtero.VerboseLevel > 0)
                    WriteColor(ConsoleColor.Yellow, FileCheckException);
            }
            return rv;
        }

        void RecursiveGenerate(string Path)
        {
            var TmpList = new List<string>();
            var CheckedList = new List<string>();
            IEnumerable<string> files = null;

            // First get the file list inclusive of our file extensions list
            files = from afile in Directory.EnumerateFiles(
                                    Path, "*.*",
                                    SearchOption.TopDirectoryOnly)
                    let file = afile.ToUpper()
                    from just in ScanExtensions
                        where file.EndsWith(just)
                    select file;
            bool banner = false;

            // strip out any banned items
            foreach (var file in files)
            {
                foreach (var banned in MaskedEntries)
                {
                    if (file.Contains(banned))
                    {
                        banner = true;
                        break;
                    }
                }
                if (!banner)
                    TmpList.Add(file);

                banner = false;
            }

            // get list of PE's we can hash
            foreach (var check in TmpList)
            {
                var carved = CheckFile(check);
                if (carved != null)
                {
                    LoadList.Add(carved);
                    if(LoadList.Count() % 1000 == 0 && GenerateSW.Elapsed.TotalSeconds > 0)
                        WriteColor(ConsoleColor.Gray, $"Loaded {LoadList.Count()} code files. {(LoadList.Count() / GenerateSW.Elapsed.TotalSeconds):N0} per second.");

                }
            }

            // Parse subdirectories
            foreach (var subdir in Directory.EnumerateDirectories(Path, "*.*", SearchOption.TopDirectoryOnly))
            {
                var dirs = from banned in MaskedEntries
                            where !subdir.ToUpper().Contains(banned)
                            select banned;
                if (dirs.Count() > 0)
                {
                    try { RecursiveGenerate(subdir); }
                    catch (Exception ex)
                    {
                        var fsLoadException = $"Problem with scanning folder: {subdir} Exeption: {ex.Message}";
                        LoadExceptions.Add(fsLoadException);

                        if (Vtero.VerboseLevel > 1) 
                            WriteColor(ConsoleColor.Yellow, fsLoadException);
                    }
                }
            }
        }
    }
}
