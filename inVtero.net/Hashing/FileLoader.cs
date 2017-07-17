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
using System.Buffers;

namespace inVtero.net.Hashing
{
    public class FileLoader : IDisposable
    {
        HashDB HDB;

        public string ScanExtensionsSpec = ":.EXE:.DLL:.SYS:.CPL:.OCX:.SCR:.DRV:.TSP:.MUI:";
        public string[] ScanExtensions;

        public string MaskedEntriesSpec = ":.MSI:.MSP:.PDB:.TDLOG:.VHD:.WIM:.DMP:.MSU:.LOG:.FON:.TTF:.TTC:FONTS:.WMV:.WAV:.CUR:.ANI:HIBERFIL.SYS:PAGEFILE.SYS:SWAPFILE.SYS:";
        public string[] MaskedEntries;

        public List<string> LoadExceptions = new List<string>();

        ConcurrentDictionary<int, Extract> LoadList = new ConcurrentDictionary<int, Extract>();

        bool DoneDirScan = false;
        bool DoneHashLoad = false;

        int MinHashSize;
        string DBFile;

        // A BILLION :)
        public int BufferCount = 1000 * 1000 * 10;
        const int PageSize = MagicNumbers.PAGE_SIZE;

        Func<HashLib.IHash> GetHP;
        ArrayPool<HashRec> aPool;
        Stopwatch GenerateSW;
        BlockingCollection<Tuple<int, HashRec[]>> ReadyQueue = new BlockingCollection<Tuple<int, HashRec[]>>();

        
        public FileLoader(HashDB hDB, int minHashSize, int bufferCount = 0, Func<HashLib.IHash> getHP = null)
        {
            var sep = new char[] { ':' };

            if(bufferCount != 0)
                BufferCount = bufferCount;

            GetHP = getHP;
            if (GetHP == null)
                GetHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            HDB = hDB;
            DBFile = HDB.HashDBFile;
            SortMask = (ulong)HDB.DBSize - 1;

            MinHashSize = minHashSize;

            ScanExtensions = ScanExtensionsSpec.ToUpper().Split(sep, StringSplitOptions.RemoveEmptyEntries);
            MaskedEntries = MaskedEntriesSpec.ToUpper().Split(sep, StringSplitOptions.RemoveEmptyEntries);
        }

        public IEnumerable<Tuple<string, double, List<bool>>> DirectoryChecker(string folder, string glob, int OnlySize = 0)
        {
            foreach(var toScan in Directory.EnumerateFiles(folder, glob, SearchOption.AllDirectories))
            {
                List<bool> rv = new List<bool>();
                int len = (int) new FileInfo(toScan).Length;
                int alignLen = (int)((len + 0xfff) & ~0xfff);
                var tot = FractHashTree.TotalHashesForSize((uint)alignLen, MinHashSize);
                var buf = new byte[alignLen];

                using (var f = new FileStream(toScan, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    f.Read(buf, 0, alignLen);

                var toCheck = FractHashTree.CreateRecsFromMemory(buf, MinHashSize, GetHP, OnlySize);
                //var bits = HDB.BitmapScan(toCheck);
                int Found = 0;
                foreach(var bit in toCheck)
                {
                    if (HDB.GetIdxBit(bit.Index))
                    {
                        Found++;
                        rv.Add(true);
                    }
                    else
                        rv.Add(false);
                }


                yield return Tuple.Create<string, double, List<bool>>(toScan, Found * 100.0 / toCheck.Length, rv);
            }
        }

        public List<bool> FileChecker(string aPath, bool Force = false, int OnlySize = 0)
        {
            var rv = new List<bool>();
            var inputFile = CheckFile(aPath);
            if (inputFile != null || Force)
            {
                if (Force && inputFile == null)
                {
                    var toCheck = FractHashTree.CreateRecsFromMemory(File.ReadAllBytes(aPath), MinHashSize, GetHP, OnlySize);
                    rv.AddRange(HashRecLookup(toCheck));
                }
                else
                {
                    foreach (var ms in inputFile.Sections)
                    {
                        if (!ms.IsCode || !ms.IsExec)
                            continue;

                        var totSiz = FractHashTree.TotalHashesForSize(ms.RawFileSize, MinHashSize);
                        var hr = new HashRec[totSiz];
                        FractHashTree.CreateRecsFromFile(aPath, ms, MinHashSize, (int) totSiz, hr, 0, GetHP);
                        rv.AddRange(HashRecLookup(hr));
                    }
                }
            }
            return rv;
        }

        public List<bool> HashRecLookup(HashRec[] hashArr)
        {
            int Count = hashArr.Length;
            var rv = new List<bool>(Count);
            var DBEntriesMask = HDB.DBEntries - 1;

            ParallelAlgorithms.Sort<HashRec>(hashArr, 0, Count, GetICompareer<HashRec>(SortByDBSizeMask));

            using (var fs = new FileStream(DBFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, PageSize*2))
            {
                // we need 2 pages now since were block reading and we might pick a hash that start's scan
                // at the very end of a page
                byte[] buff = new byte[PageSize*2];
                byte[] zero = new byte[16];
                int i = 0, firstIndex = 0;

                do
                {
                    var Index = hashArr[i].Index;
                    // convert Index to PageIndex
                    var DBPage = (long)((Index & SortMask) & ~0xfffUL);

                    // find block offset for this hash
                    fs.Seek(DBPage, SeekOrigin.Begin);
                    fs.Read(buff, 0, PageSize * 2);

                    do
                    {
                        // re-read Inxex since we could be on the inner loop
                        Index = hashArr[i].Index;
                        // Index inside of a page
                        var PageIndex = (int)Index & 0xfff;

                        // Hash to populate the DB with
                        var toRead = hashArr[i].HashData;

                        // do we already have this hash from disk? 
                        firstIndex = buff.SearchBytes(toRead, PageIndex, 16);
                        if (firstIndex >= 0)
                            rv.Add(true);
                        else
                            rv.Add(false);

                        i++;

                        // continue to next entry if it's in the same block
                    } while (i < Count && (((hashArr[i].Index & SortMask) & ~0xfffUL) == (ulong)DBPage));

                } while (i < Count);
            }
            return rv;
        }

        public void HashLookup(HashRecord[] hashArr)
        {
            int Count = hashArr.Length;
            var rv = new List<bool>(Count);
            var DBEntriesMask = HDB.DBEntries - 1;

            for (int i = 0; i < hashArr.Length; i++)
            {
                var hashModule = hashArr[i];
                for (int l = 0; l < hashModule.Regions.Count; l++)
                {
                    var hashRegion = hashArr[i].Regions[l];
                    for (int m = 0; m < hashRegion.InnerList.Count; m++)
                    {
                        var CheckHashes = hashArr[i].Regions[l].InnerList[m];
                        var checkedArr = HashRecLookup(CheckHashes).ToArray();

                        /*
                        if (hashRegion.OriginationInfo.Contains("rmclient.dll.text"))
                        {

                            var addr = hashRegion.SparseAddrs[m];

                            var name = $"c:\\temp\\dumptest\\{hashRegion.OriginationInfo}-{addr:X}.bin";
                            using (var dt = new FileStream(name, FileMode.Create, FileAccess.Write, FileShare.None, 4096))
                            {
                                dt.Seek(addr - hashRegion.Address + 1024, SeekOrigin.Begin);
                                dt.Write(hashRegion.Data[m], 0, 4096);
                            }
                        }
                        */

                        hashRegion.InnerCheckList.Add(checkedArr);
                        hashRegion.Total += checkedArr.Length;

                        // update aggrogate counters
                        for (int n = 0; n < checkedArr.Length; n++)
                        {
                            if (checkedArr[n])
                                hashArr[i].Regions[l].Validated++;
                            else
                                hashArr[i].Regions[l].Failed++;
                        }
                    }

                }
            }
            return;
        }

        public int LoadFromMem(byte[] Input)
        {
            int written = 0;
            var hashArr = FractHashTree.CreateRecsFromMemory(Input, MinHashSize, GetHP);
            var Count = hashArr.Length;

            using (var fs = new FileStream(DBFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, PageSize * 2))
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
                            && hashArr[i].Index == hashArr[i + 1].Index
                        && UnsafeHelp.UnsafeCompare(hashArr[i].HashData, hashArr[i + 1].HashData))
                        {
                            i++;
                            continue;
                        }
                        // were all done since the sort should of put these null entries at the end
                        while (i < Count && hashArr[i].HashData == null)
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

                                    written++;
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
                } while (i < Count);
            }
            return written;
        }

        public void LoadFromPath(string Folder)
        {
            aPool = ArrayPool<HashRec>.Create(BufferCount, 5);

            Parallel.Invoke(() =>
            {
                GenerateSW = Stopwatch.StartNew();
                RecursiveGenerate(Folder);
                DoneDirScan = true;
                WriteColor(ConsoleColor.Green, $"Finished FS load from {Folder} task time: {GenerateSW.Elapsed}");
            }, 
            () => {
                FillHashBuff();
                DoneHashLoad = true;
            }, 
            () => DumpBufToDisk()
            );
            WriteColor(ConsoleColor.White, $"Total task runtime: {GenerateSW.Elapsed}");
        }


        void DumpBufToDisk()
        {
            var sw = Stopwatch.StartNew();
            long TotalDBWrites = 0;
            long TotalRequested = 0;
            do
            {
                sw.Stop();

                var hashArrTpl = ReadyQueue.Take();
                var hashArr = hashArrTpl.Item2;
                var Count = hashArrTpl.Item1; 

                sw.Start();
                
                ParallelAlgorithms.Sort<HashRec>(hashArr, 0, Count, GetICompareer<HashRec>(SortByDBSizeMask));

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
                    aPool.Return(hashArr);
                }

            } while (!DoneHashLoad || ReadyQueue.Count() > 0);

            WriteColor(ConsoleColor.Cyan, $"Finished DB write {TotalDBWrites:N0} NEW entries. Requsted {TotalRequested:N0} (reduced count reflects de-duplication). Task time: {sw.Elapsed}");
        }

        void FillHashBuff()
        {
            int TotalHashGenCount = 0;
            int HashGenCnt = 0;
            int LoadedCnt = 0;
            int StartingAvailable = 0;

            Stopwatch sw = Stopwatch.StartNew();
            do
            {
                #region Partition
                // prescan enough entries to not overspill the specified hash buffer count
                int CurrAvailableMax = 0;
                int LoadCnt = 0;

                while(!DoneDirScan || (DoneDirScan && CurrAvailableMax != LoadList.Count()))
                {
                    long CountForMaxBuff = 0;
                    for (LoadCnt = StartingAvailable; LoadCnt != LoadList.Count(); LoadCnt++)
                    {
                        foreach (var ms in LoadList[LoadCnt].Sections)
                        {
                            if (!ms.IsCode && !ms.IsExec)
                                continue;

                            CountForMaxBuff += FractHashTree.TotalHashesForSize(ms.RawFileSize, MinHashSize);
                        }
                        if (CountForMaxBuff >= BufferCount)
                        {
                            CurrAvailableMax = LoadCnt-1;
                            break;
                        }
                    }
                    if(DoneDirScan && LoadCnt == LoadList.Count())
                        CurrAvailableMax = LoadCnt;
                    
                    if (CurrAvailableMax != 0)
                        break;

                    Thread.Yield();
                }
                #endregion

                var hashX = aPool.Rent(BufferCount);

                WriteColor(ConsoleColor.White, $"Parallel partition from {StartingAvailable} to {CurrAvailableMax} starting.");
                Parallel.For(StartingAvailable, CurrAvailableMax, 
                    (i) =>
                    //for (int i = StartingAvailable; i < CurrAvailableMax; i++)
                    {
                        var hashFile = LoadList[i];

                        foreach (var ms in hashFile.Sections)
                        {
                            // ONLY hash CODE/EXEC file sections & PEHeader
                            if (!ms.IsCode && !ms.IsExec)
                                continue;

                            if (ms.RawFileSize <= 0)
                            {
                                LogEx(0, $"Compressed/malishous PE {hashFile.FileName} is too small.  Consider manual review of section [{ms.Name}] (e.g. UPX will overlap sections so we will hash it on next pass, TODO: UPX decoder).");
                                continue;
                            }

                            var tot = (int)FractHashTree.TotalHashesForSize(ms.RawFileSize, MinHashSize);
                            //var myCnt = Interlocked.Add(ref HashGenCnt, tot);

                            //var fht = new FractHashTree(hashFile.FileName, ms, MinHashSize, GetHP);
                            //var dht = fht.DumpRecTree();
                            //var len = dht.Count();
                            //var myLim = Interlocked.Add(ref HashGenCnt, len);
                            //dht.CopyTo(0, hashX, myLim - len, len);
                            var ReadSize = ms.VirtualSize;
                            var BufferSize = (int)((ReadSize + 0xfff) & ~0xfff);
                            var memBuff = new byte[BufferSize];

                            using (var fread = new FileStream(hashFile.FileName, FileMode.Open, FileAccess.Read, FileShare.Read, 4096))
                            {
                                fread.Seek(ms.RawFilePointer, SeekOrigin.Begin);
                                fread.Read(memBuff, 0, (int)ReadSize);
                            }
                            var recs = FractHashTree.CreateRecsFromMemory(memBuff, MinHashSize, GetHP);

                            var myLim = Interlocked.Add(ref HashGenCnt, recs.Length);
                            recs.CopyTo(hashX, myLim - recs.Length);

                            //FractHashTree.CreateRecsFromFile(hashFile.FileName, ms, MinHashSize, tot, hashX, myCnt - tot, GetHP);

                            if ((i % 100) == 0 && sw.Elapsed.TotalSeconds > 0)
                                WriteColor(ConsoleColor.Green, $"HashGen: { ((TotalHashGenCount + HashGenCnt) / sw.Elapsed.TotalSeconds):N0} per second.");
                        //}
                        }
                    });

                TotalHashGenCount += HashGenCnt;

                WriteColor(ConsoleColor.Green, $"Filled queue {HashGenCnt:N0}, signaling readyqueue.");
                WriteColor(ConsoleColor.Green, $"Loaded-Files/Generated-Hash-Values {CurrAvailableMax:N0}/{TotalHashGenCount:N0}.  HashGen: {(TotalHashGenCount / sw.Elapsed.TotalSeconds):N0} per second.");
                
                ReadyQueue.TryAdd(Tuple.Create<int, HashRec[]>(HashGenCnt, hashX));
                HashGenCnt = 0;

                StartingAvailable = CurrAvailableMax;

            } while (!DoneDirScan || StartingAvailable < LoadList.Count());

            sw.Stop();
            WriteColor(ConsoleColor.Green, $"Finished Files/Hashes {LoadedCnt:N0}/{TotalHashGenCount:N0}.  HashGen: {(TotalHashGenCount / sw.Elapsed.TotalSeconds):N0} per second.");
        }

        void LogEx(int Level, string message)
        {
            LoadExceptions.Add(message);
            if (Vtero.VerboseLevel > Level)
                WriteColor(ConsoleColor.Yellow, message);
        }

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
                int RelocPos = 0, RelocSize = 0;
                for (int i = 0; i < e.Sections.Count(); i++)
                {
                    if (e.Sections[i].Name == ".reloc")
                    {
                        RelocPos = (int)e.Sections[i].RawFilePointer;
                        RelocSize = (int)e.Sections[i].RawFileSize;
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
                    var minRead = fs.Length >= PageSize ? PageSize : MagicNumbers.PE_TYPICAL_HEADER_SIZE;

                    int readIn = fs.Read(block, 0, minRead);
                    if (readIn != minRead)
                        LogEx(1, $"Unable to read {minRead} from file {Path}, only {readIn} available.");

                    rv = Extract.IsBlockaPE(block);
                    if (rv != null)
                    {
                        rv.FileName = Path;
                        ExtractRelocData(rv);
                    }
                }
                return rv;
            }
            catch (Exception ex)
            {
                LogEx(1, $"Skipping file [{Path}] due to error {ex.Message}.");
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
                    if (file.EndsWith(banned))
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
                    LoadList.TryAdd(LoadList.Count(), carved);
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
                        LogEx(1, $"Problem with scanning folder: {subdir} Exeption: {ex.Message}");
                    }
                }
            }
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

            return (x.Index & SortMask) == (y.Index & SortMask) ? 0 : (x.Index & SortMask) > (y.Index & SortMask) ? 1 : -1;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (HDB != null)
                        HDB.Dispose();


                    if (ReadyQueue != null)
                        ReadyQueue.Dispose();

                    HDB = null;
                    ReadyQueue = null;
                }
                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~FileLoader() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
        #endregion

    }
}
