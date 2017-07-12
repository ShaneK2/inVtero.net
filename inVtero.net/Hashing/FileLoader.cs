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

        public string MaskedEntriesSpec = ":.MSI:.MSP:.PDB:.TDLOG:.VHD:.WIM:.DMP:.MSU:.LOG:.FON:.TTF:.TTC:FONTS:.WMV:.WAV:.CUR:.ANI:HIBERFIL.SYS:PAGEFILE.SYS:";
        public string[] MaskedEntries;

        BlockingCollection<Extract> LoadList = new BlockingCollection<Extract>();

        bool DoneDirScan = false;
        int MinHashSize;
        string DBFile;

        // A BILLION :)
        public int BufferCount = 1024 * 1024 * 1024;
        const int PageSize = 4096;

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
                WriteColor(ConsoleColor.Green, $"Finished FS load from {Folder}");
            }, () => {
                HashToBuffers();
            });
        }

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
        static int SortByDBSizeMask(HashRecord x, HashRecord y)
        {
            if (x == null)
            {
                if (y == null)
                    return 0;
                return 1;
            }
            else if (y == null)
                return -1;

            return (x.Index & SortMask) == (y.Index & SortMask) ? 0 : (x.Index & SortMask) > (y.Index & SortMask )? 1 : -1;
        }

        void DumpBufToDisk()
        {
            long TotalDBWrites = 0;
            do
            {
                var ReadyHashes = ReadyQueue.Take();
                var hashArr = ReadyHashes.ToArray();
                SortMask = (ulong)HDB.DBSize - 1;
                ParallelAlgorithms.Sort<HashRecord>(hashArr, GetICompareer<HashRecord>(SortByDBSizeMask));

                var Count = hashArr.Count();
                var DBSizeMask = (ulong)HDB.DBSize - 1;

                if (Vtero.VerboseLevel >= 1)
                    WriteColor(ConsoleColor.Cyan, $"Hash entries to store: {Count}");

                using (var fw = new FileStream(DBFile, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, 8192))
                {
                    // we need 2 pages now since were block reading and we might pick a hash that start's scan
                    // at the very end of a page
                    byte[] buff = new byte[PageSize * 2];
                    byte[] zero = new byte[16];
                    int i = 0, firstIndex = 0;

                    var DBEntriesMask = HDB.DBEntries - 1;

                    var sw = Stopwatch.StartNew();
                    do
                    {
                        bool WriteBack = false;

                        var Index = hashArr[i].Index;
                        // convert Index to PageIndex
                        var DBPage = (long)((Index & DBSizeMask) & ~0xfffUL);

                        // find block offset for this hash
                        fw.Seek(DBPage, SeekOrigin.Begin);
                        fw.Read(buff, 0, PageSize * 2);

                        do
                        {
                            // skip duplicates
                            if (i+1 < Count && (hashArr[i+1] != null) && hashArr[i].Index == hashArr[i + 1].Index)
                            {
                                i++;
                                continue;
                            }

                            // re-read Inxex since we could be on the inner loop
                            Index = hashArr[i].Index;
                            // Index inside of a page
                            var PageIndex = (int)Index & 0xfff;

                            var toWrite = hashArr[i].HashData;

                            // do we already have this hash from disk?
                            firstIndex = buff.SearchBytes(toWrite, PageIndex, 16);
                            if (firstIndex >= 0)
                            {
                                i++;
                                break;
                            }

                            firstIndex = buff.SearchBytes(zero, PageIndex, 16);
                            if (firstIndex >= 0)
                            {
                                WriteBack = true;
                                // update buff with new hash entry for write back
                                Array.Copy(toWrite, 0, buff, firstIndex, toWrite.Length);
                                TotalDBWrites++;
                                // set to the origional index, shift down since were bit aligned
                                HDB.Bit.SetBit(HDB.BitMapView, ((int)Index >> 4) & (int)DBEntriesMask);
                            }
                            else if (firstIndex < 0)
                            {
                                var strerr = $"HASH TABLE SATURATED! YOU NEED TO MAKE THE DB LARGER!!";
                                WriteColor(ConsoleColor.Red, strerr);
                                throw new ApplicationException(strerr);
                            }
                            i++;

                            // continue to next entry if it's in the same block
                        } while (i < Count && (((hashArr[i].Index & DBSizeMask) & ~0xfffUL) == (ulong)DBPage));

                        if (WriteBack)
                        {
                            // reset seek position
                            fw.Seek(DBPage, SeekOrigin.Begin);
                            // only write back 1 page if we can help it
                            fw.Write(buff, 0, firstIndex < (PageSize - 16) ? PageSize : PageSize * 2);
                        }

                        if (i % 100000 == 0 && sw.Elapsed.Seconds > 0)
                            WriteColor(ConsoleColor.White, $"entries: {i}, per second {i / sw.Elapsed.Seconds} ");

                    } while (i < Count);
                }
            } while (!DoneDirScan || ReadyQueue.Count() > 0);

            WriteColor(ConsoleColor.Cyan, $"Finished DB write {TotalDBWrites} entries (reduced count reflects de-duplication).");
        }

        List<HashRecord> Hashes = new List<HashRecord>();
        BlockingCollection<List<HashRecord>> ReadyQueue = new BlockingCollection<List<HashRecord>>();

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
                readBuffer = new byte[e.RelocSize];
                fileStream.Position = e.RelocPos;
                fileStream.Read(readBuffer, 0, (int)e.RelocSize);
            }

            using (FileStream stream = new FileStream(outFile,
                    FileMode.CreateNew, FileAccess.Write, FileShare.None, (int)e.RelocSize, true))
                    stream.Write(readBuffer, 0, (int)e.RelocSize);
        }

        void FillHashBuff()
        {
            Stopwatch sw = Stopwatch.StartNew();
            do
            {
                int LoadedCnt = 0;
                //Parallel.ForEach(LoadList, (hashFile) =>
                var hashFile = LoadList.Take();
                //{
                    Interlocked.Increment(ref LoadedCnt);
                    //var hashFile = LoadList.Take();
                    Parallel.Invoke(() =>
                    {
                        ExtractRelocData(hashFile);
                    }, () =>
                    {
                        foreach (var ms in hashFile.SectionPosOffsets)
                        {
                            if (!ms.IsCode && !ms.IsExec)
                                continue;

                            var fht = new FractHashTree(hashFile.FileName, ms, MinHashSize, GetHP, HDB.DBSize);
                            var fhtree = fht.DumpTree();

                            Hashes.AddRange(fhtree);
                        }

                        if (Hashes.Count() > BufferCount)
                        {
                            WriteColor(ConsoleColor.Green, $"Filled queue past maximum (actual) {Hashes.Count()}, signaling readyqueue.");
                            ReadyQueue.Add(Hashes);
                            Hashes = new List<HashRecord>();
                        }

                        if ((LoadedCnt % 100) == 0 && sw.Elapsed.Seconds > 0)
                            WriteColor(ConsoleColor.Gray, $"Loded {LoadedCnt} of {LoadList.Count()} files.  {LoadedCnt / sw.Elapsed.Seconds} per second.");
                    });
                //});
            } while (!DoneDirScan);

            ReadyQueue.Add(Hashes);
            WriteColor(ConsoleColor.Green, $"Final hash load finished {Hashes.Count()}, signaling readyqueue for DB commit.");
            Hashes = new List<HashRecord>();
        }

        /// <summary>
        /// Set's up the FILL/SPILL into the big disk DB
        /// </summary>
        void HashToBuffers()
        {
            Parallel.Invoke(() => FillHashBuff(), () => DumpBufToDisk());
        }

        Extract CheckFile(string Path)
        {
            Extract rv = null;
            byte[] block = new byte[4096];
            try
            {
                using (var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
                {
                    fs.Read(block, 0, 4096);
                    rv = Extract.IsBlockaPE(block);
                    if (rv != null)
                        rv.FileName = Path;
                }
            }
            catch (Exception ex)
            {
                if (Vtero.VerboseLevel > 0)
                    WriteColor(ConsoleColor.Yellow, $"Skipping file [{Path}] due to error {ex.Message}.");

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
                //WriteColor(ConsoleColor.White, $"scanning file {check}");
                var carved = CheckFile(check);
                if (carved != null)
                {
                    LoadList.Add(carved);
                    if(LoadList.Count() % 1000 == 0 && GenerateSW.Elapsed.Seconds > 0)
                        WriteColor(ConsoleColor.White, $"Loaded {LoadList.Count()} code files. {LoadList.Count() / GenerateSW.Elapsed.Seconds} per second.");

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
                        WriteColor(ConsoleColor.Yellow, $"Problem with scanning folder: {subdir} Exeption: {ex.Message}");
                    }
                }
            }
        }
    }
}
