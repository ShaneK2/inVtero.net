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
using Reloc;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net.Hashing
{
    // HashFactory that will generate all hashes from minsize blocks to 4096
    public class FractHashTree
    {
        public int MinBlockSize = 0;
        public long LevelCount = 0;

        const int PageSize = 4096;

        Func<HashLib.IHash> GetHP;
        HashLib.IHash[] HPs;
        MiniSection Input;
        string FileIn;
        public ConcurrentDictionary<int, List<HashRecord>> hashes;


        public static HashRec[] CreateRecsFromMemory(byte[] MemPage, int minBlockSize, Func<HashLib.IHash> getHP, int OnlySize = 0, long VA = 0)
        {
            if (MemPage == null)
                return null;

            int RawSize = MemPage.Length;
            var topCnt = BlockCount(RawSize, PageSize);
            if (getHP == null)
                getHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            var levelMap = LevelMaps(RawSize, minBlockSize);
            int LevelCount = levelMap.Count();
            long TotalHashs = levelMap[LevelCount - 1].Item1 + levelMap[LevelCount - 1].Item2;
            HashLib.IHash[] localHashProv = new HashLib.IHash[LevelCount];

            var sHash = new HashRec[TotalHashs];

            if(OnlySize != 0)
            {
                LevelCount = 1;
                minBlockSize = OnlySize;
                TotalHashs = BlockCount(RawSize, minBlockSize);

                sHash = new HashRec[TotalHashs];
            }

            // smallest to largest orginization 
            for (int i = 0; i < LevelCount; i++)
                localHashProv[i] = getHP();

            for (byte lvl = 0; lvl < LevelCount; lvl++)
            {
                var blockSize = minBlockSize << lvl;
                var blockCnt = BlockCount(RawSize, blockSize);

                var hashLevelIndex = levelMap[lvl].Item1;

                localHashProv[lvl].Initialize();

                for (int arri = 0; arri < blockCnt; arri++)
                {
                    localHashProv[lvl].TransformBytes(MemPage, arri * blockSize, blockSize);
                    var hashBytes = localHashProv[lvl].TransformFinal().GetBytes();
                    sHash[hashLevelIndex + arri] = new HashRec(hashBytes, lvl);
                }
            }

            return sHash;
        }


        public static HashRecord[] CreateFromMemory(byte[] MemPage, int minBlockSize, Func<HashLib.IHash> getHP)
        {
            int RawSize = MemPage.Length;
            var topCnt = BlockCount(RawSize, PageSize);
            if (getHP == null)
                getHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            var levelMap = LevelMaps(RawSize, minBlockSize);
            int LevelCount = levelMap.Count();
            long TotalHashs = levelMap[LevelCount - 1].Item1 + levelMap[LevelCount - 1].Item2;
            HashLib.IHash[] localHashProv = new HashLib.IHash[LevelCount];
            var sHash = new HashRecord[TotalHashs];

            // smallest to largest orginization 
            for (int i = 0; i < LevelCount; i++)
                localHashProv[i] = getHP();

            for (byte lvl = 0; lvl < LevelCount; lvl++)
            {
                var blockSize = minBlockSize << lvl;
                var blockCnt = PageSize / blockSize;

                var hashLevelIndex = levelMap[lvl].Item1;

                localHashProv[lvl].Initialize();

                for (int arri = 0; arri < blockCnt; arri++)
                {
                    localHashProv[lvl].TransformBytes(MemPage, arri * blockSize, blockSize);
                    var hashBytes = localHashProv[lvl].TransformFinal().GetBytes();
                    sHash[hashLevelIndex + arri] = new HashRecord(hashBytes, lvl);
                }
            }

            return sHash;
        }

        public static HashRecord[] CreateFromFile(string BackingFile, MiniSection input, int minBlockSize, Func<HashLib.IHash> getHP)
        {
            int RawSize = (int) ((input.RawFileSize + 0xfff) & ~0xfff);
            //int VirtualSize = (int) input.VirtualSize;

            var topCnt = BlockCount(RawSize, PageSize);
            if (getHP == null)
                getHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            var levelMap = LevelMaps(RawSize, minBlockSize);
            int LevelCount = levelMap.Count();
            long TotalHashs = levelMap[LevelCount - 1].Item1 + levelMap[LevelCount - 1].Item2;

            var sHash = new HashRecord[TotalHashs];

            HashLib.IHash[] localHashProv = new HashLib.IHash[LevelCount];

            // smallest to largest orginization 
            for (int i = 0; i < LevelCount; i++)
                localHashProv[i] = getHP();

            byte[] pageBuf;
            byte[][] buffers = { new byte[PageSize], new byte[PageSize] };
            int filled = 0;

            // we do this many 4k Read's "top level"
            var TopCnt = levelMap[LevelCount - 1].Item2;

            using (var fs = new FileStream(BackingFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
            {
                fs.Position = input.RawFilePointer;
                int remaining = RawSize;

                int readIn = fs.Read(buffers[filled], 0, PageSize);
                remaining -= readIn;

                for (int i = 0; i < TopCnt; i++)
                {
                    // setup buffers for parallel load/read
                    pageBuf = buffers[filled];

                    // swap filled so parallel task can start loading while we compute previous chunk
                    filled ^= 1;

                    Parallel.Invoke(() =>
                    Parallel.For(0, LevelCount, (lvl) =>
                    {
                        var blockSize = (int) levelMap[lvl].Item3;
                        var blockCnt = PageSize / blockSize;
                        var hashLevelIndex = levelMap[lvl].Item1;

                        localHashProv[lvl].Initialize();

                        for (int arri = 0; arri < blockCnt; arri++)
                        {
                            localHashProv[lvl].TransformBytes(pageBuf, arri * blockSize, blockSize);
                            var hashBytes = localHashProv[lvl].TransformFinal().GetBytes();
                            sHash[hashLevelIndex + arri + (i * blockCnt)] = new HashRecord(hashBytes, (byte) lvl);
                        }
                    }), () => {
                        while (remaining > 0)
                        {
                            readIn = fs.Read(buffers[filled], 0, PageSize);
                            if (readIn < PageSize)
                            {
                                Array.Clear(buffers[filled], readIn, PageSize - readIn);
                                readIn = PageSize;
                            }

                            remaining -= readIn;
                        }
                    });
                }
            }
            return sHash;
        }

        public static long TotalHashesForSize(uint Size, int MinBlockSize)
        {
            long tally = 0;
            var AlignSize = ((Size + 0xfff) & ~0xfff);

            int iheight = TreeHeight(MagicNumbers.PAGE_SIZE, MinBlockSize);
            for (var i = 0; i < iheight; i++)
                tally += BlockCount(AlignSize, MinBlockSize << i);

            return tally;
        }

        public static HashRec[] CreateRecsFromFile(string BackingFile, MiniSection input, int minBlockSize, int Totalhash,  HashRec[] DestArr, int DestIdx, Func<HashLib.IHash> getHP)
        {
            int RawSize = (int)((input.RawFileSize + 0xfff) & ~0xfff);
            //int VirtualSize = (int) input.VirtualSize;

            var topCnt = BlockCount(RawSize, PageSize);
            if (getHP == null)
                getHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            var levelMap = LevelMaps(RawSize, minBlockSize);
            int LevelCount = levelMap.Count();
            long TotalHashs = levelMap[LevelCount - 1].Item1 + levelMap[LevelCount - 1].Item2;

            HashRec[] sHash = null;
            
            if(DestArr == null)
                sHash = new HashRec[TotalHashs];

            HashLib.IHash[] localHashProv = new HashLib.IHash[LevelCount];

            // smallest to largest orginization 
            for (int i = 0; i < LevelCount; i++)
                localHashProv[i] = getHP();

            byte[] pageBuf;
            byte[][] buffers = { new byte[PageSize], new byte[PageSize] };
            int filled = 0;

            // we do this many 4k Read's "top level"
            var TopCnt = levelMap[LevelCount - 1].Item2;

            using (var fs = new FileStream(BackingFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
            {
                fs.Position = input.RawFilePointer;
                int remaining = (int) input.RawFileSize;

                int readIn = fs.Read(buffers[filled], 0, PageSize);
                remaining -= readIn;

                if(remaining < 0)
                    Array.Clear(buffers[filled], (int) input.RawFileSize, PageSize - (int) input.RawFileSize);

                for (int i = 0; i < TopCnt; i++)
                {
                    // setup buffers for parallel load/read
                    pageBuf = buffers[filled];

                    // swap filled so parallel task can start loading while we compute previous chunk
                    filled ^= 1;

                    Parallel.Invoke(() =>
                    {
                        for (int lvl = 0; lvl < LevelCount; lvl++)
                        {
                            var blockSize = (int)levelMap[lvl].Item3;
                            var blockCnt = PageSize / blockSize;
                            var hashLevelIndex = levelMap[lvl].Item1;

                            localHashProv[lvl].Initialize();

                            for (int arri = 0; arri < blockCnt; arri++)
                            {
                                localHashProv[lvl].TransformBytes(pageBuf, arri * blockSize, blockSize);
                                var hashBytes = localHashProv[lvl].TransformFinal().GetBytes();

                                if(DestArr != null)
                                    DestArr[DestIdx + hashLevelIndex + arri + (i * blockCnt)] = new HashRec(hashBytes, (byte)lvl);
                                else 
                                    sHash[hashLevelIndex + arri + (i * blockCnt)] = new HashRec(hashBytes, (byte)lvl);
                            }
                        }
                    }, () => {
                        while (remaining > 0)
                        {
                            readIn = fs.Read(buffers[filled], 0, PageSize);
                            if (readIn < PageSize)
                            {
                                Array.Clear(buffers[filled], readIn, PageSize - readIn);
                                readIn = PageSize;
                            }
                            if(readIn > remaining)
                                Array.Clear(buffers[filled], remaining, readIn - remaining);

                            remaining -= readIn;

                        }

                    });
                }
            }
            return sHash;
        }

        public static long BlockCount(long insize, int BlockSize)
        {
            if (insize == 0) return 0;

            var count = insize / BlockSize;
            if (insize % BlockSize > 0) count++;

            return count;
        }

        public FractHashTree(int minBlockSize, Func<HashLib.IHash> getHP)
        {
            MinBlockSize = minBlockSize;
            List<HashLib.IHash> hList = new List<HashLib.IHash>();
            GetHP = getHP;
            if (GetHP == null)
                GetHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            hashes = new ConcurrentDictionary<int, List<HashRecord>>(); 
            for (int i = MinBlockSize; i <= PageSize; i *= 2)
            {
                hList.Add(GetHP());
                hashes[i] = new List<HashRecord>();
            }
            HPs = hList.ToArray();
            LevelCount = hList.Count();

        }

        public FractHashTree(byte[] MemPage, int minBlockSize, Func<HashLib.IHash> getHP)
            :this(minBlockSize, getHP)
        {

            for (byte lvl = 0; lvl < LevelCount; lvl++)
            {
                var blockSize = MinBlockSize << lvl;
                var blockCnt = PageSize / blockSize;
                HPs[lvl].Initialize();

                for (int arri = 0; arri < blockCnt; arri++)
                {
                    HPs[lvl].TransformBytes(MemPage, arri * blockSize, blockSize);
                    var hashBytes = HPs[lvl].TransformFinal().GetBytes();
                    hashes[blockSize].Add(new HashRecord(hashBytes, lvl));
                }
            }
        }

        public FractHashTree(string BackingFile, MiniSection input, int minBlockSize, Func<HashLib.IHash> getHP)
            :this(minBlockSize, getHP)
        {
            if (!IsPow2(minBlockSize))
                return;

            Input = input;
            FileIn = BackingFile;

            RunFromFile();
        }

        public List<HashRecord> DumpTree()
        {
            List<HashRecord> rv = new List<HashRecord>();
            foreach (var hashx in hashes.Values)
                rv.AddRange(hashx);

            return rv;
        }

        public List<HashRec> DumpRecTree()
        {
            List<HashRec> rv = new List<HashRec>();
            foreach (var hashx in hashes.Values)
                foreach (var hash in hashx)
                    rv.Add(hash as HashRecord);

            return rv;
        }


        void RunFromFile()
        {
            byte[] pageBuf;
            byte[][] buffers = { new byte[PageSize], new byte[PageSize] };
            int filled = 0;

            int RawSize = (int)((Input.RawFileSize + 0xfff) & ~0xfff);

            var TopCnt = BlockCount(RawSize, PageSize);

            using (var fs = new FileStream(FileIn, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fs.Position = Input.RawFilePointer;
                int readIn = fs.Read(buffers[filled], 0, PageSize);

                for (int i = 0; i < TopCnt; i++)
                {
                    // setup buffers for parallel load/read
                    pageBuf = buffers[filled];

                    // swap filled so parallel task can start loading while we compute previous chunk
                    filled ^= 1;

                    Parallel.Invoke(() => 
                    Parallel.For(0, LevelCount, (lvl) =>
                    {
                        var blockSize = MinBlockSize << (int)lvl;
                        var blockCnt = PageSize / blockSize;
                        HPs[lvl].Initialize();

                        for (int arri = 0; arri < blockCnt; arri++)
                        {
                            HPs[lvl].TransformBytes(pageBuf, arri * blockSize, blockSize);
                            var hashBytes = HPs[lvl].TransformFinal().GetBytes();
                            hashes[blockSize].Add(new HashRecord(hashBytes, (byte)lvl));
                        }
                    }), () => {
                        readIn = fs.Read(buffers[filled], 0, PageSize);
                        if (readIn < PageSize)
                            Array.Clear(buffers[filled], readIn, PageSize - readIn);
                    });
                }
            }
        }


        /// <summary>
        /// Checks the input number to identify if it is a power
        /// </summary>
        /// <param name="x"></param>
        /// <returns>True on a power</returns>
        public static bool IsPow2(ulong x)
        {
            return (x & (x - 1)) == 0;
        }
        /// <summary>
        /// Checks the input number to identify if it is a power
        /// </summary>
        /// <param name="x"></param>
        /// <returns>True on a power</returns>
        public static bool IsPow2(long x)
        {
            return (x & (x - 1)) == 0;
        }
        /// <summary>
        /// Return's the next higher POWER of 2 than the input number to the maximum of a long.
        /// If the input value is == a power of 2, the RETURN will be THE SAME AS THE INPUT
        /// </summary>
        /// <param name="v"></param>
        /// <returns>Next higher Power of 2</returns>
        public static ulong RoundUpPow2(ulong v)
        {
            v--;
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            v++;
            return v;
        }
        /// <summary>
        /// Return's the next higher POWER of 2 than the input number to the maximum of a long.
        /// If the input value is == a power of 2, the RETURN will be THE SAME AS THE INPUT
        /// </summary>
        /// <param name="v"></param>
        /// <returns>Next higher Power of 2</returns>
        public static long RoundUpPow2(long v)
        {
            v--;
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            v++;
            return v;
        }
        /// <summary>
        /// Return's the next lower power of 2 than the input number.
        /// If the input value is == a power of 2, the RETURN will be the SAME AS THE INPUT
        /// </summary>
        /// <param name="v"></param>
        /// <returns></returns>
        public static ulong RoundDownPow2(ulong v)
        {
            if (IsPow2(v)) return v;

            v--;
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            v++;
            return (v >> 1);
        }
        /// <summary>
        /// Return's the next lower power of 2 than the input number.
        /// If the input value is == a power of 2, the RETURN will be the SAME AS THE INPUT
        /// </summary>
        /// <param name="v"></param>
        /// <returns></returns>
        public static long RoundDownPow2(long v)
        {
            if (IsPow2(v)) return v;

            v--;
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            v++;
            return (v >> 1);
        }
        /// <summary>
        /// An array of Tuple which represent each level of what is required to generate a comprehensive tree for a given input size.
        /// 
        /// This makes it easy to do a single array w/o join's and too much dynamic allocation
        /// 
        /// Tuple of;
        ///     PARENT-TALLY (how many _TOTAL_ blocks for all levels above the current index),
        ///     Count (how many blocks are on this level,
        ///     Size (how large are the blocks at this level)
        /// </summary>
        /// <param name="insize">The input size</param>
        /// <returns>Tuple long, long</returns>
        public static IList<Tuple<long, long, long>> LevelMaps(long insize, int minSize)
        {
            long tally = 0, levCnt;
            int iheight = TreeHeight(MagicNumbers.PAGE_SIZE, minSize);
            var rv = new List<Tuple<long, long, long>>();

            for (var i = 0; i < iheight; i++)
            {
                levCnt = BlockCount(insize, minSize<<i);

                rv.Add(new Tuple<long, long, long>(tally, levCnt, minSize<<i));
                tally += levCnt;
            }
            return rv;
        }
        public static int TreeHeight(int MaxBlock, int MinBlock)
        {
            int rv = 1;

            int currblks = MinBlock;
            while (currblks < MaxBlock)
            {
                currblks = currblks << 1;
                rv++;
            }
            return rv;
        }

    }
}
