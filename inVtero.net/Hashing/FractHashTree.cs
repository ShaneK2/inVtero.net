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
using static inVtero.net.MagicNumbers;

namespace inVtero.net.Hashing
{
    // HashFactory that will generate all hashes from minsize blocks to 4096
    public class FractHashTree
    {
        public int MinBlockSize = 0;
        public long LevelCount = 0;

        //Func<HashLib.IHash> GetHP;
        //HashLib.IHash[] HPs;
        public ConcurrentDictionary<int, List<HashRecord>> hashes;


        public static HashRec[] CreateRecsFromMemory(byte[] MemPage, int minBlockSize, Func<HashLib.IHash> getHP, int rID = 0, long VA = 0, int OnlySize = 0, bool PreSerialize = false)
        {
            if (MemPage == null)
                return null;

            // TESTING
            OnlySize = 64;
            //var LevelCount = 1;
            int RawSize = MemPage.Length;
            var TotalHashs = BlockCount(RawSize, minBlockSize);

            //var topCnt = BlockCount(RawSize, PAGE_SIZE);
            if (getHP == null)
                getHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });
            /*
            var levelMap = LevelMaps(RawSize, minBlockSize);
            int LevelCount = levelMap.Count();
            long TotalHashs = levelMap[LevelCount - 1].Item1 + levelMap[LevelCount - 1].Item2;
            */
            HashLib.IHash localHashProv;

            var sHash = new HashRec[TotalHashs];

            //if(OnlySize != 0)
            //{
                minBlockSize = OnlySize;
                //sHash = new HashRec[TotalHashs];
            //}

            // smallest to largest orginization 
           // for (int i = 0; i < LevelCount; i++)
                localHashProv = getHP();

            //for (byte lvl = 0; lvl < LevelCount; lvl++)
            //{
                //var blockSize = minBlockSize << lvl;
                //var blockCnt = BlockCount(RawSize, OnlySize);

                //ar hashLevelIndex = levelMap[lvl].Item1;

                localHashProv.Initialize();

                for (int arri = 0; arri < TotalHashs; arri++)
                {
                    localHashProv.TransformBytes(MemPage, arri * OnlySize, OnlySize);
                    var hashBytes = localHashProv.TransformFinal().GetBytes();

                    sHash[arri] = new HashRec(hashBytes, 0, rID);

                    // trying to reduce some load in the DB commit path
                    if(PreSerialize)
                        sHash[arri].Serialized = HashRec.ToByteArr(sHash[arri]);
                }
            //}
            return sHash;
        }


        public static long TotalHashesForSize(uint Size, int MinBlockSize)
        {
            long tally = 0;
            var AlignSize = ((Size + 0xfff) & ~0xfff);

            // TESTING
            //int iheight = TreeHeight(64, 64);
            //for (var i = 0; i < iheight; i++)
                tally += BlockCount(AlignSize, MinBlockSize);

            return tally;
        }

#if FALSE

        public List<bool> FileChecker(string aPath, bool Force = false, int OnlySize = 0)
        {
            var rv = new List<bool>();
            var inputFile = CheckFile(aPath);
            if (inputFile != null || Force)
            {
                if (Force && inputFile == null)
                {
                    var toCheck = FractHashTree.CreateRecsFromMemory(File.ReadAllBytes(aPath), MinHashSize, GetHP, 0, 0, OnlySize);
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
                        FractHashTree.CreateRecsFromFile(aPath, ms, MinHashSize, (int)totSiz, hr, 0, GetHP);
                        rv.AddRange(HashRecLookup(hr));
                    }
                }
            }
            return rv;
        }
        public static HashRec[] CreateRecsFromFile(string BackingFile, MiniSection input, int minBlockSize, int Totalhash,  HashRec[] DestArr, int DestIdx, Func<HashLib.IHash> getHP)
        {
            int RawSize = (int)((input.RawFileSize + 0xfff) & ~0xfff);
            //int VirtualSize = (int) input.VirtualSize;

            var topCnt = BlockCount(RawSize, PAGE_SIZE);
            if (getHP == null)
                getHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            /*
            var levelMap = LevelMaps(RawSize, minBlockSize);
            int LevelCount = levelMap.Count();
            long TotalHashs = levelMap[LevelCount - 1].Item1 + levelMap[LevelCount - 1].Item2;
            */
            int LevelCount = 1;
            var TotalHashs = BlockCount(RawSize, minBlockSize);
            HashRec[] sHash = null;
            
            if(DestArr == null)
                sHash = new HashRec[TotalHashs];

            HashLib.IHash[] localHashProv = new HashLib.IHash[LevelCount];

            // smallest to largest orginization 
            for (int i = 0; i < LevelCount; i++)
                localHashProv[i] = getHP();

            byte[] pageBuf;
            byte[][] buffers = { new byte[PAGE_SIZE], new byte[PAGE_SIZE] };
            int filled = 0;

            // we do this many 4k Read's "top level"
            // var TopCnt = levelMap[LevelCount - 1].Item2;
            var TopCnt = 1;
            using (var fs = new FileStream(BackingFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
            {
                fs.Position = input.RawFilePointer;
                int remaining = (int) input.RawFileSize;

                int readIn = fs.Read(buffers[filled], 0, PAGE_SIZE);
                remaining -= readIn;

                if(remaining < 0)
                    Array.Clear(buffers[filled], (int) input.RawFileSize, PAGE_SIZE - (int) input.RawFileSize);

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
                            //var blockSize = (int)levelMap[lvl].Item3;
                            //var blockCnt = PAGE_SIZE / blockSize;
                            //var hashLevelIndex = levelMap[lvl].Item1;

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
                            readIn = fs.Read(buffers[filled], 0, PAGE_SIZE);
                            if (readIn < PAGE_SIZE)
                            {
                                Array.Clear(buffers[filled], readIn, PAGE_SIZE - readIn);
                                readIn = PAGE_SIZE;
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
        
        public FractHashTree(int minBlockSize, Func<HashLib.IHash> getHP)
        {
            MinBlockSize = minBlockSize;
            List<HashLib.IHash> hList = new List<HashLib.IHash>();
            GetHP = getHP;
            if (GetHP == null)
                GetHP = new Func<HashLib.IHash>(() => { return HashLib.HashFactory.Crypto.CreateTiger2(); });

            hashes = new ConcurrentDictionary<int, List<HashRecord>>(); 
            for (int i = MinBlockSize; i <= PAGE_SIZE; i *= 2)
            {
                hList.Add(GetHP());
                hashes[i] = new List<HashRecord>();
            }
            HPs = hList.ToArray();
            LevelCount = hList.Count();

        }

#endif
        public static long BlockCount(long insize, int BlockSize)
        {
            if (insize == 0) return 0;

            var count = insize / BlockSize;
            if (insize % BlockSize > 0) count++;

            return count;
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
            int iheight = TreeHeight(PAGE_SIZE, minSize);
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
