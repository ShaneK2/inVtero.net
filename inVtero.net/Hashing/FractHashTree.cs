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

        long DBSize = 0;
        const int PageSize = 4096;

        HashLib.IHash[] HPs;
        MiniSection Input;
        string FileIn;
        public ConcurrentDictionary<int, List<HashRecord>> hashes = new ConcurrentDictionary<int, List<HashRecord>>();

        public FractHashTree()
        { }

        public long BlockCount(uint insize, int BlockSize)
        {
            if (insize == 0) return 0;

            var count = insize / BlockSize;
            if (insize % BlockSize > 0) count++;

            return count;
        }

        public FractHashTree(string BackingFile, MiniSection input, int minBlockSize, Func<HashLib.IHash> getHP, long aDBSize = 0)
        {
            if (!IsPow2(minBlockSize))
                return;

            Input = input;
            MinBlockSize = minBlockSize;
            FileIn = BackingFile;
            var insize = input.RawFileSize;
            List<HashLib.IHash> hList = new List<HashLib.IHash>();
            DBSize = aDBSize;

            for (int i = MinBlockSize; i <= PageSize; i *= 2)
            {
                hList.Add(getHP());
                hashes[i] = new List<HashRecord>();
            }
            HPs = hList.ToArray();
            LevelCount = hList.Count();

            Run();
        }

        public List<HashRecord> DumpTree()
        {
            List<HashRecord> rv = new List<HashRecord>();
            foreach(var hashx in hashes.Values)
                rv.AddRange(hashx);

            return rv;
        }

        public void Run()
        {
            byte[] pageBuf;
            byte[][] buffers = { new byte[PageSize], new byte[PageSize] };
            int filled = 0;

            var TopCnt = BlockCount(Input.RawFileSize, PageSize);

            using (var fs = new FileStream(FileIn, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
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
                        var blockSize = (char) (MinBlockSize << (int)lvl);
                        var blockCnt = PageSize / blockSize;
                        HPs[lvl].Initialize();

                        for (int arri = 0; arri < blockCnt; arri++)
                        {
                            HPs[lvl].TransformBytes(pageBuf, arri * blockSize, blockSize);
                            var hashBytes = HPs[lvl].TransformFinal().GetBytes();
                            hashes[blockSize].Add(new HashRecord(hashBytes, (char)lvl));
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
    }
}
