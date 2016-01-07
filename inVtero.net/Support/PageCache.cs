using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Caching;
using System.Collections.Concurrent;

namespace inVtero.net.Support
{
    /// <summary>
    /// I've never been entirely satisfied with MemoryCache
    /// Anyhow, for my purposes I want a basic LRU, which they don't implement in .net4
    /// 
    /// Since we have ConcurrentDictionary this is a fairly trivial task, can probably 
    /// concretely implement this by encapsulating a couple methods, since were locked automatically
    /// and the underlying data is read only, pretty safe
    /// 
    /// Also since I know my key is the PFN, which can not be larger than (64 >> 12)
    /// I can cheaply use the upper 12 bits of the key as the ref count
    /// </summary>
    public class PageCache : ConcurrentDictionary<long, long[]>
    {
        internal class RefCountingComparer : IEqualityComparer<long>
        {
            const long Lower48Bits = 0xffffFFFFffff;
            public bool Equals(long a, long b) { return (a & Lower48Bits).Equals(b & Lower48Bits); }

            public int GetHashCode(long obj) { return (obj & Lower48Bits).GetHashCode(); }
        }

        public static bool Initalized;
        static ConcurrentDictionary<long, long[]> Global;
        static int Capacity;
        static int RemovalRate;
        static int RemovalRateBar;
        static IEqualityComparer<long> refCountingComparer = new RefCountingComparer();

        public static void InitPageCache(int Parallelism, int capacity)
        {
            Initalized = true;

            Capacity = capacity;
            RemovalRate = Capacity / 100;
            RemovalRateBar = RemovalRate / 10;
            Global = new ConcurrentDictionary<long, long[]>(Parallelism, capacity, refCountingComparer);
        }
        static long[] OutVar = new long[512];

        /// <summary>
        /// Specialized Add for PFN cache
        /// </summary>
        /// <param name="Key">Must be pre-shifted, upper 16 bits are used for ref counting</param>
        /// <param name="Value"></param>
        /// <returns></returns>
        public static new bool TryAdd(long Key, long[] Value) 
        {
            // leave some wiggle room for other threads so maybe we don't block too much
            if ((Global.Count + RemovalRateBar) >= Capacity)
            {
                var next_remove = (from entry in Global.Keys
                                   where (((entry >> 48) & 0xffff) <= 2) // instead of 2 I should really keep an average ref count 
                                   select entry).Take(RemovalRate).AsParallel().All(taken => Global.TryRemove(taken, out OutVar));  // 1% by default
                
                // might be a good idea to reduce the current count of all entries by 1/2 to ensure liveness
                // but this whole thing should be relatively short lived I don't foresee a huge population of max-aged items

            }
            return Global.TryAdd(Key, Value);
        }

        public static new bool TryGetValue(long Key, out long[] Value)
        {
            bool rv = false;

            //remove
            rv = Global.TryRemove(Key, out Value);

            // update ref count
            long cnt = (Key & 0x7fff000000000000)>>48;
            if (cnt < 0xffff)
                cnt++;

            // re-add
            TryAdd((Key | (cnt << 48)), Value);
            
            // return
            return rv;
        }

        public static new bool ContainsKey(long Key)
        {
            return Global.ContainsKey(Key);
        }
    }
}
