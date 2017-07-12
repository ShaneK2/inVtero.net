using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace inVtero.net.Hashing
{
    public class HashRecord : IComparable
    {
        // we store in the DB 128 bit total
        // 4 bits are the blocklen 
        // 124 upper bits from the hash are stored in the table
        // the lower N bits (depending on available) are the index
        // so if it's 192 bit tiger, the upper 124 is stored
        // the lower 72 are the index (less than that so we loose a few bits)
        // for example a 1GB table would yield 67108864 entries (26 bits of index)
        // So for a 1GB table you have 150 bit of hash maintained 
        // PLUS a length specifier that indicates how large the input was that genrated that hash value
        public HashRecord(byte[] Hash, char blockLen)
        {
            // upper 15 bytes
            HashData = new byte[16];
            Array.Copy(Hash, 0, HashData, 0, 16);

            // keep the upper nibble
            HashData[15] = (byte) (HashData[15] & (byte) 0xf0);

            HashData[15] |= Convert.ToByte(blockLen);

            // len is the len we hashed for this block
            BlockLen = blockLen;

            // lower (variable sized) bytes are the index to the DB
            var indexLoc = Hash.Length - 8;

            // shift up since were 16 byte aligned
            Index = BitConverter.ToUInt64(Hash, indexLoc) << 4;
        }

        public int CompareTo(object obj)
        {
            HashRecord hr = obj as HashRecord;
            if (hr == null) return -1;
            return Index.CompareTo(hr.Index);
        }

        public byte[] HashData;
        public char BlockLen;
        public ulong Index;
    }
}
