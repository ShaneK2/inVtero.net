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

namespace inVtero.net.Hashing
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
    public struct HashRec
    {
        public HashRec(byte[] Hash, byte blockLen)
        {
            // upper 15 bytes
            HashData = new byte[16];
            //Array.Copy(Hash, 0, HashData, 0, 16);

            for (int i = 0; i < 16; i++)
               HashData[i] = Hash[i];

            // keep the upper nibble
            HashData[15] = (byte)(HashData[15] & 0xf0);
            HashData[15] |= blockLen;

            // lower (variable sized) bytes are the index to the DB
            var indexLoc = Hash.Length - 8;

            // shift up since were 16 byte aligned
            Index = BitConverter.ToUInt64(Hash, indexLoc) << 4;
        }
        public byte[] HashData;
        public ulong Index;

        public override string ToString()
        {
            return Index.ToString("X");
        }
    }

    public class SparseRegion
    {
        public String OriginationInfo;
        public long Len;
        public long Address;

        public List<long> SparseAddrs = new List<long>();
        public List<bool[]> InnerCheckList = new List<bool[]>();
        public List<HashRec[]> InnerList = new List<HashRec[]>();
        public List<byte[]> Data = new List<byte[]>();

        public int Validated;
        public int Failed;
        public int Total;

        public double PercentValid { get {  return Total > 0 ? Validated * 100.0 / Total : 0.0; } }

        public override string ToString()
        {
            return $"Region: {OriginationInfo,70}\tAddr: {Address,20:X} Len: {Len,8:X} ({Validated,4}/{Total,4}) {PercentValid,12:N3}" ;
        }
    }

    /// <summary>
    /// HashRecord is the accounting class primative for storing data about hashrec's 
    /// </summary>
    public class HashRecord : IComparable
    {
        public List<SparseRegion> Regions;
        public DetectedProc DP;

        public HashRecord() {
            Regions = new List<SparseRegion>();
        }

        public void AddBlock(DetectedProc dp, string Info, long VA, HashRec[] hashes, byte[] data = null)
        {
            // first time
            if (Regions.Count == 0)
            {
                DP = dp;
                var r = new SparseRegion() { OriginationInfo = Info };
                if(data != null)
                    r.Data.Add(data);

                r.InnerList.Add(hashes);
                r.SparseAddrs.Add(VA);
                r.Address = VA;
                r.Len = 4096;
                Regions.Add(r);
                return;
            }
            
            foreach (var r in Regions)
            {
                // merge
                if (Info == r.OriginationInfo)
                {
                    r.Len += 4096;
                    r.SparseAddrs.Add(VA);
                    r.InnerList.Add(hashes);
                    r.Data.Add(data);
                    return;
                }
            }
            
            var rx = new SparseRegion() { OriginationInfo = Info, Address = VA };
            if(data != null)
                rx.Data.Add(data);

            rx.InnerList.Add(hashes);
            rx.SparseAddrs.Add(VA);
            rx.Len += 4096;
            Regions.Add(rx);
        }

        public HashRecord(byte[] Hash, byte blockLen)
        {
            // upper 15 bytes
            HashData = new byte[16];
            //Array.Copy(Hash, 0, HashData, 0, 16);

            for (int i = 0; i < 16; i++)
                HashData[i] = Hash[i];
            
            // keep the upper nibble
            HashData[15] = (byte) (HashData[15] & 0xf0);
            HashData[15] |= blockLen;

            // lower (variable sized) bytes are the index to the DB
            var indexLoc = Hash.Length - 8;

            // shift up since were 16 byte aligned
            Index = BitConverter.ToUInt64(Hash, indexLoc) << 4;
        }

        public static implicit operator HashRecord (HashRec rec)
        {
            return new HashRecord(rec.HashData, (byte) rec.Index);
        }
        public static implicit operator HashRec (HashRecord rec)
        {
            return new HashRec(rec.HashData, (byte)rec.Index);
        }

        public int CompareTo(object obj)
        {
            HashRecord hr = obj as HashRecord;
            if (hr == null) return -1;
            return Index.CompareTo(hr.Index);
        }

        public byte[] HashData;
        public ulong Index;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            foreach (var r in Regions)
                sb.AppendLine(r.ToString());

            return sb.ToString();
        }
    }
}
