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
#if !NETSTANDARD2_0
using static inVtero.net.Hashing.CloudDB;
#endif
using static inVtero.net.MagicNumbers;

namespace inVtero.net.Hashing
{
    /// <summary>
    /// Total Record Size = 32 bytes
    /// 160 bit's reserved for hash check explicitally
    /// variable amount of bit's used as the index location in the DB
    /// 8 GB DB = 268435456 entries = 1111 1111 1111 1111 1111 1111 1111 (28 more bit's)
    /// so an 8GB DB give's you effectivally 188 bit of un-wasted bits
    /// </summary>
    public struct HashRec
    {
        // TODO: port this back to reference type makes all the scatter/gathering so much easier
        // at the cost of a higher generation tax
        public HashRec(byte[] Hash, byte blockLenFlag, int rID = 0)
        {
            RID = rID << 2;
            RID |= blockLenFlag; // 0 = 128, 1 = 256, 2 = 512, 3 = 1024, 4 = 2048|4096

            CompressedHash = BitConverter.ToUInt64(Hash, 0);
            CompressedShortHash = BitConverter.ToUInt32(Hash, 8);
            Index = BitConverter.ToUInt64(Hash, Hash.Length - 8) << HASH_SHIFT;

            //Owner = null;
            Serialized = null;
            FullHash = Hash;
            Address = 0;
        }

        public HashRec(byte[] Hash, uint blockLen, int rID = 0)
        {
            RID = rID;
            CompressedShortHash = blockLen;
            CompressedHash = 0;
            Index = 0;

            //Owner = null;
            Serialized = null;
            FullHash = Hash;
            Address = 0;
        }

        public static HashRec Default
        {
            get
            {
                return new HashRec()
                {
                    CompressedShortHash = 0,
                    RID = 0,
                    CompressedHash = 0,
                    Index = 0,
                    Serialized = null,
                    FullHash = null,
                    //Owner = null,
                    Address = 0
                };
            }
        }

        public long Address;
        public ulong Index;
        public int RID;
        public uint CompressedShortHash;
        public ulong CompressedHash;
        public byte[] FullHash;
        public byte[] Serialized;

        // only need this if were grouping across processes
        //public HashRecord Owner;

        public static byte[] ToByteArrNoRID(HashRec rec)
        {
            byte[] rv = new byte[12];
            Array.Copy(BitConverter.GetBytes(rec.CompressedHash), 0, rv, 0, 8);
            Array.Copy(BitConverter.GetBytes(rec.CompressedShortHash), 0, rv, 8, 4);
            return rv;
        }

        public static byte[] ToByteArr(HashRec rec)
        {
            byte[] rv = new byte[HASH_REC_BYTES];

            //Array.Copy(rec.HashData, 0, rv, 0, rec.HashData.Length);

            Array.Copy(BitConverter.GetBytes(rec.CompressedHash), 0, rv, 0, 8);
            Array.Copy(BitConverter.GetBytes(rec.CompressedShortHash), 0, rv, 8, 4);
            Array.Copy(BitConverter.GetBytes(rec.RID), 0, rv, 12, 4);
            
            //Array.Copy(rec.HD2, 0, rv, 20, 3);
            //rv[24] = rec.BlockLen;
            // theorietcally we can use more of this for other purposes
            // since the index is the location in the DB..
            // depending on size, usually like 30something+ bits

            return rv;
        }
        public static HashRec FromBytes(Byte[] arr)
        {
            HashRec rec;
            //rec.HashData = new byte[16];
            //rec.HD2 = new byte[3];
            //Array.Copy(arr, 0, rec.HashData, 0, 16);
            //rec.RID = BitConverter.ToInt32(arr, 16);
            //Array.Copy(arr, 20, rec.HD2, 0, 3);
            //rec.BlockLen = arr[24];

            rec.CompressedHash = BitConverter.ToUInt64(arr, 0);
            rec.CompressedShortHash = BitConverter.ToUInt32(arr, 8);
            rec.RID = BitConverter.ToInt32(arr, 12);
            rec.Serialized = null;
            rec.Index = 0;
            rec.FullHash = arr;
            //rec.Owner = null;
            rec.Address = 0;
            return rec;
        }
#if A32byteFormat
        public HashRec(byte[] Hash, byte blockLen, long VA = 0, int rID = 0) 
        {

            RID = rID;
            BlockLen = blockLen;

            HashData = new byte[16];
            HD2 = new byte[4];

            for (int i = 0; i < 16; i++)
               HashData[i] = Hash[i];

            for (int i = 16, j = 0; i < 20; i++, j++)
                HD2[j] = Hash[i];

            // lower (variable sized) bytes are the index to the DB
            var indexLoc = Hash.Length - 8;

            // shift up since were 16 byte aligned
            Index = BitConverter.ToUInt64(Hash, indexLoc) << HASH_SHIFT;

            Serialized = null;
        }


        /*
        public byte[] HashData; // 16
        public int RID;         // 4 remote ID (meta DB)
        public byte BlockLen;   // 1
                                // public int Verified  // we steal 1 bit from RID to signafy at run time (since were a value struct) if verify was succsess
                                // oddly enough a negative RID mean's PASSED verification
        public byte[] HD2;      // 3
        public ulong Index;     // 8

        public byte[] Serialized;
        */
        public static byte[] ToByteArr(HashRec rec)
        {
            byte[] rv = new byte[HASH_REC_BYTES];

            Array.Copy(rec.HashData, 0, rv, 0, rec.HashData.Length);
            Array.Copy(BitConverter.GetBytes(rec.RID), 0, rv, 16, 4);
            Array.Copy(rec.HD2, 0, rv, 20, 3);
            rv[24] = rec.BlockLen;

            // theorietcally we can use more of this for other purposes
            // since the index is the location in the DB..
            // depending on size, usually like 30something+ bits
            Array.Copy(BitConverter.GetBytes(rec.Index), 0, rv, 24, 8);

            return rv;
        }
        public static HashRec FromBytes(Byte[] arr)
        {
            HashRec rec;
            rec.HashData = new byte[16];
            rec.HD2 = new byte[3];

            Array.Copy(arr, 0, rec.HashData, 0, 16);

            rec.RID = BitConverter.ToInt32(arr, 16);

            Array.Copy(arr, 20, rec.HD2, 0, 3);
            rec.BlockLen = arr[24];

            rec.Index = BitConverter.ToUInt64(arr, 24);
            rec.Serialized = null;
            return rec;
        }
#endif
        public bool Verified { get { return RID < 0; } set { if (value) RID |= int.MinValue; else RID = RID & int.MaxValue; } }
        public int Size { get { return RID & 0x3; } }

        public override string ToString() => Index.ToString("X");

    }

    public class SparseRegion
    {
        public String OriginationInfo;
        public long Len;
        public long Address;

        public List<long> SparseAddrs = new List<long>();
        public List<bool[]> InnerCheckList = new List<bool[]>();
        public List<HashRec[]> InnerList = new List<HashRec[]>();
#if !NETSTANDARD2_0
        public List<HashEntity[]> InnerCloudList = new List<HashEntity[]>();
#endif
        public List<byte[]> Data = new List<byte[]>();

        public int Validated;
        public int Failed;
        public int Total;

        public double PercentValid { get {  return Total > 0 ? Validated * 100.0 / Total : 0.0; } }

        public override string ToString() => $"Region: {OriginationInfo,70}\tAddr: {Address,20:X} Len: {Len,8:X} ({Validated,4}/{Total,4}) {PercentValid,12:N3}" ;


        public IEnumerable<long> GetFailedOffsets(int MinSizeBlock)
        {
            for(int i=0; i < SparseAddrs.Count; i++)
            {
                var saddr = SparseAddrs[i];
                var countOfSmallestHashBlocks = InnerList[i].Count();

                for (int h=0; h < countOfSmallestHashBlocks; h++)
                {
                    //var hashInfo = InnerList[i][h].HashData[15] & 0xf;
                    if(!InnerList[i][h].Verified)
                        yield return saddr + (h * MinSizeBlock);
                }
            }
        }
    }

    /// <summary>
    /// HashRecord is the accounting class primative for storing data about hashrec's 
    /// </summary>
    public class HashRecord 
    {
        public List<SparseRegion> Regions;

        public HashRecord() {
            Regions = new List<SparseRegion>();
        }

        // copy inner lists to a giant array
        public HashRec[] GetAllRecs()
        {
            var rv = from r in Regions
                     from s in r.InnerList
                     from h in s
                     select h;
            return rv.ToArray();
        }

        // gather scatter blocks & assign back from results into appropiate region/address
        public void AssignRecResults(IEnumerable<HashRec> results)
        {
            foreach(var h in results)
            {
                bool breakAll = false;
                foreach (var region in Regions)
                {
                    for(int sa=0; sa < region.SparseAddrs.Count; sa++)
                    {
                        var addr = region.SparseAddrs[sa];
                        if (h.Address >= addr && h.Address < addr + PAGE_SIZE)
                        {
                            for (int l = 0; l < region.InnerList[sa].Length; l++)
                            {
                                var innerHash = region.InnerList[sa][l];
                                if (innerHash.Address == h.Address)
                                {
                                    if (h.Verified)
                                    {
                                        innerHash.Verified = true;
                                        region.Validated++;
                                    } 
                                    region.Total++;
                                    breakAll = true;
                                    break;
                                }
                            }
                        }
                        if (breakAll) break;
                    }
                    if (breakAll) break;
                }
            }
        }

        public void AddBlock(string Info, long VA, HashRec[] hashes, int validated)
        {
            if (Regions.Count == 0)
            {
                var r = new SparseRegion() { OriginationInfo = Info };
                r.SparseAddrs.Add(VA);
                r.InnerList.Add(hashes);
                r.Address = VA;
                r.Len = PAGE_SIZE;
                r.Validated = validated;
                r.Total = hashes.Length;
                Regions.Add(r);
                return;
            }

            foreach (var r in Regions)
            {
                // merge
                if (Info == r.OriginationInfo)
                {
                    r.Validated += validated;
                    r.Total += hashes.Length;
                    r.Len += PAGE_SIZE;
                    r.SparseAddrs.Add(VA);
                    r.InnerList.Add(hashes);
                    return;
                }
            }

            var rx = new SparseRegion() { OriginationInfo = Info, Address = VA };
            rx.SparseAddrs.Add(VA);
            rx.InnerList.Add(hashes);
            rx.Len += PAGE_SIZE;
            rx.Validated += validated;
            rx.Total += hashes.Length;

            Regions.Add(rx);
        }

        public void AddBlock(string Info, long VA, HashRec[] hashes, byte[] data = null)
        {
            // first time
            if (Regions.Count == 0)
            {
                var r = new SparseRegion() { OriginationInfo = Info };
                if (data != null)
                    r.Data.Add(data);

                r.InnerList.Add(hashes);
                r.SparseAddrs.Add(VA);
                r.Address = VA;
                r.Len = PAGE_SIZE;
                Regions.Add(r);
                return;
            }

            foreach (var r in Regions)
            {
                // merge
                if (Info == r.OriginationInfo)
                {
                    r.Len += PAGE_SIZE;
                    r.SparseAddrs.Add(VA);
                    r.InnerList.Add(hashes);
                    r.Data.Add(data);
                    return;
                }
            }

            var rx = new SparseRegion() { OriginationInfo = Info, Address = VA };
            if (data != null)
                rx.Data.Add(data);

            rx.InnerList.Add(hashes);
            rx.SparseAddrs.Add(VA);
            rx.Len += PAGE_SIZE;
            Regions.Add(rx);
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            foreach (var r in Regions)
                sb.AppendLine(r.ToString());

            return sb.ToString();
        }
    }
}
