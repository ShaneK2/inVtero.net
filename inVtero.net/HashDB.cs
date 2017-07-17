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
using ProtoBuf;
using inVtero.net.Hashing;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Threading;
using Reloc;

namespace inVtero.net
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class HashDB : IDisposable
    {
        public string HashDBFile;
        public string HashDBBitMap;
        public long DBSize;
        public long DBEntries;
        public long DBEntriesMask;
        public int MinBlockSize;

        public ReReDB ReRe;

        [ProtoIgnore]
        UnsafeHelp HDBBitMap;

        public HashDB(int minBlockSize, string DB, string relocFolder, long Size = 0) 
        {
            HashDBFile = DB;
            HashDBBitMap = DB + ".bin";
            if(Size !=0)
                DBSize = (long) FractHashTree.RoundUpPow2(Size);

            if (!File.Exists(HashDBFile))
            {
                if (!FractHashTree.IsPow2(DBSize))
                    throw new InternalBufferOverflowException($"DB SIZE not a power of 2!");

                using (var fileStream = new FileStream(HashDBFile, FileMode.Create, FileAccess.Write, FileShare.None))
                    fileStream.SetLength(DBSize + 4096);
            }
            else
                DBSize = (long)FractHashTree.RoundDownPow2(new FileInfo(HashDBFile).Length);

            // Divide by 16
            DBEntries = DBSize >> 4;
            DBEntriesMask = DBEntries - 1;

            MinBlockSize = minBlockSize;

            ReRe = new ReReDB(relocFolder);

            HDBBitMap = new UnsafeHelp(HashDBBitMap);
        }

        /// <summary>
        /// This will destroy the 'size' bit in the low nibble
        /// However, we set 2 bits instead of just having 1 set, so you know for sure it's been processed
        /// 
        /// We also know the size implcitially by the position in the HashRec array
        /// </summary>
        /// <param name="HR"></param>
        /// <returns></returns>
        public int BitmapScan(HashRec[] HR)
        {
            int SetBits = 0;
            for (int i = 0; i < HR.Length; i++)
            {
                if (GetIdxBit(HR[i].Index))
                {
                    // 0xA is A_OK!
                    HR[i].HashData[15] = (byte)
                        ((HR[i].HashData[15] & 0xF0) + 0xA);

                    SetBits++;
                } 
                else
                    // 0xF is FAIL!
                    HR[i].HashData[15] = (byte)
                        ((HR[i].HashData[15] & 0xF0) + 0xF);
            }

            return SetBits;
        }

        public bool GetIdxBit(ulong bit)
        {
            return HDBBitMap.GetBit(((long) bit >> 4) & DBEntriesMask);
        }

        public void SetIdxBit(ulong bit)
        {
            HDBBitMap.SetBit(((long) bit >> 4) & DBEntriesMask);
        }

        public void AddNullInput()
        {
            FileLoader fl = new FileLoader(this, 32);
            var wrote = fl.LoadFromMem(new byte[4096]);
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (HDBBitMap != null)
                        HDBBitMap.Dispose();

                    HDBBitMap = null;

                    disposedValue = true;
                }
            }
        }
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
