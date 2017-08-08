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
using static inVtero.net.MagicNumbers;
using RoaringCLI;

namespace inVtero.net
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class HashDB : IDisposable
    {
        public string HashDBFile;
        public string HashDBBitMap;
        public long DBSize;
        public ulong DBEntries;
        public ulong DBEntriesMask;
        public int MinBlockSize;
        public ulong BDBEntriesMask;
        public ReReDB ReRe;

        [ProtoIgnore]
        RoarCLI r;

        [ProtoIgnore]
        UnsafeHelp HDBBitMap;
        

        /// <summary>
        /// HashDB manager
        /// MUST BE A POWER OF 2
        /// </summary>
        /// <param name="minBlockSize">POWER of 2</param>
        /// <param name="DB">Primary DB</param>
        /// <param name="relocFolder">Relocation data</param>
        /// <param name="Size">POWER OF 2!</param>
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

                using (var fileStream = new FileStream(HashDBFile, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
                    fileStream.SetLength(DBSize + (DB_READ_SIZE));
            }
            else
                DBSize = (long)FractHashTree.RoundDownPow2(new FileInfo(HashDBFile).Length);

            // Divide by HASH size
            DBEntries = (ulong) DBSize >> HASH_SHIFT;
            DBEntriesMask = (ulong) DBEntries - 1;

            MinBlockSize = minBlockSize;

            ReRe = new ReReDB(relocFolder);

            // arbitrarially big
            BDBEntriesMask = (DBEntriesMask << 3) | 0xfff;
            //r = new RoarCLI();
            //LoadBDB(HashDBBitMap);

            HDBBitMap = new UnsafeHelp(HashDBBitMap, (long)BDBEntriesMask+1);
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
                    HR[i].Verified = true;
                    SetBits++;
                }
                else
                    HR[i].Verified = false;
            }

            return SetBits;
        }

        public bool GetIdxBit(ulong bit)
        {
            //return r.contains((bit >> HASH_SHIFT) & BDBEntriesMask);

            return HDBBitMap.GetBit((bit >> HASH_SHIFT) & BDBEntriesMask);
        }

        public void SetIdxBit(ulong bit)
        {
            //r.add((bit >> HASH_SHIFT) & BDBEntriesMask);
            
            HDBBitMap.SetBit((bit >> HASH_SHIFT) & BDBEntriesMask);
        }
        /*
        public void AddNullInput()
        {
            FileLoader fl = new FileLoader(this, 32);
            var wrote = fl.LoadFromMem(new byte[MagicNumbers.PAGE_SIZE]);
        }
        */
        public void LoadBDB(string aFile)
        {
            return;
            if (File.Exists(aFile))
            {
                var bdbytes = File.ReadAllBytes(aFile);
                r = RoarCLI.read(bdbytes, false);
            }
        }
        public void Save()
        {
            // file map does not need this
            return;

            Misc.WriteColor(ConsoleColor.Black, ConsoleColor.Green, $"CRITICAL: SAVING BITMAP DATABASE!!! WAIT JUST A SECOND PLEASE!!!");

            var sizeNeeded = r.getSizeInBytes(false);
            var buff = new byte[sizeNeeded];
            r.write(buff, false);
            File.WriteAllBytes(HashDBBitMap, buff);
            Misc.WriteColor(ConsoleColor.Green, ConsoleColor.Black, $"Done.  Commited {sizeNeeded:N0} bytes to disk for bitmap.");
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
