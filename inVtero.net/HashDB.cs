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

namespace inVtero.net
{
    [ProtoContract(AsReferenceDefault = true, ImplicitFields = ImplicitFields.AllPublic)]
    public class HashDB : IDisposable
    {
        public string HashDBFile;
        public string HashDBBitMap;
        public string RelocFolder;
        public long DBSize;
        public long DBEntries;
        public long DBEntriesMask;

        public string Reloc64Dir;
        public string Reloc32Dir;

        [ProtoIgnore]
        public MemoryMappedFile BitMap;
        [ProtoIgnore]
        public MemoryMappedViewAccessor BitMapView;
        [ProtoIgnore]
        public UnsafeHelp Bit;

        public HashDB(string DB, string relocFolder, long Size = 0) 
        {
            HashDBFile = DB;
            HashDBBitMap = DB + ".bin";
            if(Size !=0)
                DBSize = (long) FractHashTree.RoundUpPow2(Size);
            RelocFolder = relocFolder;

            Init();
        }

        public int BitmapScan(HashRec[] HR)
        {
            int SetBits = 0;
            Parallel.ForEach(HR, (rec) =>
            {
                if (GetIdxBit(rec.Index))
                    Interlocked.Increment(ref SetBits);
            });
            return SetBits;
        }

        public bool GetIdxBit(ulong bit)
        {
            return Bit.GetBit(BitMapView, ((long) bit >> 4) & DBEntriesMask);
        }

        public void SetIdxBit(ulong bit)
        {
            Bit.SetBit(BitMapView, ((long) bit >> 4) & DBEntriesMask);
        }

        void Init()
        {
            Reloc64Dir = Path.Combine(RelocFolder, "64");
            Reloc32Dir = Path.Combine(RelocFolder, "32");

            if (!Directory.Exists(Reloc64Dir))
                Directory.CreateDirectory(Reloc64Dir);
            if (!Directory.Exists(Reloc32Dir))
                Directory.CreateDirectory(Reloc32Dir);

            if (!File.Exists(HashDBFile))
            {
                if(!FractHashTree.IsPow2(DBSize))
                    throw new InternalBufferOverflowException($"DB SIZE not a power of 2!");

                using (var fileStream = new FileStream(HashDBFile, FileMode.Create, FileAccess.Write, FileShare.None))
                    fileStream.SetLength(DBSize + 4096);
            } else
                DBSize = (long)FractHashTree.RoundDownPow2(new FileInfo(HashDBFile).Length);
            
            // Divide by 16
            DBEntries = DBSize >> 4;
            DBEntriesMask = DBEntries - 1;

            // is there a bitmap?
            BitMap = MemoryMappedFile.CreateFromFile(HashDBBitMap, FileMode.OpenOrCreate, "HDBBitMap" + Thread.CurrentThread.ManagedThreadId.ToString(), DBEntries >> 3);
            BitMapView = BitMap.CreateViewAccessor();

            Bit = new UnsafeHelp();
            Bit.GetBitmapHandle(BitMapView);
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
                { }

                if (BitMapView != null && Bit != null)
                {
                    Bit.ReleaseBitmapHandle(BitMapView);
                    Bit = null;
                }
                if (BitMapView != null)
                    BitMapView.Dispose();
                if(BitMap != null)
                    BitMap.Dispose();

                disposedValue = true;
            }
        }

        ~HashDB() {
           // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
           Dispose(false);
         }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
